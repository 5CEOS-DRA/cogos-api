'use strict';

/**
 * Substrate per-key state · the stateful primitive that turns the
 * substrate from a callable function library into a queryable memory
 * layer.
 *
 * v0.1 (2026-05-26). Closes the last of the four "years-ahead substrate
 * engineering" pieces. Stateful substrate is the leap that makes 5CEOs
 * structurally beyond what LLM-based systems can do today: bit-exact
 * recall of every prior mutation with a hash-chained audit per change.
 *
 * What this module is:
 *   A pure-function event-journal engine. State is a sequence of
 *   mutations; the current state is the materialization of the
 *   journal. The journal is hash-chained per-key so any mutation
 *   tampers with every subsequent row's hash. Reading state is
 *   deterministic replay.
 *
 *   The engine is storage-agnostic. It does not read or write files,
 *   open databases, or talk to the network. The caller supplies the
 *   journal (as an array of rows) and the engine materializes /
 *   verifies / extends it. The cogos-api gateway is responsible for
 *   loading the journal from durable storage and persisting new rows.
 *
 * Journal row shape:
 *   {
 *     ts:           ISO-8601 string · authoritative-clock-set,
 *     mutation:     'matter.upsert' | 'matter.archive' | 'parties.upsert' | ...
 *     payload:      mutation-specific canonical body,
 *     prev_hash:    sha256: of the prior row in this key's journal
 *                   (or workflow-anchor hash for row 0),
 *     row_hash:     sha256:(canonical(row without row_hash)),
 *   }
 *
 * Materialized state shape (current snapshot):
 *   {
 *     state_version: <integer · number of mutations applied>,
 *     state_hash:    sha256: of the last row in the journal,
 *     matters:       { [matter_id]: <Matter> },
 *     parties:       { [matter_id]: <Party[]> },
 *   }
 *
 * The schema mirrors the 5Law conflict engine input contract so that
 * stored state can feed POST /v1/process/5law-conflict-check directly:
 *   firm_matters         = Object.values(state.matters).filter(active)
 *   parties_by_matter_id = state.parties
 *
 * Determinism contract:
 *   - For a journal J, materialize(J) is bitwise-stable across calls.
 *   - For two journals J1 and J2 with the same canonical-bytes,
 *     state_hash(J1) === state_hash(J2).
 *   - Appending a mutation to J produces J' whose state_hash is a
 *     pure function of J's prior state_hash and the canonical
 *     mutation payload.
 *
 * Mutations supported in v0.1:
 *   - matter.upsert    · payload = { id, status, practice_area, ... }
 *   - matter.archive   · payload = { id }
 *   - parties.upsert   · payload = { matter_id, parties: [...] }
 *   - parties.remove   · payload = { matter_id, party_ids: [...] }
 *
 * What this module does NOT do:
 *   - Cross-key access · each key's journal is isolated. Multi-tenant
 *     enforcement is the gateway layer's concern.
 *   - Point-in-time queries · v0.1 materializes the latest state only.
 *     state_version is the integer cursor; replaying to an earlier
 *     version is roadmap.
 *   - Conflict resolution · last-write-wins on upserts. Operational
 *     concerns about concurrent writers are gateway-layer.
 *   - LLM-anything.
 */

const crypto = require('node:crypto');
const { canonicalize, canonicalBytes, canonicalHash } = require('./_canonicalize');

const STATE_ENGINE_VERSION = 1;

const MUTATION_KIND = Object.freeze({
  MATTER_UPSERT:   'matter.upsert',
  MATTER_ARCHIVE:  'matter.archive',
  PARTIES_UPSERT:  'parties.upsert',
  PARTIES_REMOVE:  'parties.remove',
});

const KNOWN_MUTATIONS = Object.freeze(new Set(Object.values(MUTATION_KIND)));

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

/**
 * Hash a journal row · excludes row_hash itself (since it's the output).
 * Returns 'sha256:<64 hex>'.
 */
function hashRow(rowWithoutRowHash) {
  return 'sha256:' + sha256Hex(canonicalBytes(rowWithoutRowHash));
}

/**
 * Build a new journal row from a mutation and a prior-row anchor.
 *
 * The engine is clock-agnostic at the API level · the caller (typically
 * the cogos-api gateway) sets `ts` so the engine remains pure.
 *
 * @param {object} args
 * @param {string} args.ts         — ISO-8601 timestamp
 * @param {string} args.mutation   — one of MUTATION_KIND
 * @param {object} args.payload    — mutation-specific body
 * @param {string} args.prev_hash  — prior row's row_hash, or the anchor for row 0
 * @returns {object} new row · { ts, mutation, payload, prev_hash, row_hash }
 */
function buildRow({ ts, mutation, payload, prev_hash }) {
  if (typeof ts !== 'string' || !/^\d{4}-\d{2}-\d{2}T/.test(ts)) {
    throw new TypeError('buildRow: ts must be an ISO-8601 string');
  }
  if (!KNOWN_MUTATIONS.has(mutation)) {
    throw new TypeError(`buildRow: unknown mutation "${mutation}"`);
  }
  if (payload == null || typeof payload !== 'object') {
    throw new TypeError('buildRow: payload must be an object');
  }
  if (typeof prev_hash !== 'string' || !prev_hash.startsWith('sha256:')) {
    throw new TypeError('buildRow: prev_hash must be a sha256:<hex> string');
  }
  const canonicalPayload = canonicalize(payload);
  const withoutHash = canonicalize({ ts, mutation, payload: canonicalPayload, prev_hash });
  return { ...withoutHash, row_hash: hashRow(withoutHash) };
}

/**
 * Verify a journal · checks that every row's row_hash matches its
 * computed hash AND that prev_hash chains correctly.
 *
 * @param {Array}  journal   — array of rows in chronological order
 * @param {string} anchor    — the anchor hash that row 0's prev_hash
 *                              must equal (typically the key's identity
 *                              hash; supplied by the caller)
 * @returns {object} { ok, broken_at?, reason? }
 */
function verifyJournal(journal, anchor) {
  if (!Array.isArray(journal)) {
    return { ok: false, reason: 'journal must be an array' };
  }
  if (typeof anchor !== 'string' || !anchor.startsWith('sha256:')) {
    return { ok: false, reason: 'anchor must be a sha256:<hex> string' };
  }
  let prev = anchor;
  for (let i = 0; i < journal.length; i++) {
    const row = journal[i];
    if (row.prev_hash !== prev) {
      return { ok: false, broken_at: i, reason: 'prev_hash mismatch' };
    }
    const { row_hash, ...rest } = row;
    const expected = hashRow(rest);
    if (row_hash !== expected) {
      return { ok: false, broken_at: i, reason: 'row_hash mismatch' };
    }
    prev = row_hash;
  }
  return { ok: true };
}

/**
 * Apply one mutation to a state snapshot · pure function.
 */
function applyMutation(state, row) {
  const { mutation, payload } = row;
  const next = {
    matters: { ...state.matters },
    parties: { ...state.parties },
  };

  if (mutation === MUTATION_KIND.MATTER_UPSERT) {
    if (typeof payload.id !== 'string' || !payload.id) {
      throw new TypeError('matter.upsert: payload.id required');
    }
    next.matters[payload.id] = { ...next.matters[payload.id], ...payload };
  } else if (mutation === MUTATION_KIND.MATTER_ARCHIVE) {
    if (typeof payload.id !== 'string' || !payload.id) {
      throw new TypeError('matter.archive: payload.id required');
    }
    if (next.matters[payload.id]) {
      next.matters[payload.id] = { ...next.matters[payload.id], status: 'closed' };
    }
  } else if (mutation === MUTATION_KIND.PARTIES_UPSERT) {
    if (typeof payload.matter_id !== 'string' || !payload.matter_id) {
      throw new TypeError('parties.upsert: payload.matter_id required');
    }
    if (!Array.isArray(payload.parties)) {
      throw new TypeError('parties.upsert: payload.parties[] required');
    }
    const existing = next.parties[payload.matter_id] || [];
    const byId = new Map(existing.map((p) => [p.id, p]));
    for (const p of payload.parties) {
      if (typeof p.id !== 'string' || !p.id) {
        throw new TypeError('parties.upsert: each party must carry an id');
      }
      byId.set(p.id, { ...byId.get(p.id), ...p });
    }
    next.parties[payload.matter_id] = Array.from(byId.values());
  } else if (mutation === MUTATION_KIND.PARTIES_REMOVE) {
    if (typeof payload.matter_id !== 'string' || !payload.matter_id) {
      throw new TypeError('parties.remove: payload.matter_id required');
    }
    if (!Array.isArray(payload.party_ids)) {
      throw new TypeError('parties.remove: payload.party_ids[] required');
    }
    const drop = new Set(payload.party_ids);
    next.parties[payload.matter_id] = (next.parties[payload.matter_id] || []).filter((p) => !drop.has(p.id));
  } else {
    throw new TypeError(`applyMutation: unknown mutation "${mutation}"`);
  }
  return next;
}

/**
 * Materialize the current state from a journal.
 *
 * @param {Array}  journal — array of rows (verified or unverified)
 * @param {object} [opts]
 * @param {number} [opts.at_version] — point-in-time replay · materialize
 *                                     state AS OF this version (1-indexed
 *                                     · 0 means "before any mutation").
 *                                     Out-of-range clamps to the journal
 *                                     length (latest state).
 * @returns {object} state snapshot:
 *   {
 *     state_version: <int>,
 *     state_hash:    'sha256:...' | null when journal is empty,
 *     matters:       { [matter_id]: Matter },
 *     parties:       { [matter_id]: Party[] },
 *   }
 */
function materialize(journal, opts = {}) {
  if (!Array.isArray(journal)) {
    throw new TypeError('materialize: journal must be an array');
  }
  let upTo = journal.length;
  if (opts.at_version != null) {
    if (!Number.isInteger(opts.at_version) || opts.at_version < 0) {
      throw new TypeError('materialize: at_version must be a non-negative integer');
    }
    upTo = Math.min(opts.at_version, journal.length);
  }
  let state = { matters: {}, parties: {} };
  for (let i = 0; i < upTo; i++) {
    state = applyMutation(state, journal[i]);
  }
  return canonicalize({
    state_version: upTo,
    state_hash:    upTo > 0 ? journal[upTo - 1].row_hash : null,
    matters:       state.matters,
    parties:       state.parties,
  });
}

/**
 * Adapter: turn a materialized state into the input shape the 5Law
 * conflict engine expects (firm_matters + parties_by_matter_id).
 *
 * The caller still supplies target_matter + target_parties for the
 * specific conflict check; this helper fills in the firm-graph half.
 */
function toConflictEngineInput(state, opts = {}) {
  const includeClosed = opts.includeClosed !== false;  // default: include closed for former-client rules
  const matters = Object.values(state.matters || {});
  const firm_matters = includeClosed ? matters : matters.filter((m) => m.status !== 'closed');
  return canonicalize({
    firm_matters,
    parties_by_matter_id: state.parties || {},
    state_version: state.state_version,
    state_hash:    state.state_hash,
  });
}

/**
 * Convenience: compute the anchor hash for a key. The anchor is what
 * row 0's prev_hash points to. We use canonicalHash of the key_id
 * itself · binds a journal to a specific key so journals from
 * different keys cannot be spliced together.
 */
function keyAnchor(key_id) {
  if (typeof key_id !== 'string' || !key_id) {
    throw new TypeError('keyAnchor: key_id must be a non-empty string');
  }
  return canonicalHash({ key_id, engine_version: STATE_ENGINE_VERSION });
}

module.exports = {
  STATE_ENGINE_VERSION,
  MUTATION_KIND,
  buildRow,
  verifyJournal,
  applyMutation,
  materialize,
  toConflictEngineInput,
  keyAnchor,
  // exported for direct tests
  hashRow,
};
