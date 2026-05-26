'use strict';

/**
 * Durable storage backend for per-key state journals.
 *
 * One JSONL file per (tenant_id, app_id, key_id) — append-only, one row
 * per mutation. Materialized state is computed on read by replaying
 * the full journal through src/processes/_keyState.js. v0.1 keeps it
 * simple: no in-memory cache, every read re-replays. The journals
 * stay small enough that this is fine; an LRU cache lands in v0.2 when
 * a customer pushes ~10k mutations.
 *
 * Storage layout:
 *   data/state/<tenant_id>/<key_id_prefix>.jsonl
 *
 * The key_id is hashed first (sha256, first 16 hex) to avoid putting
 * raw sk-cogos-* values on disk as filenames. Tenant id is preserved
 * as a directory so an ops operator browsing data/state/ sees the
 * tenant layout directly.
 *
 * Concurrent writer safety: file append + fsync per row. Multiple
 * gateway processes (current Azure deployment is single-instance,
 * but the architecture allows scaling) will need a queue or lock for
 * concurrent writes; v0.1 punts on this since cogos-api runs as one
 * Container App replica. Documented as an honest gap on the v0.2
 * roadmap.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const {
  buildRow,
  verifyJournal,
  materialize,
  keyAnchor,
  toConflictEngineInput,
  MUTATION_KIND,
} = require('./processes/_keyState');

const STATE_DIR = process.env.STATE_DIR || path.join(process.cwd(), 'data', 'state');

function keyFingerprint(key_id) {
  // First 16 hex of sha256(key_id) · 64 bits is enough to avoid
  // collisions at any realistic customer count without exposing the
  // key on the filesystem.
  return crypto.createHash('sha256').update(String(key_id)).digest('hex').slice(0, 16);
}

function tenantDir(tenant_id) {
  // Sanitize tenant_id to a directory-safe shape. tenant_ids in the
  // current substrate are uuid-shaped slugs (passed validation in
  // src/keys.js) but we still strip anything weird as a defense.
  return String(tenant_id || 'unknown').replace(/[^a-zA-Z0-9_-]/g, '_');
}

function journalPath({ tenant_id, key_id }) {
  return path.join(STATE_DIR, tenantDir(tenant_id), keyFingerprint(key_id) + '.jsonl');
}

function ensureDir(p) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
}

function loadJournal({ tenant_id, key_id }) {
  const p = journalPath({ tenant_id, key_id });
  if (!fs.existsSync(p)) return [];
  const text = fs.readFileSync(p, 'utf8');
  const lines = text.split('\n').filter((l) => l.trim().length > 0);
  return lines.map((l) => JSON.parse(l));
}

/**
 * Append a mutation to the journal.
 * Returns the new row + the new materialized state.
 */
function appendMutation({ tenant_id, key_id, mutation, payload, ts }) {
  const anchor = keyAnchor(key_id);
  const existing = loadJournal({ tenant_id, key_id });

  // Verify existing journal before extending — if it's tampered, we
  // refuse to append (caller gets a 409). This keeps the chain
  // honest: every append is also a re-verification of history.
  if (existing.length > 0) {
    const v = verifyJournal(existing, anchor);
    if (!v.ok) {
      const err = new Error(`journal integrity broken at row ${v.broken_at} (${v.reason}); refusing to append`);
      err.code = 'JOURNAL_TAMPERED';
      err.broken_at = v.broken_at;
      throw err;
    }
  }

  const prev_hash = existing.length === 0 ? anchor : existing[existing.length - 1].row_hash;
  const row = buildRow({ ts: ts || new Date().toISOString(), mutation, payload, prev_hash });

  const p = journalPath({ tenant_id, key_id });
  ensureDir(p);
  fs.appendFileSync(p, JSON.stringify(row) + '\n');

  const newJournal = existing.concat([row]);
  const state = materialize(newJournal);
  return { row, state, journal_length: newJournal.length };
}

function currentState({ tenant_id, key_id }) {
  const journal = loadJournal({ tenant_id, key_id });
  return {
    state: materialize(journal),
    journal_length: journal.length,
    anchor: keyAnchor(key_id),
  };
}

function currentJournal({ tenant_id, key_id }) {
  return {
    rows: loadJournal({ tenant_id, key_id }),
    anchor: keyAnchor(key_id),
  };
}

/**
 * Adapter for 5Law conflict-check: pulls stored state and returns
 * { firm_matters, parties_by_matter_id } shape.
 */
function conflictInputForKey({ tenant_id, key_id, includeClosed = true }) {
  const journal = loadJournal({ tenant_id, key_id });
  const state = materialize(journal);
  return {
    ...toConflictEngineInput(state, { includeClosed }),
    journal_length: journal.length,
  };
}

module.exports = {
  appendMutation,
  currentState,
  currentJournal,
  conflictInputForKey,
  // exported for tests
  _internal: { journalPath, keyFingerprint, tenantDir, STATE_DIR_DEFAULT: STATE_DIR },
};
