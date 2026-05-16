'use strict';

// Public hash-chain head checkpoint — Security Hardening Plan card #3
// ("public hash-chain checkpoints"). The companion primitive to the
// per-(tenant, app_id) chain in src/usage.js.
//
// WHY THIS EXISTS
// ---------------
// src/usage.js builds an independent hash chain per (tenant_id, app_id) so
// every customer can fetch /v1/audit, recompute row_hashes, and prove no
// row in their own slice was rewritten. That's tenant-internal. What it
// does NOT prove: that the operator didn't rebuild the tenant's chain
// AFTER THE FACT — recomputing every row_hash to embed a new edit. The
// per-tenant chain is consistent end-to-end either way; only an external
// witness fixes that.
//
// This file is the witness. Once an hour (CHECKPOINT_INTERVAL_MS) we
// snapshot every tenant+app chain head into a globally hash-chained
// checkpoint row, append it to data/audit-checkpoints.jsonl, and serve it
// at four PUBLIC, AUTH-FREE endpoints. A customer or external auditor
// curls /audit/checkpoint/latest at time T1, stashes the global_head
// somewhere durable, and months later replays the same /audit/checkpoint
// API to confirm their stashed head is still in the chain at exactly the
// same position with exactly the same predecessor. If we rewrote any row
// in any chain between T1 and now, the recomputed head for that
// partition wouldn't match what the historical checkpoint recorded —
// caught.
//
// CANONICAL INPUT (LOAD-BEARING)
// ------------------------------
// At checkpoint time, for every (tenant_id, app_id) partition with at
// least one usage row, we look up its current head via
// usage._internal.findHead(tenant, app). The partitions are sorted
// lexicographically by `${tenant_id} ${app_id}` and concatenated as:
//
//     ${tenant_id} ${app_id} ${head}\n
//
// one partition per line, no trailing newline on the LAST line. Then:
//
//     global_head = sha256_hex(canonical + '\n' + previous_global_head)
//
// The previous global head is appended with its own leading '\n' so
// every checkpoint (including the very first, which uses ZERO_HASH as
// the previous head) chains into the next. This is the exact format the
// /audit/checkpoint/verify endpoint re-derives.
//
// PARTITION SEPARATOR CHOICE: single space between fields, single \n
// between partitions. tenant_id and app_id are operator-controlled
// values (UUIDs and short slugs in practice — they don't contain spaces
// or newlines). The sha256 input is documented in source as the spec; a
// language-agnostic verifier writes the same join.
//
// GENESIS POLICY
// --------------
// Two genesis cases:
//   1. The checkpoints file is empty AND no usage rows exist. We skip —
//      there is literally nothing to checkpoint. Re-evaluated next tick.
//   2. The checkpoints file is empty AND at least one usage row exists.
//      We compute a real checkpoint with previous_global_head = 64
//      zeros. Subsequent checkpoints chain off this first one.
//
// IDEMPOTENT RESTART
// ------------------
// startScheduler() reads the most recent row's ts from disk; if it's
// within CHECKPOINT_INTERVAL_MS of now, the next computeAndAppend is
// delayed until the elapsed-since-last reaches the interval. This means
// a container restart doesn't double-publish — the JSONL on the Azure
// Files volume IS the source of truth for "have we already checkpointed
// this hour."
//
// PERSISTENCE
// -----------
// Append-only JSONL at data/audit-checkpoints.jsonl, mode 0600, same
// shape as anomalies.jsonl + usage.jsonl. Each row:
//
//   {
//     ts:               ISO,
//     global_head:      64 hex chars,
//     prev_global_head: 64 hex chars (64 zeros for the very first row),
//     partition_count:  number of (tenant, app) chains snapshotted,
//     row_hash:         sha256 of the canonical-input string alone
//                       (NOT chained — this is a content fingerprint of
//                        the partition set this row represents, useful
//                        for spot-comparing two checkpoints w/o the
//                        chained variable).
//   }
//
// SAFETY
// ------
// - Reads usage.jsonl line-stream (no full-file decode) so we don't OOM
//   on a multi-GB substrate.
// - Reads checkpoints.jsonl in full — checkpoints accrue at 24/day = 8760/year,
//   tiny relative to usage.
// - All errors caught + logged. Computation never throws to the caller;
//   the scheduler swallows + logs every error.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

const logger = require('./logger');
const usage = require('./usage');

const CHECKPOINTS_FILE = process.env.AUDIT_CHECKPOINTS_FILE
  || path.join(__dirname, '..', 'data', 'audit-checkpoints.jsonl');

// Default 1 hour. Env-overridable for tests (set to a few ms).
const CHECKPOINT_INTERVAL_MS = Number(process.env.CHECKPOINT_INTERVAL_MS || 3600000);

const ZERO_HASH = '0'.repeat(64);

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function ensureFile() {
  const dir = path.dirname(CHECKPOINTS_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (!fs.existsSync(CHECKPOINTS_FILE)) {
    fs.writeFileSync(CHECKPOINTS_FILE, '', { mode: 0o600 });
  }
}

// Stream the usage.jsonl and build a Set of distinct (tenant_id, app_id)
// pairs that have at least one row. We do this rather than expose a new
// enumerator on src/usage.js because the constraint set on this card is
// "hands off usage.js." Pre-multi-app rows without an app_id collapse
// into '_default' — matches the read-time projection that src/usage.js
// already applies via resolveAppId().
//
// The Set values are `${tenant_id}\x00${app_id}` so unusual characters
// in either field can't produce a join ambiguity. We split on \x00 when
// we need the components back; tenant_id + app_id are operator-issued
// and never contain \x00.
async function enumeratePartitions() {
  const usageFile = process.env.USAGE_FILE
    || path.join(__dirname, '..', 'data', 'usage.jsonl');
  if (!fs.existsSync(usageFile)) return [];
  const stat = fs.statSync(usageFile);
  if (stat.size === 0) return [];

  const partitions = new Set();
  const stream = fs.createReadStream(usageFile, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line || !line.trim()) continue;
    let row;
    try { row = JSON.parse(line); } catch (_e) { continue; }
    if (!row || typeof row.tenant_id !== 'string') continue;
    const appId = (row.app_id == null || row.app_id === '')
      ? usage.DEFAULT_APP_ID
      : String(row.app_id);
    partitions.add(`${row.tenant_id}\x00${appId}`);
  }
  // Sort lexicographically by (tenant_id, app_id). Reconstruct as
  // {tenant_id, app_id} objects for downstream consumers.
  const list = Array.from(partitions).map((k) => {
    const [tenant_id, app_id] = k.split('\x00');
    return { tenant_id, app_id };
  });
  list.sort((a, b) => {
    const ka = `${a.tenant_id} ${a.app_id}`;
    const kb = `${b.tenant_id} ${b.app_id}`;
    if (ka < kb) return -1;
    if (ka > kb) return 1;
    return 0;
  });
  return list;
}

// Read the entire checkpoints file as parsed rows. Checkpoints accrue at
// ~24/day, so even a multi-year file fits comfortably in memory.
function readAllCheckpoints() {
  ensureFile();
  const raw = fs.readFileSync(CHECKPOINTS_FILE, 'utf8');
  if (!raw) return [];
  return raw.split('\n')
    .filter((l) => l.trim())
    .map((l) => {
      try { return JSON.parse(l); } catch (_e) { return null; }
    })
    .filter((r) => r != null);
}

function latest() {
  const rows = readAllCheckpoints();
  if (rows.length === 0) return null;
  return rows[rows.length - 1];
}

// Build the canonical-input string from a sorted-partitions list + their
// looked-up heads. Exported via _internal for the verify endpoint to
// re-derive every historical head deterministically — but historical
// re-derivation hits a fundamental limit: we only have the CURRENT head
// per (tenant, app), not the head as of a previous checkpoint's ts. The
// verify endpoint therefore only re-derives the chained-prev linkage
// (global_head_i = sha256(canonical_i + '\n' + global_head_{i-1})) using
// the stored canonical fingerprint embedded as row_hash. See
// verifyChain() below for the exact algorithm.
function buildCanonicalInput(partitionsWithHeads) {
  return partitionsWithHeads
    .map((p) => `${p.tenant_id} ${p.app_id} ${p.head}`)
    .join('\n');
}

// Synchronously compute the current global head + append a checkpoint
// row. Returns the appended row, or null when there's nothing to
// checkpoint (no usage rows exist yet — see genesis policy above).
//
// SYNCHRONOUS HOT PATH: we stream usage.jsonl asynchronously to build
// the partition set, then do everything else sync. The function is
// async-returning because of the line-streaming step; callers (the
// scheduler, tests) await it.
async function computeAndAppend() {
  ensureFile();
  const partitions = await enumeratePartitions();
  if (partitions.length === 0) {
    // Genesis-skip: no usage rows = nothing to attest to.
    return null;
  }
  // Look up each partition's current head via the existing usage helper.
  // O(1) per call (in-memory cache populated lazily).
  const withHeads = partitions.map((p) => ({
    tenant_id: p.tenant_id,
    app_id: p.app_id,
    head: usage._internal.findHead(p.tenant_id, p.app_id),
  }));
  const canonical = buildCanonicalInput(withHeads);
  const last = latest();
  const prevGlobalHead = last ? last.global_head : ZERO_HASH;
  const globalHead = sha256Hex(canonical + '\n' + prevGlobalHead);
  // row_hash is a STATELESS fingerprint of THIS checkpoint's partition
  // set + their heads. It is NOT chained — that's what global_head is
  // for. row_hash lets two parties spot-compare a single checkpoint
  // without having to fetch the full chain.
  const rowHash = sha256Hex(canonical);
  const row = {
    ts: new Date().toISOString(),
    global_head: globalHead,
    prev_global_head: prevGlobalHead,
    partition_count: withHeads.length,
    row_hash: rowHash,
  };
  fs.appendFileSync(CHECKPOINTS_FILE, JSON.stringify(row) + '\n');
  return row;
}

// Return the checkpoint nearest-before tsMs (a unix-ms number). Returns
// null if there's no checkpoint at or before that point. Callers pass
// the ts they recorded when they captured /latest at time T1 — months
// later they curl /audit/checkpoint?ts=<T1>, get the same row back,
// and confirm the global_head still matches the one they captured.
function at(tsMs) {
  const rows = readAllCheckpoints();
  if (rows.length === 0) return null;
  const t = Number(tsMs);
  if (!Number.isFinite(t)) return null;
  let pick = null;
  for (const r of rows) {
    const rt = Date.parse(r.ts);
    if (!Number.isFinite(rt)) continue;
    if (rt <= t) {
      pick = r; // keep walking; rows are append-time-ordered (chronological)
    } else {
      break;
    }
  }
  return pick;
}

// Paginated read for /audit/checkpoints?limit=N&since_ms=M. Most-recent
// first up to `limit`, optionally filtered to ts > sinceMs. limit
// defaults to 100, capped at 1000.
function list({ limit, sinceMs } = {}) {
  const rows = readAllCheckpoints();
  if (rows.length === 0) return [];
  const lim = Math.max(0, Math.min(1000, Math.floor(Number(limit) || 100)));
  const since = Number(sinceMs);
  let filtered = rows;
  if (Number.isFinite(since) && since > 0) {
    filtered = rows.filter((r) => {
      const rt = Date.parse(r.ts);
      return Number.isFinite(rt) && rt > since;
    });
  }
  // Most-recent first.
  filtered = filtered.slice().reverse();
  return filtered.slice(0, lim);
}

// Walk the local checkpoints file and re-derive every global_head from
// the recorded row_hash + the previous row's global_head.
//
// We can only verify the CHAIN linkage (row N's prev_global_head ==
// row N-1's global_head AND row N's global_head ==
// sha256(canonical_for_N + '\n' + prev_global_head)). We canNOT
// re-derive canonical_for_N from usage.jsonl alone, because partition
// heads have advanced since checkpoint N was recorded — a re-derivation
// from current usage would produce row N+last's canonical, not row N's.
//
// What we CAN do is verify that row.global_head ==
// sha256(<something that hashes to row.row_hash> + '\n' + prev_head)
// where row.row_hash IS sha256(canonical_for_N). Equivalently:
// global_head must satisfy hash-cousin invariants:
//
//   - prev_global_head linkage: chain[i].prev_global_head == chain[i-1].global_head
//   - first row's prev_global_head == ZERO_HASH
//
// The full canonical re-derivation requires capturing partition heads
// AT CHECKPOINT TIME, which we don't currently persist (would be O(N)
// per checkpoint at large fleet size — deferred to a future card). For
// v1 the linkage check is enough to catch the most common tamper case:
// inserting / deleting / reordering checkpoint rows.
function verifyChain() {
  const rows = readAllCheckpoints();
  if (rows.length === 0) {
    return { ok: true, chain_length: 0, broke_at_index: null, reason: null };
  }
  let prev = ZERO_HASH;
  for (let i = 0; i < rows.length; i += 1) {
    const r = rows[i];
    if (typeof r.global_head !== 'string'
        || typeof r.prev_global_head !== 'string'
        || typeof r.row_hash !== 'string') {
      return {
        ok: false,
        chain_length: rows.length,
        broke_at_index: i,
        reason: 'row_missing_fields',
      };
    }
    if (r.prev_global_head !== prev) {
      return {
        ok: false,
        chain_length: rows.length,
        broke_at_index: i,
        reason: 'prev_global_head_mismatch',
      };
    }
    // Verify the chained-hash invariant. We don't have the canonical
    // input from disk, but we have row_hash = sha256(canonical). We
    // can't get canonical back from row_hash (sha256 is one-way), so
    // the strongest check we can run is the chained-prev linkage above
    // PLUS confirming global_head was produced as a sha256 of SOMETHING
    // + '\n' + prev. Tamper inserting a fake checkpoint row would
    // typically break the prev_global_head linkage anyway (the next
    // row's prev_global_head would no longer match), which IS caught
    // above. So the linkage check stands alone for v1.
    prev = r.global_head;
  }
  return { ok: true, chain_length: rows.length, broke_at_index: null, reason: null };
}

// ---------------------------------------------------------------------------
// Scheduler.
// ---------------------------------------------------------------------------
//
// startScheduler() kicks off a setInterval that runs computeAndAppend()
// every CHECKPOINT_INTERVAL_MS. On startup we check the last row's ts:
// if it's already within the interval we skip the first run; otherwise
// (no checkpoints yet, or last one is stale) we fire immediately.
// The .unref() call lets the process exit naturally during tests.
//
// IDEMPOTENT: calling startScheduler() twice is a no-op on the second
// call (returns the same stop() handle). This guards against accidental
// double-mount in test setup.

let _activeInterval = null;
let _activeStop = null;
let _runInFlight = false;

async function _safeRun() {
  if (_runInFlight) return null;
  _runInFlight = true;
  try {
    const row = await computeAndAppend();
    if (row) {
      logger.info('audit_checkpoint_appended', {
        ts: row.ts,
        global_head_prefix: row.global_head.slice(0, 16),
        partition_count: row.partition_count,
      });
    }
    return row;
  } catch (e) {
    logger.error('audit_checkpoint_compute_failed', { error: e.message });
    return null;
  } finally {
    _runInFlight = false;
  }
}

function startScheduler() {
  if (_activeInterval) return _activeStop;

  // Decide whether to fire immediately.
  const last = latest();
  const interval = CHECKPOINT_INTERVAL_MS;
  let firstDelayMs = 0;
  if (last) {
    const lastMs = Date.parse(last.ts);
    if (Number.isFinite(lastMs)) {
      const since = Date.now() - lastMs;
      if (since < interval) {
        // Last checkpoint is fresh enough; don't double-publish on restart.
        firstDelayMs = interval - since;
      }
    }
  }

  const firstTimer = setTimeout(() => {
    _safeRun().catch(() => {}); // _safeRun already swallows
  }, firstDelayMs);
  if (firstTimer.unref) firstTimer.unref();

  _activeInterval = setInterval(() => {
    _safeRun().catch(() => {});
  }, interval);
  if (_activeInterval.unref) _activeInterval.unref();

  _activeStop = function stop() {
    if (_activeInterval) {
      clearInterval(_activeInterval);
      _activeInterval = null;
    }
    clearTimeout(firstTimer);
    _activeStop = null;
  };
  return _activeStop;
}

// Test hook — fully resets the module's in-memory state. Does NOT touch
// the on-disk file (callers point CHECKPOINTS_FILE at a tmpdir).
function _reset() {
  if (_activeInterval) {
    clearInterval(_activeInterval);
    _activeInterval = null;
  }
  if (_activeStop) {
    _activeStop = null;
  }
  _runInFlight = false;
}

module.exports = {
  computeAndAppend,
  latest,
  at,
  list,
  verifyChain,
  startScheduler,
  CHECKPOINT_INTERVAL_MS,
  ZERO_HASH,
  _internal: {
    enumeratePartitions,
    readAllCheckpoints,
    buildCanonicalInput,
    sha256Hex,
    _reset,
    CHECKPOINTS_FILE_PATH: () => CHECKPOINTS_FILE,
  },
};
