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
 *   data/state/<tenant_id>/<key_id_prefix>.jsonl.lock  (transient)
 *
 * The key_id is hashed first (sha256, first 16 hex) to avoid putting
 * raw sk-cogos-* values on disk as filenames. Tenant id is preserved
 * as a directory so an ops operator browsing data/state/ sees the
 * tenant layout directly.
 *
 * Concurrent writer safety (v0.1.1):
 *   - appendMutation acquires a per-journal lockfile via O_EXCL
 *     before reading + verifying + appending. Holds the lock for
 *     the entire read-verify-write cycle. This is fcntl-grade
 *     mutual exclusion across multiple Node processes on the same
 *     filesystem (works for multi-replica deploys sharing a volume,
 *     not for cross-host replicas without a shared mount).
 *   - Lock is released in a finally block. Stale locks from a
 *     crashed writer are caught by the lock-age check (>30s old =
 *     force-release on the next acquire attempt).
 *   - Cross-host multi-replica without a shared volume still needs
 *     a Redis/queue primitive (honest gap, deferred).
 *   - Reads do NOT acquire the lock. Atomic appendFileSync of one
 *     JSON line is guaranteed atomic up to PIPE_BUF on linux for
 *     writes < ~4KB; our rows are well under that. Larger rows
 *     would need lock-on-read too, but JSONL lines that large would
 *     be a substrate-doctrine violation anyway.
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

// Lock primitive · O_EXCL atomic create. Holds the lock for the
// entire read-verify-write cycle so two concurrent writers can't
// chain-fork the journal.
//
// Stale-lock recovery: if a writer crashes mid-mutation the .lock
// file remains. Acquirers check the lock's age; older than
// STALE_LOCK_MS = 30s = force-release. 30s is comfortably longer
// than any non-pathological mutation (sync fs read + verify + write
// of a row is sub-100ms in normal conditions).
const LOCK_RETRY_ATTEMPTS = 100;
const LOCK_RETRY_DELAY_MS = 20;       // 100 * 20ms = 2s total max wait
const STALE_LOCK_MS       = 30_000;

function sleepBusyMs(ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) { /* tight loop; ms is small (20) */ }
}

function acquireLock(targetPath) {
  const lockPath = targetPath + '.lock';
  for (let i = 0; i < LOCK_RETRY_ATTEMPTS; i++) {
    try {
      const fd = fs.openSync(lockPath, 'wx');
      // Write the holder's pid so an operator can see who's holding it.
      try { fs.writeSync(fd, String(process.pid)); } catch (_) {}
      fs.closeSync(fd);
      return lockPath;
    } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      // Stale-lock check.
      try {
        const st = fs.statSync(lockPath);
        if (Date.now() - st.mtimeMs > STALE_LOCK_MS) {
          fs.unlinkSync(lockPath);
          continue;  // retry immediately
        }
      } catch (_) { /* lock vanished between check and stat; race · retry */ }
      sleepBusyMs(LOCK_RETRY_DELAY_MS);
    }
  }
  const err = new Error('failed to acquire journal lock after ' + LOCK_RETRY_ATTEMPTS + ' attempts');
  err.code = 'LOCK_TIMEOUT';
  throw err;
}

function releaseLock(lockPath) {
  try { fs.unlinkSync(lockPath); } catch (_) { /* already gone, fine */ }
}

/**
 * Append a mutation to the journal.
 * Returns the new row + the new materialized state.
 *
 * Concurrent-writer safety (v0.1.1): wraps the entire read-verify-write
 * cycle in a per-journal O_EXCL file lock. Two concurrent writers on
 * the same key will serialize through the lock; writers on different
 * keys are unaffected.
 */
function appendMutation({ tenant_id, key_id, mutation, payload, ts }) {
  const p = journalPath({ tenant_id, key_id });
  ensureDir(p);
  const lockPath = acquireLock(p);
  try {
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

    fs.appendFileSync(p, JSON.stringify(row) + '\n');

    const newJournal = existing.concat([row]);
    const state = materialize(newJournal);
    return { row, state, journal_length: newJournal.length };
  } finally {
    releaseLock(lockPath);
  }
}

function currentState({ tenant_id, key_id, at_version }) {
  const journal = loadJournal({ tenant_id, key_id });
  const state = at_version != null
    ? materialize(journal, { at_version: Number(at_version) })
    : materialize(journal);
  return {
    state,
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
function conflictInputForKey({ tenant_id, key_id, includeClosed = true, at_version }) {
  const journal = loadJournal({ tenant_id, key_id });
  const state = at_version != null
    ? materialize(journal, { at_version: Number(at_version) })
    : materialize(journal);
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
  _internal: {
    journalPath, keyFingerprint, tenantDir,
    acquireLock, releaseLock,
    STATE_DIR_DEFAULT: STATE_DIR,
    LOCK_RETRY_ATTEMPTS, LOCK_RETRY_DELAY_MS, STALE_LOCK_MS,
  },
};
