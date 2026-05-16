'use strict';

// Per-tenant + per-app daily request + fallback-token caps.
//
// WHY this exists: the gateway already enforces a *monthly* request quota
// (src/chat-api.js enforcePackage). The free tier needs a *daily* second
// budget too — the substrate constants (no GPT / no embeddings / no GPU /
// no uploads / no chains) are structural, but a single tenant can still
// drain Tier-B fallback capacity in one hot afternoon. Daily caps give the
// operator a per-day circuit breaker that does NOT depend on Stripe usage
// rollups landing on time.
//
// SHAPE: in-process Map<string, Bucket>, keyed by
//   `tenant:${tenant_id}:app:${app_id}:date:${YYYY-MM-DD}`
// where the date string is the current UTC date. The key includes the date
// so day-rollover is "free" — yesterday's key is unreachable from today's
// path, and an LRU sweep on every check ages out the dead entries.
//
// LIMITS COME FROM THE MIDDLEWARE: this module does not know about
// packages. The caller passes { request_cap, token_cap } per invocation;
// the package resolution lives in chat-api.js where enforcePackage already
// reads the request's resolved tier. That keeps this file pure-JS, no
// circular dependency on packages.js, and trivially mockable.
//
// EDGE — IN-FLIGHT TOKEN TRIP: a single completion can push today's
// fallback-token counter past the cap. The middleware allows that
// in-flight response to land (it already ran upstream) and the next
// request from the same (tenant, app) on the same UTC day gets the 429.
// Spec calls this out as fair-to-the-customer behavior — their LAST
// request shouldn't be the one that fails.
//
// MEMORY BOUNDS: MAX_BUCKETS = 50_000 (same pattern as src/anomaly.js).
// LRU eviction on every getOrCreate. BUCKET_TTL_MS = 36h covers any clock
// skew + half-day-overlap during day rollover. No setInterval — sweep
// runs opportunistically inside incrementAndCheck().

const fs = require('node:fs');
const path = require('node:path');
const logger = require('./logger');

// On-disk snapshot of the buckets Map. Synchronously rewritten via
// atomic tmp+rename on every successful increment so a process restart
// doesn't reset counters mid-day. Hydrate on first call via lazyLoad().
// Path is configurable for tests via DAILY_CAP_FILE env.
//
// Why sync, not async: we'd otherwise have a window where the bucket
// updated in memory but the request response went out before the disk
// write landed. Process restart in that window = a customer's quota
// silently resets. Sync write is ~0.3ms for the small file sizes
// involved (≤50k buckets * ~80 bytes each = ~4MB worst case; typical
// deployments will see ≤a few hundred buckets per day = a few KB).
//
// Why JSON not JSONL: the buckets map IS the source of truth — there's
// no append-only narrative we need to replay. A snapshot file is more
// honest to that shape than a journal pretending to be an event log.
function dailyCapFile() {
  return process.env.DAILY_CAP_FILE
    || path.join(process.cwd(), 'data', 'daily-cap.json');
}

let _loaded = false;
function lazyLoad() {
  if (_loaded) return;
  _loaded = true;
  const f = dailyCapFile();
  if (!fs.existsSync(f)) return;
  let raw;
  try { raw = fs.readFileSync(f, 'utf8'); } catch (e) {
    logger.warn('daily_cap_load_read_failed', { file: f, error: e.message });
    return;
  }
  let parsed;
  try { parsed = JSON.parse(raw); } catch (e) {
    logger.warn('daily_cap_load_parse_failed', { file: f, error: e.message });
    return;
  }
  if (!parsed || !Array.isArray(parsed.buckets)) {
    logger.warn('daily_cap_load_shape_invalid', { file: f });
    return;
  }
  // TTL prune at load — yesterday's buckets that survived a long restart
  // gap should not come back to haunt today's counters.
  const cutoff = Date.now() - DAILY_BUCKET_TTL_MS;
  let restored = 0;
  for (const b of parsed.buckets) {
    if (!b || typeof b !== 'object') continue;
    if (typeof b.lastTouchedMs !== 'number' || b.lastTouchedMs < cutoff) continue;
    if (!b.tenant_id || !b.date) continue;
    const key = bucketKey(b.tenant_id, b.app_id, b.date);
    buckets.set(key, {
      key,
      tenant_id: String(b.tenant_id),
      app_id: String(b.app_id || '_default'),
      date: String(b.date),
      requests: Number(b.requests) || 0,
      fallback_tokens: Number(b.fallback_tokens) || 0,
      lastTouchedMs: Number(b.lastTouchedMs),
    });
    restored += 1;
  }
  logger.info('daily_cap_loaded', { file: f, buckets: restored });
}

function persistSnapshot() {
  const f = dailyCapFile();
  const tmp = `${f}.${process.pid}.tmp`;
  const payload = {
    version: 1,
    ts: new Date().toISOString(),
    buckets: Array.from(buckets.values()).map((b) => ({
      tenant_id: b.tenant_id,
      app_id: b.app_id,
      date: b.date,
      requests: b.requests,
      fallback_tokens: b.fallback_tokens,
      lastTouchedMs: b.lastTouchedMs,
    })),
  };
  try {
    // Ensure the parent dir exists — tests use tmpdirs that may not
    // have a data/ subdirectory; production already has data/ via
    // Dockerfile but defensive mkdir keeps the code portable.
    fs.mkdirSync(path.dirname(f), { recursive: true });
    fs.writeFileSync(tmp, JSON.stringify(payload), { mode: 0o600 });
    fs.renameSync(tmp, f);
  } catch (e) {
    logger.warn('daily_cap_persist_failed', { file: f, error: e.message });
  }
}

// 36 hours: longer than 24h to catch clock-skew + a full day's worth of
// in-flight rows during a midnight-UTC rollover, but short enough that
// yesterday's buckets are gone by the end of today. Env override is for
// tests; production should never need to touch this.
const DAILY_BUCKET_TTL_MS = Number(
  process.env.DAILY_CAP_TTL_MS || 36 * 60 * 60 * 1000,
);

// Same cap-on-buckets pattern as src/anomaly.js. Bounds memory under any
// tenant-spray attempt (an attacker rotating tenant_id values can only
// allocate up to this many entries before LRU starts evicting).
const MAX_BUCKETS = Number(process.env.DAILY_CAP_MAX_BUCKETS || 50_000);

// In-memory store. Map preserves insertion order, which we use for LRU
// eviction (delete + set re-inserts at the end → least-recent is at the
// head). Persisted to disk via persistSnapshot() on every successful
// increment + hydrated on first call via lazyLoad(); a process restart
// no longer resets the counters mid-day.
const buckets = new Map();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Current UTC date as YYYY-MM-DD. Stable across processes.
function utcDateString(now = new Date()) {
  const y = now.getUTCFullYear();
  const m = String(now.getUTCMonth() + 1).padStart(2, '0');
  const d = String(now.getUTCDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

// Build the canonical bucket key. tenant_id and app_id are caller-provided;
// we coerce-to-string + fall back to '_default' when missing so the key
// shape is always well-formed (the chat-api.js handler uses the same
// '_default' app slot for pre-multi-app keys, so this stays consistent
// across files).
function bucketKey(tenantId, appId, dateIso) {
  const t = String(tenantId || '_unknown');
  const a = String(appId || '_default');
  const d = dateIso || utcDateString();
  return `tenant:${t}:app:${a}:date:${d}`;
}

// Seconds until the NEXT UTC midnight. Used for the Retry-After header
// value when we return 429. Always <= 86400 (one full day).
function secondsUntilUtcMidnight(now = new Date()) {
  const next = new Date(Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate() + 1,
    0, 0, 0, 0,
  ));
  const ms = next.getTime() - now.getTime();
  return Math.max(1, Math.ceil(ms / 1000));
}

// Opportunistic sweep — drop buckets whose lastTouchedMs is older than
// DAILY_BUCKET_TTL_MS. Cheap; only runs when we'd otherwise overshoot the
// LRU cap, plus a time-gated full sweep at most every 30s. Same shape as
// the anomaly module so the memory profile is predictable.
let lastSweepMs = 0;
function maybeSweep(now) {
  if (now - lastSweepMs < 30_000) return;
  lastSweepMs = now;
  const cutoff = now - DAILY_BUCKET_TTL_MS;
  for (const [key, b] of buckets.entries()) {
    if (b.lastTouchedMs < cutoff) buckets.delete(key);
  }
}

function getOrCreateBucket(tenantId, appId, dateIso, now) {
  const key = bucketKey(tenantId, appId, dateIso);
  let b = buckets.get(key);
  if (!b) {
    // LRU eviction at MAX_BUCKETS — drop the head (oldest) entry.
    while (buckets.size >= MAX_BUCKETS) {
      const oldest = buckets.keys().next().value;
      if (oldest === undefined) break;
      buckets.delete(oldest);
    }
    b = {
      key,
      tenant_id: String(tenantId || '_unknown'),
      app_id: String(appId || '_default'),
      date: dateIso || utcDateString(),
      requests: 0,
      fallback_tokens: 0,
      lastTouchedMs: now,
    };
    buckets.set(key, b);
  } else {
    // LRU re-insert (delete + set moves to end of insertion order).
    buckets.delete(key);
    buckets.set(key, b);
    b.lastTouchedMs = now;
  }
  return b;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// Increment the bucket counters for (tenant_id, app_id) by the supplied
// deltas, then evaluate against the caller-supplied caps. Returns:
//
//   {
//     ok: boolean,                            // false → caller should 429
//     reason: 'request_cap' | 'token_cap' | null,
//     current: { requests, fallback_tokens }, // post-increment snapshot
//     limits:  { request_cap, token_cap },    // echoed from caller
//   }
//
// CAPS SEMANTICS:
//   - request_cap=null or undefined → unlimited (this dimension passes)
//   - token_cap=null or undefined   → unlimited (this dimension passes)
//   - request_cap=0 or token_cap=0  → "always 429" (defensive; the
//     middleware treats missing-field as null, not 0, so 0 is opt-in)
//
// Request_cap is checked FIRST (it's the cheap one and matches the
// expected ordering: deny the call before we burn upstream tokens).
function incrementAndCheck(tenantId, appId, opts = {}) {
  const now = Date.now();
  lazyLoad();
  maybeSweep(now);

  const requestsNow = Number(opts.requests_now || 0);
  const tokensNow = Number(opts.fallback_tokens_now || 0);
  const requestCap = opts.request_cap;
  const tokenCap = opts.token_cap;

  // Determine the day this increment lands on. We re-compute every call so
  // a long-running process correctly drops yesterday's counter at UTC
  // midnight without any external scheduler.
  const dateIso = opts.date_iso || utcDateString();
  const b = getOrCreateBucket(tenantId, appId, dateIso, now);
  b.requests += requestsNow;
  b.fallback_tokens += tokensNow;

  const current = {
    requests: b.requests,
    fallback_tokens: b.fallback_tokens,
  };
  const limits = {
    request_cap: requestCap === undefined ? null : requestCap,
    token_cap: tokenCap === undefined ? null : tokenCap,
  };

  // Request cap evaluated first.
  if (requestCap !== null && requestCap !== undefined && b.requests > requestCap) {
    persistSnapshot();
    return { ok: false, reason: 'request_cap', current, limits };
  }
  // Then token cap. "Over" semantics: STRICT GREATER THAN — a request that
  // exactly meets the cap is still OK. The in-flight-trip case is when
  // tokens_now > 0 pushes b.fallback_tokens past the cap; we return ok:
  // false here, but the chat-api middleware deliberately calls this
  // POST-response (so the customer's response already left the wire) —
  // the NEXT request from this bucket will hit the same path and 429.
  if (tokenCap !== null && tokenCap !== undefined && b.fallback_tokens > tokenCap) {
    persistSnapshot();
    return { ok: false, reason: 'token_cap', current, limits };
  }

  persistSnapshot();
  return { ok: true, reason: null, current, limits };
}

// Read-only snapshot of the current counter for a (tenant, app, date)
// triple. Used by tests + by future operator-facing inspection endpoints.
// Does NOT touch lastTouchedMs (so it can't keep a bucket alive forever
// from a polling dashboard).
function getCounter(tenantId, appId, dateIso) {
  const key = bucketKey(tenantId, appId, dateIso);
  const b = buckets.get(key);
  if (!b) {
    return {
      tenant_id: String(tenantId || '_unknown'),
      app_id: String(appId || '_default'),
      date: dateIso || utcDateString(),
      requests: 0,
      fallback_tokens: 0,
    };
  }
  return {
    tenant_id: b.tenant_id,
    app_id: b.app_id,
    date: b.date,
    requests: b.requests,
    fallback_tokens: b.fallback_tokens,
  };
}

// ---------------------------------------------------------------------------
// Module exports + test hooks
// ---------------------------------------------------------------------------
const _test = {
  _reset() {
    buckets.clear();
    lastSweepMs = 0;
    // Also reset the lazy-load flag so a test that wants to start from
    // a clean slate doesn't get yesterday's bucket file rehydrated.
    _loaded = false;
    // Best-effort: remove the snapshot file if it exists in the path
    // env var. Tests should set DAILY_CAP_FILE to a tmpdir; production
    // never calls _reset.
    try { fs.unlinkSync(dailyCapFile()); } catch (_e) { /* missing is fine */ }
  },
  bucketCount() { return buckets.size; },
  // Surface internals for cap-aware tests without making them public API.
  utcDateString,
  secondsUntilUtcMidnight,
  DAILY_BUCKET_TTL_MS,
  MAX_BUCKETS,
  // Log helper so a developer can observe sweep behavior at debug level
  // without enabling all of cogos-api's chatter.
  _logState(label) {
    logger.debug('daily_cap_state', { label, size: buckets.size });
  },
};

module.exports = {
  incrementAndCheck,
  getCounter,
  utcDateString,
  secondsUntilUtcMidnight,
  _test,
};
