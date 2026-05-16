'use strict';

// Anomaly detector middleware. Security Hardening Card #5 — anti-tamper /
// cheat-detection pillar, lightweight in-process form.
//
// TWO MODES.
//
//   Default (ANOMALY_FAIL_CLOSED unset or != '1'):
//     The detector observes request/response shape, increments in-memory
//     per-subject counters over sliding 60-second windows, and APPENDS one
//     line to data/anomalies.jsonl every time a threshold is crossed. It
//     does NOT block, rewrite, or fail any request — the response that
//     left the wire is exactly what the upstream middleware decided.
//
//   Fail-closed (ANOMALY_FAIL_CLOSED=1):
//     Same observe / log path, AND on certain IP-scoped fires the IP
//     gets a soft-ban (auth-brute-force = 5 min, scanner = 15 min). The
//     ban is read by rate-limit-by-ip (src/rate-limit.js) which short-
//     circuits banned IPs to 429 with Retry-After. Tenant- and global-
//     scoped fires (schema_failure_spike, latency_drift_detected) stay
//     log-only regardless of mode — they would punish paying customers
//     or every caller for an upstream blip, not an attacker.
//
// Signals (parallel to SECURITY_HARDENING_PLAN.md card #5):
//   a) auth_4xx_rate          per-IP    401/403 in 60s            > 10
//      → fires "auth_brute_force_suspected"
//   b) honeypot_hit_rate      per-IP    honeypot path hits in 60s > 3
//      → fires "scanner_active"
//   c) schema_violation_rate  per-tenant /v1/chat/completions !=200 in 60s > 20
//      → fires "schema_failure_spike"
//   d) signature_failure_rate SKIPPED — signatures are verified
//      client-side; we can't observe failures from the server.
//   e) latency_p99_drift      global    p99 this minute > 3x 24h median p99
//      → fires "latency_drift_detected"
//
// FIRE-ONCE-PER-WINDOW semantics: once a counter crosses its threshold and
// fires, the same subject+kind is suppressed until the next 60-second window
// rolls. Otherwise a sustained attack would write thousands of rows for one
// event. The window resets when the counter naturally evicts old entries
// past the 60s horizon.
//
// SECURITY-OF-THE-LOG: the kind, severity, subject_type, and subject_value
// fields are server-determined enums or operator-controlled values (the IP
// is from req.ip which honours `app.set('trust proxy')`; the tenant comes
// from req.apiKey which auth.js sets after key verify). Free-form
// client-controlled text (user-agent, last_path) ONLY lands inside
// `context`. We do not echo request bodies, headers, or query strings.

const fs = require('fs');
const path = require('path');

const logger = require('./logger');
const honeypot = require('./honeypot');
const keys = require('./keys');

// ---------------------------------------------------------------------------
// Configuration.
// ---------------------------------------------------------------------------
const ANOMALIES_FILE = process.env.ANOMALIES_FILE
  || path.join(__dirname, '..', 'data', 'anomalies.jsonl');

// Sliding window length for all per-subject signals.
const WINDOW_MS = 60_000;

// Idle bucket eviction. Default 5 minutes; tests may set
// ANOMALY_BUCKET_TTL_MS to a small value to exercise eviction.
const BUCKET_TTL_MS = Number(process.env.ANOMALY_BUCKET_TTL_MS || 5 * 60_000);

// Hard cap on the number of buckets we hold for each subject_type. Without
// this an adversary could OOM the process by rotating source IPs. When the
// cap is hit we evict the least-recently-touched bucket. 50_000 covers any
// realistic operator load while keeping memory bounded.
const MAX_BUCKETS = Number(process.env.ANOMALY_MAX_BUCKETS || 50_000);

// Fail-closed enforcement. Default OFF — calibrate thresholds against real
// traffic in shadow mode before flipping. When set, fire() of certain kinds
// stamps a per-IP ban into the `bans` Map; isBlocked(ip) is the read side
// the rate-limit middleware consults. schema_failure_spike + latency_drift
// stay log-only regardless — they're per-tenant / global signals and would
// punish paying customers for an upstream blip, not an attacker. Read
// LAZILY (via shouldFailClose()) so test files can toggle the env between
// runs without restarting the module.
function shouldFailClose() {
  return process.env.ANOMALY_FAIL_CLOSED === '1';
}

// Ban durations per fired kind. Auth brute-force is suggestive but not
// unambiguous (could be a misconfigured SDK), so 5 minutes. Scanner traffic
// (3+ honeypot hits) is unambiguous, so 15 minutes.
const BAN_MS_AUTH = 5 * 60_000;
const BAN_MS_SCANNER = 15 * 60_000;

// Cap on ban entries to bound memory under a key-rotation attack.
const MAX_BANS = 10_000;
const bans = new Map(); // ip -> blockedUntilMs

// Recent successful customer-auth tracker — IP → { keyId, atMs }.
// Populated by observe() whenever res.on('finish') sees req.apiKey set
// (i.e., bearerAuth or ed25519Auth attached a record to the request).
// Used by the quarantine trigger (2026-05-15 — key lifecycle card,
// commit 3/3): if scanner_active fires for an IP that has a recent
// (≤60s) valid customer auth, we quarantine that key. The combo is the
// only auto-trigger we trust — `auth_brute_force_suspected` alone fires
// on misconfigured SDKs and customer onboarding mistakes, not just
// attackers; the scanner+valid-key combo is unambiguous (real customers
// don't hit honeypot paths).
const RECENT_AUTH_WINDOW_MS = 60_000;
const MAX_RECENT_AUTHS = 50_000;
const recentAuth = new Map(); // ip -> { keyId, atMs }

const THRESHOLDS = Object.freeze({
  // Per-IP — 10/min translates to one auth-failure every 6s. Real customers
  // misconfigure their SDK and burn through 2-3 401s in a minute; bots
  // rolling key dictionaries blow well past 10. Tight enough to catch,
  // loose enough that a single fat-fingered curl session is fine.
  auth_4xx: 10,
  // Per-IP — 3 honeypot hits in a minute is unambiguous scanner traffic.
  // Real customers cannot accidentally fetch /.env + /wp-admin + /.git/HEAD
  // — those paths aren't linked from anywhere we publish.
  honeypot: 3,
  // Per-tenant — 20 non-200 chat completions in a minute is either
  // upstream-down (we should know) or a tenant hammering with a broken
  // schema (they should know). Lower than the per-IP auth threshold
  // because tenant traffic is already scoped to one customer.
  schema_violation: 20,
  // Latency p99 drift — current-minute p99 > 3x the 24h-median p99.
  // Multiplier is the threshold; the median itself is data-driven.
  latency_drift_multiple: 3,
});

// Threshold for the firing rule is STRICT GREATER-THAN — the comment in the
// spec says "> 10" and our tests assert that 10/min does NOT fire.
const STRICT_GREATER = true;

// ---------------------------------------------------------------------------
// State. All in-memory. Process restart resets — fine for shadow mode.
// ---------------------------------------------------------------------------
//
// buckets is a Map keyed by `${subject_type}:${subject_value}` where the
// value is { type, value, counters, fired, lastTouchedMs }. Each counters
// entry is a flat array of unix-ms timestamps; we evict entries older than
// WINDOW_MS on every observe(). Arrays beat circular buffers in clarity and
// the slice is bounded by the per-window threshold anyway (10-20-ish).
//
// fired is a per-bucket Map<kind, lastFiredMs>. Suppression: while the
// counter still has any entry inside the 60s window AND lastFiredMs > 0,
// we don't fire again. New entries trigger again once the window rolls.
const buckets = new Map();

// Latency tracking. Per-minute p99 over a 24h rolling window of minute
// buckets, so we can compute the median p99 baseline cheaply.
const latency = {
  // Current minute's samples — array of latency_ms numbers. Reset each
  // minute when the bucket rolls. p99 is computed on roll.
  currentMs: null, // unix-ms of the minute bucket start
  currentSamples: [],
  // Last 24h of (minuteStartMs, p99) tuples. Cap at 1440 (24*60).
  history: [],
  lastFiredAtMinuteMs: 0,
};

// Reusable file handle is overkill — we get one append per anomaly event,
// not per request. Use writeFileSync with append flag.
function ensureFile() {
  const dir = path.dirname(ANOMALIES_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (!fs.existsSync(ANOMALIES_FILE)) {
    fs.writeFileSync(ANOMALIES_FILE, '', { mode: 0o600 });
  }
}

// ---------------------------------------------------------------------------
// Bucket helpers.
// ---------------------------------------------------------------------------
function bucketKey(subjectType, subjectValue) {
  return `${subjectType}:${subjectValue}`;
}

function getOrCreateBucket(subjectType, subjectValue, now) {
  const key = bucketKey(subjectType, subjectValue);
  let b = buckets.get(key);
  if (!b) {
    // Enforce MAX_BUCKETS cap with a simple LRU eviction. The Map preserves
    // insertion order, but we re-insert on every touch, so the first entry
    // is the least-recently-touched. O(1) per eviction.
    while (buckets.size >= MAX_BUCKETS) {
      const oldestKey = buckets.keys().next().value;
      if (!oldestKey) break;
      buckets.delete(oldestKey);
    }
    b = {
      type: subjectType,
      value: subjectValue,
      counters: {}, // kind -> [ms, ms, ms, ...]
      fired: {},    // kind -> lastFiredMs
      lastTouchedMs: now,
    };
    buckets.set(key, b);
  } else {
    // LRU re-insert: delete + set moves the entry to the end of the Map's
    // insertion order, marking it most-recently-touched.
    buckets.delete(key);
    buckets.set(key, b);
    b.lastTouchedMs = now;
  }
  return b;
}

// Periodically scan buckets and drop any whose lastTouchedMs is older than
// BUCKET_TTL_MS. Cheap because we only scan when observe() is called — we
// don't keep a setInterval (would leak in tests + interfere with shutdown).
let lastSweepMs = 0;
function maybeSweep(now) {
  // Sweep at most every 30 seconds — sweeping is O(buckets).
  if (now - lastSweepMs < 30_000) return;
  lastSweepMs = now;
  const cutoff = now - BUCKET_TTL_MS;
  for (const [key, b] of buckets.entries()) {
    if (b.lastTouchedMs < cutoff) buckets.delete(key);
  }
}

function trimWindow(arr, now) {
  // Drop entries older than WINDOW_MS. Mutates in place; returns the new
  // length. Array is kept time-sorted by construction (we only push now).
  const cutoff = now - WINDOW_MS;
  let firstKeep = 0;
  while (firstKeep < arr.length && arr[firstKeep] < cutoff) firstKeep += 1;
  if (firstKeep > 0) arr.splice(0, firstKeep);
  return arr.length;
}

// ---------------------------------------------------------------------------
// Anomaly event emission.
// ---------------------------------------------------------------------------
function emitAnomaly(event) {
  // Log + persist. Persistence is best-effort; if the disk is full or the
  // path is bad we log and move on — anomaly detection MUST NEVER fail
  // the request path even if the file write fails (it's mounted in
  // shadow mode after all).
  try {
    ensureFile();
    fs.appendFileSync(ANOMALIES_FILE, JSON.stringify(event) + '\n', { mode: 0o600 });
  } catch (e) {
    logger.warn('anomaly_write_failed', { error: e.message, kind: event.kind });
  }
  logger.warn('anomaly_detected', event);
}

// kind → (counters-key, threshold-key) lookup. Kept as a constant so the
// mapping is explicit; the fire() event names are the operator-facing
// vocabulary, while the counters[] keys are the internal signal slots.
const KIND_TO_SIGNAL = Object.freeze({
  auth_brute_force_suspected: { counter: 'auth_4xx', thresholdKey: 'auth_4xx' },
  scanner_active:             { counter: 'honeypot', thresholdKey: 'honeypot' },
  schema_failure_spike:       { counter: 'schema_violation', thresholdKey: 'schema_violation' },
});

function fire(bucket, kind, severity, now, contextExtra) {
  // Suppress re-fires within the same window.
  const last = bucket.fired[kind] || 0;
  if (last > 0 && now - last < WINDOW_MS) return false;
  bucket.fired[kind] = now;
  const m = KIND_TO_SIGNAL[kind];
  const count = m ? (bucket.counters[m.counter] || []).length : 0;
  const threshold = m ? THRESHOLDS[m.thresholdKey] : 0;
  emitAnomaly({
    ts: new Date(now).toISOString(),
    kind,
    severity,
    subject_type: bucket.type,
    subject_value: bucket.value,
    window_seconds: WINDOW_MS / 1000,
    count,
    threshold,
    context: contextExtra || {},
    enforced: shouldFailClose() && bucket.type === 'ip'
      && (kind === 'auth_brute_force_suspected' || kind === 'scanner_active'),
  });
  // Fail-closed enforcement. Only IP-scoped kinds set bans: auth-brute-
  // force (5 min) and scanner-active (15 min). Tenant- and global-scoped
  // signals never ban — they would punish paying customers / the whole
  // surface for a partial-upstream issue.
  if (shouldFailClose() && bucket.type === 'ip') {
    let banMs = 0;
    if (kind === 'auth_brute_force_suspected') banMs = BAN_MS_AUTH;
    else if (kind === 'scanner_active') banMs = BAN_MS_SCANNER;
    if (banMs > 0) {
      setBan(bucket.value, now + banMs);
    }
    // Quarantine trigger: scanner_active + recent valid customer auth
    // from the SAME IP within 60s is the only unambiguous auto-trigger
    // (see RECENT_AUTH_WINDOW_MS comment). We deliberately do NOT
    // quarantine on auth_brute_force_suspected — that fires on
    // misconfigured SDKs too often. Quarantine is fail-closed-style;
    // gated to fail-closed mode for the same reason bans are.
    if (kind === 'scanner_active') {
      const keyId = peekRecentAuth(bucket.value, now);
      if (keyId) {
        try {
          const did = keys.quarantine(keyId, 'scanner_active+valid_auth');
          if (did) {
            logger.warn('anomaly_quarantine_set', {
              key_id: keyId,
              ip: bucket.value,
              reason: 'scanner_active+valid_auth',
            });
          }
        } catch (e) {
          // Quarantine MUST NEVER block the request path. If the store
          // is unhappy we log and move on; the ban above still applies.
          logger.warn('anomaly_quarantine_failed', { key_id: keyId, error: e.message });
        }
      }
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Recent-auth tracker. Read/write side for the quarantine trigger.
// ---------------------------------------------------------------------------
function recordRecentAuth(ip, keyId, now) {
  if (!ip || !keyId) return;
  // LRU re-insert keeps the most recent at the end; eviction drops the
  // oldest entry when the cap is hit. Memory bound is the same shape as
  // the bans Map — keep them parallel.
  recentAuth.delete(ip);
  while (recentAuth.size >= MAX_RECENT_AUTHS) {
    const oldest = recentAuth.keys().next().value;
    if (oldest === undefined) break;
    recentAuth.delete(oldest);
  }
  recentAuth.set(ip, { keyId, atMs: now });
}

// Returns the keyId of the most recent successful auth from `ip` within
// RECENT_AUTH_WINDOW_MS, or null. Stale entries are evicted on read so
// we don't accumulate cruft from IPs that auth once and never again.
function peekRecentAuth(ip, now) {
  if (!ip) return null;
  const entry = recentAuth.get(ip);
  if (!entry) return null;
  if (now - entry.atMs > RECENT_AUTH_WINDOW_MS) {
    recentAuth.delete(ip);
    return null;
  }
  return entry.keyId;
}

// ---------------------------------------------------------------------------
// Ban map. Read-side is isBlocked(ip); write-side is setBan(ip, untilMs).
// ---------------------------------------------------------------------------
function setBan(ip, untilMs) {
  // LRU eviction at MAX_BANS — Map insertion order, re-insert on every set.
  bans.delete(ip);
  while (bans.size >= MAX_BANS) {
    const oldestKey = bans.keys().next().value;
    if (oldestKey === undefined) break;
    bans.delete(oldestKey);
  }
  bans.set(ip, untilMs);
  logger.warn('anomaly_ban_set', { ip, until_ms: untilMs, duration_ms: untilMs - Date.now() });
}

// Read side. Returns the blocked-until-ms timestamp if the IP is banned,
// or 0 if not. Cleans up expired entries opportunistically. NEVER throws.
function isBlocked(ip) {
  if (!ip) return 0;
  const until = bans.get(ip);
  if (!until) return 0;
  const now = Date.now();
  if (until <= now) {
    bans.delete(ip);
    return 0;
  }
  return until;
}

// ---------------------------------------------------------------------------
// Per-signal observers. Each takes the bucket + now and returns nothing.
// ---------------------------------------------------------------------------
function observeAuth4xx(bucket, now, ctx) {
  const arr = (bucket.counters.auth_4xx = bucket.counters.auth_4xx || []);
  arr.push(now);
  const count = trimWindow(arr, now);
  const over = STRICT_GREATER ? count > THRESHOLDS.auth_4xx : count >= THRESHOLDS.auth_4xx;
  if (over) fire(bucket, 'auth_brute_force_suspected', 'warn', now, ctx);
}

function observeHoneypot(bucket, now, ctx) {
  const arr = (bucket.counters.honeypot = bucket.counters.honeypot || []);
  arr.push(now);
  const count = trimWindow(arr, now);
  const over = STRICT_GREATER ? count > THRESHOLDS.honeypot : count >= THRESHOLDS.honeypot;
  if (over) fire(bucket, 'scanner_active', 'warn', now, ctx);
}

function observeSchemaViolation(bucket, now, ctx) {
  const arr = (bucket.counters.schema_violation = bucket.counters.schema_violation || []);
  arr.push(now);
  const count = trimWindow(arr, now);
  const over = STRICT_GREATER
    ? count > THRESHOLDS.schema_violation
    : count >= THRESHOLDS.schema_violation;
  if (over) fire(bucket, 'schema_failure_spike', 'warn', now, ctx);
}

// ---------------------------------------------------------------------------
// Latency drift. Global; not bucket-scoped.
// ---------------------------------------------------------------------------
function percentile(samples, p) {
  if (samples.length === 0) return 0;
  const sorted = samples.slice().sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.floor(sorted.length * p));
  return sorted[idx];
}

function median(values) {
  if (values.length === 0) return 0;
  const sorted = values.slice().sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
}

function rollLatencyMinute(now) {
  if (latency.currentMs === null) return;
  const p99 = percentile(latency.currentSamples, 0.99);
  latency.history.push({ minuteMs: latency.currentMs, p99 });
  // Cap at 24h of minute buckets.
  while (latency.history.length > 1440) latency.history.shift();
  // Check drift on the just-closed minute (not the one we're about to open).
  if (latency.history.length >= 10) {
    // Need at least 10 minutes of baseline before drift is meaningful —
    // otherwise the very first slow request would fire on minute 2.
    const medP99 = median(latency.history.slice(0, -1).map((h) => h.p99));
    if (medP99 > 0 && p99 > medP99 * THRESHOLDS.latency_drift_multiple) {
      // Once per minute max — and the minuteMs IS the dedup key.
      if (latency.lastFiredAtMinuteMs !== latency.currentMs) {
        latency.lastFiredAtMinuteMs = latency.currentMs;
        emitAnomaly({
          ts: new Date(now).toISOString(),
          kind: 'latency_drift_detected',
          severity: 'warn',
          subject_type: 'global',
          subject_value: 'latency_p99',
          window_seconds: 60,
          count: Math.round(p99),
          threshold: Math.round(medP99 * THRESHOLDS.latency_drift_multiple),
          context: {
            current_p99_ms: Math.round(p99),
            median_p99_ms_24h: Math.round(medP99),
            multiplier: THRESHOLDS.latency_drift_multiple,
          },
        });
      }
    }
  }
}

function observeLatency(ms, now) {
  const minuteMs = Math.floor(now / 60_000) * 60_000;
  if (latency.currentMs === null) {
    latency.currentMs = minuteMs;
    latency.currentSamples = [];
  }
  if (minuteMs !== latency.currentMs) {
    // The minute rolled while we were running — finalize the previous
    // minute's bucket, push to history, then reset for the new minute.
    rollLatencyMinute(now);
    latency.currentMs = minuteMs;
    latency.currentSamples = [];
  }
  latency.currentSamples.push(ms);
}

// ---------------------------------------------------------------------------
// Public middleware. Late observer — hooks res.on('finish').
// ---------------------------------------------------------------------------
function middleware(req, res, next) {
  const startMs = Date.now();
  // CAPTURE the request path AT ENTRY time. Express mutates req.url when
  // a sub-Router dispatches (the mount prefix is stripped from req.url
  // inside the router handler), and that mutation is visible in the
  // res.on('finish') callback below. So if we read req.path inside
  // observe(), routes mounted via app.use('/v1', v1Router) report a
  // last_path of '/chat/completions' instead of '/v1/chat/completions'
  // — breaking signals that match on the full path. originalUrl is set
  // once and never mutated; we strip the query to mirror req.path.
  const originalUrl = req.originalUrl || req.url || '';
  req._anomalyPath = originalUrl.split('?')[0];
  res.on('finish', () => {
    try {
      observe(req, res, startMs);
    } catch (e) {
      // Detection must NEVER throw into the request path. Shadow mode.
      logger.warn('anomaly_observe_failed', { error: e.message });
    }
  });
  next();
}

function observe(req, res, startMs) {
  const now = Date.now();
  maybeSweep(now);

  const ip = req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';
  const ua = req.headers && req.headers['user-agent'];
  // req._anomalyPath was captured at middleware entry time (see comment in
  // middleware() above) — req.path would be the post-router-strip version.
  const lastPath = req._anomalyPath || req.path;
  const status = res.statusCode;

  // Recent-auth tracker for the quarantine trigger. req.apiKey is set
  // by bearerAuth/ed25519Auth only on successful verification — so any
  // time we see it here, auth succeeded for THIS request on THIS IP.
  // We record regardless of downstream status (a 500 from the upstream
  // doesn't mean the auth was bad). Window is 60s; see
  // RECENT_AUTH_WINDOW_MS comment above.
  if (req.apiKey && req.apiKey.id) {
    recordRecentAuth(String(ip), req.apiKey.id, now);
  }

  // a) auth_4xx per-IP
  if (status === 401 || status === 403) {
    const b = getOrCreateBucket('ip', String(ip), now);
    observeAuth4xx(b, now, { ua: ua || null, last_path: lastPath });
  }

  // b) honeypot_hit per-IP. We can't observe the honeypot middleware's
  // logger.warn directly — instead we recognize the path via the table
  // exported from src/honeypot.js. Tests rely on this path-matching to
  // exercise the signal without forking honeypot.js's contract.
  if (typeof honeypot.isHoneypotPath === 'function' && honeypot.isHoneypotPath(lastPath)) {
    const b = getOrCreateBucket('ip', String(ip), now);
    observeHoneypot(b, now, { ua: ua || null, last_path: lastPath });
  }

  // c) schema_violation per-(tenant, app). Only counts when bearer auth
  // identified a tenant (req.apiKey set) — pre-auth failures fall to the
  // per-IP auth_4xx signal instead. Limited to /v1/chat/completions
  // because the signal name is about schema/upstream failures on the
  // model path.
  //
  // Multi-app round (2026-05-14): the per-tenant bucket is now
  // partitioned by (tenant_id, app_id) so a misbehaving app inside a
  // tenant doesn't trip alerts on the tenant's other apps. Pre-multi-app
  // keys fall under app_id='_default' via the read-time normalization
  // in src/keys.js (verify/findByEd25519KeyId both backfill). IP-based
  // counters above intentionally do NOT split by app — an attacker
  // hitting many apps from one IP still trips one IP bucket.
  if (req.apiKey && req.apiKey.tenant_id
      && lastPath === '/v1/chat/completions'
      && status !== 200) {
    const appId = req.apiKey.app_id || '_default';
    const subjectValue = `${req.apiKey.tenant_id}:app:${appId}`;
    const b = getOrCreateBucket('tenant', subjectValue, now);
    observeSchemaViolation(b, now, {
      ua: ua || null,
      last_path: lastPath,
      status,
      app_id: appId,
    });
  }

  // e) global p99 latency drift. Track every request.
  observeLatency(now - startMs, now);
}

// ---------------------------------------------------------------------------
// Test helpers. Exposed via the _test namespace so tests don't reach into
// module internals.
// ---------------------------------------------------------------------------
const _test = {
  reset() {
    buckets.clear();
    bans.clear();
    recentAuth.clear();
    latency.currentMs = null;
    latency.currentSamples = [];
    latency.history = [];
    latency.lastFiredAtMinuteMs = 0;
    lastSweepMs = 0;
  },
  recordRecentAuth(ip, keyId, now) { recordRecentAuth(ip, keyId, now || Date.now()); },
  peekRecentAuth(ip) { return peekRecentAuth(ip, Date.now()); },
  recentAuthCount() { return recentAuth.size; },
  RECENT_AUTH_WINDOW_MS,
  forceBan(ip, ms) {
    setBan(ip, Date.now() + ms);
  },
  bansCount() { return bans.size; },
  isFailClosed() { return shouldFailClose(); },
  getCounter(subjectType, subjectValue, kind) {
    const b = buckets.get(bucketKey(subjectType, subjectValue));
    if (!b) return 0;
    const arr = b.counters[kind];
    return arr ? arr.length : 0;
  },
  getBucket(subjectType, subjectValue) {
    return buckets.get(bucketKey(subjectType, subjectValue)) || null;
  },
  bucketCount() {
    return buckets.size;
  },
  // Force time forward — used to test eviction without sleeping.
  ageAllBuckets(deltaMs) {
    for (const b of buckets.values()) {
      b.lastTouchedMs -= deltaMs;
    }
    lastSweepMs -= deltaMs;
  },
  forceFire(kind) {
    // Direct emit, bypasses thresholds. Useful when a test wants to verify
    // file shape without arranging full state.
    emitAnomaly({
      ts: new Date().toISOString(),
      kind,
      severity: 'warn',
      subject_type: 'ip',
      subject_value: '127.0.0.1',
      window_seconds: 60,
      count: 0,
      threshold: 0,
      context: { forced: true },
    });
  },
  anomaliesFile() { return ANOMALIES_FILE; },
  THRESHOLDS,
  WINDOW_MS,
  BUCKET_TTL_MS,
};

module.exports = middleware;
module.exports.middleware = middleware;
module.exports.isBlocked = isBlocked;
module.exports._test = _test;

// FAIL_CLOSED (2026-05-14, pentest F2): when ANOMALY_FAIL_CLOSED=1 is set,
// fire() of IP-scoped kinds (auth_brute_force_suspected, scanner_active)
// stamps a per-IP ban into `bans` via setBan(). The rate-limit middleware
// (src/rate-limit.js) calls isBlocked(ip) at the head of every request
// and short-circuits to 429 with Retry-After while a ban is active.
// Shadow path is untouched: anomaly observer still runs at res.on('finish');
// the gate runs inside rate-limit-by-ip which sits between the observer
// and the rest of the stack. Tenant- and global-scoped signals are
// log-only by design (don't punish paying customers for an upstream blip).
