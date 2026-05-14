'use strict';

// Anomaly detector middleware. Security Hardening Card #5 — anti-tamper /
// cheat-detection pillar, lightweight in-process form.
//
// SHADOW MODE — this file's contract.
//
//   The detector observes request/response shape, increments in-memory
//   per-subject counters over sliding 60-second windows, and APPENDS one
//   line to data/anomalies.jsonl every time a threshold is crossed. It
//   does NOT block, rewrite, or fail any request — the response that left
//   the wire is exactly what the upstream middleware decided.
//
//   A future card flips it to fail-closed (e.g. rate-limit response,
//   429 reply). The seams for that flip are marked TODO_FAIL_CLOSED.
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
  });
  return true;
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
  const lastPath = req.path;
  const status = res.statusCode;

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

  // c) schema_violation per-tenant. Only counts when bearer auth identified
  // a tenant (req.apiKey set) — pre-auth failures fall to the per-IP
  // auth_4xx signal instead. Limited to /v1/chat/completions because the
  // signal name is about schema/upstream failures on the model path.
  if (req.apiKey && req.apiKey.tenant_id
      && lastPath === '/v1/chat/completions'
      && status !== 200) {
    const b = getOrCreateBucket('tenant', String(req.apiKey.tenant_id), now);
    observeSchemaViolation(b, now, { ua: ua || null, last_path: lastPath, status });
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
    latency.currentMs = null;
    latency.currentSamples = [];
    latency.history = [];
    latency.lastFiredAtMinuteMs = 0;
    lastSweepMs = 0;
  },
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
module.exports._test = _test;

// TODO_FAIL_CLOSED: when this card flips to enforcement, hoist a config
// flag (e.g. ANOMALY_ENFORCE=1) and on fire() inside observe(), short-
// circuit *future* requests from the same subject with 429 for a cooldown
// window. The seam is `fire()` returning true on a brand-new fire — read
// that signal and stash a `blockedUntilMs` on the bucket. Response would
// then be set by a separate gate middleware that runs PRE-handler. Two-
// middleware structure (observe + gate) keeps the shadow path untouched.
