'use strict';

// In-process token-bucket rate limiter. Pentest finding F2 (2026-05-14):
// every unauthenticated path (health, /v1/* 401 reject, /admin/* 401 reject,
// honeypots) accepts unlimited requests. No CDN/Cloudflare edge sits in
// front of the Container App, so a flood lands on Node directly. This module
// is the explicit-limits layer; the anomaly detector (src/anomaly.js) is the
// threshold-tripped-ban layer that runs alongside it.
//
// DESIGN NOTES.
//
//   * In-memory only. No Redis, no shared store. Process restart clears
//     buckets. Two-replica horizontal scale would let an attacker get
//     ~2x the per-IP allowance, which is acceptable for the threat model
//     (this is defence-in-depth; the per-tenant quota is the billing-grade
//     limiter).
//
//   * Fixed-window in design (60s window via Math.floor(now / 60_000)), not
//     a true token bucket — fixed windows are easier to reason about, and
//     for our threat model (flood-of-cheap-requests) a burst at the boundary
//     is fine (the next window's 100 starts immediately).
//
//     We expose the API as "token bucket" because that's the doctrine name
//     and the observable behaviour from a caller's perspective is identical:
//     `limit` requests per `windowMs`, `Retry-After` on overflow.
//
//   * LRU-capped at MAX_BUCKETS (default 50_000), same pattern as anomaly.js
//     — Map insertion-order is the LRU; we re-insert on every touch. Without
//     this an attacker rotating source IPs could OOM the process.
//
//   * 5-minute idle TTL with periodic sweep (gated to once-per-30s so the
//     sweep is O(buckets) but only when the limiter is actively used).
//
// HEADER CONTRACT.
//
//   429 response always carries:
//     - Retry-After: <integer seconds until the window rolls>
//     - Content-Type: application/json
//
//   Body shape matches the rest of the API:
//     { "error": { "message": "...", "type": "rate_limit_exceeded",
//                  "retry_after_s": N } }
//
// ENV OVERRIDES.
//   RATE_LIMIT_IP_PER_MIN       (default 100)  unauth per-IP cap
//   RATE_LIMIT_TENANT_PER_MIN   (default 1000) authed per-tenant cap
//   RATE_LIMIT_MAX_BUCKETS      (default 50000) memory ceiling

const path = require('path');
const logger = require('./logger');
const eventLog = require('./event-log');

// File-path resolver for the rate-limit event log. Honors RATE_LIMITS_FILE
// so tests can point this at a tmpdir without bleeding into the repo
// data/ directory. Default matches the convention used by other event
// logs (data/<name>.jsonl under process.cwd()).
function rateLimitsFile() {
  return process.env.RATE_LIMITS_FILE
    || path.join(process.cwd(), 'data', 'rate-limits.jsonl');
}

// Append one rate-limit event row. Schema (locked v1):
//
//   { ts, kind, subject_type, subject_value, path, status, retry_after_s, package_id }
//
// `kind` is one of the locked enum:
//   - 'rate_limit_ip'         — per-IP fixed-window cap from rateLimitByIp
//   - 'rate_limit_tenant'     — per-tenant fixed-window cap from rateLimitByTenant
//   - 'daily_quota_request'   — per-(tenant,app) daily request cap from
//                               src/chat-api.js enforceDailyCap
//   - 'daily_quota_token'     — per-(tenant,app) daily token cap from
//                               src/chat-api.js enforceDailyCap
//   - 'anomaly_block'         — the per-IP ban set by anomaly.js's
//                               fail-closed mode, short-circuited at the
//                               head of rateLimitByIp via isBlocked()
//
// `subject_type` is 'ip' or 'tenant'. `subject_value` is the FULL ip /
// tenant_id (not a redaction) — operator needs the full value for
// anomaly correlation against the per-IP / per-tenant counters elsewhere
// in the system. The file is mode-0600 + operator-only by construction.
function appendRateLimit(row) {
  return eventLog.appendEvent(rateLimitsFile(), row);
}

// Defer to avoid circular require with src/index.js loading both.
let _anomaly = null;
function anomaly() {
  if (_anomaly === null) {
    try {
      _anomaly = require('./anomaly');
    } catch (_e) {
      _anomaly = {};
    }
  }
  return _anomaly;
}

// ---------------------------------------------------------------------------
// Configuration. Read env at module load — tests reset between runs via
// _test.reset() which re-reads.
// ---------------------------------------------------------------------------
const WINDOW_MS = 60_000;

function envInt(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

function getMaxBuckets() {
  return envInt('RATE_LIMIT_MAX_BUCKETS', 50_000);
}

// ---------------------------------------------------------------------------
// State.
// ---------------------------------------------------------------------------
//
// One Map per "namespace" (ip vs tenant) so the LRU eviction inside one
// namespace doesn't punish the other. Both share the MAX_BUCKETS ceiling
// per-Map, so worst-case memory is 2 * MAX_BUCKETS entries.
//
// Each bucket: { windowStartMs, count, lastTouchedMs }
//
const ipBuckets = new Map();
const tenantBuckets = new Map();

let lastSweepMs = 0;
const BUCKET_TTL_MS = 5 * 60_000;

function getOrCreateBucket(map, key, now) {
  let b = map.get(key);
  if (!b) {
    const max = getMaxBuckets();
    while (map.size >= max) {
      const oldestKey = map.keys().next().value;
      if (oldestKey === undefined) break;
      map.delete(oldestKey);
    }
    b = { windowStartMs: now, count: 0, lastTouchedMs: now };
    map.set(key, b);
  } else {
    // LRU re-insert.
    map.delete(key);
    map.set(key, b);
    b.lastTouchedMs = now;
  }
  return b;
}

function maybeSweep(now) {
  if (now - lastSweepMs < 30_000) return;
  lastSweepMs = now;
  const cutoff = now - BUCKET_TTL_MS;
  for (const map of [ipBuckets, tenantBuckets]) {
    for (const [key, b] of map.entries()) {
      if (b.lastTouchedMs < cutoff) map.delete(key);
    }
  }
}

// ---------------------------------------------------------------------------
// Core: hit a bucket and decide allow/deny.
// ---------------------------------------------------------------------------
function consume(map, key, limit, now) {
  const b = getOrCreateBucket(map, key, now);
  // Roll the fixed window if the previous one ended.
  if (now - b.windowStartMs >= WINDOW_MS) {
    b.windowStartMs = now;
    b.count = 0;
  }
  b.count += 1;
  if (b.count > limit) {
    const retryAfterMs = WINDOW_MS - (now - b.windowStartMs);
    return { allowed: false, retryAfterS: Math.max(1, Math.ceil(retryAfterMs / 1000)) };
  }
  return { allowed: true };
}

function send429(res, retryAfterS, message) {
  res.setHeader('Retry-After', String(retryAfterS));
  return res.status(429).json({
    error: {
      message: message || 'Too many requests',
      type: 'rate_limit_exceeded',
      retry_after_s: retryAfterS,
    },
  });
}

// ---------------------------------------------------------------------------
// Public middleware factories.
// ---------------------------------------------------------------------------

/**
 * Per-IP rate limit. Applies to every request reaching this middleware
 * (intended for the unauth surface: health, honeypots, /v1/* before auth,
 * /admin/* before auth). Also short-circuits banned IPs from anomaly.js if
 * ANOMALY_FAIL_CLOSED is on.
 *
 *   rateLimitByIp({ limit: 100, label: 'global' })
 *
 *   limit  — requests per 60s window (default from env)
 *   label  — short string included in the log line for diagnostics
 */
function rateLimitByIp(opts = {}) {
  const limit = opts.limit || envInt('RATE_LIMIT_IP_PER_MIN', 100);
  const label = opts.label || 'ip';
  return function rateLimitByIpMw(req, res, next) {
    const now = Date.now();
    maybeSweep(now);
    const ip = req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';

    // Anomaly-derived ban takes precedence: a banned IP can't be rescued by
    // a fresh bucket window. Header carries the longer of the two retry-after
    // values so the client doesn't retry too eagerly.
    const a = anomaly();
    if (a && typeof a.isBlocked === 'function') {
      const banUntilMs = a.isBlocked(ip);
      if (banUntilMs && banUntilMs > now) {
        const retryAfterS = Math.max(1, Math.ceil((banUntilMs - now) / 1000));
        logger.warn('rate_limit_anomaly_ban', { ip, retry_after_s: retryAfterS, label });
        // Persist anomaly-block 429 for analytics (kind='anomaly_block').
        // This is the fail-closed-mode path: anomaly.js stamped a ban
        // when scanner_active/auth_brute_force_suspected fired, and the
        // rate limiter is the gate that actually returns the 429.
        appendRateLimit({
          ts: new Date(now).toISOString(),
          kind: 'anomaly_block',
          subject_type: 'ip',
          subject_value: String(ip),
          path: (req.baseUrl || '') + req.path,
          status: 429,
          retry_after_s: retryAfterS,
          package_id: null,
        });
        return send429(res, retryAfterS, 'IP temporarily blocked');
      }
    }

    // Namespace by label so the same IP can hit /admin/* (stricter 30/min)
    // and the global path (100/min) without their counters colliding.
    const result = consume(ipBuckets, `ip:${label}:${ip}`, limit, now);
    if (!result.allowed) {
      logger.warn('rate_limit_exceeded_ip', { ip, retry_after_s: result.retryAfterS, label });
      // Persist per-IP 429 for analytics (kind='rate_limit_ip'). package_id
      // is null at the per-IP layer — the limiter runs before customerAuth
      // so no package context is available.
      appendRateLimit({
        ts: new Date(now).toISOString(),
        kind: 'rate_limit_ip',
        subject_type: 'ip',
        subject_value: String(ip),
        path: (req.baseUrl || '') + req.path,
        status: 429,
        retry_after_s: result.retryAfterS,
        package_id: null,
      });
      return send429(res, result.retryAfterS);
    }
    return next();
  };
}

/**
 * Per-tenant rate limit. Only runs against authenticated requests — caller
 * mounts this AFTER customerAuth has populated req.apiKey.tenant_id.
 * If req.apiKey is absent, the middleware is a pass-through (anonymous
 * traffic is handled by rateLimitByIp upstream).
 *
 *   rateLimitByTenant({ limit: 1000 })
 */
function rateLimitByTenant(opts = {}) {
  const limit = opts.limit || envInt('RATE_LIMIT_TENANT_PER_MIN', 1000);
  return function rateLimitByTenantMw(req, res, next) {
    const tenantId = req.apiKey && req.apiKey.tenant_id;
    if (!tenantId) return next();
    const now = Date.now();
    maybeSweep(now);
    const result = consume(tenantBuckets, `tenant:${tenantId}`, limit, now);
    if (!result.allowed) {
      logger.warn('rate_limit_exceeded_tenant', { tenant_id: tenantId, retry_after_s: result.retryAfterS });
      // Persist per-tenant 429 for analytics (kind='rate_limit_tenant').
      // package_id is derivable from req.apiKey when present — useful for
      // the operator's "which tier hits the cap most" view.
      appendRateLimit({
        ts: new Date(now).toISOString(),
        kind: 'rate_limit_tenant',
        subject_type: 'tenant',
        subject_value: String(tenantId),
        path: (req.baseUrl || '') + req.path,
        status: 429,
        retry_after_s: result.retryAfterS,
        package_id: (req.apiKey && req.apiKey.package_id) || null,
      });
      return send429(res, result.retryAfterS, 'Tenant rate limit exceeded');
    }
    return next();
  };
}

// ---------------------------------------------------------------------------
// Test helpers.
// ---------------------------------------------------------------------------
const _test = {
  reset() {
    ipBuckets.clear();
    tenantBuckets.clear();
    lastSweepMs = 0;
  },
  getBucket(key) {
    if (key.startsWith('tenant:')) return tenantBuckets.get(key) || null;
    if (key.startsWith('ip:')) return ipBuckets.get(key) || null;
    return ipBuckets.get(key) || tenantBuckets.get(key) || null;
  },
  // Push a key past its limit so the next request 429s. Used by tests that
  // want to verify the response shape without firing N requests first.
  forceLimit(key, limit) {
    const map = key.startsWith('tenant:') ? tenantBuckets : ipBuckets;
    const b = getOrCreateBucket(map, key, Date.now());
    b.windowStartMs = Date.now();
    b.count = (limit || 100) + 1;
  },
  bucketCount() {
    return ipBuckets.size + tenantBuckets.size;
  },
  WINDOW_MS,
  BUCKET_TTL_MS,
};

module.exports = {
  rateLimitByIp,
  rateLimitByTenant,
  appendRateLimit,
  rateLimitsFile,
  _test,
};
