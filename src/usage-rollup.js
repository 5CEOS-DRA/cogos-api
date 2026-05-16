'use strict';

// Daily JSON rollup index for usage.jsonl.
//
// ---------------------------------------------------------------------------
// Why this exists.
// ---------------------------------------------------------------------------
// At 1000 customers averaging 100 req/day each the usage substrate grows by
// ~100K rows/day → ~365M rows/year. Streaming reads through analytics.js
// stay fast through ~10M rows but slow noticeably past that. The fix is
// the standard one: pre-aggregate completed days into a small per-day JSON
// summary so a "last 30 days" query reads 30 small files instead of
// streaming the full append-only log.
//
// CONTRACT:
//   - Rollups are a CACHE. The source of truth is still usage.jsonl. If a
//     row arrives AFTER a rollup file has been written for that day,
//     callers can detect the drift via row_count: re-running
//     computeDayRollup(date) overwrites the file with the corrected
//     aggregate. The rollup file's `row_count` is the count of rows
//     consumed at compute time and is what analytics.js should compare
//     against when it wants to verify completeness.
//   - We ONLY auto-compute rollups for COMPLETE UTC days (date < today
//     UTC). Today's data is in-progress and is NEVER pre-aggregated by
//     the scheduler — readers ALWAYS stream usage.jsonl for the current
//     UTC day. This eliminates the "rollup-stale-for-today" failure mode
//     by construction.
//   - Idempotent: re-running computeDayRollup for the same date
//     overwrites the file with the new aggregate. Safe to re-run if the
//     operator suspects the rollup is stale.
//   - On-disk shape is a single JSON object per day:
//       {
//         date: 'YYYY-MM-DD',
//         generated_at: '...',
//         row_count: <int>,                     // rows consumed at compute time
//         globals: { requests, prompt_tokens, completion_tokens,
//                    p50_latency_ms, p95_latency_ms, p99_latency_ms,
//                    errors, latency_samples: [...] },
//         by_tenant_app: { 'tenant\x00app': { requests, prompt_tokens,
//                          completion_tokens, p50, p95, p99, errors } },
//         by_hour: { 'HH': { requests, prompt_tokens, completion_tokens,
//                            errors, p50, p95 } }
//       }
//     `latency_samples` is kept (capped at 10K random samples for memory
//     safety) so a multi-day aggregation can still compute a faithful
//     window-level percentile by merging samples across rollups instead
//     of trying to combine pre-computed percentiles (which is wrong —
//     median-of-medians ≠ median).
//
// FILES:
//   - data/usage-rollup-YYYY-MM-DD.json  (mode 0600)
//
// SCHEDULER:
//   - In-process setInterval that fires daily at 01:00 UTC and calls
//     computeMissingRollups({ sinceDateIso: 30 days ago }). Same shape
//     as audit-checkpoint.startScheduler(). The exact wall-clock isn't
//     load-bearing — anytime after the day boundary is correct.
//
// SECURITY:
//   - No customer content. We aggregate by tenant_id + app_id +
//     latency/token counters. Rollup files carry NO prompt content,
//     NO sealed-content envelopes, NO API keys. They're operator
//     summaries and have the same sensitivity class as
//     /admin/analytics/* responses.

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const DATA_DIR = path.join(__dirname, '..', 'data');

function rollupDir() {
  return process.env.USAGE_ROLLUP_DIR || DATA_DIR;
}

function usageFile() {
  return process.env.USAGE_FILE || path.join(DATA_DIR, 'usage.jsonl');
}

function rollupPath(dateIso) {
  return path.join(rollupDir(), `usage-rollup-${dateIso}.json`);
}

// Sample-size cap for the per-bucket latency arrays. Picked so a single
// rollup file stays under ~1MB on a busy day. Reservoir sampling keeps
// the percentile estimate honest above the cap — well above what we
// actually expect on the bucket cardinalities here, but bounded
// nonetheless.
const LATENCY_SAMPLE_CAP = 10000;

function percentile(samples, p) {
  if (!samples || samples.length === 0) return 0;
  const sorted = samples.slice().sort((a, b) => a - b);
  const rank = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, Math.min(sorted.length - 1, rank))];
}

// Reservoir sampling for the latency array — keeps it bounded at
// LATENCY_SAMPLE_CAP entries while preserving an unbiased sample of
// the day's distribution. The bucket aggregators below all use this so
// busy tenants don't blow the rollup file size up.
function reservoirPush(samples, value, seenSoFar) {
  if (samples.length < LATENCY_SAMPLE_CAP) {
    samples.push(value);
    return;
  }
  const idx = Math.floor(Math.random() * (seenSoFar + 1));
  if (idx < LATENCY_SAMPLE_CAP) {
    samples[idx] = value;
  }
}

function utcDay(ms) {
  return new Date(ms).toISOString().slice(0, 10);
}

function utcHour(ms) {
  return new Date(ms).toISOString().slice(11, 13);
}

function todayIso() {
  return utcDay(Date.now());
}

function ensureDir() {
  const dir = rollupDir();
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
}

// Compute the rollup for a given UTC date by streaming usage.jsonl
// line-by-line, filtering to rows whose ts falls inside that day, and
// aggregating per-(tenant,app) + per-hour + global. Writes the result
// to disk and returns the in-memory object.
//
// IDEMPOTENT: overwrites any existing rollup file for that date. Use
// this directly when you want to force-recompute (e.g., a late-arriving
// row was detected).
async function computeDayRollup(dateIso) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateIso || '')) {
    throw new Error(`computeDayRollup: dateIso must be YYYY-MM-DD, got ${JSON.stringify(dateIso)}`);
  }
  ensureDir();

  // Tenant\x00app → bucket. \x00 is the canonical separator (same as
  // usage.js _cacheKey) because tenant_ids are arbitrary strings; \x00
  // is the only byte guaranteed not to appear in any plausible id.
  const byTenantApp = new Map();
  const byHour = new Map();
  const globals = {
    requests: 0,
    prompt_tokens: 0,
    completion_tokens: 0,
    errors: 0,
    _latency: [],
  };

  let rowCount = 0;
  let seenLatency = 0;

  const usagePath = usageFile();
  if (fs.existsSync(usagePath)) {
    const stream = fs.createReadStream(usagePath, { encoding: 'utf8' });
    const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
    for await (const line of rl) {
      if (!line || !line.trim()) continue;
      let row;
      try { row = JSON.parse(line); } catch { continue; }
      if (!row || !row.ts) continue;
      const ms = Date.parse(row.ts);
      if (!Number.isFinite(ms)) continue;
      if (utcDay(ms) !== dateIso) continue;
      // Match analytics.requestsByHour: only count chat completions.
      // Default-route rows (older history) are counted because
      // route was added later.
      if (row.route && row.route !== '/v1/chat/completions') continue;

      rowCount += 1;
      const pt = Number(row.prompt_tokens) || 0;
      const ct = Number(row.completion_tokens) || 0;
      const lat = Number(row.latency_ms);
      const isErr = row.status && row.status !== 'success';

      globals.requests += 1;
      globals.prompt_tokens += pt;
      globals.completion_tokens += ct;
      if (isErr) globals.errors += 1;
      if (Number.isFinite(lat) && lat > 0) {
        reservoirPush(globals._latency, lat, seenLatency);
        seenLatency += 1;
      }

      const tenantId = row.tenant_id || '_unknown';
      const appId = row.app_id || '_default';
      const taKey = `${tenantId}\x00${appId}`;
      if (!byTenantApp.has(taKey)) {
        byTenantApp.set(taKey, {
          tenant_id: tenantId,
          app_id: appId,
          requests: 0,
          prompt_tokens: 0,
          completion_tokens: 0,
          errors: 0,
          _latency: [],
          _seen: 0,
        });
      }
      const tab = byTenantApp.get(taKey);
      tab.requests += 1;
      tab.prompt_tokens += pt;
      tab.completion_tokens += ct;
      if (isErr) tab.errors += 1;
      if (Number.isFinite(lat) && lat > 0) {
        reservoirPush(tab._latency, lat, tab._seen);
        tab._seen += 1;
      }

      const hour = utcHour(ms);
      if (!byHour.has(hour)) {
        byHour.set(hour, {
          hour,
          requests: 0,
          prompt_tokens: 0,
          completion_tokens: 0,
          errors: 0,
          _latency: [],
          _seen: 0,
        });
      }
      const hb = byHour.get(hour);
      hb.requests += 1;
      hb.prompt_tokens += pt;
      hb.completion_tokens += ct;
      if (isErr) hb.errors += 1;
      if (Number.isFinite(lat) && lat > 0) {
        reservoirPush(hb._latency, lat, hb._seen);
        hb._seen += 1;
      }
    }
  }

  // Finalize: compute percentiles, project to JSON-safe shape.
  const byTenantAppOut = {};
  for (const [key, v] of byTenantApp.entries()) {
    byTenantAppOut[key] = {
      tenant_id: v.tenant_id,
      app_id: v.app_id,
      requests: v.requests,
      prompt_tokens: v.prompt_tokens,
      completion_tokens: v.completion_tokens,
      errors: v.errors,
      p50_latency_ms: percentile(v._latency, 50),
      p95_latency_ms: percentile(v._latency, 95),
      p99_latency_ms: percentile(v._latency, 99),
      // Keep raw samples so a window aggregator can merge faithfully.
      latency_samples: v._latency,
    };
  }

  const byHourOut = {};
  for (const [hour, v] of byHour.entries()) {
    byHourOut[hour] = {
      hour,
      requests: v.requests,
      prompt_tokens: v.prompt_tokens,
      completion_tokens: v.completion_tokens,
      errors: v.errors,
      p50_latency_ms: percentile(v._latency, 50),
      p95_latency_ms: percentile(v._latency, 95),
      latency_samples: v._latency,
    };
  }

  const out = {
    date: dateIso,
    generated_at: new Date().toISOString(),
    row_count: rowCount,
    globals: {
      requests: globals.requests,
      prompt_tokens: globals.prompt_tokens,
      completion_tokens: globals.completion_tokens,
      errors: globals.errors,
      p50_latency_ms: percentile(globals._latency, 50),
      p95_latency_ms: percentile(globals._latency, 95),
      p99_latency_ms: percentile(globals._latency, 99),
      latency_samples: globals._latency,
    },
    by_tenant_app: byTenantAppOut,
    by_hour: byHourOut,
    schema_version: 1,
  };

  fs.writeFileSync(rollupPath(dateIso), JSON.stringify(out), { mode: 0o600 });
  return out;
}

// Fast load — JSON.parse on a small file. Returns null if missing so
// the caller can decide to fall back to a streaming read.
function readRollup(dateIso) {
  const fp = rollupPath(dateIso);
  if (!fs.existsSync(fp)) return null;
  try {
    return JSON.parse(fs.readFileSync(fp, 'utf8'));
  } catch {
    return null;
  }
}

// List YYYY-MM-DD strings for which a rollup file exists. Sorted
// ascending so the caller can pick a range easily.
function listAvailableRollups() {
  ensureDir();
  const dir = rollupDir();
  let entries;
  try {
    entries = fs.readdirSync(dir);
  } catch {
    return [];
  }
  const out = [];
  for (const name of entries) {
    const m = name.match(/^usage-rollup-(\d{4}-\d{2}-\d{2})\.json$/);
    if (m) out.push(m[1]);
  }
  out.sort();
  return out;
}

// Walk back from `sinceDateIso` (inclusive) to YESTERDAY (today is
// IN-PROGRESS and never auto-rolled). For each missing date, compute
// the rollup. Returns the list of dates actually computed.
//
// `sinceDateIso` defaults to 30 days before today UTC.
async function computeMissingRollups({ sinceDateIso } = {}) {
  const todayMs = Date.now();
  const todayIsoStr = utcDay(todayMs);
  const dayMs = 24 * 60 * 60 * 1000;

  let startMs;
  if (sinceDateIso && /^\d{4}-\d{2}-\d{2}$/.test(sinceDateIso)) {
    startMs = Date.parse(`${sinceDateIso}T00:00:00.000Z`);
  } else {
    startMs = todayMs - 30 * dayMs;
  }

  // Generate every UTC day from startMs through YESTERDAY (today excluded).
  const dates = [];
  for (let ms = startMs; ms < todayMs; ms += dayMs) {
    const d = utcDay(ms);
    if (d === todayIsoStr) continue;
    if (!dates.includes(d)) dates.push(d);
  }

  const computed = [];
  for (const d of dates) {
    const fp = rollupPath(d);
    if (fs.existsSync(fp)) continue;
    try {
      await computeDayRollup(d);
      computed.push(d);
    } catch {
      // Per-day failure shouldn't poison the rest of the catch-up run.
      // The scheduler will retry tomorrow.
    }
  }
  return computed;
}

// In-process scheduler. Same pattern as audit-checkpoint.startScheduler:
// idempotent, .unref()'d so tests don't hang, returns a stop() handle.
//
// CADENCE: fires once at startup (after a short delay so the rest of
// boot can complete) and then daily. The exact time-of-day doesn't
// matter — anytime after the UTC day boundary catches yesterday.

const DEFAULT_INTERVAL_MS = Number(
  process.env.USAGE_ROLLUP_INTERVAL_MS || 24 * 60 * 60 * 1000,
);
// First-run delay: 5s after startScheduler() so we don't slam disk
// during the rest of boot. Test override via env so we can pin to 1ms.
const DEFAULT_FIRST_DELAY_MS = Number(
  process.env.USAGE_ROLLUP_FIRST_DELAY_MS || 5000,
);

let _activeInterval = null;
let _activeFirstTimer = null;
let _activeStop = null;
let _runInFlight = false;

async function _safeRun() {
  if (_runInFlight) return [];
  _runInFlight = true;
  try {
    return await computeMissingRollups({});
  } catch {
    return [];
  } finally {
    _runInFlight = false;
  }
}

function startScheduler() {
  if (_activeInterval) return _activeStop;

  _activeFirstTimer = setTimeout(() => {
    _safeRun().catch(() => {});
  }, DEFAULT_FIRST_DELAY_MS);
  if (_activeFirstTimer.unref) _activeFirstTimer.unref();

  _activeInterval = setInterval(() => {
    _safeRun().catch(() => {});
  }, DEFAULT_INTERVAL_MS);
  if (_activeInterval.unref) _activeInterval.unref();

  _activeStop = function stop() {
    if (_activeInterval) {
      clearInterval(_activeInterval);
      _activeInterval = null;
    }
    if (_activeFirstTimer) {
      clearTimeout(_activeFirstTimer);
      _activeFirstTimer = null;
    }
    _activeStop = null;
  };
  return _activeStop;
}

function _resetForTest() {
  if (_activeInterval) clearInterval(_activeInterval);
  if (_activeFirstTimer) clearTimeout(_activeFirstTimer);
  _activeInterval = null;
  _activeFirstTimer = null;
  _activeStop = null;
  _runInFlight = false;
}

module.exports = {
  computeDayRollup,
  readRollup,
  listAvailableRollups,
  computeMissingRollups,
  startScheduler,
  // Test hooks
  _internal: {
    rollupPath,
    utcDay,
    todayIso,
    percentile,
    LATENCY_SAMPLE_CAP,
    _resetForTest,
  },
};
