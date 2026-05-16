'use strict';

// Unit tests for src/usage-rollup.js — daily JSON rollup index over the
// usage.jsonl substrate. Every test points USAGE_FILE + USAGE_ROLLUP_DIR
// at a tmpdir so the real data/ directory is never touched.

process.env.NODE_ENV = 'test';

const fs = require('fs');
const path = require('path');
const os = require('os');

let tmpDir;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-usage-rollup-test-'));
  process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
  process.env.USAGE_ROLLUP_DIR = tmpDir;
  // First-delay/interval don't matter for these tests — but bound the
  // first delay so the .unref() interval doesn't accidentally race.
  process.env.USAGE_ROLLUP_FIRST_DELAY_MS = '60000';
  process.env.USAGE_ROLLUP_INTERVAL_MS = '60000';
  jest.resetModules();
});

afterEach(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

function freshRollup() {
  jest.resetModules();
  return require('../src/usage-rollup');
}

function writeUsageRows(rows) {
  const body = rows.map((r) => JSON.stringify(r)).join('\n') + (rows.length ? '\n' : '');
  fs.writeFileSync(path.join(tmpDir, 'usage.jsonl'), body);
}

function rollupExistsFor(date) {
  return fs.existsSync(path.join(tmpDir, `usage-rollup-${date}.json`));
}

// ---------------------------------------------------------------------------
// computeDayRollup
// ---------------------------------------------------------------------------

describe('usage-rollup.computeDayRollup', () => {
  test('aggregates per-tenant + per-app + per-hour + global', async () => {
    writeUsageRows([
      // 2026-05-01, tenant a, app _default
      { ts: '2026-05-01T01:00:00.000Z', tenant_id: 'a', app_id: '_default', prompt_tokens: 10, completion_tokens: 5, latency_ms: 100, status: 'success' },
      { ts: '2026-05-01T01:30:00.000Z', tenant_id: 'a', app_id: '_default', prompt_tokens: 20, completion_tokens: 10, latency_ms: 200, status: 'success' },
      // 2026-05-01, tenant a, app truthpulse
      { ts: '2026-05-01T03:00:00.000Z', tenant_id: 'a', app_id: 'truthpulse', prompt_tokens: 5, completion_tokens: 5, latency_ms: 500, status: 'error' },
      // 2026-05-01, tenant b
      { ts: '2026-05-01T05:00:00.000Z', tenant_id: 'b', app_id: '_default', prompt_tokens: 1, completion_tokens: 1, latency_ms: 300, status: 'success' },
      // 2026-05-02 — DIFFERENT day, must be excluded
      { ts: '2026-05-02T01:00:00.000Z', tenant_id: 'a', app_id: '_default', prompt_tokens: 99, completion_tokens: 99, latency_ms: 999, status: 'success' },
    ]);
    const r = freshRollup();
    const out = await r.computeDayRollup('2026-05-01');

    expect(out.date).toBe('2026-05-01');
    expect(out.row_count).toBe(4);

    // Globals
    expect(out.globals.requests).toBe(4);
    expect(out.globals.prompt_tokens).toBe(10 + 20 + 5 + 1);
    expect(out.globals.completion_tokens).toBe(5 + 10 + 5 + 1);
    expect(out.globals.errors).toBe(1);
    // p50 of [100,200,300,500] nearest-rank → ceil(0.5*4)-1 = 1 → 200
    expect(out.globals.p50_latency_ms).toBe(200);

    // Per-tenant-app
    const aDefault = out.by_tenant_app['a\x00_default'];
    expect(aDefault.requests).toBe(2);
    expect(aDefault.prompt_tokens).toBe(30);
    const aTruth = out.by_tenant_app['a\x00truthpulse'];
    expect(aTruth.requests).toBe(1);
    expect(aTruth.errors).toBe(1);
    const bDefault = out.by_tenant_app['b\x00_default'];
    expect(bDefault.requests).toBe(1);

    // Per-hour — hours 01, 03, 05 should be populated
    expect(out.by_hour['01'].requests).toBe(2);
    expect(out.by_hour['03'].requests).toBe(1);
    expect(out.by_hour['05'].requests).toBe(1);
    expect(out.by_hour['02']).toBeUndefined();
  });

  test('idempotent — re-running produces same file shape', async () => {
    writeUsageRows([
      { ts: '2026-05-01T01:00:00.000Z', tenant_id: 'a', prompt_tokens: 1, completion_tokens: 1, latency_ms: 50, status: 'success' },
    ]);
    const r = freshRollup();
    const first = await r.computeDayRollup('2026-05-01');
    const second = await r.computeDayRollup('2026-05-01');
    expect(first.row_count).toBe(second.row_count);
    expect(first.globals.requests).toBe(second.globals.requests);
    expect(first.by_tenant_app).toEqual(second.by_tenant_app);
  });

  test('writes file with mode 0600', async () => {
    writeUsageRows([
      { ts: '2026-05-01T01:00:00.000Z', tenant_id: 'a', prompt_tokens: 1, completion_tokens: 1, latency_ms: 50, status: 'success' },
    ]);
    const r = freshRollup();
    await r.computeDayRollup('2026-05-01');
    const stat = fs.statSync(path.join(tmpDir, 'usage-rollup-2026-05-01.json'));
    // Permissions: lower 9 bits; we asked for 0600.
    // On some test environments umask can elide group/other bits, so we
    // check that group/other have no permissions.
    expect(stat.mode & 0o077).toBe(0);
  });

  test('rejects bad date shape', async () => {
    const r = freshRollup();
    await expect(r.computeDayRollup('2026/05/01')).rejects.toThrow(/YYYY-MM-DD/);
    await expect(r.computeDayRollup(null)).rejects.toThrow(/YYYY-MM-DD/);
  });

  test('skips non-chat-completions routes', async () => {
    writeUsageRows([
      { ts: '2026-05-01T01:00:00.000Z', tenant_id: 'a', route: '/v1/chat/completions', prompt_tokens: 1, completion_tokens: 1, latency_ms: 50, status: 'success' },
      { ts: '2026-05-01T02:00:00.000Z', tenant_id: 'a', route: '/v1/models', prompt_tokens: 0, completion_tokens: 0, latency_ms: 5, status: 'success' },
    ]);
    const r = freshRollup();
    const out = await r.computeDayRollup('2026-05-01');
    expect(out.row_count).toBe(1);
    expect(out.globals.requests).toBe(1);
  });

  test('missing usage.jsonl → empty rollup, no crash', async () => {
    const r = freshRollup();
    const out = await r.computeDayRollup('2026-05-01');
    expect(out.row_count).toBe(0);
    expect(out.globals.requests).toBe(0);
    expect(Object.keys(out.by_tenant_app).length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// readRollup + listAvailableRollups
// ---------------------------------------------------------------------------

describe('usage-rollup.readRollup / listAvailableRollups', () => {
  test('readRollup returns the same JSON written by compute', async () => {
    writeUsageRows([
      { ts: '2026-05-01T01:00:00.000Z', tenant_id: 'a', prompt_tokens: 1, completion_tokens: 1, latency_ms: 50, status: 'success' },
    ]);
    const r = freshRollup();
    const written = await r.computeDayRollup('2026-05-01');
    const read = r.readRollup('2026-05-01');
    expect(read.date).toBe(written.date);
    expect(read.row_count).toBe(written.row_count);
    expect(read.globals.requests).toBe(written.globals.requests);
  });

  test('readRollup returns null when file missing', async () => {
    const r = freshRollup();
    expect(r.readRollup('1999-01-01')).toBeNull();
  });

  test('listAvailableRollups returns sorted dates', async () => {
    // Pre-create three rollup files manually so we don't depend on
    // ordering of computeDayRollup runs.
    for (const d of ['2026-05-03', '2026-05-01', '2026-05-02']) {
      fs.writeFileSync(
        path.join(tmpDir, `usage-rollup-${d}.json`),
        JSON.stringify({ date: d, row_count: 0, globals: { requests: 0 } }),
        { mode: 0o600 },
      );
    }
    // Also drop a non-rollup file to make sure the regex filters it.
    fs.writeFileSync(path.join(tmpDir, 'usage.jsonl'), '');
    fs.writeFileSync(path.join(tmpDir, 'usage-rollup-nope.json'), '');
    const r = freshRollup();
    expect(r.listAvailableRollups()).toEqual(['2026-05-01', '2026-05-02', '2026-05-03']);
  });
});

// ---------------------------------------------------------------------------
// computeMissingRollups
// ---------------------------------------------------------------------------

describe('usage-rollup.computeMissingRollups', () => {
  test('auto-computes rollups for completed days only (never today)', async () => {
    // Build rows for yesterday and the day before yesterday + today.
    const dayMs = 24 * 60 * 60 * 1000;
    const now = new Date();
    const today = now.toISOString().slice(0, 10);
    const yesterday = new Date(now.getTime() - dayMs).toISOString().slice(0, 10);
    const dayBefore = new Date(now.getTime() - 2 * dayMs).toISOString().slice(0, 10);
    writeUsageRows([
      { ts: `${dayBefore}T01:00:00.000Z`, tenant_id: 'a', prompt_tokens: 1, completion_tokens: 1, latency_ms: 100, status: 'success' },
      { ts: `${yesterday}T01:00:00.000Z`, tenant_id: 'a', prompt_tokens: 2, completion_tokens: 2, latency_ms: 200, status: 'success' },
      // today — must NEVER be rolled up automatically
      { ts: `${today}T01:00:00.000Z`, tenant_id: 'a', prompt_tokens: 99, completion_tokens: 99, latency_ms: 999, status: 'success' },
    ]);
    const r = freshRollup();
    const computed = await r.computeMissingRollups({});
    expect(computed).toContain(yesterday);
    expect(computed).toContain(dayBefore);
    expect(computed).not.toContain(today);
    expect(rollupExistsFor(today)).toBe(false);
    expect(rollupExistsFor(yesterday)).toBe(true);
  });

  test('honors sinceDateIso — earlier dates excluded', async () => {
    const dayMs = 24 * 60 * 60 * 1000;
    const now = new Date();
    const yesterday = new Date(now.getTime() - dayMs).toISOString().slice(0, 10);
    const tenDaysAgo = new Date(now.getTime() - 10 * dayMs).toISOString().slice(0, 10);
    writeUsageRows([
      { ts: `${tenDaysAgo}T01:00:00.000Z`, tenant_id: 'a', prompt_tokens: 1, completion_tokens: 1, latency_ms: 100, status: 'success' },
      { ts: `${yesterday}T01:00:00.000Z`, tenant_id: 'a', prompt_tokens: 2, completion_tokens: 2, latency_ms: 200, status: 'success' },
    ]);
    const r = freshRollup();
    // since = yesterday → tenDaysAgo MUST be skipped
    const computed = await r.computeMissingRollups({ sinceDateIso: yesterday });
    expect(computed).toContain(yesterday);
    expect(computed).not.toContain(tenDaysAgo);
  });

  test('skips dates that already have a rollup file', async () => {
    const dayMs = 24 * 60 * 60 * 1000;
    const now = new Date();
    const yesterday = new Date(now.getTime() - dayMs).toISOString().slice(0, 10);
    writeUsageRows([
      { ts: `${yesterday}T01:00:00.000Z`, tenant_id: 'a', prompt_tokens: 1, completion_tokens: 1, latency_ms: 50, status: 'success' },
    ]);
    const r = freshRollup();
    const first = await r.computeMissingRollups({});
    expect(first).toContain(yesterday);
    // Second run: rollup already exists, so it's NOT re-computed.
    const second = await r.computeMissingRollups({});
    expect(second).not.toContain(yesterday);
  });
});

// ---------------------------------------------------------------------------
// analytics.requestsByHour integration — rollup-cache hit path
// ---------------------------------------------------------------------------

describe('analytics integration — requestsByHour reads rollup cache', () => {
  test('with 7 days of rollups present, requestsByHour reports cache hit + correct totals', async () => {
    // Build 7 completed-day rollup files (manually so we don't depend on
    // wall-clock; rollups are READ as-is so the file is the truth).
    const days = [];
    for (let i = 7; i >= 1; i -= 1) {
      const d = new Date(Date.now() - i * 24 * 60 * 60 * 1000)
        .toISOString().slice(0, 10);
      days.push(d);
      const rollup = {
        date: d,
        generated_at: new Date().toISOString(),
        row_count: 10,
        globals: {
          requests: 10,
          prompt_tokens: 100,
          completion_tokens: 50,
          errors: 1,
          p50_latency_ms: 100,
          p95_latency_ms: 200,
          p99_latency_ms: 250,
          latency_samples: [50, 100, 150, 200, 250],
        },
        by_tenant_app: {
          'a\x00_default': {
            tenant_id: 'a', app_id: '_default',
            requests: 10, prompt_tokens: 100, completion_tokens: 50,
            errors: 1, p50_latency_ms: 100, p95_latency_ms: 200,
            p99_latency_ms: 250, latency_samples: [50, 100, 150, 200, 250],
          },
        },
        by_hour: {
          '01': {
            hour: '01', requests: 10, prompt_tokens: 100,
            completion_tokens: 50, errors: 1, p50_latency_ms: 100,
            p95_latency_ms: 200, latency_samples: [50, 100, 150, 200, 250],
          },
        },
        schema_version: 1,
      };
      fs.writeFileSync(
        path.join(tmpDir, `usage-rollup-${d}.json`),
        JSON.stringify(rollup),
        { mode: 0o600 },
      );
    }
    // Put one row for TODAY in usage.jsonl so the streaming half also fires.
    const today = new Date().toISOString().slice(0, 10);
    writeUsageRows([
      { ts: `${today}T12:00:00.000Z`, tenant_id: 'a', app_id: '_default', prompt_tokens: 1, completion_tokens: 1, latency_ms: 10, status: 'success' },
    ]);

    jest.resetModules();
    const analytics = require('../src/analytics');
    const sinceMs = Date.now() - 30 * 24 * 60 * 60 * 1000;
    const out = await analytics.requestsByHour({ sinceMs, granularity: 'day' });

    // 7 rollup days × 10 requests + 1 streamed row = 71
    expect(out.totals.requests).toBe(71);
    expect(out.rollup_cache_hit).toBe(true);
    expect(out.rollup_dates.length).toBe(7);
    expect(out.source).toMatch(/daily rollup/);
  });

  test('with no rollups present, behavior is unchanged (streams jsonl)', async () => {
    writeUsageRows([
      { ts: '2026-05-01T01:00:00.000Z', tenant_id: 'a', prompt_tokens: 10, completion_tokens: 5, latency_ms: 100, status: 'success' },
      { ts: '2026-05-01T02:00:00.000Z', tenant_id: 'a', prompt_tokens: 20, completion_tokens: 10, latency_ms: 200, status: 'success' },
    ]);
    jest.resetModules();
    const analytics = require('../src/analytics');
    const out = await analytics.requestsByHour({ sinceMs: 0, granularity: 'hour' });
    expect(out.totals.requests).toBe(2);
    expect(out.rollup_cache_hit).toBe(false);
    expect(out.source).toBe('usage.jsonl');
  });

  test('day covered by rollup is NOT double-counted from usage.jsonl', async () => {
    // Yesterday: usage.jsonl has 3 rows AND a rollup says requests=3.
    // Result should be 3, not 6.
    const dayMs = 24 * 60 * 60 * 1000;
    const now = new Date();
    const yesterday = new Date(now.getTime() - dayMs).toISOString().slice(0, 10);
    writeUsageRows([
      { ts: `${yesterday}T01:00:00.000Z`, tenant_id: 'a', prompt_tokens: 1, completion_tokens: 1, latency_ms: 100, status: 'success' },
      { ts: `${yesterday}T02:00:00.000Z`, tenant_id: 'a', prompt_tokens: 1, completion_tokens: 1, latency_ms: 100, status: 'success' },
      { ts: `${yesterday}T03:00:00.000Z`, tenant_id: 'a', prompt_tokens: 1, completion_tokens: 1, latency_ms: 100, status: 'success' },
    ]);
    const rollup = {
      date: yesterday,
      generated_at: new Date().toISOString(),
      row_count: 3,
      globals: {
        requests: 3, prompt_tokens: 3, completion_tokens: 3,
        errors: 0, p50_latency_ms: 100, p95_latency_ms: 100,
        p99_latency_ms: 100, latency_samples: [100, 100, 100],
      },
      by_tenant_app: {
        'a\x00_default': {
          tenant_id: 'a', app_id: '_default',
          requests: 3, prompt_tokens: 3, completion_tokens: 3,
          errors: 0, p50_latency_ms: 100, p95_latency_ms: 100,
          p99_latency_ms: 100, latency_samples: [100, 100, 100],
        },
      },
      by_hour: {},
      schema_version: 1,
    };
    fs.writeFileSync(
      path.join(tmpDir, `usage-rollup-${yesterday}.json`),
      JSON.stringify(rollup),
      { mode: 0o600 },
    );
    jest.resetModules();
    const analytics = require('../src/analytics');
    const out = await analytics.requestsByHour({ sinceMs: 0, granularity: 'day' });
    expect(out.totals.requests).toBe(3); // not 6
    expect(out.rollup_cache_hit).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Scheduler — startScheduler / stop
// ---------------------------------------------------------------------------

describe('usage-rollup.startScheduler', () => {
  test('returns the same stop handle on double start (idempotent)', () => {
    const r = freshRollup();
    const stop1 = r.startScheduler();
    const stop2 = r.startScheduler();
    expect(stop1).toBe(stop2);
    stop1();
  });

  test('stop() does not throw and is safe to call twice', () => {
    const r = freshRollup();
    const stop = r.startScheduler();
    expect(() => stop()).not.toThrow();
    expect(() => stop()).not.toThrow();
  });
});
