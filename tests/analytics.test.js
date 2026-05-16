'use strict';

// Unit + HTTP-level tests for the operator-analytics module.
// Companion module: src/analytics.js.
//
// Strategy: every test points the data-source env vars at a tmpdir so
// we never touch the real data/ directory. Most tests exercise the
// aggregators directly via require('../src/analytics'); the HTTP-level
// tests use supertest against createApp() to verify auth + route wiring.

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

let tmpDir;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-analytics-test-'));
  process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
  process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
  process.env.ANOMALIES_FILE = path.join(tmpDir, 'anomalies.jsonl');
  process.env.NOTIFY_SIGNUPS_FILE = path.join(tmpDir, 'notify-signups.jsonl');
  process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
  jest.resetModules();
});

afterEach(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

function freshAnalytics() {
  jest.resetModules();
  return require('../src/analytics');
}

function writeKeys(records) {
  fs.writeFileSync(path.join(tmpDir, 'keys.json'), JSON.stringify(records, null, 2));
}
function writeJsonl(name, rows) {
  fs.writeFileSync(
    path.join(tmpDir, name),
    rows.map((r) => JSON.stringify(r)).join('\n') + (rows.length ? '\n' : ''),
  );
}
function writePackages(records) {
  fs.writeFileSync(path.join(tmpDir, 'packages.json'), JSON.stringify(records, null, 2));
}

// ---------------------------------------------------------------------------
// signupsByDay
// ---------------------------------------------------------------------------

describe('analytics.signupsByDay', () => {
  test('partitions free vs paid keys by issued_at', async () => {
    const now = Date.now();
    const dayMs = 24 * 60 * 60 * 1000;
    writeKeys([
      // free signup yesterday
      { id: 'k1', tenant_id: 'a', package_id: 'free', issued_at: new Date(now - dayMs).toISOString() },
      // paid signup today (Stripe-bound)
      { id: 'k2', tenant_id: 'b', package_id: 'starter', stripe_customer_id: 'cus_1', issued_at: new Date(now).toISOString() },
      // admin-issued key with no Stripe metadata — NOT a paid signup
      { id: 'k3', tenant_id: 'c', package_id: 'starter', issued_at: new Date(now).toISOString() },
      // another free signup today
      { id: 'k4', tenant_id: 'd', package_id: 'free', issued_at: new Date(now).toISOString() },
    ]);
    const a = freshAnalytics();
    const out = await a.signupsByDay({ sinceMs: now - 7 * dayMs });
    expect(out.totals.free).toBe(2);
    expect(out.totals.paid).toBe(1);
    expect(out.totals.total).toBe(3);
    expect(out.by_day.length).toBeGreaterThanOrEqual(1);
    expect(out.source).toMatch(/keys\.json/);
  });

  test('honors sinceMs window — older rows excluded', async () => {
    const now = Date.now();
    const dayMs = 24 * 60 * 60 * 1000;
    writeKeys([
      { id: 'old', tenant_id: 'a', package_id: 'free', issued_at: new Date(now - 60 * dayMs).toISOString() },
      { id: 'new', tenant_id: 'b', package_id: 'free', issued_at: new Date(now).toISOString() },
    ]);
    const a = freshAnalytics();
    const out = await a.signupsByDay({ sinceMs: now - 7 * dayMs });
    expect(out.totals.free).toBe(1);
  });

  test('missing keys.json → empty aggregation, no crash', async () => {
    const a = freshAnalytics();
    const out = await a.signupsByDay({ sinceMs: 0 });
    expect(out.totals.free).toBe(0);
    expect(out.totals.paid).toBe(0);
    expect(Array.isArray(out.by_day)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// requestsByHour
// ---------------------------------------------------------------------------

describe('analytics.requestsByHour', () => {
  test('buckets rows into UTC hours, computes percentiles', async () => {
    // Two rows at 12:00, one at 13:00, latencies 100/200/500.
    const base = '2026-05-14T12:';
    writeJsonl('usage.jsonl', [
      { ts: `${base}05:00.000Z`, tenant_id: 'a', prompt_tokens: 10, completion_tokens: 5, latency_ms: 100, status: 'success' },
      { ts: `${base}45:00.000Z`, tenant_id: 'a', prompt_tokens: 20, completion_tokens: 10, latency_ms: 200, status: 'success' },
      { ts: `2026-05-14T13:10:00.000Z`, tenant_id: 'b', prompt_tokens: 5, completion_tokens: 5, latency_ms: 500, status: 'error' },
    ]);
    const a = freshAnalytics();
    const out = await a.requestsByHour({ sinceMs: 0, granularity: 'hour' });
    expect(out.by_bucket.length).toBe(2);
    const noon = out.by_bucket.find((b) => b.ts_iso === '2026-05-14T12:00:00.000Z');
    expect(noon.requests).toBe(2);
    expect(noon.prompt_tokens).toBe(30);
    expect(noon.completion_tokens).toBe(15);
    expect(noon.errors).toBe(0);
    const one = out.by_bucket.find((b) => b.ts_iso === '2026-05-14T13:00:00.000Z');
    expect(one.requests).toBe(1);
    expect(one.errors).toBe(1);
    expect(out.totals.requests).toBe(3);
    expect(out.totals.errors).toBe(1);
    // p50 of [100,200,500] should be 200 nearest-rank.
    expect(out.totals.p50_latency_ms).toBe(200);
  });

  test('day granularity flattens to one bucket per UTC day', async () => {
    writeJsonl('usage.jsonl', [
      { ts: '2026-05-14T01:00:00.000Z', latency_ms: 10, status: 'success' },
      { ts: '2026-05-14T23:30:00.000Z', latency_ms: 20, status: 'success' },
      { ts: '2026-05-15T00:00:00.000Z', latency_ms: 30, status: 'success' },
    ]);
    const a = freshAnalytics();
    const out = await a.requestsByHour({ sinceMs: 0, granularity: 'day' });
    expect(out.by_bucket.length).toBe(2);
    expect(out.granularity).toBe('day');
  });

  test('malformed JSONL lines are skipped, not crashed', async () => {
    const file = path.join(tmpDir, 'usage.jsonl');
    fs.writeFileSync(file, [
      JSON.stringify({ ts: '2026-05-14T12:00:00.000Z', latency_ms: 100, status: 'success' }),
      'not-valid-json-line',
      JSON.stringify({ ts: '2026-05-14T13:00:00.000Z', latency_ms: 200, status: 'success' }),
      '{}{garbage{',
    ].join('\n') + '\n');
    const a = freshAnalytics();
    const out = await a.requestsByHour({ sinceMs: 0 });
    expect(out.totals.requests).toBe(2);
    expect(out.skipped_lines).toBe(2);
  });

  test('missing usage.jsonl → empty aggregation, no crash', async () => {
    const a = freshAnalytics();
    const out = await a.requestsByHour({ sinceMs: 0 });
    expect(out.totals.requests).toBe(0);
    expect(out.by_bucket).toEqual([]);
  });

  test('sinceMs filter excludes older rows', async () => {
    const now = Date.now();
    const oldTs = new Date(now - 60 * 24 * 60 * 60 * 1000).toISOString();
    const newTs = new Date(now).toISOString();
    writeJsonl('usage.jsonl', [
      { ts: oldTs, latency_ms: 100, status: 'success' },
      { ts: newTs, latency_ms: 200, status: 'success' },
    ]);
    const a = freshAnalytics();
    const out = await a.requestsByHour({ sinceMs: now - 7 * 24 * 60 * 60 * 1000 });
    expect(out.totals.requests).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// anomaliesByKind
// ---------------------------------------------------------------------------

describe('analytics.anomaliesByKind', () => {
  test('aggregates kinds + returns recent[]', async () => {
    const rows = [];
    for (let i = 0; i < 25; i += 1) {
      rows.push({
        ts: new Date(Date.now() - (25 - i) * 1000).toISOString(),
        kind: i % 2 === 0 ? 'scanner_active' : 'auth_brute_force_suspected',
        context: { last_path: '/.env' },
      });
    }
    writeJsonl('anomalies.jsonl', rows);
    const a = freshAnalytics();
    const out = await a.anomaliesByKind({ sinceMs: 0 });
    expect(out.by_kind.scanner_active).toBe(13);
    expect(out.by_kind.auth_brute_force_suspected).toBe(12);
    expect(out.recent.length).toBe(20);
    expect(out.total).toBe(25);
  });

  test('missing anomalies.jsonl → empty by_kind', async () => {
    const a = freshAnalytics();
    const out = await a.anomaliesByKind({ sinceMs: 0 });
    expect(out.by_kind).toEqual({});
    expect(out.recent).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// honeypotsByPath
// ---------------------------------------------------------------------------

describe('analytics.honeypotsByPath', () => {
  test('missing data/honeypots.jsonl → zeros + a note flagging the gap', async () => {
    const a = freshAnalytics();
    process.env.HONEYPOTS_FILE = path.join(tmpDir, 'honeypots.jsonl');
    const out = await a.honeypotsByPath({ sinceMs: 0 });
    expect(out.note).toMatch(/does not exist/i);
    expect(out.source).toMatch(/honeypots\.jsonl/);
    expect(out.total).toBe(0);
  });

  test('reads from seeded honeypots.jsonl + aggregates by normalized_path', async () => {
    process.env.HONEYPOTS_FILE = path.join(tmpDir, 'honeypots.jsonl');
    fs.writeFileSync(process.env.HONEYPOTS_FILE, [
      JSON.stringify({ ts: new Date().toISOString(), path: '/.env',  normalized_path: '/.env',  method: 'GET', ip: '1.2.3.4', ua: 'curl', country: null }),
      JSON.stringify({ ts: new Date().toISOString(), path: '/.ENV',  normalized_path: '/.env',  method: 'GET', ip: '1.2.3.5', ua: 'curl', country: null }),
      JSON.stringify({ ts: new Date().toISOString(), path: '/wp-admin', normalized_path: '/wp-admin', method: 'GET', ip: '1.2.3.6', ua: 'curl', country: null }),
    ].join('\n') + '\n');
    const a = freshAnalytics();
    const out = await a.honeypotsByPath({ sinceMs: 0 });
    expect(out.total).toBe(3);
    expect(out.by_path['/.env']).toBe(2);
    expect(out.by_path['/wp-admin']).toBe(1);
    // File exists with data → no `note` field.
    expect(out.note).toBeUndefined();
    // top_paths is sorted by count descending.
    expect(out.top_paths[0]).toEqual({ path: '/.env', count: 2 });
  });
});

// ---------------------------------------------------------------------------
// rateLimitsByDay
// ---------------------------------------------------------------------------

describe('analytics.rateLimitsByDay', () => {
  test('missing data/rate-limits.jsonl → zeros + a note flagging the gap', async () => {
    process.env.RATE_LIMITS_FILE = path.join(tmpDir, 'rate-limits.jsonl');
    const a = freshAnalytics();
    const out = await a.rateLimitsByDay({ sinceMs: 0 });
    // Five known kinds are seeded to zero so a UI legend pre-render works.
    expect(out.by_kind.rate_limit_ip).toBe(0);
    expect(out.by_kind.rate_limit_tenant).toBe(0);
    expect(out.by_kind.daily_quota_request).toBe(0);
    expect(out.by_kind.daily_quota_token).toBe(0);
    expect(out.by_kind.anomaly_block).toBe(0);
    expect(out.total).toBe(0);
    expect(out.note).toMatch(/does not exist/i);
  });

  test('reads from seeded rate-limits.jsonl + aggregates by kind + by_day', async () => {
    process.env.RATE_LIMITS_FILE = path.join(tmpDir, 'rate-limits.jsonl');
    const today = new Date().toISOString();
    fs.writeFileSync(process.env.RATE_LIMITS_FILE, [
      JSON.stringify({ ts: today, kind: 'rate_limit_ip',       subject_type: 'ip',     subject_value: '1.2.3.4',   path: '/health',             status: 429, retry_after_s: 60, package_id: null }),
      JSON.stringify({ ts: today, kind: 'rate_limit_ip',       subject_type: 'ip',     subject_value: '1.2.3.4',   path: '/health',             status: 429, retry_after_s: 60, package_id: null }),
      JSON.stringify({ ts: today, kind: 'rate_limit_tenant',   subject_type: 'tenant', subject_value: 'tenant-x',  path: '/v1/chat/completions', status: 429, retry_after_s: 60, package_id: 'starter' }),
      JSON.stringify({ ts: today, kind: 'daily_quota_request', subject_type: 'tenant', subject_value: 'tenant-y',  path: '/v1/chat/completions', status: 429, retry_after_s: 60, package_id: 'free' }),
      JSON.stringify({ ts: today, kind: 'daily_quota_token',   subject_type: 'tenant', subject_value: 'tenant-y',  path: '/v1/chat/completions', status: 429, retry_after_s: 60, package_id: 'free' }),
      JSON.stringify({ ts: today, kind: 'anomaly_block',       subject_type: 'ip',     subject_value: '4.5.6.7',   path: '/.env',                status: 429, retry_after_s: 300, package_id: null }),
    ].join('\n') + '\n');
    const a = freshAnalytics();
    const out = await a.rateLimitsByDay({ sinceMs: 0 });
    expect(out.total).toBe(6);
    expect(out.by_kind.rate_limit_ip).toBe(2);
    expect(out.by_kind.rate_limit_tenant).toBe(1);
    expect(out.by_kind.daily_quota_request).toBe(1);
    expect(out.by_kind.daily_quota_token).toBe(1);
    expect(out.by_kind.anomaly_block).toBe(1);
    // by_day is one bucket today with the kind breakdown rolled up.
    expect(out.by_day.length).toBe(1);
    expect(out.by_day[0].total).toBe(6);
    expect(out.by_day[0].rate_limit_ip).toBe(2);
    // File exists with data → no `note` field.
    expect(out.note).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// tenantsActive
// ---------------------------------------------------------------------------

describe('analytics.tenantsActive', () => {
  test('counts distinct tenants + builds top_by_usage', async () => {
    writeKeys([
      { id: 'k1', tenant_id: 't1', tier: 'starter', active: true, issued_at: '2026-05-01T00:00:00.000Z' },
      { id: 'k2', tenant_id: 't2', tier: 'free', active: true, issued_at: '2026-05-01T00:00:00.000Z' },
    ]);
    writeJsonl('usage.jsonl', [
      { ts: new Date().toISOString(), tenant_id: 't1', status: 'success' },
      { ts: new Date().toISOString(), tenant_id: 't1', status: 'success' },
      { ts: new Date().toISOString(), tenant_id: 't1', status: 'success' },
      { ts: new Date().toISOString(), tenant_id: 't2', status: 'success' },
    ]);
    const a = freshAnalytics();
    const out = await a.tenantsActive({ sinceMs: 0 });
    expect(out.active).toBe(2);
    expect(out.top_by_usage[0].tenant_id).toBe('t1');
    expect(out.top_by_usage[0].requests).toBe(3);
    expect(out.by_tier.starter).toBe(1);
    expect(out.by_tier.free).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// revenueSnapshot
// ---------------------------------------------------------------------------

describe('analytics.revenueSnapshot', () => {
  test('computes MRR from active Stripe-bound subscriptions', () => {
    writePackages([
      { id: 'starter', monthly_usd: 25, active: true },
      { id: 'pro', monthly_usd: 100, active: true },
      { id: 'free', monthly_usd: 0, active: true },
    ]);
    writeKeys([
      { id: 'k1', tenant_id: 't1', package_id: 'starter', stripe_subscription_status: 'active', active: true },
      { id: 'k2', tenant_id: 't2', package_id: 'pro', stripe_subscription_status: 'active', active: true },
      { id: 'k3', tenant_id: 't3', package_id: 'pro', stripe_subscription_status: 'trialing', active: true },
      { id: 'k4', tenant_id: 't4', package_id: 'starter', stripe_subscription_status: 'canceled', active: true },
      { id: 'k5', tenant_id: 't5', package_id: 'free', active: true }, // free tier excluded
    ]);
    const a = freshAnalytics();
    const out = a.revenueSnapshot();
    expect(out.monthly_recurring_usd).toBe(225); // 25 + 100 + 100
    expect(out.active_subscriptions).toBe(3);
    expect(out.by_tier.starter).toBe(1);
    expect(out.by_tier.pro).toBe(2);
    expect(out.note).toMatch(/does NOT call Stripe/);
  });

  test('missing keys.json / packages.json → zeros + note', () => {
    const a = freshAnalytics();
    const out = a.revenueSnapshot();
    expect(out.monthly_recurring_usd).toBe(0);
    expect(out.active_subscriptions).toBe(0);
    expect(out.note).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// summary — union of all sections
// ---------------------------------------------------------------------------

describe('analytics.summary', () => {
  test('returns union of all per-section results', async () => {
    const a = freshAnalytics();
    const out = await a.summary({ sinceMs: 0 });
    expect(out).toHaveProperty('since_ms');
    expect(out).toHaveProperty('generated_at');
    expect(out).toHaveProperty('signups');
    expect(out).toHaveProperty('requests');
    expect(out).toHaveProperty('anomalies');
    expect(out).toHaveProperty('honeypots');
    expect(out).toHaveProperty('rate_limits');
    expect(out).toHaveProperty('tenants');
    expect(out).toHaveProperty('revenue');
  });

  test('defaults sinceMs to 30 days ago when not provided', async () => {
    const a = freshAnalytics();
    const out = await a.summary();
    const expected = Date.now() - 30 * 24 * 60 * 60 * 1000;
    // Allow a few seconds of slack between Date.now() in test and inside summary().
    expect(Math.abs(out.since_ms - expected)).toBeLessThan(60 * 1000);
  });
});

// ---------------------------------------------------------------------------
// HTTP — admin auth + route shape
// ---------------------------------------------------------------------------

describe('GET /admin/analytics/* — auth + shape', () => {
  function freshApp() {
    jest.resetModules();
    const { createApp } = require('../src/index');
    return createApp();
  }

  const request = require('supertest');

  test('GET /admin/analytics/summary without admin key → 401', async () => {
    const app = freshApp();
    const res = await request(app).get('/admin/analytics/summary');
    expect(res.status).toBe(401);
  });

  test('GET /admin/analytics/summary with wrong admin key → 401', async () => {
    const app = freshApp();
    const res = await request(app)
      .get('/admin/analytics/summary')
      .set('X-Admin-Key', 'wrong-key-but-same-length-as-real');
    expect(res.status).toBe(401);
  });

  test('GET /admin/analytics/summary with admin key → 200 with expected shape', async () => {
    const app = freshApp();
    const res = await request(app)
      .get('/admin/analytics/summary')
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('signups');
    expect(res.body).toHaveProperty('requests');
    expect(res.body).toHaveProperty('anomalies');
    expect(res.body).toHaveProperty('honeypots');
    expect(res.body).toHaveProperty('rate_limits');
    expect(res.body).toHaveProperty('tenants');
    expect(res.body).toHaveProperty('revenue');
    expect(res.headers['content-type']).toMatch(/application\/json/);
  });

  test('each per-section endpoint requires admin auth', async () => {
    const app = freshApp();
    const endpoints = [
      '/admin/analytics/signups',
      '/admin/analytics/requests',
      '/admin/analytics/anomalies',
      '/admin/analytics/honeypots',
      '/admin/analytics/rate-limits',
      '/admin/analytics/tenants',
      '/admin/analytics/revenue',
    ];
    for (const ep of endpoints) {
      const res = await request(app).get(ep);
      expect(res.status).toBe(401);
    }
  });

  test('each per-section endpoint returns 200 + JSON with admin key', async () => {
    const app = freshApp();
    const endpoints = [
      '/admin/analytics/signups',
      '/admin/analytics/requests',
      '/admin/analytics/anomalies',
      '/admin/analytics/honeypots',
      '/admin/analytics/rate-limits',
      '/admin/analytics/tenants',
      '/admin/analytics/revenue',
    ];
    for (const ep of endpoints) {
      const res = await request(app)
        .get(ep)
        .set('X-Admin-Key', process.env.ADMIN_KEY);
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toMatch(/application\/json/);
    }
  });

  test('since_ms query parameter is honored', async () => {
    const app = freshApp();
    const since = Date.now() - 1000;
    const res = await request(app)
      .get(`/admin/analytics/summary?since_ms=${since}`)
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(res.status).toBe(200);
    expect(res.body.since_ms).toBe(since);
  });

  test('garbage since_ms falls back to the 30-day default (no 400)', async () => {
    const app = freshApp();
    const res = await request(app)
      .get('/admin/analytics/summary?since_ms=not-a-number')
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(res.status).toBe(200);
    const expected = Date.now() - 30 * 24 * 60 * 60 * 1000;
    expect(Math.abs(res.body.since_ms - expected)).toBeLessThan(60 * 1000);
  });

  test('granularity=day is forwarded to requestsByHour', async () => {
    const app = freshApp();
    const res = await request(app)
      .get('/admin/analytics/requests?granularity=day')
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(res.status).toBe(200);
    expect(res.body.granularity).toBe('day');
  });
});

// ---------------------------------------------------------------------------
// Rate limit — /admin/* per-IP 30/min — analytics is not a bypass
// ---------------------------------------------------------------------------

describe('per-IP rate limit on /admin/* covers analytics', () => {
  test('31st request from one IP within 60s → 429', async () => {
    jest.resetModules();
    const { createApp } = require('../src/index');
    const app = createApp();
    const request = require('supertest');
    let saw429 = false;
    for (let i = 0; i < 35; i += 1) {
      const res = await request(app)
        .get('/admin/analytics/summary')
        .set('X-Admin-Key', process.env.ADMIN_KEY);
      if (res.status === 429) { saw429 = true; break; }
    }
    expect(saw429).toBe(true);
  });
});
