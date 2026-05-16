'use strict';

// Unit tests for src/daily-cap.js — the per-(tenant, app) daily counter
// + per-call cap evaluator backing the free tier.
//
// We exercise the module directly (no Express), then add one integration
// test in tests/api.test.js for the /v1/chat/completions middleware path.

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

// Point daily-cap's snapshot file at a tmpdir BEFORE requiring the
// module — production data/daily-cap.json must not be touched by tests.
const _testTmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-daily-cap-test-'));
process.env.DAILY_CAP_FILE = path.join(_testTmpDir, 'daily-cap.json');
process.env.RATE_LIMITS_FILE = path.join(_testTmpDir, 'rate-limits.jsonl');

const dailyCap = require('../src/daily-cap');

afterAll(() => {
  try { fs.rmSync(_testTmpDir, { recursive: true, force: true }); } catch (_e) {}
});

beforeEach(() => {
  dailyCap._test._reset();
});

// ---------------------------------------------------------------------------
// Basic counter mechanics — single tenant + single app
// ---------------------------------------------------------------------------
describe('daily-cap: request_cap', () => {
  test('100 calls succeed; 101st returns ok=false reason=request_cap', () => {
    for (let i = 1; i <= 100; i += 1) {
      const r = dailyCap.incrementAndCheck('tenant-a', 'app-x', {
        requests_now: 1,
        request_cap: 100,
      });
      expect(r.ok).toBe(true);
      expect(r.reason).toBe(null);
      expect(r.current.requests).toBe(i);
      expect(r.limits.request_cap).toBe(100);
    }
    const r = dailyCap.incrementAndCheck('tenant-a', 'app-x', {
      requests_now: 1,
      request_cap: 100,
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('request_cap');
    expect(r.current.requests).toBe(101);
  });

  test('request_cap=null → never trips (unlimited tier)', () => {
    for (let i = 0; i < 1000; i += 1) {
      const r = dailyCap.incrementAndCheck('tenant-a', 'app-x', {
        requests_now: 1,
        request_cap: null,
      });
      expect(r.ok).toBe(true);
    }
  });

  test('request_cap=undefined → never trips (legacy tier)', () => {
    for (let i = 0; i < 50; i += 1) {
      const r = dailyCap.incrementAndCheck('tenant-a', 'app-x', {
        requests_now: 1,
      });
      expect(r.ok).toBe(true);
    }
  });
});

describe('daily-cap: token_cap', () => {
  test('cumulative tokens past cap → next request 429 reason=token_cap', () => {
    // Round 1: pre-call request increment is fine.
    const pre1 = dailyCap.incrementAndCheck('tenant-b', 'app-x', {
      requests_now: 1,
      token_cap: 50,
    });
    expect(pre1.ok).toBe(true);
    // Post-call: response burned 30 tokens.
    const post1 = dailyCap.incrementAndCheck('tenant-b', 'app-x', {
      requests_now: 0,
      fallback_tokens_now: 30,
      token_cap: 50,
    });
    expect(post1.ok).toBe(true);
    expect(post1.current.fallback_tokens).toBe(30);

    // Round 2: pre-call is still under cap (30 ≤ 50) so OK.
    const pre2 = dailyCap.incrementAndCheck('tenant-b', 'app-x', {
      requests_now: 1,
      token_cap: 50,
    });
    expect(pre2.ok).toBe(true);
    // Post-call adds another 30 — cumulative 60, over the 50 cap.
    const post2 = dailyCap.incrementAndCheck('tenant-b', 'app-x', {
      requests_now: 0,
      fallback_tokens_now: 30,
      token_cap: 50,
    });
    // The in-flight call already shipped — but the trip is logged in the
    // counter; the NEXT request sees ok=false.
    expect(post2.ok).toBe(false);
    expect(post2.reason).toBe('token_cap');

    // Round 3: pre-call now trips.
    const pre3 = dailyCap.incrementAndCheck('tenant-b', 'app-x', {
      requests_now: 1,
      token_cap: 50,
    });
    expect(pre3.ok).toBe(false);
    expect(pre3.reason).toBe('token_cap');
    expect(pre3.current.fallback_tokens).toBe(60);
  });

  test('token_cap=null → never trips regardless of tokens', () => {
    const r = dailyCap.incrementAndCheck('tenant-b', 'app-x', {
      requests_now: 1,
      fallback_tokens_now: 1_000_000,
      token_cap: null,
    });
    expect(r.ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// In-flight token-cap trip — the customer's LAST request still ships.
// ---------------------------------------------------------------------------
describe('daily-cap: in-flight token trip', () => {
  test('single response exceeding cap → ok=false but next request is the one that 429s', () => {
    // Cap = 100. Single call burns 150 tokens. The MIDDLEWARE calls
    // incrementAndCheck post-call with requests_now=0; ok=false signals
    // the trip. The actual response has already been sent — the test for
    // that lives in tests/api.test.js — but the counter shows the trip.
    const post = dailyCap.incrementAndCheck('tenant-c', 'app-x', {
      requests_now: 0,
      fallback_tokens_now: 150,
      token_cap: 100,
    });
    expect(post.ok).toBe(false);
    expect(post.reason).toBe('token_cap');
    expect(post.current.fallback_tokens).toBe(150);

    // Following request — even with zero new tokens — hits the trip too,
    // because the counter is now PAST the cap.
    const next = dailyCap.incrementAndCheck('tenant-c', 'app-x', {
      requests_now: 1,
      token_cap: 100,
    });
    expect(next.ok).toBe(false);
    expect(next.reason).toBe('token_cap');
  });
});

// ---------------------------------------------------------------------------
// Tenant + app namespace isolation
// ---------------------------------------------------------------------------
describe('daily-cap: namespace isolation', () => {
  test('different tenants do not share counters', () => {
    for (let i = 0; i < 5; i += 1) {
      dailyCap.incrementAndCheck('tenant-x', 'app-x', {
        requests_now: 1,
        request_cap: 10,
      });
    }
    const ax = dailyCap.getCounter('tenant-x', 'app-x');
    const ay = dailyCap.getCounter('tenant-y', 'app-x');
    expect(ax.requests).toBe(5);
    expect(ay.requests).toBe(0);
  });

  test('different apps under same tenant do not share counters', () => {
    for (let i = 0; i < 5; i += 1) {
      dailyCap.incrementAndCheck('tenant-x', 'app-a', {
        requests_now: 1,
        request_cap: 10,
      });
    }
    for (let i = 0; i < 3; i += 1) {
      dailyCap.incrementAndCheck('tenant-x', 'app-b', {
        requests_now: 1,
        request_cap: 10,
      });
    }
    expect(dailyCap.getCounter('tenant-x', 'app-a').requests).toBe(5);
    expect(dailyCap.getCounter('tenant-x', 'app-b').requests).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// Day rollover — counters from yesterday don't leak into today
// ---------------------------------------------------------------------------
describe('daily-cap: day rollover', () => {
  test('counter for prior date does not affect today', () => {
    // Push 99 calls onto a fake "yesterday" date.
    for (let i = 0; i < 99; i += 1) {
      dailyCap.incrementAndCheck('tenant-z', 'app-x', {
        requests_now: 1,
        request_cap: 100,
        date_iso: '2020-01-01',
      });
    }
    expect(dailyCap.getCounter('tenant-z', 'app-x', '2020-01-01').requests).toBe(99);

    // Today (default date) starts at zero. 100 calls all succeed.
    for (let i = 1; i <= 100; i += 1) {
      const r = dailyCap.incrementAndCheck('tenant-z', 'app-x', {
        requests_now: 1,
        request_cap: 100,
      });
      expect(r.ok).toBe(true);
    }
    // The 101st today trips, regardless of yesterday's history.
    const r = dailyCap.incrementAndCheck('tenant-z', 'app-x', {
      requests_now: 1,
      request_cap: 100,
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('request_cap');
  });
});

// ---------------------------------------------------------------------------
// Retry-After / secondsUntilUtcMidnight
// ---------------------------------------------------------------------------
describe('daily-cap: secondsUntilUtcMidnight', () => {
  test('value is always positive and ≤ 86400', () => {
    const s = dailyCap.secondsUntilUtcMidnight();
    expect(s).toBeGreaterThan(0);
    expect(s).toBeLessThanOrEqual(86400);
  });
});

// ---------------------------------------------------------------------------
// getCounter snapshot behavior
// ---------------------------------------------------------------------------
describe('daily-cap: getCounter', () => {
  test('unknown (tenant, app) returns a zero snapshot, not undefined', () => {
    const c = dailyCap.getCounter('never-seen', 'either');
    expect(c.requests).toBe(0);
    expect(c.fallback_tokens).toBe(0);
    expect(c.tenant_id).toBe('never-seen');
    expect(c.app_id).toBe('either');
  });

  test('does not allocate a bucket (does not extend LRU)', () => {
    const beforeCount = dailyCap._test.bucketCount();
    dailyCap.getCounter('nobody', 'noapp');
    expect(dailyCap._test.bucketCount()).toBe(beforeCount);
  });
});

// ---------------------------------------------------------------------------
// enforceDailyCap 429 → event-log persistence
// ---------------------------------------------------------------------------
// Integration-style test: spin up an app, set a tier with daily_request_cap=1,
// fire two requests, assert the 2nd 429 writes one row to RATE_LIMITS_FILE
// with kind=daily_quota_request. The unit-level cap mechanics are covered
// above; this case nails down the analytics-event side of the pipeline.
describe('daily-cap: enforceDailyCap event-log persistence', () => {
  let tmpDir;
  let request;
  let nock;
  let createApp;
  let packages;

  beforeEach(() => {
    // Pristine tmpdir per test so the rate-limits file starts empty.
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-dc-evt-test-'));
    process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
    process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
    process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
    process.env.RATE_LIMITS_FILE = path.join(tmpDir, 'rate-limits.jsonl');
    process.env.OLLAMA_URL = 'http://ollama.test';
    jest.resetModules();
    dailyCap._test._reset();
    request = require('supertest');
    nock = require('nock');
    nock.disableNetConnect();
    nock.enableNetConnect(/127\.0\.0\.1|localhost/);
    createApp = require('../src/index').createApp;
    packages = require('../src/packages');
  });

  afterEach(() => {
    try { nock.cleanAll(); nock.enableNetConnect(); nock.restore(); } catch (_e) {}
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
    delete process.env.RATE_LIMITS_FILE;
  });

  test('429 from enforceDailyCap writes a row to RATE_LIMITS_FILE with kind=daily_quota_request', async () => {
    const tierId = 'dc-evt-tier';
    await packages.create({
      id: tierId,
      display_name: 'DC Evt',
      monthly_usd: 0,
      monthly_request_quota: 1000,
      allowed_model_tiers: ['cogos-tier-b'],
      daily_request_cap: 1,
    });

    nock('http://ollama.test')
      .post('/api/chat')
      .reply(200, {
        message: { role: 'assistant', content: 'ok' },
        prompt_eval_count: 5,
        eval_count: 2,
      });

    const app = createApp();
    const issue = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'dc-tenant', tier: tierId });
    expect(issue.status).toBe(201);
    const apiKey = issue.body.api_key;

    // 1st call succeeds (cap of 1 not yet crossed).
    const r1 = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ messages: [{ role: 'user', content: 'hi' }] });
    expect(r1.status).toBe(200);

    // 2nd call trips the daily_request_cap → 429 + persisted event.
    const r2 = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ messages: [{ role: 'user', content: 'hi again' }] });
    expect(r2.status).toBe(429);
    expect(r2.body.error.type).toBe('daily_quota_exceeded');
    expect(r2.body.error.reason).toBe('request_cap');

    expect(fs.existsSync(process.env.RATE_LIMITS_FILE)).toBe(true);
    const lines = fs.readFileSync(process.env.RATE_LIMITS_FILE, 'utf8')
      .split('\n').filter((l) => l.trim());
    // Find the daily-quota row — the file MAY also have an upstream rate_limit_*
    // row if the test environment surfaced one; we only assert on the one we
    // expect to exist.
    const dailyRow = lines.map((l) => JSON.parse(l))
      .find((r) => r.kind === 'daily_quota_request');
    expect(dailyRow).toBeDefined();
    expect(dailyRow.subject_type).toBe('tenant');
    expect(dailyRow.subject_value).toBe('dc-tenant');
    expect(dailyRow.path).toBe('/v1/chat/completions');
    expect(dailyRow.status).toBe(429);
    expect(typeof dailyRow.retry_after_s).toBe('number');
    expect(dailyRow.retry_after_s).toBeGreaterThan(0);
    expect(dailyRow.package_id).toBe(tierId);
  });
});

// ---------------------------------------------------------------------------
// LRU bounding — adversarial tenant-spray cannot OOM the process
// ---------------------------------------------------------------------------
describe('daily-cap: LRU bound', () => {
  test('bucket count never exceeds MAX_BUCKETS', () => {
    // We can't easily lower MAX_BUCKETS at runtime (it's captured at
    // module-load), but we can verify that even after 100 inserts the
    // count is correct + bounded. The default cap (50_000) is enormous,
    // so this is a sanity check on the data structure rather than the
    // hard bound.
    for (let i = 0; i < 100; i += 1) {
      dailyCap.incrementAndCheck(`tenant-${i}`, 'app-x', {
        requests_now: 1,
        request_cap: 1000,
      });
    }
    expect(dailyCap._test.bucketCount()).toBe(100);
    expect(dailyCap._test.bucketCount()).toBeLessThanOrEqual(dailyCap._test.MAX_BUCKETS);
  });
});

// ---------------------------------------------------------------------------
// Persistence — counters must survive a process restart so the free-tier
// 100-req/day cap can't be reset by a deploy or a crash.
// ---------------------------------------------------------------------------
describe('daily-cap: snapshot persistence + hydrate on load', () => {
  test('an increment writes data/daily-cap.json', () => {
    dailyCap.incrementAndCheck('tenant-persist', 'app-x', {
      requests_now: 3,
      request_cap: 100,
    });
    const f = process.env.DAILY_CAP_FILE;
    expect(fs.existsSync(f)).toBe(true);
    const parsed = JSON.parse(fs.readFileSync(f, 'utf8'));
    expect(parsed.version).toBe(1);
    expect(Array.isArray(parsed.buckets)).toBe(true);
    const ours = parsed.buckets.find((b) => b.tenant_id === 'tenant-persist');
    expect(ours).toBeTruthy();
    expect(ours.requests).toBe(3);
  });

  test('process restart hydrates from disk on next increment', () => {
    // Round 1: rack up 50 of a 100-cap budget.
    for (let i = 0; i < 50; i += 1) {
      dailyCap.incrementAndCheck('tenant-restart', 'app-x', {
        requests_now: 1,
        request_cap: 100,
      });
    }
    expect(dailyCap.getCounter('tenant-restart', 'app-x').requests).toBe(50);

    // Simulate process restart: clear in-memory state + lazy-load flag,
    // BUT leave the snapshot file on disk (we don't call unlink).
    // _test._reset does both, but we want to keep the file — patch:
    // re-require the module after clearing the in-memory map manually.
    jest.resetModules();
    // Re-require gives us a fresh module instance with empty in-memory
    // buckets and _loaded=false; the file from round 1 is still on disk.
    const dailyCapFresh = require('../src/daily-cap');

    // Round 2: a single additional increment. Should see the previous
    // 50 hydrated from disk and the new 1 added → 51.
    const r = dailyCapFresh.incrementAndCheck('tenant-restart', 'app-x', {
      requests_now: 1,
      request_cap: 100,
    });
    expect(r.ok).toBe(true);
    expect(r.current.requests).toBe(51);
  });

  test('hydrate prunes stale buckets older than TTL', () => {
    // Write a snapshot with one fresh bucket and one ancient bucket.
    const ancient = Date.now() - 48 * 60 * 60 * 1000; // 48h ago
    const fresh = Date.now() - 60 * 1000; // 1 min ago
    const f = process.env.DAILY_CAP_FILE;
    fs.writeFileSync(f, JSON.stringify({
      version: 1,
      ts: new Date().toISOString(),
      buckets: [
        {
          tenant_id: 'tenant-stale', app_id: 'app-x',
          date: '2026-01-01',
          requests: 999, fallback_tokens: 0,
          lastTouchedMs: ancient,
        },
        {
          tenant_id: 'tenant-fresh', app_id: 'app-x',
          date: '2026-05-16',
          requests: 7, fallback_tokens: 0,
          lastTouchedMs: fresh,
        },
      ],
    }));
    jest.resetModules();
    const dailyCapFresh = require('../src/daily-cap');

    // Touching tenant-stale should NOT rehydrate the 999 — it's
    // older than the 36h TTL and was pruned at load time.
    const r1 = dailyCapFresh.incrementAndCheck('tenant-stale', 'app-x', {
      requests_now: 1,
      request_cap: 100,
    });
    expect(r1.current.requests).toBe(1);

    // tenant-fresh should rehydrate cleanly.
    const r2 = dailyCapFresh.incrementAndCheck('tenant-fresh', 'app-x', {
      requests_now: 1,
      request_cap: 100,
    });
    expect(r2.current.requests).toBe(8);
  });

  test('malformed snapshot file does not crash — module starts empty', () => {
    const f = process.env.DAILY_CAP_FILE;
    fs.writeFileSync(f, '{not valid json');
    jest.resetModules();
    const dailyCapFresh = require('../src/daily-cap');
    const r = dailyCapFresh.incrementAndCheck('tenant-corrupt', 'app-x', {
      requests_now: 1,
      request_cap: 100,
    });
    expect(r.ok).toBe(true);
    expect(r.current.requests).toBe(1);
  });
});
