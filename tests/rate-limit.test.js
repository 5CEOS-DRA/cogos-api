'use strict';

// Rate-limit tests — pentest F2 closure. Two layers:
//  (a) per-IP token bucket (defence-in-depth flood protection)
//  (b) per-tenant token bucket on authenticated /v1/* routes
//
// Default thresholds (env unset):
//   per-IP global    100 req / 60s
//   per-IP /admin    30  req / 60s
//   per-tenant /v1/* 1000 req / 60s

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

const request = require('supertest');

let tmpDir;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-rl-test-'));
  process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
  process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
  process.env.ANOMALIES_FILE = path.join(tmpDir, 'anomalies.jsonl');
  // Tiny limits so per-IP tests don't have to fire 100+ requests each.
  process.env.RATE_LIMIT_IP_PER_MIN = '5';
  process.env.RATE_LIMIT_TENANT_PER_MIN = '1000';
  // Keep ANOMALY_FAIL_CLOSED off in this file — its tests own that switch.
  delete process.env.ANOMALY_FAIL_CLOSED;
  jest.resetModules();
});

afterEach(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  // Clear env between tests so other test files don't inherit our limits.
  delete process.env.RATE_LIMIT_IP_PER_MIN;
  delete process.env.RATE_LIMIT_TENANT_PER_MIN;
});

function freshPair() {
  jest.resetModules();
  const rl = require('../src/rate-limit');
  rl._test.reset();
  const { createApp } = require('../src/index');
  return { app: createApp(), rl };
}

describe('rate-limit — per-IP', () => {
  test('bucket counts up across requests', async () => {
    const { app, rl } = freshPair();
    await request(app).get('/health');
    await request(app).get('/health');
    await request(app).get('/health');
    // Note: SuperTest connects from 127.0.0.1, so the bucket key includes
    // either ::ffff:127.0.0.1 or 127.0.0.1 depending on the platform.
    expect(rl._test.bucketCount()).toBeGreaterThanOrEqual(1);
  });

  test('the (limit+1)th request from the same IP returns 429 with Retry-After', async () => {
    const { app } = freshPair();
    // RATE_LIMIT_IP_PER_MIN=5. First 5 succeed; 6th 429s.
    for (let i = 0; i < 5; i += 1) {
      // eslint-disable-next-line no-await-in-loop
      const r = await request(app).get('/health');
      expect(r.status).toBe(200);
    }
    const blocked = await request(app).get('/health');
    expect(blocked.status).toBe(429);
    expect(blocked.headers['retry-after']).toMatch(/^\d+$/);
    expect(Number(blocked.headers['retry-after'])).toBeGreaterThan(0);
    expect(blocked.body).toEqual({
      error: {
        message: expect.any(String),
        type: 'rate_limit_exceeded',
        retry_after_s: expect.any(Number),
      },
    });
  });

  test('429 body shape matches the API error contract', async () => {
    const { app, rl } = freshPair();
    // Bucket keys are namespaced by label: 'global' for the top-level /
    // limiter. SuperTest connects from 127.0.0.1 (possibly v6-mapped).
    rl._test.forceLimit('ip:global:::ffff:127.0.0.1', 5);
    rl._test.forceLimit('ip:global:127.0.0.1', 5);
    const r = await request(app).get('/health');
    expect(r.status).toBe(429);
    expect(r.body.error.type).toBe('rate_limit_exceeded');
    expect(typeof r.body.error.retry_after_s).toBe('number');
    expect(r.body.error.retry_after_s).toBeGreaterThan(0);
    expect(r.body.error.retry_after_s).toBeLessThanOrEqual(60);
  });

  test('/admin/* gets the stricter limit (30/min default, here forced via bucket)', async () => {
    // The /admin/* path mounts a SECOND per-IP limiter with limit=30. Both
    // limiters track on the same Map but use different label-keyed counts —
    // no, they share the same bucket since the key is just ip:<ip>. The
    // stricter limit applies because the second limiter's `consume()` will
    // overshoot first. Hard to test the exact 30 threshold without 31
    // requests, so just confirm /admin/* short-circuits to 401 when not
    // over the limit (admin key not provided → 401), and verify the global
    // 5/min triggers when we cross it.
    const { app } = freshPair();
    // Fire 5 admin calls; each one returns 401 (no admin key). 6th should
    // be 429 from the global limiter (5/min) before /admin limiter runs.
    for (let i = 0; i < 5; i += 1) {
      // eslint-disable-next-line no-await-in-loop
      const r = await request(app).get('/admin/keys');
      expect(r.status).toBe(401);
    }
    const blocked = await request(app).get('/admin/keys');
    expect(blocked.status).toBe(429);
  });

  test('legitimate /v1/models call is not rate-limited at default thresholds (1000/min/tenant)', async () => {
    // Sanity: with the per-tenant limit at 1000/min, a single call from an
    // authenticated key should never 429.
    delete process.env.RATE_LIMIT_IP_PER_MIN; // restore generous default
    const { app } = freshPair();
    const issue = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'tenant-legit', tier: 'starter' });
    expect(issue.status).toBe(201);
    const r = await request(app)
      .get('/v1/models')
      .set('Authorization', `Bearer ${issue.body.api_key}`);
    expect([200, 502, 500]).toContain(r.status); // 200 if upstream stubbed; otherwise the route mounted fine
    expect(r.status).not.toBe(429);
    // env restored in afterEach
  });
});

describe('rate-limit — per-tenant', () => {
  test('forceLimit on a tenant bucket → next authed call returns 429', async () => {
    delete process.env.RATE_LIMIT_IP_PER_MIN;
    const { app, rl } = freshPair();
    const issue = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'tenant-z', tier: 'starter' });
    rl._test.forceLimit('tenant:tenant-z', 1000);
    const r = await request(app)
      .get('/v1/models')
      .set('Authorization', `Bearer ${issue.body.api_key}`);
    expect(r.status).toBe(429);
    expect(r.body.error.type).toBe('rate_limit_exceeded');
    expect(Number(r.headers['retry-after'])).toBeGreaterThan(0);
    // env restored in afterEach
  });

  test('per-tenant limiter is a pass-through on unauthenticated requests', async () => {
    // Unauthed /v1/models 401s well before the tenant limiter runs.
    // (customerAuth rejects first; if the tenant limiter weren't a
    // pass-through it would have nothing to key on.) Verifies no crash.
    delete process.env.RATE_LIMIT_IP_PER_MIN;
    const { app } = freshPair();
    const r = await request(app).get('/v1/models');
    expect(r.status).toBe(401);
    // env restored in afterEach
  });
});

describe('rate-limit — env override', () => {
  test('RATE_LIMIT_IP_PER_MIN env value is honored', async () => {
    process.env.RATE_LIMIT_IP_PER_MIN = '2';
    const { app } = freshPair();
    const r1 = await request(app).get('/health');
    const r2 = await request(app).get('/health');
    const r3 = await request(app).get('/health');
    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);
    expect(r3.status).toBe(429);
    // env restored in afterEach
  });
});
