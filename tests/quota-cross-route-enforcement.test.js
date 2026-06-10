'use strict';

// B1 regression — daily-cap + monthly-quota enforcement on routes that
// used to bypass it. Before this fix, only /v1/chat/completions ran
// enforceDailyCap + enforcePackage; /v1/chat-grounded, /v1/process/*,
// /v1/search, /v1/compose, /v1/state mounted without them, letting a
// free-tier key exhaust /v1/chat then route around the cap on grounded
// or process.
//
// Each test sets daily_request_cap=1 and confirms:
//   1. The 1st call to /v1/chat/completions succeeds (cap not crossed).
//   2. The 2nd call to /v1/chat-grounded (or /v1/process/...) — a
//      DIFFERENT route — gets 429 daily_quota_exceeded.
// If the 2nd call returns 200, B1 has regressed.

const fs = require('fs');
const os = require('os');
const path = require('path');
const dailyCap = require('../src/daily-cap');

describe('B1: cross-route quota enforcement (regression)', () => {
  let tmpDir;
  let request;
  let nock;
  let createApp;
  let packages;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-b1-test-'));
    process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
    process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
    process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
    process.env.RATE_LIMITS_FILE = path.join(tmpDir, 'rate-limits.jsonl');
    process.env.OLLAMA_URL = 'http://ollama.test';
    process.env.UPSTREAM_URL = 'http://ollama.test';
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

  async function setupTenant(tierId) {
    await packages.create({
      id: tierId,
      display_name: 'B1 Test Tier',
      monthly_usd: 0,
      monthly_request_quota: 1000,
      allowed_model_tiers: ['cogos-tier-b'],
      daily_request_cap: 1,
    });
    const app = createApp();
    const issue = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'b1-tenant', tier: tierId });
    expect(issue.status).toBe(201);
    return { app, apiKey: issue.body.api_key };
  }

  test('after /v1/chat exhausts daily cap, /v1/chat-grounded 429s instead of bypassing', async () => {
    // Two upstream mocks: one for the /v1/chat success, one in case grounded
    // were (incorrectly) to reach upstream. If B1 regresses, the 2nd call
    // would consume the second nock — we assert it does NOT.
    nock('http://ollama.test')
      .post('/api/chat')
      .reply(200, {
        message: { role: 'assistant', content: 'ok' },
        prompt_eval_count: 5, eval_count: 2,
      });
    // Sentinel: if grounded leaks through to upstream, this would 200.
    // We expect it NEVER to be consumed.
    const groundedNock = nock('http://ollama.test')
      .post('/api/chat')
      .reply(200, {
        message: { role: 'assistant', content: 'leaked through' },
        prompt_eval_count: 5, eval_count: 2,
      });

    const { app, apiKey } = await setupTenant('b1-tier-grounded');

    // 1st call: /v1/chat succeeds (cap of 1 not yet crossed).
    const r1 = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ messages: [{ role: 'user', content: 'hi' }] });
    expect(r1.status).toBe(200);

    // 2nd call: /v1/chat-grounded — DIFFERENT route. Before B1 fix this
    // would 200 (bypass). After fix, must 429 daily_quota_exceeded.
    const r2 = await request(app)
      .post('/v1/chat-grounded')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ query: 'what is the capital of france' });
    expect(r2.status).toBe(429);
    expect(r2.body.error.type).toBe('daily_quota_exceeded');
    expect(r2.body.error.reason).toBe('request_cap');

    // Sentinel: grounded must NOT have reached upstream.
    expect(groundedNock.isDone()).toBe(false);
  });

  test('after /v1/chat exhausts daily cap, /v1/process/iolta-reconcile 429s instead of bypassing', async () => {
    nock('http://ollama.test')
      .post('/api/chat')
      .reply(200, {
        message: { role: 'assistant', content: 'ok' },
        prompt_eval_count: 5, eval_count: 2,
      });

    const { app, apiKey } = await setupTenant('b1-tier-process');

    const r1 = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ messages: [{ role: 'user', content: 'hi' }] });
    expect(r1.status).toBe(200);

    // /v1/process/iolta-reconcile — deterministic, no upstream call,
    // but must still respect the daily cap.
    const r2 = await request(app)
      .post('/v1/process/iolta-reconcile')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ ledger: [], bank: [] });
    expect(r2.status).toBe(429);
    expect(r2.body.error.type).toBe('daily_quota_exceeded');
  });

  test('after /v1/chat exhausts daily cap, /v1/state/matters 429s instead of bypassing', async () => {
    nock('http://ollama.test')
      .post('/api/chat')
      .reply(200, {
        message: { role: 'assistant', content: 'ok' },
        prompt_eval_count: 5, eval_count: 2,
      });

    const { app, apiKey } = await setupTenant('b1-tier-state');

    const r1 = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ messages: [{ role: 'user', content: 'hi' }] });
    expect(r1.status).toBe(200);

    const r2 = await request(app)
      .post('/v1/state/matters')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ matter_id: 'm1', name: 'test matter' });
    expect(r2.status).toBe(429);
    expect(r2.body.error.type).toBe('daily_quota_exceeded');
  });
});
