'use strict';

// Replay test for the sovereign-retry escalation reduction.
//
// DATASET: the 21 historical `sovereign_error` escalation rows from
// `data/usage.jsonl` (escalation_reason=sovereign_error, was_escalated=true).
// Measured at audit time (2026-06-08 snapshot): 25 total escalations of
// 424 calls = 5.90% raw rate; of those, 21 were sovereign_error (the rest
// 4 were manual_override which retry must NOT affect).
//
// REPLAY MODEL: 20 of the 21 sovereign_error rows are clustered in a single
// 30-second window for one tenant. Treating that as the "real-world worst
// case" — a single tenant burst against a briefly-flaky Ollama — we
// simulate two failure modes:
//   (a) "transient blip"   — first call throws, second call (after backoff)
//                            succeeds. With retry, NO escalation.
//   (b) "sustained outage" — every retry attempt also fails. WITH retry,
//                            escalation still triggers (correct behavior).
//
// What the test proves:
//   1. Mode (a) sovereign succeeds on retry, sovereign_attempts=2 in the
//      audit row, was_escalated NOT set — escalation rate stays the same
//      regardless of feature flag.
//   2. Mode (b) all retries fail, escalation triggers, sovereign_attempts=
//      (MAX_RETRIES+1) recorded, was_escalated=true. Backward-compatible.
//   3. SOVEREIGN_MAX_RETRIES=0 disables the feature entirely (back-compat
//      for operators who want the pre-retry behavior).
//   4. manual_override bypasses retry — caller wants frontier on purpose.

const fs = require('fs');
const os = require('os');
const path = require('path');

describe('Sovereign retry · escalation-rate replay', () => {
  let tmpDir;
  let request;
  let nock;
  let createApp;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-retry-replay-'));
    process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
    process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
    process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
    process.env.RATE_LIMITS_FILE = path.join(tmpDir, 'rate-limits.jsonl');
    process.env.OLLAMA_URL = 'http://ollama.test';
    process.env.UPSTREAM_URL = 'http://ollama.test';
    process.env.FRONTIER_ESCALATION_ENABLED = 'true';
    process.env.FRONTIER_API_BASE = 'http://frontier.test';
    process.env.FRONTIER_API_KEY = 'replay-test-key';
    process.env.FRONTIER_MODEL = 'gemini-2.5-flash';
    process.env.FRONTIER_DAILY_BUDGET_USD_CAP = '50';
    // Test default: 1 retry, 5ms backoff (fast for the suite).
    process.env.SOVEREIGN_MAX_RETRIES = '1';
    process.env.SOVEREIGN_RETRY_BACKOFF_MS = '5';
    jest.resetModules();
    request = require('supertest');
    nock = require('nock');
    nock.disableNetConnect();
    nock.enableNetConnect(/127\.0\.0\.1|localhost/);
    createApp = require('../src/index').createApp;
    const chatApi = require('../src/chat-api');
    if (chatApi._invalidateBudgetCache) chatApi._invalidateBudgetCache();
  });

  afterEach(() => {
    try { nock.cleanAll(); nock.enableNetConnect(); nock.restore(); } catch (_e) {}
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
    delete process.env.SOVEREIGN_MAX_RETRIES;
    delete process.env.SOVEREIGN_RETRY_BACKOFF_MS;
    delete process.env.FRONTIER_ESCALATION_ENABLED;
    delete process.env.FRONTIER_API_BASE;
    delete process.env.FRONTIER_API_KEY;
    delete process.env.FRONTIER_MODEL;
    delete process.env.FRONTIER_DAILY_BUDGET_USD_CAP;
  });

  async function issueKey(app, tenantId = 'retry-tenant') {
    const r = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: tenantId });
    expect(r.status).toBe(201);
    return r.body.api_key;
  }

  function readUsageRows() {
    const text = fs.readFileSync(process.env.USAGE_FILE, 'utf8').trim();
    if (!text) return [];
    return text.split('\n').filter(Boolean).map((l) => JSON.parse(l));
  }

  // ── Mode (a): transient blip — first sovereign call throws, retry succeeds
  test('transient sovereign blip → retry succeeds → NO escalation, sovereign_attempts=2', async () => {
    // First /api/chat returns 503; second /api/chat returns 200.
    nock('http://ollama.test')
      .post('/api/chat')
      .reply(503, 'briefly down');
    nock('http://ollama.test')
      .post('/api/chat')
      .reply(200, {
        message: { role: 'assistant', content: 'recovered' },
        prompt_eval_count: 5, eval_count: 2,
      });
    // Sentinel: frontier MUST NOT be called.
    const frontierGuard = nock('http://frontier.test')
      .post('/chat/completions')
      .reply(200, { choices: [{ message: { content: 'leaked' }, finish_reason: 'stop' }], usage: {} });

    const app = createApp();
    const apiKey = await issueKey(app);

    const r = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ messages: [{ role: 'user', content: 'hi' }] });

    expect(r.status).toBe(200);
    expect(r.body.choices[0].message.content).toBe('recovered');
    expect(frontierGuard.isDone()).toBe(false); // frontier untouched

    const rows = readUsageRows();
    // Pick the chat-completion row specifically — other success rows can
    // exist (admin events have no model field).
    const successRow = rows.find((x) => x.status === 'success' && x.model === 'qwen2.5:3b-instruct');
    expect(successRow).toBeDefined();
    expect(successRow.sovereign_attempts).toBe(2);
    expect(successRow.was_escalated).toBeUndefined();
  });

  // ── Mode (b): sustained outage — both attempts fail → escalation
  test('sustained outage → all retries fail → frontier escalates, sovereign_attempts=2 recorded', async () => {
    nock('http://ollama.test').post('/api/chat').reply(503, 'down1');
    nock('http://ollama.test').post('/api/chat').reply(503, 'down2');
    nock('http://frontier.test')
      .post('/chat/completions')
      .reply(200, {
        choices: [{ message: { role: 'assistant', content: 'frontier saved it' }, finish_reason: 'stop' }],
        usage: { prompt_tokens: 5, completion_tokens: 4 },
      });

    const app = createApp();
    const apiKey = await issueKey(app, 'retry-tenant-b');

    const r = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ messages: [{ role: 'user', content: 'hi' }] });

    expect(r.status).toBe(200);
    expect(r.body.choices[0].message.content).toBe('frontier saved it');

    const rows = readUsageRows();
    const escalatedRow = rows.find((x) => x.was_escalated === true);
    expect(escalatedRow).toBeDefined();
    expect(escalatedRow.sovereign_attempts).toBe(2);
    expect(escalatedRow.escalation_reason).toBe('sovereign_error');
  });

  // ── Back-compat: SOVEREIGN_MAX_RETRIES=0 disables the feature
  test('SOVEREIGN_MAX_RETRIES=0 → no retry, escalation triggers on first failure (pre-retry behavior)', async () => {
    process.env.SOVEREIGN_MAX_RETRIES = '0';
    jest.resetModules();
    createApp = require('../src/index').createApp;

    nock('http://ollama.test').post('/api/chat').reply(503, 'down');
    nock('http://frontier.test')
      .post('/chat/completions')
      .reply(200, {
        choices: [{ message: { role: 'assistant', content: 'frontier' }, finish_reason: 'stop' }],
        usage: { prompt_tokens: 5, completion_tokens: 4 },
      });

    const app = createApp();
    const apiKey = await issueKey(app, 'retry-tenant-c');

    const r = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ messages: [{ role: 'user', content: 'hi' }] });

    expect(r.status).toBe(200);
    const rows = readUsageRows();
    const escalatedRow = rows.find((x) => x.was_escalated === true);
    expect(escalatedRow).toBeDefined();
    expect(escalatedRow.sovereign_attempts).toBe(1); // exactly one try, no retry
  });

  // ── manual_override bypasses retry (caller explicitly wants frontier)
  test('X-Cogos-Escalate:1 → no retry, immediate escalation, sovereign_attempts=1', async () => {
    nock('http://ollama.test')
      .post('/api/chat')
      .reply(200, {
        message: { role: 'assistant', content: 'sovereign worked' },
        prompt_eval_count: 5, eval_count: 2,
      });
    nock('http://frontier.test')
      .post('/chat/completions')
      .reply(200, {
        choices: [{ message: { role: 'assistant', content: 'manual override → frontier' }, finish_reason: 'stop' }],
        usage: { prompt_tokens: 5, completion_tokens: 4 },
      });

    const app = createApp();
    const apiKey = await issueKey(app, 'retry-tenant-d');

    const r = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${apiKey}`)
      .set('X-Cogos-Escalate', '1')
      .send({ messages: [{ role: 'user', content: 'force frontier' }] });

    expect(r.status).toBe(200);
    expect(r.body.choices[0].message.content).toBe('manual override → frontier');
    const rows = readUsageRows();
    const escalatedRow = rows.find((x) => x.was_escalated === true);
    expect(escalatedRow).toBeDefined();
    expect(escalatedRow.escalation_reason).toBe('manual_override');
    expect(escalatedRow.sovereign_attempts).toBe(1); // not retried; caller forced
  });

  // ── Aggregate: replay the 30-second sustained-outage burst (20 calls)
  // and confirm that with retry NONE of the burst calls are saved (since
  // all retries also fail) — honest about retry's ceiling.
  test('burst of 20 calls during sustained outage → retry does not save them; honest about the ceiling', async () => {
    // 40 nock interceptors (20 calls × 2 attempts each), all 503.
    for (let i = 0; i < 40; i++) {
      nock('http://ollama.test').post('/api/chat').reply(503, 'down ' + i);
    }
    // 20 frontier wins.
    for (let i = 0; i < 20; i++) {
      nock('http://frontier.test')
        .post('/chat/completions')
        .reply(200, {
          choices: [{ message: { role: 'assistant', content: 'frontier ' + i }, finish_reason: 'stop' }],
          usage: { prompt_tokens: 5, completion_tokens: 4 },
        });
    }

    const app = createApp();
    const apiKey = await issueKey(app, 'burst-tenant');

    let escalations = 0;
    for (let i = 0; i < 20; i++) {
      const r = await request(app)
        .post('/v1/chat/completions')
        .set('Authorization', `Bearer ${apiKey}`)
        .send({ messages: [{ role: 'user', content: 'call ' + i }] });
      if (r.status === 200 && /^frontier/.test(r.body.choices[0].message.content)) escalations++;
    }

    expect(escalations).toBe(20); // retry did not save any — outage was sustained
    const rows = readUsageRows();
    const escalatedRows = rows.filter((x) => x.was_escalated === true);
    expect(escalatedRows.length).toBe(20);
    // Every escalated row should show 2 sovereign attempts (1 + 1 retry).
    for (const row of escalatedRows) expect(row.sovereign_attempts).toBe(2);
  });
});
