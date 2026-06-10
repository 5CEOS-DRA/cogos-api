'use strict';

// B4 regression — /v1/chat-grounded used to call callOllama directly with
// no fallback. If sovereign failed, the customer got a 502 even though
// frontier escalation could have produced a valid answer. The asymmetry
// with /v1/chat/completions (which DOES escalate) was a real reliability
// gap; this test pins the fix.
//
// Setup: nock returns 500 from Ollama (sovereign fail). Frontier endpoint
// returns 200 with content. Expected: 200, answer carries the frontier
// content, receipt.evidence_chain.was_escalated is true.

const fs = require('fs');
const os = require('os');
const path = require('path');

describe('B4: /v1/chat-grounded frontier escalation on sovereign failure', () => {
  let tmpDir;
  let request;
  let nock;
  let createApp;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-b4-test-'));
    process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
    process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
    process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
    process.env.RATE_LIMITS_FILE = path.join(tmpDir, 'rate-limits.jsonl');
    process.env.OLLAMA_URL = 'http://ollama.test';
    process.env.UPSTREAM_URL = 'http://ollama.test';
    // Enable frontier escalation pointing at a nock-mockable host.
    process.env.FRONTIER_ESCALATION_ENABLED = 'true';
    process.env.FRONTIER_API_BASE = 'http://frontier.test';
    process.env.FRONTIER_API_KEY = 'b4-test-key';
    process.env.FRONTIER_MODEL = 'gemini-flash-test';
    process.env.FRONTIER_DAILY_BUDGET_USD_CAP = '50';
    jest.resetModules();
    request = require('supertest');
    nock = require('nock');
    nock.disableNetConnect();
    nock.enableNetConnect(/127\.0\.0\.1|localhost/);
    createApp = require('../src/index').createApp;
    // Invalidate the frontier budget cache (else test bleeds into prior).
    const chatApi = require('../src/chat-api');
    if (chatApi._invalidateBudgetCache) chatApi._invalidateBudgetCache();
  });

  afterEach(() => {
    try { nock.cleanAll(); nock.enableNetConnect(); nock.restore(); } catch (_e) {}
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
    delete process.env.FRONTIER_ESCALATION_ENABLED;
    delete process.env.FRONTIER_API_BASE;
    delete process.env.FRONTIER_API_KEY;
    delete process.env.FRONTIER_MODEL;
    delete process.env.FRONTIER_DAILY_BUDGET_USD_CAP;
  });

  test('sovereign 500 → frontier escalates → 200 with was_escalated in receipt', async () => {
    nock('http://ollama.test')
      .post('/api/chat')
      .reply(500, 'ollama is down');
    nock('http://frontier.test')
      .post('/chat/completions')
      .reply(200, {
        choices: [{
          message: { role: 'assistant', content: 'paris is the capital [escalated]' },
          finish_reason: 'stop',
        }],
        usage: { prompt_tokens: 10, completion_tokens: 7 },
      });

    const app = createApp();
    const issue = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'b4-tenant' });
    expect(issue.status).toBe(201);
    const apiKey = issue.body.api_key;

    const r = await request(app)
      .post('/v1/chat-grounded')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ query: 'what is the capital of france', mode: 'never-search' });

    expect(r.status).toBe(200);
    expect(r.body.answer).toBe('paris is the capital [escalated]');
    expect(r.body.receipt).toBeDefined();
    expect(r.body.receipt.evidence_chain).toBeDefined();
    expect(r.body.receipt.evidence_chain.was_escalated).toBe(true);
    expect(r.body.receipt.evidence_chain.frontier_provider).toBe('gemini');
    expect(r.body.receipt.evidence_chain.escalation_reason).toBe('sovereign_error');
  });

  test('sovereign 500 + frontier 500 → 502 with both failure paths in evidence', async () => {
    nock('http://ollama.test').post('/api/chat').reply(500, 'down');
    nock('http://frontier.test').post('/chat/completions').reply(500, 'also down');

    const app = createApp();
    const issue = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'b4-tenant-2' });
    const apiKey = issue.body.api_key;

    const r = await request(app)
      .post('/v1/chat-grounded')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ query: 'something', mode: 'never-search' });

    expect(r.status).toBe(502);
    expect(r.body.error.type).toBe('bad_gateway');
    expect(r.body.receipt.evidence_chain.escalation_reason).toBe('sovereign_error');
    expect(r.body.receipt.evidence_chain.frontier_reason).toBeDefined();
  });

  test('sovereign succeeds → no escalation, no was_escalated flag', async () => {
    nock('http://ollama.test')
      .post('/api/chat')
      .reply(200, {
        message: { role: 'assistant', content: 'sovereign answer' },
        prompt_eval_count: 5, eval_count: 3,
      });

    const app = createApp();
    const issue = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'b4-tenant-3' });
    const apiKey = issue.body.api_key;

    const r = await request(app)
      .post('/v1/chat-grounded')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ query: 'what is 2+2', mode: 'never-search' });

    expect(r.status).toBe(200);
    expect(r.body.answer).toBe('sovereign answer');
    expect(r.body.receipt.evidence_chain.was_escalated).toBeUndefined();
  });
});
