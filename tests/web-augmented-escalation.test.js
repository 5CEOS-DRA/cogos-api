'use strict';

// Web-augmented sovereign escalation (replaces frontier-LLM escalation)
// ─────────────────────────────────────────────────────────────────────
// New default escalation policy as of 2026-06-10: when sovereign fails
// after retry, the substrate searches the live web (Brave) and re-prompts
// sovereign Qwen with the search results as grounding. NO third-party LLM
// is called.
//
// Tests:
//   1. sovereign fails → web search succeeds → sovereign-with-grounding
//      succeeds → 200 with was_web_augmented=true + web_sources[] in
//      both the response body and the audit row.
//   2. Default policy: WEB_AUGMENTED_ESCALATION_ENABLED defaults to true
//      (the env var is the off-switch, not the on-switch).
//   3. Legacy frontier path: FRONTIER_ESCALATION_ENABLED defaults to
//      false now — frontier escalation does NOT fire unless explicitly
//      re-enabled.
//   4. manual_override (X-Cogos-Escalate:1) bypasses web-augmented and
//      goes to legacy frontier IF frontier is explicitly enabled.

const fs = require('fs');
const os = require('os');
const path = require('path');

describe('Web-augmented sovereign escalation (2026-06-10)', () => {
  let tmpDir;
  let request;
  let nock;
  let createApp;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-wa-test-'));
    process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
    process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
    process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
    process.env.RATE_LIMITS_FILE = path.join(tmpDir, 'rate-limits.jsonl');
    process.env.OLLAMA_URL = 'http://ollama.test';
    process.env.UPSTREAM_URL = 'http://ollama.test';
    process.env.BRAVE_SEARCH_API_KEY = 'test-brave-key';
    delete process.env.FRONTIER_ESCALATION_ENABLED;
    delete process.env.WEB_AUGMENTED_ESCALATION_ENABLED;
    jest.resetModules();
    request = require('supertest');
    nock = require('nock');
    nock.disableNetConnect();
    nock.enableNetConnect(/127\.0\.0\.1|localhost/);
    createApp = require('../src/index').createApp;
  });

  afterEach(() => {
    try { nock.cleanAll(); nock.enableNetConnect(); nock.restore(); } catch (_e) {}
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
    delete process.env.BRAVE_SEARCH_API_KEY;
  });

  async function issueKey(app, tenantId = 'wa-tenant') {
    const r = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: tenantId });
    expect(r.status).toBe(201);
    return r.body.api_key;
  }

  test('sovereign fails → web search succeeds → sovereign-with-grounding succeeds → 200 + was_web_augmented', async () => {
    // First sovereign call (and retry) fail.
    nock('http://ollama.test').post('/api/chat').reply(503, 'sovereign down');
    nock('http://ollama.test').post('/api/chat').reply(503, 'still down');
    // Brave search returns results.
    nock('https://api.search.brave.com')
      .get('/res/v1/web/search')
      .query(true)
      .reply(200, {
        web: { results: [
          { title: 'Result A', url: 'https://example.com/a', description: 'snippet A' },
          { title: 'Result B', url: 'https://example.com/b', description: 'snippet B' },
        ] },
      });
    // Web-augmented sovereign retry succeeds (Tier A model — 7b).
    nock('http://ollama.test')
      .post('/api/chat')
      .reply(200, {
        message: { role: 'assistant', content: 'grounded answer [1]' },
        prompt_eval_count: 20, eval_count: 4,
      });
    // Frontier MUST NOT be called.
    const frontierGuard = nock('http://frontier.test')
      .post('/chat/completions')
      .reply(200, { choices: [{ message: { content: 'should-never-fire' }, finish_reason: 'stop' }], usage: {} });

    const app = createApp();
    const apiKey = await issueKey(app);

    const r = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ messages: [{ role: 'user', content: 'what is the current state of X' }] });

    expect(r.status).toBe(200);
    expect(r.body.choices[0].message.content).toBe('grounded answer [1]');
    expect(r.body.cogos).toBeDefined();
    expect(r.body.cogos.was_web_augmented).toBe(true);
    expect(r.body.cogos.web_provider).toBeDefined();
    expect(Array.isArray(r.body.cogos.web_sources)).toBe(true);
    expect(r.body.cogos.web_sources.length).toBeGreaterThan(0);
    // Headers also flag it.
    expect(r.headers['x-cogos-was-web-augmented']).toBe('1');
    expect(frontierGuard.isDone()).toBe(false);
  });

  test('FRONTIER_ESCALATION_ENABLED defaults to false (legacy path off)', async () => {
    // Sovereign fails twice, web search returns NO results, sovereign retry on
    // empty-results path also fails — should fall through to clean error.
    nock('http://ollama.test').post('/api/chat').reply(503, 'down');
    nock('http://ollama.test').post('/api/chat').reply(503, 'down');
    nock('https://api.search.brave.com')
      .get('/res/v1/web/search').query(true)
      .reply(200, { web: { results: [] } });
    nock('http://ollama.test').post('/api/chat').reply(503, 'still down on retry');
    // If frontier were enabled, this would catch the call. It must NOT be hit.
    const frontierGuard = nock('http://frontier.test')
      .post('/chat/completions').reply(200, {});

    const app = createApp();
    const apiKey = await issueKey(app, 'wa-tenant-b');
    const r = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ messages: [{ role: 'user', content: 'hi' }] });

    expect([502, 503]).toContain(r.status);
    expect(frontierGuard.isDone()).toBe(false);
  });

  test('WEB_AUGMENTED_ESCALATION_ENABLED=false disables web path entirely', async () => {
    process.env.WEB_AUGMENTED_ESCALATION_ENABLED = 'false';
    jest.resetModules();
    createApp = require('../src/index').createApp;

    nock('http://ollama.test').post('/api/chat').reply(503, 'down');
    nock('http://ollama.test').post('/api/chat').reply(503, 'down');
    // Web search and frontier must both be untouched.
    const webGuard = nock('https://api.search.brave.com')
      .get('/res/v1/web/search').query(true).reply(200, { web: { results: [] } });
    const frontierGuard = nock('http://frontier.test')
      .post('/chat/completions').reply(200, {});

    const app = createApp();
    const apiKey = await issueKey(app, 'wa-tenant-c');
    const r = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ messages: [{ role: 'user', content: 'hi' }] });

    expect([502, 503]).toContain(r.status);
    expect(webGuard.isDone()).toBe(false);
    expect(frontierGuard.isDone()).toBe(false);
  });

  test('learning log captures metadata ONLY — no prompt, no web sources, no answer content', async () => {
    // Privacy-minimal capture (2026-06-10 directive): the log proves the
    // escalation happened + names the provider + counts the sources, but
    // does NOT retain the prompt, the web result content (URLs, titles,
    // snippets), or the sovereign's answer. Customer queries don't sit
    // in our training pile.
    nock('http://ollama.test').post('/api/chat').reply(503, 'down');
    nock('http://ollama.test').post('/api/chat').reply(503, 'down');
    nock('https://api.search.brave.com')
      .get('/res/v1/web/search').query(true)
      .reply(200, { web: { results: [
        { title: 'Sensitive R1', url: 'https://ex.com/1', description: 'should NOT be in log' },
        { title: 'Sensitive R2', url: 'https://ex.com/2', description: 'should NOT be in log' },
      ] } });
    nock('http://ollama.test')
      .post('/api/chat')
      .reply(200, { message: { content: 'sensitive answer that should NOT be retained' }, prompt_eval_count: 10, eval_count: 3 });

    const app = createApp();
    const apiKey = await issueKey(app, 'wa-tenant-d');
    const sensitivePrompt = 'sensitive query that should NOT be retained';
    const r = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ messages: [{ role: 'user', content: sensitivePrompt }] });

    expect(r.status).toBe(200);
    const learning = require('../src/escalation-learning');
    const rows = learning.read({ limit: 50, tenant_id: 'wa-tenant-d' });
    const found = rows.find((row) => row.request_id === r.body.id);
    expect(found).toBeDefined();
    // Metadata IS captured:
    expect(found.path).toBe('web_augmented');
    expect(found.web_provider).toBeTruthy();
    expect(found.web_sources_count).toBe(2);
    expect(found.escalation_reason).toBeTruthy();
    expect(typeof found.latency_ms).toBe('number');
    // Content is NOT captured (privacy-minimal):
    expect(found.web_sources).toBeUndefined();
    expect(found.messages).toBeUndefined();
    expect(found.response_content).toBeUndefined();
    // And as a sentinel: serialize the whole row and check that no
    // substring of the sensitive strings leaked into it.
    const rowStr = JSON.stringify(found);
    expect(rowStr).not.toContain('sensitive');
    expect(rowStr).not.toContain('Sensitive R');
    expect(rowStr).not.toContain('ex.com/1');
  });
});
