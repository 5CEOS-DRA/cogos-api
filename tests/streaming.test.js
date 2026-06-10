'use strict';

// G — SSE streaming on /v1/chat/completions (body.stream === true).
//
// Before this feature, stream:false was hardcoded and the gateway always
// buffered the full response. Devs using OpenAI-style streaming (typing
// effect, agent loops, real-time UX) were forced to wait for the full
// answer. Table-stakes for "drop-in OpenAI replacement."
//
// Stream contract:
//   - Content-Type: text/event-stream
//   - First chunk: delta:{role:'assistant'} per OpenAI convention
//   - Subsequent chunks: delta:{content:'...'} per partial
//   - Terminal chunk: delta:{} with finish_reason:'stop'
//   - Sentinel: data: [DONE]
// Honest gap: streamed responses do NOT carry per-response HMAC +
// attestation signatures (signing requires the full body). Auditability
// is preserved via the usage row + /v1/audit/chain-head — the SSE
// response carries X-Cogos-Stream-Receipt: audit-chain-only header.

const fs = require('fs');
const os = require('os');
const path = require('path');
const stream = require('stream');

describe('G: SSE streaming on /v1/chat/completions', () => {
  let tmpDir;
  let request;
  let nock;
  let createApp;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-stream-test-'));
    process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
    process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
    process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
    process.env.RATE_LIMITS_FILE = path.join(tmpDir, 'rate-limits.jsonl');
    process.env.OLLAMA_URL = 'http://ollama.test';
    process.env.UPSTREAM_URL = 'http://ollama.test';
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
  });

  async function issueKey(app) {
    const r = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'stream-tenant' });
    expect(r.status).toBe(201);
    return r.body.api_key;
  }

  function ollamaNdjson(chunks) {
    // Build a Readable stream of NDJSON lines, one Ollama frame per line.
    const lines = chunks.map((c) => JSON.stringify(c)).join('\n') + '\n';
    return stream.Readable.from([Buffer.from(lines, 'utf8')]);
  }

  test('streaming emits SSE chunks with role-first + content deltas + [DONE]', async () => {
    nock('http://ollama.test')
      .post('/api/chat')
      .reply(200, () => ollamaNdjson([
        { message: { content: 'hello ' }, done: false },
        { message: { content: 'world' }, done: false },
        { message: { content: '' }, done: true, done_reason: 'stop',
          prompt_eval_count: 7, eval_count: 2 },
      ]));

    const app = createApp();
    const apiKey = await issueKey(app);

    const r = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ messages: [{ role: 'user', content: 'hi' }], stream: true });

    expect(r.status).toBe(200);
    expect(r.headers['content-type']).toMatch(/text\/event-stream/);
    expect(r.headers['x-cogos-request-id']).toMatch(/^chatcmpl-/);
    expect(r.headers['x-cogos-stream-receipt']).toBe('audit-chain-only');

    // Parse SSE frames. Each is "data: <json>\n\n" or the [DONE] sentinel.
    const text = r.text;
    expect(text).toContain('data: [DONE]');

    const dataLines = text
      .split('\n\n')
      .map((b) => b.trim())
      .filter((b) => b.startsWith('data: '))
      .map((b) => b.slice('data: '.length));

    // First payload: role:'assistant'.
    const first = JSON.parse(dataLines[0]);
    expect(first.choices[0].delta.role).toBe('assistant');

    // Find content-bearing chunks and reassemble.
    const contents = dataLines
      .filter((l) => l !== '[DONE]')
      .map(JSON.parse)
      .map((c) => c.choices[0].delta.content)
      .filter((c) => typeof c === 'string')
      .join('');
    expect(contents).toBe('hello world');

    // Last non-[DONE] frame should carry finish_reason.
    const nonDone = dataLines.filter((l) => l !== '[DONE]').map(JSON.parse);
    const terminal = nonDone[nonDone.length - 1];
    expect(terminal.choices[0].finish_reason).toBe('stop');
  });

  test('streaming with upstream 500 → error SSE event + [DONE] terminator', async () => {
    nock('http://ollama.test')
      .post('/api/chat')
      .reply(500, 'down');

    const app = createApp();
    const apiKey = await issueKey(app);

    const r = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ messages: [{ role: 'user', content: 'hi' }], stream: true });

    expect(r.headers['content-type']).toMatch(/text\/event-stream/);
    expect(r.text).toContain('event: error');
    expect(r.text).toContain('data: [DONE]');
  });

  test('stream:false (or missing) goes through buffered path (back-compat)', async () => {
    nock('http://ollama.test')
      .post('/api/chat')
      .reply(200, {
        message: { role: 'assistant', content: 'buffered hi' },
        prompt_eval_count: 5, eval_count: 2,
      });

    const app = createApp();
    const apiKey = await issueKey(app);

    const r = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ messages: [{ role: 'user', content: 'hi' }] }); // no stream

    expect(r.status).toBe(200);
    expect(r.headers['content-type']).toMatch(/application\/json/);
    expect(r.body.object).toBe('chat.completion');
    expect(r.body.choices[0].message.content).toBe('buffered hi');
  });
});
