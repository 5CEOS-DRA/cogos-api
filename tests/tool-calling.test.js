'use strict';

// H — tool/function-calling support on /v1/chat/completions.
//
// Before this feature, the handler dropped body.tools and body.tool_choice
// silently and the upstream response's tool_calls[] never made it back to
// the customer. Developers using LangChain / Vercel AI SDK / OpenAI SDK
// with tools got back assistant content like "I'd call function X" as
// plain text, no tool_calls[] — breaking agent loops.
//
// Now: tools[] and tool_choice are forwarded to upstream verbatim, and
// tool_calls[] on the upstream response is surfaced in the assistant
// message in the OpenAI-canonical shape.

const fs = require('fs');
const os = require('os');
const path = require('path');

describe('H: tool/function-calling on /v1/chat/completions', () => {
  let tmpDir;
  let request;
  let nock;
  let createApp;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-tool-test-'));
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
      .send({ tenant_id: 'tool-tenant' });
    expect(r.status).toBe(201);
    return r.body.api_key;
  }

  test('body.tools[] is forwarded to upstream payload', async () => {
    let capturedPayload = null;
    nock('http://ollama.test')
      .post('/api/chat', (body) => { capturedPayload = body; return true; })
      .reply(200, {
        message: { role: 'assistant', content: 'I should look that up' },
        prompt_eval_count: 10, eval_count: 5,
      });

    const app = createApp();
    const apiKey = await issueKey(app);

    const tools = [
      {
        type: 'function',
        function: {
          name: 'get_weather',
          description: 'Get current weather',
          parameters: {
            type: 'object',
            properties: { city: { type: 'string' } },
            required: ['city'],
          },
        },
      },
    ];

    const r = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({
        messages: [{ role: 'user', content: 'weather in paris?' }],
        tools,
        tool_choice: 'auto',
      });

    expect(r.status).toBe(200);
    expect(capturedPayload).toBeTruthy();
    expect(capturedPayload.tools).toEqual(tools);
    expect(capturedPayload.tool_choice).toBe('auto');
  });

  test('upstream tool_calls[] is surfaced in assistant message', async () => {
    const upstreamToolCalls = [
      {
        id: 'call_abc123',
        type: 'function',
        function: {
          name: 'get_weather',
          arguments: '{"city":"paris"}',
        },
      },
    ];
    nock('http://ollama.test')
      .post('/api/chat')
      .reply(200, {
        message: {
          role: 'assistant',
          content: '',
          tool_calls: upstreamToolCalls,
        },
        prompt_eval_count: 10, eval_count: 5,
        done_reason: 'tool_calls',
      });

    const app = createApp();
    const apiKey = await issueKey(app);

    const r = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({
        messages: [{ role: 'user', content: 'weather in paris?' }],
        tools: [{
          type: 'function',
          function: { name: 'get_weather', parameters: { type: 'object', properties: {} } },
        }],
      });

    expect(r.status).toBe(200);
    expect(r.body.choices[0].message.role).toBe('assistant');
    expect(r.body.choices[0].message.tool_calls).toEqual(upstreamToolCalls);
    expect(r.body.choices[0].finish_reason).toBe('tool_calls');
  });

  test('absence of tools[] in request means no tools field on upstream payload', async () => {
    let capturedPayload = null;
    nock('http://ollama.test')
      .post('/api/chat', (body) => { capturedPayload = body; return true; })
      .reply(200, {
        message: { role: 'assistant', content: 'hi' },
        prompt_eval_count: 1, eval_count: 1,
      });

    const app = createApp();
    const apiKey = await issueKey(app);

    const r = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ messages: [{ role: 'user', content: 'hi' }] });

    expect(r.status).toBe(200);
    expect(capturedPayload).toBeTruthy();
    expect(capturedPayload.tools).toBeUndefined();
    expect(capturedPayload.tool_choice).toBeUndefined();
  });

  test('absence of tool_calls in upstream response means no tool_calls in client response', async () => {
    nock('http://ollama.test')
      .post('/api/chat')
      .reply(200, {
        message: { role: 'assistant', content: 'plain text answer' },
        prompt_eval_count: 1, eval_count: 1,
      });

    const app = createApp();
    const apiKey = await issueKey(app);

    const r = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${apiKey}`)
      .send({ messages: [{ role: 'user', content: 'hi' }] });

    expect(r.status).toBe(200);
    expect(r.body.choices[0].message.tool_calls).toBeUndefined();
    expect(r.body.choices[0].message.content).toBe('plain text answer');
  });
});
