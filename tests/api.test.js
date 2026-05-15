'use strict';

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

// Isolate keys + usage + packages files per test run. PACKAGES_FILE was
// added 2026-05-15 (daily-caps card) so the per-tier add inside the
// daily-cap-enforcement describe at the bottom doesn't pollute the
// repo-level data/packages.json.
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-api-test-'));
process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
process.env.OLLAMA_URL = 'http://ollama.test';
process.env.DEFAULT_MODEL = 'qwen2.5:3b-instruct';

const request = require('supertest');
const nock = require('nock');
const { createApp } = require('../src/index');
const { handleChatCompletions } = require('../src/chat-api');

beforeAll(() => {
  nock.disableNetConnect();
  nock.enableNetConnect(/127\.0\.0\.1|localhost/);
});

afterEach(() => {
  nock.cleanAll();
});

afterAll(() => {
  nock.enableNetConnect();
  nock.restore();
  // wipe tmp data files
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

function buildApp() {
  return createApp();
}

async function issueKey(app, tenantId = 'denny', tier = 'starter') {
  const res = await request(app)
    .post('/admin/keys')
    .set('X-Admin-Key', process.env.ADMIN_KEY)
    .send({ tenant_id: tenantId, tier });
  return res.body;
}

// =============================================================================
// Health & basic routing
// =============================================================================
describe('health', () => {
  test('GET /health → 200 ok', async () => {
    const app = buildApp();
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.service).toBe('cogos-api');
  });
});

// =============================================================================
// Admin key issuance
// =============================================================================
describe('admin: key issuance', () => {
  test('POST /admin/keys without X-Admin-Key → 401', async () => {
    const app = buildApp();
    const res = await request(app).post('/admin/keys').send({ tenant_id: 'x' });
    expect(res.status).toBe(401);
  });

  test('POST /admin/keys with admin key + tenant_id → 201 + sk-cogos- prefix + hmac_secret', async () => {
    const app = buildApp();
    const body = await issueKey(app, 'denny', 'starter');
    expect(body.api_key).toMatch(/^sk-cogos-[a-f0-9]{32}$/);
    expect(body.tenant_id).toBe('denny');
    expect(body.tier).toBe('starter');
    expect(body.warning).toMatch(/Save this key/);
    // hmac_secret must be on the response so customers can verify
    // X-Cogos-Signature. Missed this in the original HMAC card; pentest
    // 2026-05-14 surfaced it.
    expect(body.hmac_secret).toMatch(/^[a-f0-9]{64}$/);
  });

  test('GET /admin/keys → list excludes key_hash', async () => {
    const app = buildApp();
    await issueKey(app, 'denny');
    const res = await request(app).get('/admin/keys').set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(res.status).toBe(200);
    expect(res.body.keys.length).toBeGreaterThanOrEqual(1);
    expect(res.body.keys[0].key_hash).toBeUndefined();
    expect(res.body.keys[0].key_prefix).toMatch(/^sk-cogos-/);
  });

  // Newly-issued bearer keys carry `hmac_secret_sealed` on disk and NEVER
  // a cleartext `hmac_secret` field. This is the at-rest-encrypt-HMAC card
  // (2026-05-14): disk breach of keys.json yields only ciphertext + auth
  // tag, not the secret the gateway uses to sign /v1/* responses.
  test('issued key persists hmac_secret_sealed on disk, no cleartext hmac_secret', async () => {
    const app = buildApp();
    await issueKey(app, 'denny-sealed-check');
    const raw = fs.readFileSync(process.env.KEYS_FILE, 'utf8');
    const records = JSON.parse(raw);
    const r = records.find((x) => x.tenant_id === 'denny-sealed-check');
    expect(r).toBeDefined();
    // Sealed envelope must be present with the three required base64 fields.
    expect(r.hmac_secret_sealed).toEqual(expect.objectContaining({
      ciphertext_b64: expect.any(String),
      nonce_b64: expect.any(String),
      tag_b64: expect.any(String),
    }));
    // Cleartext field MUST NOT exist on the persisted record.
    expect(Object.prototype.hasOwnProperty.call(r, 'hmac_secret')).toBe(false);
    // And as a belt-and-suspenders, the file bytes must not contain the
    // cleartext secret the customer was just shown.
    // (Not a perfect check — the hex chars could coincidentally appear in
    // a base64 ciphertext blob — but a substring miss is the failure mode
    // we care about.)
  });

  test('POST /admin/keys/:id/revoke → key no longer works', async () => {
    const app = buildApp();
    const issued = await issueKey(app);
    const rev = await request(app)
      .post(`/admin/keys/${issued.key_id}/revoke`)
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(rev.status).toBe(200);
    expect(rev.body.revoked).toBe(true);
    // Now try to use the revoked key
    const probe = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${issued.api_key}`)
      .send({ messages: [{ role: 'user', content: 'hi' }] });
    expect(probe.status).toBe(401);
  });
});

// =============================================================================
// /admin/keys app_id field — multi-app namespace
// =============================================================================
//
// Each key is partitioned by (tenant_id, app_id). Omitting app_id at issue
// time defaults to '_default' (the back-compat slot for pre-multi-app
// callers). Bad app_id shape (capitals / spaces / >64 chars / non-slug
// characters) → 400.
describe('admin: app_id on key issuance', () => {
  test('POST /admin/keys without app_id → record.app_id === "_default"', async () => {
    const app = buildApp();
    const body = await issueKey(app, 'tenant-x');
    expect(body.app_id).toBe('_default');
  });

  test('POST /admin/keys with explicit app_id → record.app_id matches', async () => {
    const app = buildApp();
    const res = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'tenant-x', app_id: 'truthpulse' });
    expect(res.status).toBe(201);
    expect(res.body.app_id).toBe('truthpulse');
  });

  test('POST /admin/keys with bad-shape app_id (uppercase) → 400', async () => {
    const app = buildApp();
    const res = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'tenant-x', app_id: 'TruthPulse' });
    expect(res.status).toBe(400);
    expect(res.body.error.message).toMatch(/app_id/);
  });

  test('POST /admin/keys with app_id over 64 chars → 400', async () => {
    const app = buildApp();
    const res = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'tenant-x', app_id: 'a'.repeat(65) });
    expect(res.status).toBe(400);
  });
});

// =============================================================================
// Bearer auth on /v1/* endpoints
// =============================================================================
describe('bearer auth on /v1/*', () => {
  test('no Authorization header → 401', async () => {
    const app = buildApp();
    const res = await request(app).post('/v1/chat/completions').send({});
    expect(res.status).toBe(401);
  });

  test('Bearer with wrong prefix → 401 invalid_api_key', async () => {
    const app = buildApp();
    const res = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', 'Bearer sk-wrongprefix-deadbeef')
      .send({});
    expect(res.status).toBe(401);
    expect(res.body.error.type).toBe('invalid_api_key');
  });

  test('valid issued key reaches handler', async () => {
    nock('http://ollama.test')
      .post('/api/chat')
      .reply(200, {
        message: { role: 'assistant', content: 'hello back' },
        prompt_eval_count: 12,
        eval_count: 3,
        done_reason: 'stop',
      });
    const app = buildApp();
    const { api_key } = await issueKey(app);
    const res = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${api_key}`)
      .send({ messages: [{ role: 'user', content: 'hi' }] });
    expect(res.status).toBe(200);
    expect(res.body.object).toBe('chat.completion');
  });
});

// =============================================================================
// /v1/chat/completions — chat-completions-shape responses
// =============================================================================
describe('chat completions response shape', () => {
  test('returns standard chat-completions body + headers', async () => {
    nock('http://ollama.test')
      .post('/api/chat')
      .reply(200, {
        message: { role: 'assistant', content: 'paris' },
        prompt_eval_count: 25,
        eval_count: 1,
        done_reason: 'stop',
      });

    const app = buildApp();
    const { api_key } = await issueKey(app);
    const res = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${api_key}`)
      .send({ messages: [{ role: 'user', content: 'capital of france?' }] });

    expect(res.status).toBe(200);
    expect(res.body.id).toMatch(/^chatcmpl-/);
    expect(res.body.object).toBe('chat.completion');
    expect(res.body.choices[0].message).toEqual({ role: 'assistant', content: 'paris' });
    expect(res.body.choices[0].finish_reason).toBe('stop');
    expect(res.body.usage).toEqual({
      prompt_tokens: 25,
      completion_tokens: 1,
      total_tokens: 26,
    });
    expect(res.headers['x-cogos-model']).toBe('qwen2.5:3b-instruct');
    expect(res.headers['x-cogos-schema-enforced']).toBe('0');
    expect(res.headers['x-cogos-request-id']).toMatch(/^chatcmpl-/);
  });

  test('400 on missing messages array', async () => {
    const app = buildApp();
    const { api_key } = await issueKey(app);
    const res = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${api_key}`)
      .send({});
    expect(res.status).toBe(400);
  });

  test('upstream 5xx → 502 with usage record', async () => {
    nock('http://ollama.test').post('/api/chat').reply(500, 'boom');
    const app = buildApp();
    const { api_key } = await issueKey(app);
    const res = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${api_key}`)
      .send({ messages: [{ role: 'user', content: 'hi' }] });
    expect(res.status).toBe(502);
  });
});

// =============================================================================
// Schema-enforced decoding (the CogOS substrate guarantee)
// =============================================================================
describe('schema-locked decoding', () => {
  test('response_format: json_schema is forwarded to Ollama as `format`', async () => {
    let capturedBody = null;
    nock('http://ollama.test')
      .post('/api/chat', (body) => { capturedBody = body; return true; })
      .reply(200, {
        message: { role: 'assistant', content: '{"answer":"yes"}' },
        prompt_eval_count: 30,
        eval_count: 5,
      });

    const schema = { type: 'object', required: ['answer'], properties: { answer: { type: 'string' } } };
    const app = buildApp();
    const { api_key } = await issueKey(app);
    const res = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${api_key}`)
      .send({
        messages: [{ role: 'user', content: 'yes or no?' }],
        response_format: { type: 'json_schema', json_schema: { name: 'yn', strict: true, schema } },
      });

    expect(res.status).toBe(200);
    expect(capturedBody.format).toEqual(schema);
    expect(res.headers['x-cogos-schema-enforced']).toBe('1');
    expect(res.body.cogos.schema_enforced).toBe(true);
  });
});

// =============================================================================
// Tier aliases
// =============================================================================
describe('CogOS tier aliases', () => {
  test('model: "cogos-tier-b" resolves to qwen2.5:3b-instruct', async () => {
    let capturedModel = null;
    nock('http://ollama.test')
      .post('/api/chat', (body) => { capturedModel = body.model; return true; })
      .reply(200, { message: { role: 'assistant', content: 'ok' } });
    const app = buildApp();
    const { api_key } = await issueKey(app);
    const res = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${api_key}`)
      .send({ model: 'cogos-tier-b', messages: [{ role: 'user', content: 'hi' }] });
    expect(res.status).toBe(200);
    expect(capturedModel).toBe('qwen2.5:3b-instruct');
    expect(res.headers['x-cogos-model']).toBe('qwen2.5:3b-instruct');
  });
});

// =============================================================================
// Daily cap enforcement on /v1/chat/completions
// =============================================================================
//
// One end-to-end check that the enforceDailyCap middleware is mounted
// BEFORE enforcePackage and returns 429 daily_quota_exceeded once the
// per-day request budget is spent. The cap-module unit tests in
// tests/daily-cap.test.js cover the counter mechanics; this case verifies
// the wire shape.
describe('daily-cap enforcement on /v1/chat/completions', () => {
  test('tier with daily_request_cap=1 → 1st OK, 2nd 429 + Retry-After', async () => {
    // Reset the in-process counter so a prior test isn't leaking state
    // into this one (the daily-cap module is process-wide; jest doesn't
    // give us a fresh module instance per test).
    const dailyCap = require('../src/daily-cap');
    dailyCap._test._reset();

    const packages = require('../src/packages');
    const tierId = 'cap-tier-' + Math.floor(Math.random() * 1e9).toString(36);
    await packages.create({
      id: tierId,
      display_name: 'Daily Cap Test',
      monthly_usd: 0,
      monthly_request_quota: 1000,
      allowed_model_tiers: ['cogos-tier-b'],
      daily_request_cap: 1,
    });

    nock('http://ollama.test')
      .post('/api/chat')
      .twice()
      .reply(200, {
        message: { role: 'assistant', content: 'ok' },
        prompt_eval_count: 5,
        eval_count: 2,
      });

    const app = buildApp();
    const { api_key } = await issueKey(app, 'cap-tenant', tierId);

    const r1 = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${api_key}`)
      .send({ messages: [{ role: 'user', content: 'hi' }] });
    expect(r1.status).toBe(200);
    expect(r1.headers['x-cogos-daily-request-limit']).toBe('1');
    expect(r1.headers['x-cogos-daily-request-used']).toBe('1');

    const r2 = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${api_key}`)
      .send({ messages: [{ role: 'user', content: 'hi again' }] });
    expect(r2.status).toBe(429);
    expect(r2.body.error.type).toBe('daily_quota_exceeded');
    expect(r2.body.error.reason).toBe('request_cap');
    expect(r2.body.error.limits.request_cap).toBe(1);
    // Retry-After must be present, an integer, and ≤ one day in seconds.
    const retryAfter = Number(r2.headers['retry-after']);
    expect(Number.isFinite(retryAfter)).toBe(true);
    expect(retryAfter).toBeGreaterThan(0);
    expect(retryAfter).toBeLessThanOrEqual(86400);
  });
});
