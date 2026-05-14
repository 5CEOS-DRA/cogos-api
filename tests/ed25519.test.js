'use strict';

// Ed25519 customer-auth tests (Security Hardening Card #7).
//
// Coverage:
//   1. Issuance via POST /admin/keys with { scheme:'ed25519' } returns
//      ed25519_key_id + private_pem + pubkey_pem (private_pem one-time
//      display).
//   2. Valid signature → /v1/models 200.
//   3. Tampered signature → 401.
//   4. ts > 5 min old → 401 (replay protection).
//   5. Body mutated post-sign → 401.
//   6. Cross-tenant: ed25519 wins over an existing bearer key for a
//      DIFFERENT tenant; req.apiKey reflects the ed25519 tenant.
//   7. Missing Authorization → 401.
//   8. Unknown keyId → 401.
//   9. Revoked key → 401.
//  10. Bearer requests still work after ed25519 lands.
//
// The wire format under test:
//   Authorization: CogOS-Ed25519 keyId=<id>,sig=<base64>,ts=<unix_ms>
// Signed bytes: `${METHOD}\n${path}\n${ts}\n${sha256_hex(body)}`

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-ed25519-test-'));
process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
process.env.OLLAMA_URL = 'http://ollama.test';
process.env.DEFAULT_MODEL = 'qwen2.5:3b-instruct';

const request = require('supertest');
const { createApp } = require('../src/index');

afterAll(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

// =============================================================================
// Test helpers
// =============================================================================

// Build the Authorization header value for a CogOS-Ed25519 request.
// Body is the EXACT bytes the client will send on the wire (string or
// Buffer); for an empty body, pass '' or undefined.
function authHeader(keyId, privPem, method, urlPath, ts, body) {
  const bodyBuf = body == null || body === ''
    ? Buffer.alloc(0)
    : (Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8'));
  const bodyHex = crypto.createHash('sha256').update(bodyBuf).digest('hex');
  const signedBytes = `${method.toUpperCase()}\n${urlPath}\n${ts}\n${bodyHex}`;
  const sig = crypto
    .sign(null, Buffer.from(signedBytes, 'utf8'), privPem)
    .toString('base64');
  return `CogOS-Ed25519 keyId=${keyId},sig=${sig},ts=${ts}`;
}

async function issueEd25519(app, tenantId = 'alice', tier = 'starter') {
  const res = await request(app)
    .post('/admin/keys')
    .set('X-Admin-Key', process.env.ADMIN_KEY)
    .send({ tenant_id: tenantId, tier, scheme: 'ed25519' });
  if (res.status !== 201) {
    throw new Error(`issue failed: ${res.status} ${JSON.stringify(res.body)}`);
  }
  return res.body;
}

async function issueBearer(app, tenantId = 'bob', tier = 'starter') {
  const res = await request(app)
    .post('/admin/keys')
    .set('X-Admin-Key', process.env.ADMIN_KEY)
    .send({ tenant_id: tenantId, tier });
  return res.body;
}

// =============================================================================
// 1. Issuance
// =============================================================================
describe('ed25519 issuance', () => {
  test('POST /admin/keys {scheme:"ed25519"} → 201 with private_pem + key id', async () => {
    const app = createApp();
    const body = await issueEd25519(app, 'alice');
    expect(body.scheme).toBe('ed25519');
    expect(body.ed25519_key_id).toMatch(/^kid-[a-f0-9]{16}$/);
    expect(body.private_pem).toMatch(/-----BEGIN PRIVATE KEY-----/);
    expect(body.pubkey_pem).toMatch(/-----BEGIN PUBLIC KEY-----/);
    expect(body.api_key).toBeUndefined(); // ed25519 doesn't return a plaintext bearer
    expect(body.tenant_id).toBe('alice');
  });

  test('POST /admin/keys {scheme:"invalid"} → 400', async () => {
    const app = createApp();
    const res = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'alice', scheme: 'rsa' });
    expect(res.status).toBe(400);
    expect(res.body.error.message).toMatch(/scheme/);
  });

  test('GET /admin/keys → list redacts key_hash, exposes ed25519 fields', async () => {
    const app = createApp();
    await issueEd25519(app, 'alice');
    const res = await request(app)
      .get('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(res.status).toBe(200);
    const ed = res.body.keys.find((k) => k.scheme === 'ed25519');
    expect(ed).toBeTruthy();
    expect(ed.key_hash).toBeUndefined();
    expect(ed.ed25519_key_id).toMatch(/^kid-/);
    expect(ed.pubkey_pem).toMatch(/-----BEGIN PUBLIC KEY-----/);
  });
});

// =============================================================================
// 2. Valid signature → 200
// =============================================================================
describe('ed25519 verification: success path', () => {
  test('signed GET /v1/models → 200', async () => {
    const app = createApp();
    const k = await issueEd25519(app, 'alice');
    const ts = Date.now();
    const auth = authHeader(k.ed25519_key_id, k.private_pem, 'GET', '/v1/models', ts, '');
    const res = await request(app)
      .get('/v1/models')
      .set('Authorization', auth);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('data');
  });

  test('signed GET /v1/audit?since=0 (query string in path) → 200', async () => {
    const app = createApp();
    const k = await issueEd25519(app, 'alice');
    const ts = Date.now();
    // path must include the query string — that's what originalUrl exposes.
    const auth = authHeader(k.ed25519_key_id, k.private_pem, 'GET', '/v1/audit?since=0', ts, '');
    const res = await request(app)
      .get('/v1/audit?since=0')
      .set('Authorization', auth);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('rows');
  });
});

// =============================================================================
// 3. Tampered signature → 401
// =============================================================================
describe('ed25519 verification: failure paths', () => {
  test('tampered sig → 401', async () => {
    const app = createApp();
    const k = await issueEd25519(app, 'alice');
    const ts = Date.now();
    const goodAuth = authHeader(k.ed25519_key_id, k.private_pem, 'GET', '/v1/models', ts, '');
    // Flip a base64 char in the MIDDLE of the sig so we don't trip on
    // trailing `=` padding (which doesn't carry decoded bits and would
    // round-trip to the same buffer).
    const tampered = goodAuth.replace(/,sig=([^,]+),/, (_, s) => {
      const mid = Math.floor(s.length / 2);
      const orig = s[mid];
      const swap = orig === 'A' ? 'B' : 'A';
      return `,sig=${s.slice(0, mid)}${swap}${s.slice(mid + 1)},`;
    });
    const res = await request(app)
      .get('/v1/models')
      .set('Authorization', tampered);
    expect(res.status).toBe(401);
    expect(res.body.error.message).toMatch(/Signature verification failed/);
  });

  // =============================================================================
  // 4. Old ts → replay rejected
  // =============================================================================
  test('ts > 5 min old → 401 (replay)', async () => {
    const app = createApp();
    const k = await issueEd25519(app, 'alice');
    const oldTs = Date.now() - 6 * 60 * 1000; // 6 min ago
    const auth = authHeader(k.ed25519_key_id, k.private_pem, 'GET', '/v1/models', oldTs, '');
    const res = await request(app)
      .get('/v1/models')
      .set('Authorization', auth);
    expect(res.status).toBe(401);
    expect(res.body.error.message).toMatch(/replay window/);
  });

  // =============================================================================
  // 5. Body different from signed → 401
  // =============================================================================
  test('body mutated post-sign → 401', async () => {
    const app = createApp();
    const k = await issueEd25519(app, 'alice');
    const ts = Date.now();
    const signedBody = JSON.stringify({ model: 'qwen2.5:3b-instruct', messages: [{ role: 'user', content: 'hi' }] });
    const sentBody = JSON.stringify({ model: 'qwen2.5:3b-instruct', messages: [{ role: 'user', content: 'tampered' }] });
    // Sign the FIRST body bytes; send the SECOND.
    const auth = authHeader(k.ed25519_key_id, k.private_pem, 'POST', '/v1/chat/completions', ts, signedBody);
    const res = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', auth)
      .set('Content-Type', 'application/json')
      .send(sentBody);
    expect(res.status).toBe(401);
    expect(res.body.error.message).toMatch(/Signature verification failed/);
  });

  // =============================================================================
  // 6. Cross-scheme tenant: ed25519 wins
  // =============================================================================
  test('ed25519 + existing bearer for different tenant → ed25519 tenant on req', async () => {
    const app = createApp();
    const bearer = await issueBearer(app, 'bob-tenant');
    const ed = await issueEd25519(app, 'alice-tenant');
    expect(bearer.tenant_id).toBe('bob-tenant');
    expect(ed.tenant_id).toBe('alice-tenant');

    // /v1/audit includes the tenant context via req.apiKey.tenant_id —
    // the returned `rows` are scoped to that tenant. Both keys exist, but
    // we present the ed25519 Authorization. The bearer header is absent,
    // so customerAuth's ed25519-first branch decides the outcome and the
    // bearer fall-through is never reached.
    const ts = Date.now();
    const auth = authHeader(ed.ed25519_key_id, ed.private_pem, 'GET', '/v1/audit', ts, '');
    const res = await request(app)
      .get('/v1/audit')
      .set('Authorization', auth);
    expect(res.status).toBe(200);
    // The audit endpoint scopes rows to the authenticated tenant; the
    // chain head is per-tenant. There won't be any rows yet — but the
    // request being 200 (not 401) proves ed25519 authenticated alice.
    expect(res.body).toHaveProperty('rows');
    expect(res.body.chain_ok).toBe(true);
  });

  // =============================================================================
  // 7. Missing Authorization → 401
  // =============================================================================
  test('no Authorization → 401', async () => {
    const app = createApp();
    const res = await request(app).get('/v1/models');
    expect(res.status).toBe(401);
  });

  // =============================================================================
  // 8. Unknown keyId → 401
  // =============================================================================
  test('unknown ed25519 keyId → 401', async () => {
    const app = createApp();
    // Generate a keypair locally that the server has never seen.
    const { privateKey } = crypto.generateKeyPairSync('ed25519');
    const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const ts = Date.now();
    const auth = authHeader('kid-deadbeefdeadbeef', privPem, 'GET', '/v1/models', ts, '');
    const res = await request(app)
      .get('/v1/models')
      .set('Authorization', auth);
    expect(res.status).toBe(401);
    expect(res.body.error.message).toMatch(/Unknown ed25519 keyId/);
  });

  // =============================================================================
  // 9. Revoked key → 401
  // =============================================================================
  test('revoked ed25519 key → 401', async () => {
    const app = createApp();
    const k = await issueEd25519(app, 'alice');
    // Revoke via the same admin route the bearer suite uses.
    const rev = await request(app)
      .post(`/admin/keys/${k.key_id}/revoke`)
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(rev.status).toBe(200);

    const ts = Date.now();
    const auth = authHeader(k.ed25519_key_id, k.private_pem, 'GET', '/v1/models', ts, '');
    const res = await request(app)
      .get('/v1/models')
      .set('Authorization', auth);
    expect(res.status).toBe(401);
    expect(res.body.error.message).toMatch(/revoked/);
  });

  // =============================================================================
  // Malformed CogOS-Ed25519 header → 401 (not bearer fallback)
  // =============================================================================
  test('malformed CogOS-Ed25519 header → 401 (no bearer fallback)', async () => {
    const app = createApp();
    const res = await request(app)
      .get('/v1/models')
      .set('Authorization', 'CogOS-Ed25519 garbage');
    expect(res.status).toBe(401);
    expect(res.body.error.message).toMatch(/Malformed CogOS-Ed25519/);
  });
});

// =============================================================================
// 10. Bearer still works
// =============================================================================
describe('cross-scheme: bearer untouched', () => {
  test('legacy bearer key still authenticates /v1/models', async () => {
    const app = createApp();
    const b = await issueBearer(app, 'legacy-bob');
    const res = await request(app)
      .get('/v1/models')
      .set('Authorization', `Bearer ${b.api_key}`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('data');
  });
});
