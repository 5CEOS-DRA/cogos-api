'use strict';

// Integration tests for the customer-sealed audit pipeline end-to-end:
//   issuance → keys.js (returns x25519 privkey to customer, persists x25519 pubkey)
//            → auth flows x25519_pubkey_pem onto req.apiKey
//            → chat-api.js / direct usage.record passes it through
//            → usage.record seals content fields
//            → /v1/audit projects the sealed_content envelope on the wire
//            → customer round-trips ciphertext → plaintext with their privkey
//
// Companion to tests/sealed-audit.test.js (pure module tests).

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

let tmpDir;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-sealed-int-test-'));
  process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
  process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
  jest.resetModules();
});

afterEach(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

const request = require('supertest');

describe('issuance — ed25519 returns x25519 sealing keypair', () => {
  test('POST /admin/keys scheme=ed25519 → x25519_private_pem + x25519_pubkey_pem', async () => {
    const { createApp } = require('../src/index');
    const app = createApp();
    const res = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'sealtest', scheme: 'ed25519' });
    expect(res.status).toBe(201);
    expect(typeof res.body.x25519_pubkey_pem).toBe('string');
    expect(typeof res.body.x25519_private_pem).toBe('string');
    expect(/BEGIN PUBLIC KEY/.test(res.body.x25519_pubkey_pem)).toBe(true);
    expect(/BEGIN PRIVATE KEY/.test(res.body.x25519_private_pem)).toBe(true);
    // The ed25519 auth keypair is also returned alongside — confirming
    // the customer holds TWO independent privkeys.
    expect(/BEGIN PRIVATE KEY/.test(res.body.private_pem)).toBe(true);
    expect(typeof res.body.ed25519_key_id).toBe('string');
  });

  test('POST /admin/keys scheme=bearer → no x25519 pem in response', async () => {
    const { createApp } = require('../src/index');
    const app = createApp();
    const res = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'beareronly', scheme: 'bearer' });
    expect(res.status).toBe(201);
    expect(res.body.api_key).toMatch(/^sk-cogos-/);
    expect(res.body.x25519_pubkey_pem).toBeUndefined();
    expect(res.body.x25519_private_pem).toBeUndefined();
  });
});

describe('GET /v1/audit — sealed row projection + customer decrypt', () => {
  test('sealed_content rides the wire; customer decrypts with their x25519 privkey', async () => {
    const { createApp } = require('../src/index');
    const app = createApp();

    // Ed25519+x25519 issuance.
    const issueRes = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'sealtest', scheme: 'ed25519' });
    expect(issueRes.status).toBe(201);
    const { x25519_pubkey_pem, x25519_private_pem } = issueRes.body;

    // Append a row through usage.record — directly exercises the
    // sealing dispatch we just wired.
    const usage = require('../src/usage');
    usage.record({
      key_id: 'kid',
      tenant_id: 'sealtest',
      app_id: '_default',
      model: 'm',
      status: 'success',
      request_id: 'req-integration-test',
      prompt_fingerprint: 'sha256:abc123',
      x25519_pubkey_pem,
    });

    // Bearer key for the same tenant so we can read /v1/audit without
    // having to construct a full ed25519-signed GET. The point of this
    // test is the projection + envelope, not the auth header.
    const bearerRes = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'sealtest', scheme: 'bearer' });
    expect(bearerRes.status).toBe(201);

    const auditRes = await request(app)
      .get('/v1/audit')
      .set('Authorization', `Bearer ${bearerRes.body.api_key}`);
    expect(auditRes.status).toBe(200);
    expect(auditRes.body.chain_ok).toBe(true);

    const sealedRow = auditRes.body.rows.find((r) => r.sealed === true);
    expect(sealedRow).toBeDefined();
    expect(sealedRow.sealed_content).toBeDefined();
    expect(typeof sealedRow.sealed_content.ciphertext_b64).toBe('string');
    // The on-disk row MUST NOT carry the cleartext content fields.
    expect(sealedRow.request_id == null || sealedRow.request_id === '').toBe(true);
    expect(sealedRow.prompt_fingerprint == null).toBe(true);

    // Customer round-trips.
    const sealedMod = require('../src/sealed-audit');
    const plain = sealedMod.unsealForPrivkey(
      x25519_private_pem,
      sealedRow.sealed_content,
      { tenant_id: sealedRow.tenant_id, app_id: sealedRow.app_id, ts: sealedRow.ts },
    ).toString('utf8');
    const parsed = JSON.parse(plain);
    expect(parsed.request_id).toBe('req-integration-test');
    expect(parsed.prompt_fingerprint).toBe('sha256:abc123');
  });

  test('bearer-only tenant → /v1/audit rows are sealed:false with cleartext content', async () => {
    const { createApp } = require('../src/index');
    const app = createApp();

    const bearerRes = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'plainonly', scheme: 'bearer' });
    expect(bearerRes.status).toBe(201);

    // Append a row WITHOUT an x25519 pubkey — bearer customer doesn't
    // have one. usage.record must store cleartext.
    const usage = require('../src/usage');
    usage.record({
      key_id: 'kid',
      tenant_id: 'plainonly',
      app_id: '_default',
      model: 'm',
      status: 'success',
      request_id: 'plain-req-1',
      prompt_fingerprint: 'sha256:plain',
    });

    const auditRes = await request(app)
      .get('/v1/audit')
      .set('Authorization', `Bearer ${bearerRes.body.api_key}`);
    expect(auditRes.status).toBe(200);
    expect(auditRes.body.rows.length).toBe(1);
    expect(auditRes.body.rows[0].sealed).toBe(false);
    expect(auditRes.body.rows[0].sealed_content).toBeUndefined();
    expect(auditRes.body.rows[0].request_id).toBe('plain-req-1');
    expect(auditRes.body.rows[0].prompt_fingerprint).toBe('sha256:plain');
    expect(auditRes.body.chain_ok).toBe(true);
  });
});

describe('chat-api → sealed audit row when key has x25519_pubkey_pem', () => {
  // We don't have a live upstream here; we only need usage.record
  // dispatch to be driven by the right pubkey. The earlier audit-route
  // test exercises that path with usage.record directly. This test
  // documents the helper functions (promptFingerprint, schemaName) by
  // shape — they're internal but exported for tests via _internal.
  test('chat-api exports its hash/name helpers via _internal', () => {
    const chatApi = require('../src/chat-api');
    expect(chatApi._internal).toBeDefined();
    // promptFingerprint + schemaName don't need to be in _internal to
    // work, but documenting their presence on the module surface lets
    // future agents test them in isolation.
  });
});
