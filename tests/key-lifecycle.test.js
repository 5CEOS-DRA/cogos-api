'use strict';

// Key-lifecycle suite. Lifecycle has three primitives, each added in
// its own commit:
//
//   1) Expiration       — issued keys carry expires_at; auth path 401s
//                         past it with type='expired_api_key'.
//   2) Rotation         — POST /v1/keys/rotate; 24h grace window;
//                         X-Cogos-Key-Deprecated on old-key responses.
//   3) Quarantine       — anomaly-driven (scanner_active + recent valid
//                         auth from same IP, fail-closed mode only);
//                         operator clears via /admin/keys/:id/clear-quarantine.
//
// Tests are added in the matching commit so reverting any one piece
// keeps the suite consistent.

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

let tmpDir;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-keylife-test-'));
  process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
  process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
  process.env.ANOMALIES_FILE = path.join(tmpDir, 'anomalies.jsonl');
  jest.resetModules();
});

afterEach(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

const request = require('supertest');

function freshApp() {
  jest.resetModules();
  const { createApp } = require('../src/index');
  return createApp();
}

async function issueKey(app, body) {
  return request(app)
    .post('/admin/keys')
    .set('X-Admin-Key', process.env.ADMIN_KEY)
    .send(body);
}

// ---------------------------------------------------------------------------
// Expiration
// ---------------------------------------------------------------------------
describe('key lifecycle — expiration', () => {
  test('POST /admin/keys returns an expires_at; default is ~1 year forward', async () => {
    const app = freshApp();
    const res = await issueKey(app, { tenant_id: 'tenant-e1' });
    expect(res.status).toBe(201);
    expect(typeof res.body.expires_at).toBe('string');
    const exp = Date.parse(res.body.expires_at);
    expect(Number.isFinite(exp)).toBe(true);
    // Default is 365 days. Use a wide window to absorb test-clock skew.
    const yearMs = 365 * 24 * 60 * 60_000;
    expect(exp - Date.now()).toBeGreaterThan(yearMs - 60_000);
    expect(exp - Date.now()).toBeLessThan(yearMs + 60_000);
  });

  test('caller can override expires_at_iso on issuance', async () => {
    const app = freshApp();
    const future = new Date(Date.now() + 30 * 60_000).toISOString();
    const res = await issueKey(app, { tenant_id: 'tenant-e2', expires_at_iso: future });
    expect(res.status).toBe(201);
    expect(res.body.expires_at).toBe(future);
  });

  test('invalid expires_at_iso rejected at issue time', async () => {
    const app = freshApp();
    const res = await issueKey(app, { tenant_id: 'tenant-e3', expires_at_iso: 'not a date' });
    expect(res.status).toBe(400);
    expect(res.body.error.message).toMatch(/expires_at_iso/);
  });

  test('past expires_at_iso → auth fails with error.type=expired_api_key', async () => {
    const app = freshApp();
    const past = new Date(Date.now() - 60_000).toISOString();
    const issue = await issueKey(app, { tenant_id: 'tenant-e4', expires_at_iso: past });
    expect(issue.status).toBe(201);
    expect(issue.body.expires_at).toBe(past);

    const res = await request(app)
      .get('/v1/models')
      .set('Authorization', `Bearer ${issue.body.api_key}`);
    expect(res.status).toBe(401);
    expect(res.body.error.type).toBe('expired_api_key');
    expect(res.body.error.message).toMatch(/expired/i);
  });

  test('not-yet-expired key authenticates normally (no 401 from lifecycle gate)', async () => {
    const app = freshApp();
    const future = new Date(Date.now() + 10 * 60_000).toISOString();
    const issue = await issueKey(app, { tenant_id: 'tenant-e5', expires_at_iso: future });
    const res = await request(app)
      .get('/v1/models')
      .set('Authorization', `Bearer ${issue.body.api_key}`);
    // /v1/models routes through to the upstream — without a configured
    // backend the call may 500/502, but it MUST NOT be 401. The point
    // of this test is the lifecycle gate doesn't fire for a valid key.
    expect(res.status).not.toBe(401);
  });
});

// ---------------------------------------------------------------------------
// Rotation
// ---------------------------------------------------------------------------
describe('key lifecycle — rotation', () => {
  test('customer rotates with valid bearer → new key issued, old still works during grace', async () => {
    const app = freshApp();
    const issue = await issueKey(app, { tenant_id: 'tenant-r1' });
    const oldKey = issue.body.api_key;

    const rot = await request(app)
      .post('/v1/keys/rotate')
      .set('Authorization', `Bearer ${oldKey}`)
      .send({});
    expect(rot.status).toBe(201);
    expect(rot.body.api_key).toMatch(/^sk-cogos-/);
    expect(rot.body.api_key).not.toBe(oldKey);
    expect(rot.body.rotated_from_key_id).toBe(issue.body.key_id);
    expect(rot.body.rotation_grace_until).toEqual(expect.any(String));
    expect(rot.body.expires_at).toBe(issue.body.expires_at); // parent's window
    expect(rot.body.tenant_id).toBe('tenant-r1');
    expect(rot.body.tier).toBe(issue.body.tier);

    // The NEW key authenticates with no deprecation header.
    const r1 = await request(app)
      .get('/v1/models')
      .set('Authorization', `Bearer ${rot.body.api_key}`);
    expect(r1.status).not.toBe(401);
    expect(r1.headers['x-cogos-key-deprecated']).toBeUndefined();

    // The OLD key still authenticates during grace AND carries the header.
    const r2 = await request(app)
      .get('/v1/models')
      .set('Authorization', `Bearer ${oldKey}`);
    expect(r2.status).not.toBe(401);
    expect(r2.headers['x-cogos-key-deprecated']).toMatch(/rotation_grace_until=/);
  });

  test('after grace window elapses, old key auto-revokes → 401 invalid_api_key', async () => {
    const app = freshApp();
    const issue = await issueKey(app, { tenant_id: 'tenant-r2' });
    const oldKey = issue.body.api_key;

    // Drive rotation through the route so the on-disk record is canonical.
    const rot = await request(app)
      .post('/v1/keys/rotate')
      .set('Authorization', `Bearer ${oldKey}`)
      .send({});
    expect(rot.status).toBe(201);

    // Manually fast-forward the on-disk record so grace is past.
    const keysFile = process.env.KEYS_FILE;
    const records = JSON.parse(fs.readFileSync(keysFile, 'utf8'));
    const oldRec = records.find((r) => r.id === issue.body.key_id);
    expect(oldRec.rotation_grace_until).toEqual(expect.any(Number));
    oldRec.rotation_grace_until = Date.now() - 1000; // 1s in the past
    fs.writeFileSync(keysFile, JSON.stringify(records, null, 2));

    // Auth with old key → 401 invalid_api_key (the auto-revoke flips
    // active=false; verify() returns null; bearerAuth emits the generic
    // invalid_api_key code).
    const r = await request(app)
      .get('/v1/models')
      .set('Authorization', `Bearer ${oldKey}`);
    expect(r.status).toBe(401);
    expect(r.body.error.type).toBe('invalid_api_key');

    // And the new key still works.
    const r2 = await request(app)
      .get('/v1/models')
      .set('Authorization', `Bearer ${rot.body.api_key}`);
    expect(r2.status).not.toBe(401);
  });

  test('rotation requires authentication with the OLD key (defense against future leaks)', async () => {
    const app = freshApp();
    // No Authorization header → 401, never reaches rotate().
    const res = await request(app).post('/v1/keys/rotate').send({});
    expect(res.status).toBe(401);
  });

  test('rotation grace inheritance: new key expires_at matches parent (no renewal)', async () => {
    const app = freshApp();
    const future = new Date(Date.now() + 30 * 60_000).toISOString();
    const issue = await issueKey(app, { tenant_id: 'tenant-r3', expires_at_iso: future });
    const rot = await request(app)
      .post('/v1/keys/rotate')
      .set('Authorization', `Bearer ${issue.body.api_key}`)
      .send({});
    expect(rot.status).toBe(201);
    expect(rot.body.expires_at).toBe(future);
  });

  test('rotation does not regenerate hmac_secret of old key + new key gets a fresh one', async () => {
    const app = freshApp();
    const issue = await issueKey(app, { tenant_id: 'tenant-r4' });
    const rot = await request(app)
      .post('/v1/keys/rotate')
      .set('Authorization', `Bearer ${issue.body.api_key}`)
      .send({});
    expect(rot.status).toBe(201);
    expect(typeof rot.body.hmac_secret).toBe('string');
    expect(rot.body.hmac_secret).not.toBe(issue.body.hmac_secret);
    expect(rot.body.hmac_secret.length).toBeGreaterThan(0);
  });
});
