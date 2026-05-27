'use strict';

/**
 * GET /v1/me · identity probe · Phase 4 wedge 3.
 *
 * Per Phase 4 acceptance criterion D.
 *
 * Covers:
 *   - Unauthenticated → 401
 *   - Subscriber key → tenant_type='subscriber'
 *   - Operator key → tenant_type='operator'
 *   - Legacy key (no tenant_type on disk) → reads as 'subscriber'
 *     via the read-time backfill (wedge 1)
 *   - Cache-Control: no-store (rotation/quarantine state mid-session)
 *   - No chain row written (read-only endpoint)
 */

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-phase-4-me-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

let tmpDir;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-phase-4-me-test-'));
  process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
  process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
  process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
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

async function mintKey(app, tenantId, tenantType) {
  const body = { tenant_id: tenantId, tier: 'starter' };
  if (tenantType) body.tenant_type = tenantType;
  const res = await request(app)
    .post('/admin/keys')
    .set('X-Admin-Key', process.env.ADMIN_KEY)
    .send(body);
  return res.body;
}

function chainRowCount() {
  if (!fs.existsSync(process.env.USAGE_FILE)) return 0;
  return fs.readFileSync(process.env.USAGE_FILE, 'utf8')
    .split('\n').filter(Boolean).length;
}

describe('GET /v1/me', () => {
  test('unauthenticated → 401', async () => {
    const app = freshApp();
    const res = await request(app).get('/v1/me');
    expect(res.status).toBe(401);
  });

  test('subscriber key → tenant_type=subscriber + full identity', async () => {
    const app = freshApp();
    const issued = await mintKey(app, 'acme-corp');
    const res = await request(app)
      .get('/v1/me')
      .set('Authorization', 'Bearer ' + issued.api_key);
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.tenant_id).toBe('acme-corp');
    expect(res.body.tenant_type).toBe('subscriber');
    expect(res.body.key_id).toBe(issued.key_id);
    expect(res.body.tier).toBe('starter');
    expect(res.body.scheme).toBe('bearer');
    expect(res.body.issued_at).toBeTruthy();
    expect(res.body.expires_at).toBeTruthy();
    expect(res.body.active).toBe(true);
    expect(res.body.rotation_grace).toBe(false);
  });

  test('operator key → tenant_type=operator', async () => {
    const app = freshApp();
    const issued = await mintKey(app, 'denny', 'operator');
    const res = await request(app)
      .get('/v1/me')
      .set('Authorization', 'Bearer ' + issued.api_key);
    expect(res.status).toBe(200);
    expect(res.body.tenant_id).toBe('denny');
    expect(res.body.tenant_type).toBe('operator');
  });

  test('legacy key on disk (no tenant_type field) → reads as subscriber', async () => {
    const app = freshApp();
    const issued = await mintKey(app, 'legacy-co');
    // Hand-strip tenant_type from on-disk record
    const arr = JSON.parse(fs.readFileSync(process.env.KEYS_FILE, 'utf8'));
    arr.forEach((r) => { delete r.tenant_type; });
    fs.writeFileSync(process.env.KEYS_FILE, JSON.stringify(arr));

    const res = await request(app)
      .get('/v1/me')
      .set('Authorization', 'Bearer ' + issued.api_key);
    expect(res.status).toBe(200);
    expect(res.body.tenant_type).toBe('subscriber');
  });

  test('Cache-Control: no-store', async () => {
    const app = freshApp();
    const issued = await mintKey(app, 'cache-test');
    const res = await request(app)
      .get('/v1/me')
      .set('Authorization', 'Bearer ' + issued.api_key);
    expect(res.status).toBe(200);
    expect(res.headers['cache-control']).toBe('no-store');
  });

  test('no chain row written (read-only endpoint)', async () => {
    const app = freshApp();
    const issued = await mintKey(app, 'no-chain');
    const before = chainRowCount();
    const res = await request(app)
      .get('/v1/me')
      .set('Authorization', 'Bearer ' + issued.api_key);
    expect(res.status).toBe(200);
    expect(chainRowCount()).toBe(before);
  });
});
