'use strict';

/**
 * Phase 4 wedge 2: adminAuth dual-mode.
 *
 * Per Phase 4 acceptance criterion C + E.
 *
 * Covers:
 *   - Path 1 (legacy): X-Admin-Key valid → 2xx · X-Cogos-Key-Deprecated absent
 *     unless ADMIN_KEY_GRACE_UNTIL set
 *   - X-Admin-Key mismatch falls through to path 2 (so operators in
 *     transition can send both headers)
 *   - X-Admin-Key + ADMIN_KEY env missing → 503 misconfig
 *   - X-Admin-Key valid + past grace → 401 expired_admin_key
 *   - X-Admin-Key valid + inside grace → 2xx + X-Cogos-Key-Deprecated header
 *   - Path 2 (new): Bearer sk-cogos-* with tenant_type=operator → 2xx
 *   - Bearer sk-cogos-* with tenant_type=subscriber → 401 (no escalation)
 *   - Bearer sk-cogos-* invalid → 401
 *   - Neither path → 401 invalid_admin_credentials
 *   - Chain attribution: x-admin-key uses '_operator' sentinel;
 *     sk-cogos-operator uses actual tenant_id (per-operator attribution)
 */

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-phase-4-dual-mode-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

let tmpDir;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-phase-4-dm-test-'));
  process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
  process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
  process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
  delete process.env.ADMIN_KEY_GRACE_UNTIL;
  jest.resetModules();
});

afterEach(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  delete process.env.ADMIN_KEY_GRACE_UNTIL;
});

const request = require('supertest');

function freshApp() {
  jest.resetModules();
  process.env.ADMIN_KEY = 'test-admin-key-phase-4-dual-mode-very-long';
  const { createApp } = require('../src/index');
  return createApp();
}

async function mintOperatorKey(app, tenantId = 'denny') {
  // Mint via legacy X-Admin-Key so we have a real sk-cogos-* + tenant_type=operator
  const res = await request(app)
    .post('/admin/keys')
    .set('X-Admin-Key', process.env.ADMIN_KEY)
    .send({ tenant_id: tenantId, tier: 'starter', tenant_type: 'operator' });
  return res.body;
}

async function mintSubscriberKey(app, tenantId = 'acme') {
  const res = await request(app)
    .post('/admin/keys')
    .set('X-Admin-Key', process.env.ADMIN_KEY)
    .send({ tenant_id: tenantId, tier: 'starter' /* default subscriber */ });
  return res.body;
}

function operatorChainRows() {
  if (!fs.existsSync(process.env.USAGE_FILE)) return [];
  return fs.readFileSync(process.env.USAGE_FILE, 'utf8')
    .split('\n').filter(Boolean).map(JSON.parse)
    .filter((r) => r.tenant_id === '_operator');
}

function rowsForTenant(tenantId) {
  if (!fs.existsSync(process.env.USAGE_FILE)) return [];
  return fs.readFileSync(process.env.USAGE_FILE, 'utf8')
    .split('\n').filter(Boolean).map(JSON.parse)
    .filter((r) => r.tenant_id === tenantId);
}

describe('adminAuth · path 1 (legacy X-Admin-Key)', () => {
  test('valid X-Admin-Key → 200 + no deprecation header (no grace set)', async () => {
    const app = freshApp();
    const res = await request(app)
      .get('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(res.status).toBe(200);
    expect(res.headers['x-cogos-key-deprecated']).toBeUndefined();
  });

  test('X-Admin-Key inside grace → 200 + deprecation header', async () => {
    process.env.ADMIN_KEY_GRACE_UNTIL = new Date(Date.now() + 30 * 86_400_000).toISOString();
    const app = freshApp();
    const res = await request(app)
      .get('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(res.status).toBe(200);
    expect(res.headers['x-cogos-key-deprecated']).toMatch(/rotation_grace_until=/);
  });

  test('X-Admin-Key past grace → 401 expired_admin_key', async () => {
    process.env.ADMIN_KEY_GRACE_UNTIL = new Date(Date.now() - 86_400_000).toISOString();
    const app = freshApp();
    const res = await request(app)
      .get('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(res.status).toBe(401);
    expect(res.body.error.type).toBe('expired_admin_key');
  });

  test('X-Admin-Key + ADMIN_KEY env missing → 503 misconfig', async () => {
    const savedKey = process.env.ADMIN_KEY;
    const app = freshApp();
    delete process.env.ADMIN_KEY;
    try {
      const res = await request(app)
        .get('/admin/keys')
        .set('X-Admin-Key', 'whatever-anyway');
      expect(res.status).toBe(503);
    } finally {
      process.env.ADMIN_KEY = savedKey;
    }
  });

  test('X-Admin-Key mismatch falls through (and 401 if no path 2 header)', async () => {
    const app = freshApp();
    const res = await request(app)
      .get('/admin/keys')
      .set('X-Admin-Key', 'wrong-secret');
    expect(res.status).toBe(401);
    expect(res.body.error.type || res.body.error.message)
      .toMatch(/invalid_admin_credentials/);
  });

  test('chain attribution: x-admin-key writes to _operator sentinel', async () => {
    const app = freshApp();
    await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'some-tenant', tier: 'starter' });
    const rows = operatorChainRows();
    expect(rows.length).toBeGreaterThan(0);
    expect(rows[rows.length - 1].tenant_id).toBe('_operator');
    expect(rows[rows.length - 1].key_id).toBeNull();
  });
});

describe('adminAuth · path 2 (sk-cogos-* + tenant_type=operator)', () => {
  test('valid operator bearer → 200 + no deprecation header', async () => {
    const app = freshApp();
    const opKey = await mintOperatorKey(app, 'denny');
    const res = await request(app)
      .get('/admin/keys')
      .set('Authorization', 'Bearer ' + opKey.api_key);
    expect(res.status).toBe(200);
    expect(res.headers['x-cogos-key-deprecated']).toBeUndefined();
  });

  test('subscriber bearer rejected → 401 (no privilege escalation)', async () => {
    const app = freshApp();
    const subKey = await mintSubscriberKey(app, 'acme');
    const res = await request(app)
      .get('/admin/keys')
      .set('Authorization', 'Bearer ' + subKey.api_key);
    expect(res.status).toBe(401);
    expect(res.body.error.type).toBe('invalid_admin_credentials');
  });

  test('invalid bearer → 401', async () => {
    const app = freshApp();
    const res = await request(app)
      .get('/admin/keys')
      .set('Authorization', 'Bearer sk-cogos-nope');
    expect(res.status).toBe(401);
    expect(res.body.error.type).toBe('invalid_admin_credentials');
  });

  test('chain attribution: sk-cogos-operator writes per-operator tenant_id', async () => {
    const app = freshApp();
    const opKey = await mintOperatorKey(app, 'denny');
    // Issue a fresh key VIA the operator bearer (state-changing → chain row)
    const res = await request(app)
      .post('/admin/keys')
      .set('Authorization', 'Bearer ' + opKey.api_key)
      .send({ tenant_id: 'new-customer', tier: 'starter' });
    expect(res.status).toBe(201);
    // Per-operator chain row appears under 'denny', not '_operator'
    const dennyRows = rowsForTenant('denny');
    expect(dennyRows.length).toBeGreaterThan(0);
    const lastDenny = dennyRows[dennyRows.length - 1];
    expect(lastDenny.tenant_id).toBe('denny');
    expect(lastDenny.key_id).toBe(opKey.key_id);
    expect(lastDenny.route).toBe('POST /admin/keys');
  });
});

describe('adminAuth · neither path', () => {
  test('no headers at all → 401 invalid_admin_credentials', async () => {
    const app = freshApp();
    const res = await request(app).get('/admin/keys');
    expect(res.status).toBe(401);
    expect(res.body.error.type).toBe('invalid_admin_credentials');
  });
});
