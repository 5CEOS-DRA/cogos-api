'use strict';

// HTTP-level tests for GET /v1/audit. Companion to tests/usage.test.js
// (the chain-mechanics unit tests).

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

let tmpDir;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-audit-test-'));
  process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
  process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
  jest.resetModules();
});

afterEach(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

function freshApp() {
  jest.resetModules();
  const { createApp } = require('../src/index');
  return createApp();
}
function freshUsage() {
  jest.resetModules();
  return require('../src/usage');
}

const request = require('supertest');

async function issueKey(app, tenantId, tier = 'starter') {
  const res = await request(app)
    .post('/admin/keys')
    .set('X-Admin-Key', process.env.ADMIN_KEY)
    .send({ tenant_id: tenantId, tier });
  return res.body;
}

describe('GET /v1/audit — auth', () => {
  test('missing bearer → 401', async () => {
    const app = freshApp();
    const res = await request(app).get('/v1/audit');
    expect(res.status).toBe(401);
  });

  test('wrong-prefix bearer → 401', async () => {
    const app = freshApp();
    const res = await request(app)
      .get('/v1/audit')
      .set('Authorization', 'Bearer sk-wrongprefix-deadbeef');
    expect(res.status).toBe(401);
  });
});

describe('GET /v1/audit — chain returned', () => {
  test('5 appended rows for tenant A — all returned, chain_ok true', async () => {
    const app = freshApp();
    const { api_key } = await issueKey(app, 'tenant-A');
    // Append via the usage module directly — exercises the chain code.
    const usage = freshUsage();
    for (let i = 0; i < 5; i += 1) {
      usage.record({ key_id: 'k', tenant_id: 'tenant-A', model: 'm', status: 'success' });
    }
    const res = await request(app)
      .get('/v1/audit')
      .set('Authorization', `Bearer ${api_key}`);
    expect(res.status).toBe(200);
    expect(res.body.rows.length).toBe(5);
    expect(res.body.chain_ok).toBe(true);
    expect(res.body.chain_break).toBeNull();
    expect(res.body.rows[0].prev_hash).toBe('0'.repeat(64));
    expect(res.body.server_time_ms).toEqual(expect.any(Number));
  });

  test('cross-tenant isolation — A only sees A, B only sees B', async () => {
    const app = freshApp();
    const a = await issueKey(app, 'tenant-A');
    const b = await issueKey(app, 'tenant-B');
    const usage = freshUsage();
    usage.record({ key_id: 'ka', tenant_id: 'tenant-A', model: 'm', status: 'success' });
    usage.record({ key_id: 'kb', tenant_id: 'tenant-B', model: 'm', status: 'success' });
    usage.record({ key_id: 'ka', tenant_id: 'tenant-A', model: 'm', status: 'success' });
    usage.record({ key_id: 'kb', tenant_id: 'tenant-B', model: 'm', status: 'success' });

    const aRes = await request(app)
      .get('/v1/audit')
      .set('Authorization', `Bearer ${a.api_key}`);
    const bRes = await request(app)
      .get('/v1/audit')
      .set('Authorization', `Bearer ${b.api_key}`);
    expect(aRes.body.rows.length).toBe(2);
    expect(bRes.body.rows.length).toBe(2);
    aRes.body.rows.forEach((r) => expect(r.tenant_id).toBe('tenant-A'));
    bRes.body.rows.forEach((r) => expect(r.tenant_id).toBe('tenant-B'));
    expect(aRes.body.chain_ok).toBe(true);
    expect(bRes.body.chain_ok).toBe(true);
  });

  test('tampered row on disk → chain_ok false with broke_at_index', async () => {
    const app = freshApp();
    const { api_key } = await issueKey(app, 'tenant-A');
    const usage = freshUsage();
    for (let i = 0; i < 5; i += 1) {
      usage.record({ key_id: 'k', tenant_id: 'tenant-A', model: 'm', status: 'success' });
    }
    // Simulate file corruption: rewrite row index 2 with a different
    // status string but leave the original row_hash in place.
    const raw = fs.readFileSync(process.env.USAGE_FILE, 'utf8');
    const lines = raw.split('\n').filter((l) => l.trim());
    const row2 = JSON.parse(lines[2]);
    row2.status = 'tampered';
    lines[2] = JSON.stringify(row2);
    fs.writeFileSync(process.env.USAGE_FILE, lines.join('\n') + '\n');

    const res = await request(app)
      .get('/v1/audit')
      .set('Authorization', `Bearer ${api_key}`);
    expect(res.status).toBe(200);
    expect(res.body.rows.length).toBe(5);
    expect(res.body.chain_ok).toBe(false);
    expect(res.body.chain_break.broke_at_index).toBe(2);
    expect(res.body.chain_break.reason).toBe('row_hash_mismatch');
  });

  test('since= filter excludes earlier rows', async () => {
    const app = freshApp();
    const { api_key } = await issueKey(app, 'tenant-A');
    const usage = freshUsage();
    usage.record({ key_id: 'k', tenant_id: 'tenant-A', model: 'm', status: 'success' });
    await new Promise((r) => setTimeout(r, 10));
    const cutoff = Date.now();
    await new Promise((r) => setTimeout(r, 10));
    usage.record({ key_id: 'k', tenant_id: 'tenant-A', model: 'm', status: 'success' });
    usage.record({ key_id: 'k', tenant_id: 'tenant-A', model: 'm', status: 'success' });
    const res = await request(app)
      .get(`/v1/audit?since=${cutoff}`)
      .set('Authorization', `Bearer ${api_key}`);
    expect(res.status).toBe(200);
    expect(res.body.rows.length).toBe(2);
  });

  test('limit caps response and exposes next_cursor for pagination', async () => {
    const app = freshApp();
    const { api_key } = await issueKey(app, 'tenant-A');
    const usage = freshUsage();
    // Space rows by >1ms each so timestamps differ; pagination via
    // since=<ms> uses strict-greater-than semantics.
    for (let i = 0; i < 4; i += 1) {
      usage.record({ key_id: 'k', tenant_id: 'tenant-A', model: 'm', status: 'success' });
      await new Promise((r) => setTimeout(r, 5));
    }
    const res = await request(app)
      .get('/v1/audit?limit=2')
      .set('Authorization', `Bearer ${api_key}`);
    expect(res.status).toBe(200);
    expect(res.body.rows.length).toBe(2);
    expect(res.body.next_cursor).toEqual(expect.any(Number));
    // Second page
    const res2 = await request(app)
      .get(`/v1/audit?limit=2&since=${res.body.next_cursor}`)
      .set('Authorization', `Bearer ${api_key}`);
    expect(res2.body.rows.length).toBe(2);
  });

  test('limit > 1000 is clamped to 1000', async () => {
    const app = freshApp();
    const { api_key } = await issueKey(app, 'tenant-A');
    const usage = freshUsage();
    usage.record({ key_id: 'k', tenant_id: 'tenant-A', model: 'm', status: 'success' });
    const res = await request(app)
      .get('/v1/audit?limit=99999')
      .set('Authorization', `Bearer ${api_key}`);
    expect(res.status).toBe(200);
    expect(res.body.rows.length).toBe(1);
    // next_cursor is null because the slice didn't fill the (clamped) limit.
    expect(res.body.next_cursor).toBeNull();
  });

  test('negative since → 400', async () => {
    const app = freshApp();
    const { api_key } = await issueKey(app, 'tenant-A');
    const res = await request(app)
      .get('/v1/audit?since=-1')
      .set('Authorization', `Bearer ${api_key}`);
    expect(res.status).toBe(400);
  });

  test('negative limit → 400', async () => {
    const app = freshApp();
    const { api_key } = await issueKey(app, 'tenant-A');
    const res = await request(app)
      .get('/v1/audit?limit=-5')
      .set('Authorization', `Bearer ${api_key}`);
    expect(res.status).toBe(400);
  });

  test('empty audit log for new tenant — rows: [], chain_ok true', async () => {
    const app = freshApp();
    const { api_key } = await issueKey(app, 'tenant-fresh');
    const res = await request(app)
      .get('/v1/audit')
      .set('Authorization', `Bearer ${api_key}`);
    expect(res.status).toBe(200);
    expect(res.body.rows).toEqual([]);
    expect(res.body.chain_ok).toBe(true);
    expect(res.body.next_cursor).toBeNull();
  });
});

// ===========================================================================
// Multi-app namespace — per-(tenant, app_id) chain semantics.
// ===========================================================================
//
// Each app within a tenant runs an INDEPENDENT chain. The cross-app /v1/audit
// read returns rows interleaved by ts, but chain_ok_by_app reports per-app
// integrity. Scoped reads (?app_id=...) return one app's slice and a single
// chain verdict.
//
// Backward compat: a key issued WITHOUT app_id lands in app_id='_default',
// and rows persisted before the multi-app rollout (no app_id on disk) are
// surfaced under '_default' at read time so existing customers see no
// regression. The chain epoch boundary is documented in src/usage.js.
describe('GET /v1/audit — multi-app namespace', () => {
  test('per-(tenant, app) chains: two apps in tenant A each start at ZERO_HASH', async () => {
    const app = freshApp();
    // Issue one key per app — the gateway uses req.apiKey.app_id at
    // append time, but readSlice() filters by (tenant_id, app_id) so
    // the slice for app1 must be independent of app2 even though both
    // belong to the same tenant.
    const app1Key = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'tenant-A', app_id: 'app1' });
    const app2Key = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'tenant-A', app_id: 'app2' });
    expect(app1Key.body.app_id).toBe('app1');
    expect(app2Key.body.app_id).toBe('app2');

    const usage = freshUsage();
    usage.record({ key_id: 'k1', tenant_id: 'tenant-A', app_id: 'app1', model: 'm', status: 'success' });
    usage.record({ key_id: 'k2', tenant_id: 'tenant-A', app_id: 'app2', model: 'm', status: 'success' });
    usage.record({ key_id: 'k1', tenant_id: 'tenant-A', app_id: 'app1', model: 'm', status: 'success' });
    usage.record({ key_id: 'k2', tenant_id: 'tenant-A', app_id: 'app2', model: 'm', status: 'success' });

    // Scoped read on app1 — only app1 rows, chain starts at ZERO.
    const r1 = await request(app)
      .get('/v1/audit?app_id=app1')
      .set('Authorization', `Bearer ${app1Key.body.api_key}`);
    expect(r1.status).toBe(200);
    expect(r1.body.rows.length).toBe(2);
    r1.body.rows.forEach((r) => expect(r.app_id).toBe('app1'));
    expect(r1.body.rows[0].prev_hash).toBe('0'.repeat(64));
    expect(r1.body.rows[1].prev_hash).toBe(r1.body.rows[0].row_hash);
    expect(r1.body.chain_ok).toBe(true);
    expect(r1.body.chain_ok_by_app).toEqual({ app1: true });
    expect(r1.body.app_id).toBe('app1');

    // Scoped read on app2 — independent chain, also starts at ZERO.
    const r2 = await request(app)
      .get('/v1/audit?app_id=app2')
      .set('Authorization', `Bearer ${app2Key.body.api_key}`);
    expect(r2.status).toBe(200);
    expect(r2.body.rows.length).toBe(2);
    r2.body.rows.forEach((r) => expect(r.app_id).toBe('app2'));
    expect(r2.body.rows[0].prev_hash).toBe('0'.repeat(64));
    expect(r2.body.chain_ok).toBe(true);
    expect(r2.body.chain_ok_by_app).toEqual({ app2: true });
  });

  test('cross-app read interleaves rows but reports chain_ok_by_app per app', async () => {
    const app = freshApp();
    const k = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'tenant-A', app_id: 'app1' });
    const usage = freshUsage();
    // Interleave appends from two apps under the same tenant.
    usage.record({ key_id: 'k1', tenant_id: 'tenant-A', app_id: 'app1', model: 'm', status: 'success' });
    usage.record({ key_id: 'k2', tenant_id: 'tenant-A', app_id: 'app2', model: 'm', status: 'success' });
    usage.record({ key_id: 'k1', tenant_id: 'tenant-A', app_id: 'app1', model: 'm', status: 'success' });
    usage.record({ key_id: 'k2', tenant_id: 'tenant-A', app_id: 'app2', model: 'm', status: 'success' });

    // No app_id query — cross-app response.
    const res = await request(app)
      .get('/v1/audit')
      .set('Authorization', `Bearer ${k.body.api_key}`);
    expect(res.status).toBe(200);
    expect(res.body.rows.length).toBe(4);
    // app_id field on the response is null in cross-app mode.
    expect(res.body.app_id).toBeNull();
    // chain_ok_by_app has one entry per app present in the slice.
    expect(res.body.chain_ok_by_app).toEqual({ app1: true, app2: true });
    expect(res.body.chain_ok).toBe(true);
    // Rows still appear in ts order (the interleaved view the customer
    // asked for) — not grouped by app.
    const apps = res.body.rows.map((r) => r.app_id);
    expect(apps).toContain('app1');
    expect(apps).toContain('app2');
  });

  test('cross-tenant isolation preserved with multi-app: B cannot see A even with matching app_id', async () => {
    const app = freshApp();
    const aKey = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'tenant-A', app_id: 'shared' });
    const bKey = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'tenant-B', app_id: 'shared' });
    const usage = freshUsage();
    usage.record({ key_id: 'ka', tenant_id: 'tenant-A', app_id: 'shared', model: 'm', status: 'success' });
    usage.record({ key_id: 'kb', tenant_id: 'tenant-B', app_id: 'shared', model: 'm', status: 'success' });

    // B asks for app_id=shared. Must return ONLY tenant-B rows — the
    // app_id query param does NOT widen the tenant scope.
    const res = await request(app)
      .get('/v1/audit?app_id=shared')
      .set('Authorization', `Bearer ${bKey.body.api_key}`);
    expect(res.status).toBe(200);
    expect(res.body.rows.length).toBe(1);
    expect(res.body.rows[0].tenant_id).toBe('tenant-B');
  });

  test('keys with NO app_id default to "_default" and chain there', async () => {
    const app = freshApp();
    // Note: no app_id in the issue body — must default to _default.
    const k = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'tenant-A' });
    expect(k.body.app_id).toBe('_default');

    const usage = freshUsage();
    // Two rows persisted with no app_id (mimics the pre-multi-app
    // call sites). Reader projects them under _default.
    usage.record({ key_id: 'k1', tenant_id: 'tenant-A', model: 'm', status: 'success' });
    usage.record({ key_id: 'k1', tenant_id: 'tenant-A', model: 'm', status: 'success' });

    const res = await request(app)
      .get('/v1/audit')
      .set('Authorization', `Bearer ${k.body.api_key}`);
    expect(res.status).toBe(200);
    expect(res.body.rows.length).toBe(2);
    expect(res.body.chain_ok).toBe(true);
    expect(res.body.chain_ok_by_app).toEqual({ _default: true });
    res.body.rows.forEach((r) => expect(r.app_id).toBe('_default'));
  });

  test('app_id with invalid shape → 400 (slug-only, max 64 chars)', async () => {
    const app = freshApp();
    const { api_key } = await issueKey(app, 'tenant-A');
    const bad = await request(app)
      .get('/v1/audit?app_id=' + encodeURIComponent('NOT VALID'))
      .set('Authorization', `Bearer ${api_key}`);
    expect(bad.status).toBe(400);
    // Capital-letter rejection comes via the same normalizer.
    const bad2 = await request(app)
      .get('/v1/audit?app_id=Apps')
      .set('Authorization', `Bearer ${api_key}`);
    expect(bad2.status).toBe(400);
  });

  test('tampered row in one app does not falsely flag the other', async () => {
    const app = freshApp();
    const k = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'tenant-A', app_id: 'app1' });
    const usage = freshUsage();
    usage.record({ key_id: 'k1', tenant_id: 'tenant-A', app_id: 'app1', model: 'm', status: 'success' });
    usage.record({ key_id: 'k2', tenant_id: 'tenant-A', app_id: 'app2', model: 'm', status: 'success' });
    usage.record({ key_id: 'k1', tenant_id: 'tenant-A', app_id: 'app1', model: 'm', status: 'success' });
    usage.record({ key_id: 'k2', tenant_id: 'tenant-A', app_id: 'app2', model: 'm', status: 'success' });

    // Corrupt the app2 row by flipping status — leaves the row_hash
    // intact, so verifyChain catches the content mismatch.
    const raw = fs.readFileSync(process.env.USAGE_FILE, 'utf8');
    const lines = raw.split('\n').filter((l) => l.trim());
    const idx = lines.findIndex((l) => {
      const r = JSON.parse(l);
      return r.app_id === 'app2';
    });
    const row = JSON.parse(lines[idx]);
    row.status = 'tampered';
    lines[idx] = JSON.stringify(row);
    fs.writeFileSync(process.env.USAGE_FILE, lines.join('\n') + '\n');

    const res = await request(app)
      .get('/v1/audit')
      .set('Authorization', `Bearer ${k.body.api_key}`);
    expect(res.status).toBe(200);
    // app1 chain still OK; app2 chain is broken.
    expect(res.body.chain_ok_by_app.app1).toBe(true);
    expect(res.body.chain_ok_by_app.app2).toBe(false);
    expect(res.body.chain_ok).toBe(false);
    expect(res.body.chain_break.app_id).toBe('app2');
  });
});
