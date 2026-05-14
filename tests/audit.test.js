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
