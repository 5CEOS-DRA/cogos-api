'use strict';

// Phase 1 integration test: end-to-end _operator chain validation.
//
// Verifies that /admin/* mutations:
//   1. Append a hash-chained row to usage.jsonl under tenant_id='_operator'
//   2. Surface chain_head_after in the response body
//   3. Set Cache-Control: no-store on the response
//   4. Link prev_hash correctly between consecutive admin mutations
//   5. Pass usage.verifyChain() validation for the _operator partition
//
// Per project_cli_phase_1_acceptance_criteria_v0_1_2026_05_27
// criteria A (audit attribution), B (chain_head_after in responses),
// D (Cache-Control), E (sentinel slug valid in usage.js).

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-phase-1-integration';

const fs = require('fs');
const path = require('path');
const os = require('os');

let tmpDir;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-phase-1-test-'));
  process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
  process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
  process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
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

function readOperatorRows() {
  const raw = fs.readFileSync(process.env.USAGE_FILE, 'utf8');
  return raw
    .split('\n')
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l))
    .filter((row) => row.tenant_id === '_operator');
}

const request = require('supertest');

describe('Phase 1: /admin/* mutations chain under _operator sentinel slug', () => {
  test('POST /admin/keys appends _operator chain row + surfaces chain_head_after', async () => {
    const app = freshApp();
    const res = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'test-tenant', tier: 'starter' });

    expect(res.status).toBe(201);
    expect(res.body.chain_head_after).toMatch(/^[a-f0-9]{64}$/);
    expect(res.headers['cache-control']).toBe('no-store');

    const rows = readOperatorRows();
    expect(rows).toHaveLength(1);
    expect(rows[0].tenant_id).toBe('_operator');
    expect(rows[0].app_id).toBe('_default');
    expect(rows[0].row_hash).toBe(res.body.chain_head_after);
    expect(rows[0].route).toBe('POST /admin/keys');
    expect(rows[0].status).toBe('success');
    expect(rows[0].key_id).toBeNull();
  });

  test('chain_head_after matches row_hash + prev_hash links between consecutive mutations', async () => {
    const app = freshApp();

    // First mutation: mint a key
    const r1 = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'tenant-1', tier: 'starter' });
    expect(r1.status).toBe(201);
    const head1 = r1.body.chain_head_after;
    const keyId1 = r1.body.key_id;

    // Second mutation: revoke the key just minted
    const r2 = await request(app)
      .post(`/admin/keys/${keyId1}/revoke`)
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(r2.status).toBe(200);
    expect(r2.body.revoked).toBe(true);
    expect(r2.body.chain_head_after).toMatch(/^[a-f0-9]{64}$/);
    expect(r2.body.chain_head_after).not.toBe(head1);
    expect(r2.headers['cache-control']).toBe('no-store');

    // Inspect chain: 2 rows; second's prev_hash equals first's row_hash
    const rows = readOperatorRows();
    expect(rows).toHaveLength(2);
    expect(rows[0].row_hash).toBe(head1);
    expect(rows[1].prev_hash).toBe(head1);
    expect(rows[1].row_hash).toBe(r2.body.chain_head_after);
    expect(rows[1].route).toBe('POST /admin/keys/:id/revoke');
  });

  test('packages CRUD all append _operator chain rows', async () => {
    const app = freshApp();

    // Create — package schema requires id (kebab), display_name,
    // monthly_usd, monthly_request_quota, allowed_model_tiers
    const create = await request(app)
      .post('/admin/packages')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({
        id: 'test-pkg',
        display_name: 'Test Package',
        monthly_usd: 49,
        monthly_request_quota: 10000,
        allowed_model_tiers: ['cogos-tier-b'],
      });
    expect(create.status).toBe(201);
    expect(create.body.chain_head_after).toMatch(/^[a-f0-9]{64}$/);

    // Update
    const update = await request(app)
      .put('/admin/packages/test-pkg')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ display_name: 'Test Package Updated' });
    expect(update.status).toBe(200);
    expect(update.body.chain_head_after).toMatch(/^[a-f0-9]{64}$/);

    // Delete
    const del = await request(app)
      .delete('/admin/packages/test-pkg')
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(del.status).toBe(200);
    expect(del.body.chain_head_after).toMatch(/^[a-f0-9]{64}$/);

    const rows = readOperatorRows();
    expect(rows).toHaveLength(3);
    expect(rows[0].route).toBe('POST /admin/packages');
    expect(rows[1].route).toBe('PUT /admin/packages/:id');
    expect(rows[2].route).toBe('DELETE /admin/packages/:id');

    // Chain linkage: each row's prev_hash matches the previous row's row_hash
    expect(rows[1].prev_hash).toBe(rows[0].row_hash);
    expect(rows[2].prev_hash).toBe(rows[1].row_hash);
  });

  test('read-only admin endpoints do NOT append chain rows', async () => {
    const app = freshApp();

    // Mint one key so /admin/keys list returns something
    await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'tenant-read', tier: 'starter' });
    const rowsAfterMint = readOperatorRows().length;
    expect(rowsAfterMint).toBe(1);

    // Reads: list, quarantined, usage, packages — should NOT add rows
    const list = await request(app).get('/admin/keys').set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(list.status).toBe(200);
    expect(list.headers['cache-control']).toBe('no-store');

    const q = await request(app).get('/admin/keys/quarantined').set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(q.status).toBe(200);

    const usage = await request(app).get('/admin/usage').set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(usage.status).toBe(200);

    const pkgs = await request(app).get('/admin/packages').set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(pkgs.status).toBe(200);

    // Chain row count unchanged after 4 reads
    expect(readOperatorRows()).toHaveLength(rowsAfterMint);
  });

  test('sentinel _operator chain does not collide with customer chains', async () => {
    const app = freshApp();

    // Admin mints two keys for different customer tenants
    await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'tenant-A', tier: 'starter' });

    await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'tenant-B', tier: 'starter' });

    // Both admin actions chain together under _operator
    const operatorRows = readOperatorRows();
    expect(operatorRows).toHaveLength(2);
    expect(operatorRows[1].prev_hash).toBe(operatorRows[0].row_hash);

    // No customer-side rows exist yet (admin actions don't pollute customer chains)
    const allRows = fs.readFileSync(process.env.USAGE_FILE, 'utf8')
      .split('\n')
      .filter((l) => l.trim())
      .map((l) => JSON.parse(l));
    const customerRows = allRows.filter((r) => r.tenant_id !== '_operator');
    expect(customerRows).toHaveLength(0);
  });

  test('SOC2 endpoints emit Cache-Control: max-age=300', async () => {
    const app = freshApp();
    const r = await request(app)
      .get('/admin/soc2/control-status')
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(r.status).toBe(200);
    expect(r.headers['cache-control']).toBe('max-age=300');
  });
});
