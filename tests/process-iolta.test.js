'use strict';

// Process Library v0.1 — IOLTA reconcile endpoint.
//
// Covers: contract shape (input/output), happy-path three-way match,
// commingling detection (negative client balance), divergence cases,
// auth, deterministic hash stability across syntactic noise, usage
// row emission per invocation.

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-process-test-'));
process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
process.env.HONEYPOTS_FILE = path.join(tmpDir, 'honeypots.jsonl');
process.env.RATE_LIMITS_FILE = path.join(tmpDir, 'rate-limits.jsonl');

const request = require('supertest');
const { createApp } = require('../src/index');
const procRouter = require('../src/routers/process');

afterAll(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

async function issueKey(app, tenantId = 'denny', tier = 'starter') {
  const res = await request(app)
    .post('/admin/keys')
    .set('X-Admin-Key', process.env.ADMIN_KEY)
    .send({ tenant_id: tenantId, tier });
  return res.body;
}

const balancedBody = {
  bank_balance_cents: 12500000,
  as_of_date: '2026-05-31',
  trust_ledger_rows: [
    { side: 'credit', amount_cents: 10000000, transaction_type: 'retainer_in' },
    { side: 'credit', amount_cents:  2500000, transaction_type: 'retainer_in' },
  ],
  client_sub_ledger_rows: [
    { client_contact_id: 'c-001', side: 'credit', amount_cents: 10000000, balance_after_cents: 10000000 },
    { client_contact_id: 'c-002', side: 'credit', amount_cents:  2500000, balance_after_cents:  2500000 },
  ],
};

describe('process: iolta-reconcile', () => {
  test('POST /v1/process/iolta-reconcile without auth → 401', async () => {
    const app = createApp();
    const res = await request(app).post('/v1/process/iolta-reconcile').send(balancedBody);
    expect(res.status).toBe(401);
  });

  test('POST /v1/process/iolta-reconcile · balanced ledger · three_way_match=true, can_close=true', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    const res = await request(app)
      .post('/v1/process/iolta-reconcile')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send(balancedBody);
    expect(res.status).toBe(200);
    expect(res.body.three_way_match).toBe(true);
    expect(res.body.can_close_period).toBe(true);
    expect(res.body.block_reason).toBeNull();
    expect(res.body.divergences).toEqual([]);
    expect(res.body.commingling_violations).toEqual([]);
    expect(res.body.receipt).toBeDefined();
    expect(typeof res.body.receipt.request_id).toBe('string');
    expect(res.body.receipt.request_id).toMatch(/^proc_/);
    expect(typeof res.body.receipt.ms).toBe('number');
    expect(res.body.receipt.deterministic_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(res.body.reconciler_version).toBe(1);
  });

  test('commingling case · sub-ledger goes negative · block_reason=commingling_block', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    const res = await request(app)
      .post('/v1/process/iolta-reconcile')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send({
        bank_balance_cents: 0,
        trust_ledger_rows: [],
        client_sub_ledger_rows: [
          { client_contact_id: 'c-001', side: 'credit', amount_cents: 1000, balance_after_cents: 1000 },
          { client_contact_id: 'c-001', side: 'debit',  amount_cents: 2000, balance_after_cents: -1000 },
        ],
      });
    expect(res.status).toBe(200);
    expect(res.body.three_way_match).toBe(false);  // bank 0 != sub_total -1000
    expect(res.body.can_close_period).toBe(false);
    expect(res.body.commingling_violations).toHaveLength(1);
    expect(res.body.commingling_violations[0].client_contact_id).toBe('c-001');
    expect(res.body.block_reason).toBe('commingling_block');
  });

  test('divergence case · bank vs ledger mismatch · block_reason=reconciliation_failed', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    const res = await request(app)
      .post('/v1/process/iolta-reconcile')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send({
        bank_balance_cents: 5000,
        trust_ledger_rows: [{ side: 'credit', amount_cents: 4000 }],
        client_sub_ledger_rows: [{ client_contact_id: 'c-001', side: 'credit', amount_cents: 4000 }],
      });
    expect(res.status).toBe(200);
    expect(res.body.three_way_match).toBe(false);
    expect(res.body.can_close_period).toBe(false);
    expect(res.body.commingling_violations).toEqual([]);
    expect(res.body.block_reason).toBe('reconciliation_failed');
    expect(res.body.divergences.length).toBeGreaterThan(0);
  });

  test('invalid input · bank_balance_cents is float · 400 invalid_request_error with receipt', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    const res = await request(app)
      .post('/v1/process/iolta-reconcile')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send({ bank_balance_cents: 1.5, trust_ledger_rows: [], client_sub_ledger_rows: [] });
    expect(res.status).toBe(400);
    expect(res.body.error.type).toBe('invalid_request_error');
    expect(res.body.error.code).toBe('invalid_input');
    // Even failed calls carry a receipt so customers can re-verify the
    // canonical hash off their exact request body.
    expect(res.body.receipt.deterministic_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  test('GET /v1/process · catalog endpoint · no auth · lists iolta-reconcile', async () => {
    const app = createApp();
    const res = await request(app).get('/v1/process');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.processes)).toBe(true);
    const iolta = res.body.processes.find((p) => p.id === 'iolta-reconcile');
    expect(iolta).toBeDefined();
    expect(iolta.status).toBe('available');
    expect(iolta.endpoint).toBe('/v1/process/iolta-reconcile');
  });

  test('GET /v1/process · catalog surfaces pricing fields with draft flag', async () => {
    const app = createApp();
    const res = await request(app).get('/v1/process');
    expect(res.status).toBe(200);
    // Every shipped process should advertise tier + USD + draft until
    // the operator confirms dollar amounts (see Process Library pricing
    // memo 2026-05-26). Don't strip pricing_draft without sign-off.
    for (const p of res.body.processes) {
      expect(typeof p.pricing_tier).toBe('number');
      expect([1, 2, 3]).toContain(p.pricing_tier);
      expect(typeof p.pricing_usd).toBe('number');
      expect(p.pricing_usd).toBeGreaterThan(0);
      expect(typeof p.pricing_label).toBe('string');
      expect(p.pricing_draft).toBe(true);
    }
  });

  test('deterministic hash · re-orders keys + reformats whitespace, hash stable', () => {
    const { canonicalize, sha256Hex } = procRouter._internal;
    const a = JSON.stringify(canonicalize({
      b: 2, a: 1, nested: { y: 'two', x: 'one' }, list: [1, 2, 3],
    }));
    const b = JSON.stringify(canonicalize({
      nested: { x: 'one', y: 'two' }, a: 1, list: [1, 2, 3], b: 2,
    }));
    expect(a).toBe(b);
    expect(sha256Hex(a)).toBe(sha256Hex(b));
  });

  test('deterministic hash · array order is preserved (semantically meaningful)', () => {
    const { canonicalize, sha256Hex } = procRouter._internal;
    const a = JSON.stringify(canonicalize({ list: [1, 2, 3] }));
    const b = JSON.stringify(canonicalize({ list: [3, 2, 1] }));
    expect(a).not.toBe(b);
    expect(sha256Hex(a)).not.toBe(sha256Hex(b));
  });

  test('usage row emitted per invocation · audit shows it back via /v1/audit', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    await request(app)
      .post('/v1/process/iolta-reconcile')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send(balancedBody);
    const audit = await request(app)
      .get('/v1/audit')
      .set('Authorization', 'Bearer ' + issued.api_key);
    expect(audit.status).toBe(200);
    const procRow = (audit.body.rows || []).find((r) => r.route === '/v1/process/iolta-reconcile');
    expect(procRow).toBeDefined();
    expect(procRow.model).toBe('process:iolta-reconcile-v1');
    expect(procRow.status).toBe('success');
  });
});
