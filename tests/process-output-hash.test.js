'use strict';

/**
 * Process Library v0.2 · output_hash receipt field + bitwise stability
 * end-to-end through the HTTP boundary.
 *
 * These tests are the customer-facing proof of Canon I1 v0.2: every
 * /v1/process/* response now carries an output_hash on its receipt,
 * and that hash is identical across 100 repeated calls with the same
 * input, AND across input permutations that should yield the same
 * logical output.
 *
 * If these fail, the substrate's "same input → same output → same hash"
 * claim is broken end-to-end (not just at the engine layer).
 */

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-output-hash-test-'));
process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
process.env.HONEYPOTS_FILE = path.join(tmpDir, 'honeypots.jsonl');
process.env.RATE_LIMITS_FILE = path.join(tmpDir, 'rate-limits.jsonl');

const request = require('supertest');
const { createApp } = require('../src/index');

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

const ioltaInput = {
  bank_balance_cents: 12500000,
  as_of_date: '2026-05-31',
  trust_ledger_rows: [
    { side: 'credit', amount_cents: 10000000 },
    { side: 'credit', amount_cents:  2500000 },
  ],
  client_sub_ledger_rows: [
    { client_contact_id: 'c-001', side: 'credit', amount_cents: 10000000 },
    { client_contact_id: 'c-002', side: 'credit', amount_cents:  2500000 },
  ],
};

const conflictInput = {
  target_matter: { id: 'M_new', status: 'inquiry', practice_area: 'litigation' },
  target_parties: [
    { id: 'p1', party_role: 'client',  display_name: 'Bob',  effective_to: null },
    { id: 'p2', party_role: 'adverse', display_name: 'Acme', effective_to: null },
  ],
  firm_matters: [{ id: 'M_old', status: 'active', practice_area: 'corporate' }],
  parties_by_matter_id: {
    M_old: [{ id: 'p3', party_role: 'client', display_name: 'Acme', effective_to: null }],
  },
};

async function postProcess(app, apiKey, name, body) {
  return await request(app)
    .post(`/v1/process/${name}`)
    .set('Authorization', 'Bearer ' + apiKey)
    .send(body);
}

describe('process · receipt carries output_hash (v0.2)', () => {
  test('iolta-reconcile · receipt has output_hash in sha256:<hex> format', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    const r = await postProcess(app, issued.api_key, 'iolta-reconcile', ioltaInput);
    expect(r.status).toBe(200);
    expect(r.body.receipt.output_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  test('5law-conflict-check · receipt has output_hash in sha256:<hex> format', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    const r = await postProcess(app, issued.api_key, '5law-conflict-check', conflictInput);
    expect(r.status).toBe(200);
    expect(r.body.receipt.output_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  test('input_hash and output_hash are distinct (no accidental aliasing)', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    const r = await postProcess(app, issued.api_key, 'iolta-reconcile', ioltaInput);
    expect(r.body.receipt.deterministic_hash).not.toBe(r.body.receipt.output_hash);
  });
});

describe('process · output_hash bitwise stability end-to-end', () => {
  // Per-test repeat count kept low so daily-cap stays out of the way.
  // Engine-level 100-run bitwise stability is already covered by
  // platform-side backend/tests/5law-engine-output-stability.test.js.
  // What we're proving here is the HTTP boundary preserves the engine's
  // canonical bytes — 10 repeats is sufficient signal.
  test('iolta-reconcile · 10 repeated calls → identical output_hash', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    const first = await postProcess(app, issued.api_key, 'iolta-reconcile', ioltaInput);
    const expected = first.body.receipt.output_hash;
    for (let i = 0; i < 9; i++) {
      const r = await postProcess(app, issued.api_key, 'iolta-reconcile', ioltaInput);
      expect(r.body.receipt.output_hash).toBe(expected);
    }
  }, 15000);

  test('5law-conflict-check · 10 repeated calls → identical output_hash', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    const first = await postProcess(app, issued.api_key, '5law-conflict-check', conflictInput);
    const expected = first.body.receipt.output_hash;
    for (let i = 0; i < 9; i++) {
      const r = await postProcess(app, issued.api_key, '5law-conflict-check', conflictInput);
      expect(r.body.receipt.output_hash).toBe(expected);
    }
  }, 15000);

  test('iolta-reconcile · sub-ledger row reorder → same output_hash', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    const a = await postProcess(app, issued.api_key, 'iolta-reconcile', ioltaInput);
    const reordered = {
      ...ioltaInput,
      client_sub_ledger_rows: ioltaInput.client_sub_ledger_rows.slice().reverse(),
    };
    const b = await postProcess(app, issued.api_key, 'iolta-reconcile', reordered);
    expect(a.body.receipt.output_hash).toBe(b.body.receipt.output_hash);
  });

  test('5law-conflict-check · target_parties reorder → same output_hash', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    const a = await postProcess(app, issued.api_key, '5law-conflict-check', conflictInput);
    const reordered = {
      ...conflictInput,
      target_parties: conflictInput.target_parties.slice().reverse(),
    };
    const b = await postProcess(app, issued.api_key, '5law-conflict-check', reordered);
    expect(a.body.receipt.output_hash).toBe(b.body.receipt.output_hash);
  });

  test('deterministic_hash differs when input differs but logical output is same', async () => {
    // Reordering inputs DOES change canonical_input (arrays preserve
    // order); but the OUTPUT is the same because the engine canonicalizes
    // the result. This is the substrate's value prop: input order
    // matters for the receipt-of-receipt; engine result does not.
    const app = createApp();
    const issued = await issueKey(app);
    const a = await postProcess(app, issued.api_key, 'iolta-reconcile', ioltaInput);
    const reordered = {
      ...ioltaInput,
      client_sub_ledger_rows: ioltaInput.client_sub_ledger_rows.slice().reverse(),
    };
    const b = await postProcess(app, issued.api_key, 'iolta-reconcile', reordered);
    expect(a.body.receipt.deterministic_hash).not.toBe(b.body.receipt.deterministic_hash);
    expect(a.body.receipt.output_hash).toBe(b.body.receipt.output_hash);
  });
});
