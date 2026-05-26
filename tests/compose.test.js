'use strict';

/**
 * /v1/compose HTTP-boundary tests · multi-step deterministic workflow.
 *
 * Engine determinism is proven at the unit layer
 * (5ceos-platform-internal/backend/tests/substrate-compose.test.js, 21
 * cases). These tests prove the HTTP boundary preserves the chain
 * bitwise — same body[steps] across runs produces the same compose_hash
 * end-to-end.
 */

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-compose-test-'));
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
  const res = await request(app).post('/admin/keys').set('X-Admin-Key', process.env.ADMIN_KEY).send({ tenant_id: tenantId, tier });
  return res.body;
}

// ── Fixtures ────────────────────────────────────────────────────

const ioltaInput = {
  bank_balance_cents: 100,
  trust_ledger_rows: [{ side: 'credit', amount_cents: 100 }],
  client_sub_ledger_rows: [{ client_contact_id: 'c-1', side: 'credit', amount_cents: 100 }],
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

// ── Tests ──────────────────────────────────────────────────────

describe('compose · auth + shape', () => {
  test('POST /v1/compose without auth → 401', async () => {
    const app = createApp();
    const res = await request(app).post('/v1/compose').send({
      steps: [{ name: 'iolta-reconcile', args: ioltaInput }],
    });
    expect(res.status).toBe(401);
  });

  test('GET /v1/compose · catalog endpoint · no auth · lists composable processes', async () => {
    const app = createApp();
    const res = await request(app).get('/v1/compose');
    expect(res.status).toBe(200);
    expect(res.body.composition_version).toBe(1);
    expect(res.body.endpoint).toBe('/v1/compose');
    expect(Array.isArray(res.body.composable_processes)).toBe(true);
    expect(res.body.composable_processes).toContain('iolta-reconcile');
    expect(res.body.composable_processes).toContain('5law-conflict-check');
  });

  test('missing steps[] → 400 invalid_request_error with receipt', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    const res = await request(app)
      .post('/v1/compose')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send({});
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('invalid_input');
    expect(res.body.receipt.deterministic_hash).toMatch(/^sha256:/);
  });
});

describe('compose · happy-path single-step', () => {
  test('single-step composition over iolta-reconcile', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    const res = await request(app)
      .post('/v1/compose')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send({ steps: [{ name: 'iolta-reconcile', args: ioltaInput }] });
    expect(res.status).toBe(200);
    expect(res.body.composition_version).toBe(1);
    expect(res.body.workflow_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(res.body.compose_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(res.body.chain).toHaveLength(1);
    expect(res.body.chain[0].name).toBe('iolta-reconcile');
    expect(res.body.chain[0].prev_chain_hash).toBe(res.body.workflow_hash);
    expect(res.body.chain[0].chain_hash).toBe(res.body.compose_hash);
    expect(res.body.results[0].three_way_match).toBe(true);
    expect(res.body.receipt.request_id).toMatch(/^comp_/);
  });
});

describe('compose · happy-path two-step (no refs)', () => {
  test('IOLTA followed by 5Law · independent steps · chain hashes linked', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    const res = await request(app)
      .post('/v1/compose')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send({
        steps: [
          { name: 'iolta-reconcile', args: ioltaInput },
          { name: '5law-conflict-check', args: conflictInput },
        ],
      });
    expect(res.status).toBe(200);
    expect(res.body.chain).toHaveLength(2);
    expect(res.body.chain[1].prev_chain_hash).toBe(res.body.chain[0].chain_hash);
    expect(res.body.compose_hash).toBe(res.body.chain[1].chain_hash);
    expect(res.body.results[1].rows.length).toBeGreaterThan(0);
  });
});

describe('compose · determinism · bitwise stable end-to-end', () => {
  test('10 repeated calls of the same steps[] → identical compose_hash', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    const steps = [
      { name: 'iolta-reconcile', args: ioltaInput },
      { name: '5law-conflict-check', args: conflictInput },
    ];
    const first = await request(app).post('/v1/compose').set('Authorization', 'Bearer ' + issued.api_key).send({ steps });
    const expected = first.body.compose_hash;
    for (let i = 0; i < 9; i++) {
      const r = await request(app).post('/v1/compose').set('Authorization', 'Bearer ' + issued.api_key).send({ steps });
      expect(r.body.compose_hash).toBe(expected);
    }
  }, 15000);

  test('mutating ONE step arg propagates through the entire compose_hash', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    const a = await request(app).post('/v1/compose').set('Authorization', 'Bearer ' + issued.api_key).send({
      steps: [{ name: 'iolta-reconcile', args: ioltaInput }],
    });
    const b = await request(app).post('/v1/compose').set('Authorization', 'Bearer ' + issued.api_key).send({
      steps: [{ name: 'iolta-reconcile', args: { ...ioltaInput, bank_balance_cents: 99 } }],
    });
    expect(a.body.compose_hash).not.toBe(b.body.compose_hash);
    expect(a.body.workflow_hash).not.toBe(b.body.workflow_hash);
  });
});

describe('compose · failure semantics · partial chain visibility', () => {
  test('unknown process in steps[] → 400 with empty partial chain', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    const res = await request(app)
      .post('/v1/compose')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send({ steps: [{ name: 'nonexistent-process', args: {} }] });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('invalid_input');
    expect(res.body.error.failed_step).toBe(0);
    expect(res.body.partial_chain).toEqual([]);
  });

  test('mid-chain failure exposes partial chain + verifiable continuity', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    // First step succeeds (valid IOLTA); second step fails (bad input shape).
    const res = await request(app)
      .post('/v1/compose')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send({
        steps: [
          { name: 'iolta-reconcile', args: ioltaInput },
          { name: '5law-conflict-check', args: { /* missing target_matter */ } },
        ],
      });
    expect(res.status).toBe(400);
    expect(res.body.error.failed_step).toBe(1);
    expect(res.body.error.failed_step_name).toBe('5law-conflict-check');
    expect(res.body.partial_chain).toHaveLength(1);
    expect(res.body.partial_chain[0].name).toBe('iolta-reconcile');
    expect(res.body.partial_results).toHaveLength(1);
  });
});

describe('compose · usage row · one per composition (not per step)', () => {
  test('two-step composition records ONE usage row per composition (not per step)', async () => {
    // Fresh tenant so the audit log isolates this test's single call.
    const app = createApp();
    const issued = await issueKey(app, 'compose-usage-test-' + Date.now());
    await request(app).post('/v1/compose').set('Authorization', 'Bearer ' + issued.api_key).send({
      steps: [
        { name: 'iolta-reconcile', args: ioltaInput },
        { name: '5law-conflict-check', args: conflictInput },
      ],
    });
    const audit = await request(app).get('/v1/audit').set('Authorization', 'Bearer ' + issued.api_key);
    const composeRows = (audit.body.rows || []).filter((r) => r.route === '/v1/compose');
    expect(composeRows).toHaveLength(1);
    expect(composeRows[0].model).toBe('process:compose-v1');
    expect(composeRows[0].status).toBe('success');
    // No per-step rows · billing is one-per-composition by design.
    const processRows = (audit.body.rows || []).filter((r) => r.route && r.route.startsWith('/v1/process/'));
    expect(processRows).toHaveLength(0);
  });
});
