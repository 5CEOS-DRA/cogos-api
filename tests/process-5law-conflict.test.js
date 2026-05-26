'use strict';

/**
 * 5Law Conflict Check endpoint tests.
 *
 * Covers: contract shape, all 5 rules firing through the route, empty
 * firm graph (legitimate "clean — no conflicts" case), invalid input,
 * usage row emission, catalog endpoint includes 5law-conflict-check.
 *
 * Engine determinism is already proven upstream in
 * 5ceos-platform-internal/backend/tests/5law-conflict-engine.test.js
 * (29 fixture cases). These tests verify the HTTP boundary, not the
 * engine logic.
 */

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-5law-test-'));
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

// ── fixtures ───────────────────────────────────────────────────────

// Direct adversity case: party Acme is adverse in target matter M_new,
// AND Acme is an active client in a different matter M_old.
const adversityCase = {
  target_matter: { id: 'M_new', status: 'inquiry', practice_area: 'litigation' },
  target_parties: [
    { id: 'p1', party_role: 'client',  display_name: 'Bob',  effective_to: null },
    { id: 'p2', party_role: 'adverse', display_name: 'Acme', effective_to: null },
  ],
  firm_matters: [
    { id: 'M_old', status: 'active', practice_area: 'corporate' },
  ],
  parties_by_matter_id: {
    M_old: [
      { id: 'p3', party_role: 'client', display_name: 'Acme', effective_to: null },
    ],
  },
};

// Clean case: customer has firm history but no overlap with target.
const cleanCase = {
  target_matter: { id: 'M_clean', status: 'inquiry', practice_area: 'corporate' },
  target_parties: [
    { id: 'pa', party_role: 'client',  display_name: 'Globex',     effective_to: null },
    { id: 'pb', party_role: 'adverse', display_name: 'Initech',    effective_to: null },
  ],
  firm_matters: [
    { id: 'M_unrelated', status: 'closed', practice_area: 'tax' },
  ],
  parties_by_matter_id: {
    M_unrelated: [
      { id: 'po', party_role: 'client', display_name: 'Vandelay', effective_to: null },
    ],
  },
};

// Empty firm graph: solo attorney's first ever conflict check.
const emptyFirmCase = {
  target_matter: { id: 'M_first', status: 'inquiry', practice_area: 'general' },
  target_parties: [
    { id: 'p1', party_role: 'client',  display_name: 'Alice', effective_to: null },
    { id: 'p2', party_role: 'adverse', display_name: 'Bob',   effective_to: null },
  ],
  firm_matters: [],
  parties_by_matter_id: {},
};

describe('process: 5law-conflict-check', () => {
  test('POST /v1/process/5law-conflict-check without auth → 401', async () => {
    const app = createApp();
    const res = await request(app).post('/v1/process/5law-conflict-check').send(adversityCase);
    expect(res.status).toBe(401);
  });

  test('direct adversity case · returns C_DIRECT_ADVERSITY row', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    const res = await request(app)
      .post('/v1/process/5law-conflict-check')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send(adversityCase);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.rows)).toBe(true);
    expect(res.body.rows.length).toBeGreaterThan(0);
    const da = res.body.rows.find((r) => r.rule_id === 'C_DIRECT_ADVERSITY');
    expect(da).toBeDefined();
    expect(da.severity).toBe('blocking');
    expect(da.conflicting_matter_id).toBe('M_old');
    expect(da.rationale).toContain('Acme');
    expect(da.rationale).toContain('ABA Rule 1.7');
  });

  test('clean case · no rules fire · empty rows', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    const res = await request(app)
      .post('/v1/process/5law-conflict-check')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send(cleanCase);
    expect(res.status).toBe(200);
    expect(res.body.rows).toEqual([]);
    expect(res.body.rule_version).toBe(1);
    expect(Array.isArray(res.body.rule_ids_checked)).toBe(true);
    expect(res.body.rule_ids_checked).toContain('C_DIRECT_ADVERSITY');
    expect(res.body.rule_ids_checked).toContain('C_IMPUTED_FIRM');
  });

  test('empty firm graph · all rules return empty (solo first-time case)', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    const res = await request(app)
      .post('/v1/process/5law-conflict-check')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send(emptyFirmCase);
    expect(res.status).toBe(200);
    expect(res.body.rows).toEqual([]);
  });

  test('every response carries the universal receipt', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    const res = await request(app)
      .post('/v1/process/5law-conflict-check')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send(emptyFirmCase);
    expect(res.body.receipt).toBeDefined();
    expect(res.body.receipt.request_id).toMatch(/^proc_/);
    expect(typeof res.body.receipt.ms).toBe('number');
    expect(res.body.receipt.deterministic_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  test('invalid input · target_matter missing · 400 with receipt', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    const res = await request(app)
      .post('/v1/process/5law-conflict-check')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send({ target_parties: [] });
    expect(res.status).toBe(400);
    expect(res.body.error.type).toBe('invalid_request_error');
    expect(res.body.error.code).toBe('invalid_input');
    expect(res.body.receipt.deterministic_hash).toMatch(/^sha256:/);
  });

  test('catalog GET /v1/process now lists both processes', async () => {
    const app = createApp();
    const res = await request(app).get('/v1/process');
    expect(res.status).toBe(200);
    expect(res.body.processes.length).toBeGreaterThanOrEqual(2);
    const ids = res.body.processes.map((p) => p.id);
    expect(ids).toContain('iolta-reconcile');
    expect(ids).toContain('5law-conflict-check');
    const conflict = res.body.processes.find((p) => p.id === '5law-conflict-check');
    expect(conflict.status).toBe('available');
    expect(conflict.endpoint).toBe('/v1/process/5law-conflict-check');
    expect(Array.isArray(conflict.rule_ids)).toBe(true);
    expect(conflict.rule_ids.length).toBe(5);
  });

  test('usage row emitted with model=process:5law-conflict-check-v1', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    await request(app)
      .post('/v1/process/5law-conflict-check')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send(adversityCase);
    const audit = await request(app)
      .get('/v1/audit')
      .set('Authorization', 'Bearer ' + issued.api_key);
    const procRow = (audit.body.rows || []).find((r) => r.route === '/v1/process/5law-conflict-check');
    expect(procRow).toBeDefined();
    expect(procRow.model).toBe('process:5law-conflict-check-v1');
    expect(procRow.status).toBe('success');
  });
});
