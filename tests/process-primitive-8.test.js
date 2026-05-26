'use strict';

/**
 * Primitive 8 organizational-integrity check endpoint tests.
 *
 * Engine determinism is proven upstream
 * (5ceos-platform-internal/backend/tests/primitive-8-rules.test.js).
 * These tests verify the HTTP boundary: routing, auth, input contract,
 * receipt shape, output_hash determinism, and that both rules fire
 * correctly through the gateway.
 */

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-p8-test-'));
process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
process.env.HONEYPOTS_FILE = path.join(tmpDir, 'honeypots.jsonl');
process.env.RATE_LIMITS_FILE = path.join(tmpDir, 'rate-limits.jsonl');
process.env.STATE_DIR = path.join(tmpDir, 'state');

const request = require('supertest');
const { createApp } = require('../src/index');

afterAll(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

async function issueKey(app, tenantId, tier = 'starter') {
  const res = await request(app).post('/admin/keys').set('X-Admin-Key', process.env.ADMIN_KEY).send({ tenant_id: tenantId, tier });
  return res.body;
}

// Fixture: a contradiction cluster that will fire RULE_8_04 (>12
// contradictions, >=3 surfaces, within 14d window).
const NOW = '2026-05-26T10:00:00.000Z';
function makeContradictionClusterInputs() {
  const contradictions = [];
  const surfaces = ['email', 'doc', 'meeting'];
  for (let i = 0; i < 13; i++) {
    contradictions.push({
      id: `c-${i}`,
      surface: surfaces[i % 3],
      occurred_at: '2026-05-20T10:00:00.000Z',
    });
  }
  return { contradictions, now: NOW };
}

describe('process: primitive-8-integrity-check · HTTP boundary', () => {
  test('POST without auth → 401', async () => {
    const app = createApp();
    const res = await request(app).post('/v1/process/primitive-8-integrity-check').send({ contradictions: [], now: NOW });
    expect(res.status).toBe(401);
  });

  test('catalog GET /v1/process now lists primitive-8-integrity-check', async () => {
    const app = createApp();
    const res = await request(app).get('/v1/process');
    expect(res.status).toBe(200);
    const ids = res.body.processes.map((p) => p.id);
    expect(ids).toContain('primitive-8-integrity-check');
    const p8 = res.body.processes.find((p) => p.id === 'primitive-8-integrity-check');
    expect(p8.status).toBe('available');
    expect(p8.pricing_tier).toBe(1);
    expect(p8.pricing_draft).toBe(true);
    expect(p8.rule_ids).toEqual(['RULE_8_03', 'RULE_8_04']);
  });

  test('happy path · contradiction cluster fires RULE_8_04', async () => {
    const app = createApp();
    const issued = await issueKey(app, 'p8-cluster-' + Date.now());
    const res = await request(app)
      .post('/v1/process/primitive-8-integrity-check')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send(makeContradictionClusterInputs());
    expect(res.status).toBe(200);
    expect(res.body.rule_version).toBe(1);
    expect(res.body.total_rules).toBe(2);
    expect(Array.isArray(res.body.rules)).toBe(true);
    const r8_04 = res.body.rules.find((r) => r.rule_key === 'RULE_8_04');
    expect(r8_04.fired).toBe(true);
    expect(r8_04.severity).toBe('high');
    expect(r8_04.evidence.contradictions_in_window).toBe(13);
    expect(r8_04.evidence.surfaces_involved).toBe(3);
    expect(res.body.fired_count).toBe(1);
  });

  test('empty inputs · neither rule fires · clean response', async () => {
    const app = createApp();
    const issued = await issueKey(app, 'p8-empty-' + Date.now());
    const res = await request(app)
      .post('/v1/process/primitive-8-integrity-check')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send({ now: NOW });
    expect(res.status).toBe(200);
    expect(res.body.fired_count).toBe(0);
    expect(res.body.total_rules).toBe(2);
  });

  test('receipt carries both deterministic_hash and output_hash', async () => {
    const app = createApp();
    const issued = await issueKey(app, 'p8-receipt-' + Date.now());
    const res = await request(app)
      .post('/v1/process/primitive-8-integrity-check')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send(makeContradictionClusterInputs());
    expect(res.body.receipt.deterministic_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(res.body.receipt.output_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(res.body.receipt.deterministic_hash).not.toBe(res.body.receipt.output_hash);
  });

  test('output_hash bitwise-stable across 10 repeated calls', async () => {
    const app = createApp();
    const issued = await issueKey(app, 'p8-stable-' + Date.now());
    const body = makeContradictionClusterInputs();
    const first = await request(app).post('/v1/process/primitive-8-integrity-check').set('Authorization', 'Bearer ' + issued.api_key).send(body);
    const expected = first.body.receipt.output_hash;
    for (let i = 0; i < 9; i++) {
      const r = await request(app).post('/v1/process/primitive-8-integrity-check').set('Authorization', 'Bearer ' + issued.api_key).send(body);
      expect(r.body.receipt.output_hash).toBe(expected);
    }
  }, 15000);

  test('enabled_rules filter · only RULE_8_03 requested', async () => {
    const app = createApp();
    const issued = await issueKey(app, 'p8-filter-' + Date.now());
    const res = await request(app)
      .post('/v1/process/primitive-8-integrity-check')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send({ ...makeContradictionClusterInputs(), enabled_rules: ['RULE_8_03'] });
    expect(res.status).toBe(200);
    expect(res.body.total_rules).toBe(1);
    expect(res.body.rules[0].rule_key).toBe('RULE_8_03');
  });

  test('missing now · server-supplies + flags it', async () => {
    const app = createApp();
    const issued = await issueKey(app, 'p8-no-now-' + Date.now());
    const res = await request(app)
      .post('/v1/process/primitive-8-integrity-check')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send({ contradictions: [] });
    expect(res.status).toBe(200);
    expect(typeof res.body.server_supplied_now).toBe('string');
    expect(res.body.server_supplied_now).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  test('usage row tagged model=process:primitive-8-integrity-check-v1', async () => {
    const app = createApp();
    const issued = await issueKey(app, 'p8-usage-' + Date.now());
    await request(app).post('/v1/process/primitive-8-integrity-check').set('Authorization', 'Bearer ' + issued.api_key).send({ contradictions: [], now: NOW });
    const audit = await request(app).get('/v1/audit').set('Authorization', 'Bearer ' + issued.api_key);
    const procRow = (audit.body.rows || []).find((r) => r.route === '/v1/process/primitive-8-integrity-check');
    expect(procRow).toBeDefined();
    expect(procRow.model).toBe('process:primitive-8-integrity-check-v1');
    expect(procRow.status).toBe('success');
  });
});
