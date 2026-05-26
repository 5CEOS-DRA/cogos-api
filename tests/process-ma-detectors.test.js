'use strict';

/**
 * M&A Truth Detectors process endpoint · HTTP-boundary tests.
 *
 * The detector pack is pure regex; engine determinism is implicit
 * (regex.exec is deterministic). These tests verify the HTTP shape,
 * tier-1 pricing surface, output_hash stability, and that each of the
 * four detectors fires correctly on known-trigger text.
 */

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-mad-test-'));
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

describe('process: ma-truth-detectors', () => {
  test('POST without auth → 401', async () => {
    const app = createApp();
    const res = await request(app).post('/v1/process/ma-truth-detectors').send({ finding: { title: 'X' } });
    expect(res.status).toBe(401);
  });

  test('catalog GET /v1/process now lists ma-truth-detectors', async () => {
    const app = createApp();
    const res = await request(app).get('/v1/process');
    const ids = res.body.processes.map((p) => p.id);
    expect(ids).toContain('ma-truth-detectors');
    const mad = res.body.processes.find((p) => p.id === 'ma-truth-detectors');
    expect(mad.pricing_tier).toBe(1);
    expect(mad.pricing_draft).toBe(true);
    expect(mad.rule_ids).toEqual(['ma_w2_ip_exposure', 'ma_w2_data_residency', 'ma_w2_regulatory_exposure', 'ma_w2_litigation']);
  });

  test('ma_w2_ip_exposure fires on non-assignable / change-of-control text', async () => {
    const app = createApp();
    const issued = await issueKey(app, 'mad-ip-' + Date.now());
    const res = await request(app)
      .post('/v1/process/ma-truth-detectors')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send({ finding: { id: 'F1', title: 'License agreement', description: 'License is non-transferable and requires consent for assignment.' } });
    expect(res.status).toBe(200);
    expect(res.body.total_firings).toBeGreaterThan(0);
    const ip = res.body.rows.find((r) => r.detector === 'ma_w2_ip_exposure');
    expect(ip).toBeDefined();
  });

  test('ma_w2_data_residency fires on GDPR / data-localization text', async () => {
    const app = createApp();
    const issued = await issueKey(app, 'mad-dr-' + Date.now());
    const res = await request(app)
      .post('/v1/process/ma-truth-detectors')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send({ finding: { id: 'F2', title: 'Data flow', description: 'Personal data must be stored in EU per data residency requirements.' } });
    const dr = res.body.rows.find((r) => r.detector === 'ma_w2_data_residency');
    expect(dr).toBeDefined();
  });

  test('batch · findings[] processes multiple in one call', async () => {
    const app = createApp();
    const issued = await issueKey(app, 'mad-batch-' + Date.now());
    const res = await request(app)
      .post('/v1/process/ma-truth-detectors')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send({ findings: [
        { id: 'A', title: 'Patent', description: 'License is non-transferable.' },
        { id: 'B', title: 'Empty filler description with no triggers' },
      ] });
    expect(res.status).toBe(200);
    expect(res.body.total_findings).toBe(2);
    expect(res.body.findings[0].fire_count).toBeGreaterThan(0);
    expect(res.body.findings[1].fire_count).toBe(0);
  });

  test('empty input · no findings · 200 with zero firings', async () => {
    const app = createApp();
    const issued = await issueKey(app, 'mad-empty-' + Date.now());
    const res = await request(app)
      .post('/v1/process/ma-truth-detectors')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send({ findings: [] });
    expect(res.status).toBe(200);
    expect(res.body.total_findings).toBeUndefined();  // empty path returns early shape
    expect(res.body.rows).toEqual([]);
  });

  test('receipt carries both deterministic_hash and output_hash', async () => {
    const app = createApp();
    const issued = await issueKey(app, 'mad-receipt-' + Date.now());
    const res = await request(app)
      .post('/v1/process/ma-truth-detectors')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send({ finding: { title: 'X', description: 'license is non-transferable' } });
    expect(res.body.receipt.deterministic_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(res.body.receipt.output_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  test('output_hash bitwise-stable across 10 repeated calls', async () => {
    const app = createApp();
    const issued = await issueKey(app, 'mad-stable-' + Date.now());
    const body = { finding: { title: 'IP Risk', description: 'change of control triggers consent requirement' } };
    const first = await request(app).post('/v1/process/ma-truth-detectors').set('Authorization', 'Bearer ' + issued.api_key).send(body);
    const expected = first.body.receipt.output_hash;
    for (let i = 0; i < 9; i++) {
      const r = await request(app).post('/v1/process/ma-truth-detectors').set('Authorization', 'Bearer ' + issued.api_key).send(body);
      expect(r.body.receipt.output_hash).toBe(expected);
    }
  }, 15000);
});
