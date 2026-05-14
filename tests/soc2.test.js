'use strict';

// SOC 2 evidence-collection endpoint tests.
//
// Verifies:
//   - GET /admin/soc2/evidence-bundle requires X-Admin-Key (401 without)
//   - Returns 200 with admin key + expected response shape
//   - No env var VALUES leak (asserts the response does NOT contain the
//     ADMIN_KEY value or other secret-shaped strings)
//   - GET /admin/soc2/control-status returns the parsed CSV as JSON
//
// Storage isolation per test via mkdtemp; admin key set on process.env so
// the adminAuth middleware finds it.

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long-secret-do-not-leak';

const fs = require('fs');
const path = require('path');
const os = require('os');

let tmpDir;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-soc2-test-'));
  process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
  process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
  process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
  process.env.ANOMALIES_FILE = path.join(tmpDir, 'anomalies.jsonl');
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

const request = require('supertest');

// =============================================================================
// Auth gating
// =============================================================================
describe('SOC 2 evidence endpoints — auth', () => {
  test('GET /admin/soc2/evidence-bundle without X-Admin-Key → 401', async () => {
    const app = freshApp();
    const res = await request(app).get('/admin/soc2/evidence-bundle');
    expect(res.status).toBe(401);
  });

  test('GET /admin/soc2/evidence-bundle with wrong X-Admin-Key → 401', async () => {
    const app = freshApp();
    const res = await request(app)
      .get('/admin/soc2/evidence-bundle')
      .set('X-Admin-Key', 'this-is-not-the-admin-key');
    expect(res.status).toBe(401);
  });

  test('GET /admin/soc2/control-status without X-Admin-Key → 401', async () => {
    const app = freshApp();
    const res = await request(app).get('/admin/soc2/control-status');
    expect(res.status).toBe(401);
  });

  test('GET /admin/soc2/control-status with wrong X-Admin-Key → 401', async () => {
    const app = freshApp();
    const res = await request(app)
      .get('/admin/soc2/control-status')
      .set('X-Admin-Key', 'this-is-not-the-admin-key');
    expect(res.status).toBe(401);
  });
});

// =============================================================================
// Evidence bundle — shape and content
// =============================================================================
describe('GET /admin/soc2/evidence-bundle — response shape', () => {
  test('200 with admin key and well-formed payload', async () => {
    const app = freshApp();
    const res = await request(app)
      .get('/admin/soc2/evidence-bundle')
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(res.status).toBe(200);
    expect(res.body).toBeDefined();
    expect(res.body.schema_version).toBe(1);
    expect(typeof res.body.captured_at).toBe('string');
  });

  test('response contains expected top-level keys', async () => {
    const app = freshApp();
    const res = await request(app)
      .get('/admin/soc2/evidence-bundle')
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(res.status).toBe(200);
    expect(res.body).toEqual(expect.objectContaining({
      schema_version: expect.any(Number),
      captured_at: expect.any(String),
      service: expect.any(Object),
      cosign: expect.any(Object),
      audit: expect.any(Object),
      admin_actions_recent: expect.any(Array),
      env_var_names: expect.any(Array),
    }));
  });

  test('service block carries name, version, uptime, node_version', async () => {
    const app = freshApp();
    const res = await request(app)
      .get('/admin/soc2/evidence-bundle')
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(res.body.service).toEqual(expect.objectContaining({
      name: 'cogos-api',
      version: expect.any(String),
      node_version: expect.any(String),
      uptime_s: expect.any(Number),
    }));
  });

  test('audit block carries chain_head_row_count and anomaly_log_row_count', async () => {
    const app = freshApp();
    const res = await request(app)
      .get('/admin/soc2/evidence-bundle')
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(res.body.audit).toEqual(expect.objectContaining({
      chain_head_row_count: expect.any(Number),
      anomaly_log_row_count: expect.any(Number),
    }));
    // Fresh app + tmpdir — no rows yet
    expect(res.body.audit.chain_head_row_count).toBe(0);
    expect(res.body.audit.anomaly_log_row_count).toBe(0);
  });

  test('env_var_names is a sorted string array of NAMES only — never values', async () => {
    const app = freshApp();
    const res = await request(app)
      .get('/admin/soc2/evidence-bundle')
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(Array.isArray(res.body.env_var_names)).toBe(true);
    // All entries are strings
    for (const name of res.body.env_var_names) {
      expect(typeof name).toBe('string');
    }
    // Sorted alphabetically (stable diffing across captures)
    const sorted = [...res.body.env_var_names].sort();
    expect(res.body.env_var_names).toEqual(sorted);
    // Includes our test ADMIN_KEY env var BY NAME
    expect(res.body.env_var_names).toContain('ADMIN_KEY');
  });

  test('CRITICAL: response body does NOT contain ADMIN_KEY VALUE', async () => {
    const app = freshApp();
    const res = await request(app)
      .get('/admin/soc2/evidence-bundle')
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(res.status).toBe(200);
    const stringified = JSON.stringify(res.body);
    // The literal value of process.env.ADMIN_KEY must not appear anywhere
    // in the serialized response. This is the no-env-value-leak invariant.
    expect(stringified).not.toContain(process.env.ADMIN_KEY);
  });

  test('CRITICAL: response body does NOT contain other secret-shaped env values', async () => {
    // Pollute the env with a recognizable secret-shaped value and verify it
    // does NOT appear in the response body. The endpoint must never serialize
    // env var values.
    const canary = 'CANARY-VALUE-DO-NOT-LEAK-9f8e7d6c5b4a';
    process.env.SOC2_TEST_CANARY = canary;
    try {
      const app = freshApp();
      const res = await request(app)
        .get('/admin/soc2/evidence-bundle')
        .set('X-Admin-Key', process.env.ADMIN_KEY);
      expect(res.status).toBe(200);
      const stringified = JSON.stringify(res.body);
      expect(stringified).not.toContain(canary);
      // But the NAME does appear — that's the contract
      expect(res.body.env_var_names).toContain('SOC2_TEST_CANARY');
    } finally {
      delete process.env.SOC2_TEST_CANARY;
    }
  });

  test('admin_actions_recent is bounded and most-recent-first', async () => {
    const app = freshApp();
    // Issue a few keys so the recap has something to project
    for (let i = 0; i < 3; i += 1) {
      const r = await request(app)
        .post('/admin/keys')
        .set('X-Admin-Key', process.env.ADMIN_KEY)
        .send({ tenant_id: `tenant-${i}`, tier: 'starter' });
      expect(r.status).toBe(201);
    }
    const res = await request(app)
      .get('/admin/soc2/evidence-bundle')
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(res.status).toBe(200);
    expect(res.body.admin_actions_recent.length).toBeGreaterThanOrEqual(3);
    expect(res.body.admin_actions_recent.length).toBeLessThanOrEqual(100);
    // Sorted descending by ts: each entry's ts >= the next entry's ts
    const tsValues = res.body.admin_actions_recent
      .map((e) => (e.ts ? Date.parse(e.ts) : 0));
    for (let i = 1; i < tsValues.length; i += 1) {
      expect(tsValues[i - 1]).toBeGreaterThanOrEqual(tsValues[i]);
    }
  });
});

// =============================================================================
// Control status — CSV parsed to JSON
// =============================================================================
describe('GET /admin/soc2/control-status — response shape', () => {
  test('200 with admin key and well-formed payload', async () => {
    const app = freshApp();
    const res = await request(app)
      .get('/admin/soc2/control-status')
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(res.status).toBe(200);
    expect(res.body.schema_version).toBe(1);
    expect(res.body.source_path).toBe('docs/soc2/control-mapping.csv');
    expect(typeof res.body.captured_at).toBe('string');
    expect(Array.isArray(res.body.columns)).toBe(true);
    expect(Array.isArray(res.body.rows)).toBe(true);
    expect(res.body.row_count).toBe(res.body.rows.length);
  });

  test('columns match expected schema', async () => {
    const app = freshApp();
    const res = await request(app)
      .get('/admin/soc2/control-status')
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(res.body.columns).toEqual([
      'tsc_id',
      'tsc_description',
      'our_control',
      'evidence_location',
      'status',
      'last_tested',
    ]);
  });

  test('rows include all six common-criteria categories at minimum', async () => {
    const app = freshApp();
    const res = await request(app)
      .get('/admin/soc2/control-status')
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    const tscIds = res.body.rows.map((r) => r.tsc_id);
    // Coverage assertion — these are the must-have CCs from the spec
    expect(tscIds).toEqual(expect.arrayContaining([
      'CC1.1', 'CC3.1', 'CC6.1', 'CC6.2', 'CC6.3',
      'CC7.1', 'CC7.2', 'CC7.3', 'CC8.1', 'CC9.2',
    ]));
    // Plus rows from the four other trust-service categories
    expect(tscIds.some((id) => id.startsWith('A1.'))).toBe(true);
    expect(tscIds.some((id) => id.startsWith('C1.'))).toBe(true);
    expect(tscIds.some((id) => id.startsWith('PI1.'))).toBe(true);
    expect(tscIds.some((id) => id.startsWith('P1.'))).toBe(true);
  });

  test('status_counts sums to row count', async () => {
    const app = freshApp();
    const res = await request(app)
      .get('/admin/soc2/control-status')
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    const totalFromCounts = Object.values(res.body.status_counts || {})
      .reduce((a, b) => a + b, 0);
    expect(totalFromCounts).toBe(res.body.row_count);
  });
});
