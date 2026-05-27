'use strict';

/**
 * Zone C mutation proxy + chain anchoring · HTTP boundary tests.
 *
 * Per Phase 3 acceptance criteria F + H · charter v0.2 C-14.
 *
 * Covers:
 *   - Unauthenticated → 401 on all 4 verbs
 *   - Add: platform 201 → chain row written with mutation_type='add' ·
 *          row_version_after populated · chain_head_after returned
 *   - Add: platform 400 VALIDATION_FAILED forwarded · NO chain row
 *   - Update: chain row mutation_type='update' · row_version_before
 *             from request body · row_version_after from platform resp
 *   - Update: 409 CONFLICT forwarded · NO chain row
 *   - Delete: chain row mutation_type='delete' · row_version_before
 *             from ?expected_version query · row_version_after null
 *   - Import: chain row mutation_type='import' · single row per batch
 *   - Import: 413 PAYLOAD_TOO_LARGE forwarded · NO chain row
 *   - tenant query stripping (client can't tunnel cross-tenant)
 *   - Connection refused → 503 upstream_unavailable
 *   - Chain shape: verifyChain re-derives mutation row hash correctly
 */

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-zone-c-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-zone-c-'));
process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
process.env.COGOS_INTERNAL_HMAC_SECRET = 'test-internal-hmac-zone-c-aaaaaaa';

const http = require('http');
const request = require('supertest');
const { createApp } = require('../src/index');
const usage = require('../src/usage');

afterAll(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

async function issueKey(app, tenantId) {
  const res = await request(app)
    .post('/admin/keys')
    .set('X-Admin-Key', process.env.ADMIN_KEY)
    .send({ tenant_id: tenantId, tier: 'starter' });
  return res.body;
}

function startPlatformStub(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, baseUrl: `http://127.0.0.1:${port}` });
    });
  });
}

function chainRowsForTenant(tenantId) {
  if (!fs.existsSync(process.env.USAGE_FILE)) return [];
  return fs.readFileSync(process.env.USAGE_FILE, 'utf8')
    .split('\n').filter(Boolean).map(JSON.parse)
    .filter((r) => r.tenant_id === tenantId);
}

const VP = '00000000-0000-0000-0000-000000000001';
const ROW_ID = 'sha256:' + 'a'.repeat(64);

describe('Zone C · auth', () => {
  test('add unsigned → 401', async () => {
    const app = createApp();
    const r = await request(app).post(`/v1/viewports/${VP}/sections/tasks/rows`).send({ row: { x: 1 } });
    expect(r.status).toBe(401);
  });
  test('update unsigned → 401', async () => {
    const app = createApp();
    const r = await request(app).put(`/v1/viewports/${VP}/sections/tasks/rows/${ROW_ID}`).send({ row: {}, expected_version: 'sha256:v' });
    expect(r.status).toBe(401);
  });
  test('delete unsigned → 401', async () => {
    const app = createApp();
    const r = await request(app).delete(`/v1/viewports/${VP}/sections/tasks/rows/${ROW_ID}?expected_version=sha256:v`);
    expect(r.status).toBe(401);
  });
  test('import unsigned → 401', async () => {
    const app = createApp();
    const r = await request(app).post(`/v1/viewports/${VP}/sections/tasks/rows/import`).send({ rows: [] });
    expect(r.status).toBe(401);
  });
});

describe('Zone C · POST add', () => {
  test('happy path · chain row written · mutation_type=add', async () => {
    const { server, baseUrl } = await startPlatformStub((req, res) => {
      let body = ''; req.on('data', c => body += c); req.on('end', () => {
        res.statusCode = 201;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({
          ok: true, idempotent: false,
          row_id: ROW_ID, row_version: 'sha256:vNEW',
          section_id: 'tasks', viewport_id: VP,
          viewport_name: 'tasks', app_name: 'tasks',
        }));
      });
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const tenant = 'tenant-zc-add-' + Date.now();
      const issued = await issueKey(app, tenant);
      const before = chainRowsForTenant(tenant).length;
      const res = await request(app)
        .post(`/v1/viewports/${VP}/sections/tasks/rows`)
        .set('Authorization', 'Bearer ' + issued.api_key)
        .send({ row: { title: 'x' } });
      expect(res.status).toBe(201);
      expect(res.body.row_id).toBe(ROW_ID);
      expect(res.body.chain_head_after).toMatch(/^[a-f0-9]{64}$/);

      const after = chainRowsForTenant(tenant);
      expect(after.length).toBe(before + 1);
      const last = after[after.length - 1];
      expect(last.mutation_type).toBe('add');
      expect(last.viewport_id).toBe(VP);
      expect(last.section_id).toBe('tasks');
      expect(last.row_version_before).toBeNull();
      expect(last.row_version_after).toBe('sha256:vNEW');
      expect(last.app_id).toBe('tasks');  // partitioned by viewport's app
    } finally {
      server.close();
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });

  test('VALIDATION_FAILED forwarded · NO chain row', async () => {
    const { server, baseUrl } = await startPlatformStub((_req, res) => {
      res.statusCode = 400;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({
        ok: false, error: 'VALIDATION_FAILED',
        errors: [{ code: 'REQUIRED_FIELD_MISSING', field: 'title' }],
      }));
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const tenant = 'tenant-zc-vf-' + Date.now();
      const issued = await issueKey(app, tenant);
      const before = chainRowsForTenant(tenant).length;
      const res = await request(app)
        .post(`/v1/viewports/${VP}/sections/tasks/rows`)
        .set('Authorization', 'Bearer ' + issued.api_key)
        .send({ row: { /* missing title */ } });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('VALIDATION_FAILED');
      expect(chainRowsForTenant(tenant).length).toBe(before);
    } finally {
      server.close();
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });

  test('client cannot tunnel ?tenant — gets stripped + replaced', async () => {
    let capturedUrl = null;
    const { server, baseUrl } = await startPlatformStub((req, res) => {
      capturedUrl = req.url;
      let body = ''; req.on('data', c => body += c); req.on('end', () => {
        res.statusCode = 201;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({
          ok: true, row_id: ROW_ID, row_version: 'sha256:v',
          section_id: 'tasks', viewport_id: VP, app_name: 'tasks',
        }));
      });
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const tenant = 'tenant-zc-strip-' + Date.now();
      const issued = await issueKey(app, tenant);
      await request(app)
        .post(`/v1/viewports/${VP}/sections/tasks/rows?tenant=other-tenant`)
        .set('Authorization', 'Bearer ' + issued.api_key)
        .send({ row: { title: 'x' } });
      expect(capturedUrl).toContain(`tenant=${encodeURIComponent(tenant)}`);
      expect(capturedUrl).not.toContain('other-tenant');
    } finally {
      server.close();
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });
});

describe('Zone C · PUT update', () => {
  test('happy path · chain row mutation_type=update · before/after both set', async () => {
    const { server, baseUrl } = await startPlatformStub((_req, res) => {
      let body = ''; _req.on('data', c => body += c); _req.on('end', () => {
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({
          ok: true, row_id: ROW_ID, row_version: 'sha256:vAFTER',
          section_id: 'tasks', viewport_id: VP, app_name: 'tasks',
        }));
      });
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const tenant = 'tenant-zc-upd-' + Date.now();
      const issued = await issueKey(app, tenant);
      const res = await request(app)
        .put(`/v1/viewports/${VP}/sections/tasks/rows/${ROW_ID}`)
        .set('Authorization', 'Bearer ' + issued.api_key)
        .send({ row: { title: 'y' }, expected_version: 'sha256:vBEFORE' });
      expect(res.status).toBe(200);

      const rows = chainRowsForTenant(tenant);
      const last = rows[rows.length - 1];
      expect(last.mutation_type).toBe('update');
      expect(last.row_version_before).toBe('sha256:vBEFORE');
      expect(last.row_version_after).toBe('sha256:vAFTER');
    } finally {
      server.close();
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });

  test('409 CONFLICT forwarded · NO chain row', async () => {
    const { server, baseUrl } = await startPlatformStub((_req, res) => {
      let body = ''; _req.on('data', c => body += c); _req.on('end', () => {
        res.statusCode = 409;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({
          ok: false, error: 'CONFLICT', row_id: ROW_ID,
          expected_version: 'sha256:vSTALE',
          actual_version: 'sha256:vCURRENT',
          current_row: { title: 'current' },
        }));
      });
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const tenant = 'tenant-zc-conflict-' + Date.now();
      const issued = await issueKey(app, tenant);
      const before = chainRowsForTenant(tenant).length;
      const res = await request(app)
        .put(`/v1/viewports/${VP}/sections/tasks/rows/${ROW_ID}`)
        .set('Authorization', 'Bearer ' + issued.api_key)
        .send({ row: { title: 'y' }, expected_version: 'sha256:vSTALE' });
      expect(res.status).toBe(409);
      expect(res.body.error).toBe('CONFLICT');
      expect(res.body.actual_version).toBe('sha256:vCURRENT');
      expect(chainRowsForTenant(tenant).length).toBe(before);
    } finally {
      server.close();
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });
});

describe('Zone C · DELETE', () => {
  test('happy path · chain row mutation_type=delete · before from query', async () => {
    const { server, baseUrl } = await startPlatformStub((req, res) => {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({
        ok: true, deleted: true, row_id: ROW_ID,
        section_id: 'tasks', viewport_id: VP, app_name: 'tasks',
      }));
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const tenant = 'tenant-zc-del-' + Date.now();
      const issued = await issueKey(app, tenant);
      const res = await request(app)
        .delete(`/v1/viewports/${VP}/sections/tasks/rows/${ROW_ID}?expected_version=sha256:vBEFORE`)
        .set('Authorization', 'Bearer ' + issued.api_key);
      expect(res.status).toBe(200);

      const rows = chainRowsForTenant(tenant);
      const last = rows[rows.length - 1];
      expect(last.mutation_type).toBe('delete');
      expect(last.row_version_before).toBe('sha256:vBEFORE');
      expect(last.row_version_after).toBeNull();
    } finally {
      server.close();
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });
});

describe('Zone C · POST import', () => {
  test('happy path · single chain row per batch · mutation_type=import', async () => {
    const { server, baseUrl } = await startPlatformStub((req, res) => {
      let body = ''; req.on('data', c => body += c); req.on('end', () => {
        res.statusCode = 201;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({
          ok: true, total: 3, inserted: 3, deduped: 0,
          row_ids: [ROW_ID, ROW_ID, ROW_ID],
          viewport_id: VP, section_id: 'tasks', app_name: 'tasks',
        }));
      });
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const tenant = 'tenant-zc-imp-' + Date.now();
      const issued = await issueKey(app, tenant);
      const before = chainRowsForTenant(tenant).length;
      const res = await request(app)
        .post(`/v1/viewports/${VP}/sections/tasks/rows/import`)
        .set('Authorization', 'Bearer ' + issued.api_key)
        .send({ rows: [{ title: 'a' }, { title: 'b' }, { title: 'c' }] });
      expect(res.status).toBe(201);
      expect(res.body.inserted).toBe(3);

      const after = chainRowsForTenant(tenant);
      // SINGLE chain row per batch · NOT per-row
      expect(after.length).toBe(before + 1);
      expect(after[after.length - 1].mutation_type).toBe('import');
    } finally {
      server.close();
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });

  test('PAYLOAD_TOO_LARGE forwarded · NO chain row', async () => {
    const { server, baseUrl } = await startPlatformStub((_req, res) => {
      let body = ''; _req.on('data', c => body += c); _req.on('end', () => {
        res.statusCode = 413;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ ok: false, error: 'PAYLOAD_TOO_LARGE', cap: 1000 }));
      });
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const tenant = 'tenant-zc-2big-' + Date.now();
      const issued = await issueKey(app, tenant);
      const before = chainRowsForTenant(tenant).length;
      const res = await request(app)
        .post(`/v1/viewports/${VP}/sections/tasks/rows/import`)
        .set('Authorization', 'Bearer ' + issued.api_key)
        .send({ rows: [{ title: 'a' }] }); // platform will return 413
      expect(res.status).toBe(413);
      expect(res.body.error).toBe('PAYLOAD_TOO_LARGE');
      expect(chainRowsForTenant(tenant).length).toBe(before);
    } finally {
      server.close();
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });
});

describe('Zone C · verifyChain compatibility', () => {
  test('mutation chain row re-derives hash via canonicalMutationChainPayload', async () => {
    const { server, baseUrl } = await startPlatformStub((req, res) => {
      let body = ''; req.on('data', c => body += c); req.on('end', () => {
        res.statusCode = 201;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({
          ok: true, row_id: ROW_ID, row_version: 'sha256:vFRESH',
          section_id: 'tasks', viewport_id: VP, app_name: 'verifyApp',
        }));
      });
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const tenant = 'tenant-zc-verify-' + Date.now();
      const issued = await issueKey(app, tenant);
      await request(app)
        .post(`/v1/viewports/${VP}/sections/tasks/rows`)
        .set('Authorization', 'Bearer ' + issued.api_key)
        .send({ row: { title: 'x' } });

      // Read all rows under tenant + app and verifyChain
      const rows = chainRowsForTenant(tenant).filter((r) => r.app_id === 'verifyApp');
      expect(rows.length).toBeGreaterThan(0);
      const result = usage.verifyChain(rows);
      expect(result.ok).toBe(true);
    } finally {
      server.close();
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });
});

describe('Zone C · upstream failure', () => {
  test('connection refused → 503 upstream_unavailable', async () => {
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = 'http://127.0.0.1:1';
    try {
      const app = createApp();
      const tenant = 'tenant-zc-down-' + Date.now();
      const issued = await issueKey(app, tenant);
      const res = await request(app)
        .post(`/v1/viewports/${VP}/sections/tasks/rows`)
        .set('Authorization', 'Bearer ' + issued.api_key)
        .send({ row: { title: 'x' } });
      expect(res.status).toBe(503);
      expect(res.body.error.type).toBe('upstream_unavailable');
    } finally {
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });
});

// ─────────────────────────────────────────────────────────────────────
// GET /v1/viewports/:vid/sections/:section/rows/find · proxy
// ─────────────────────────────────────────────────────────────────────

describe('GET .../rows/find · proxy', () => {
  test('unauthenticated → 401', async () => {
    const app = createApp();
    const r = await request(app)
      .get(`/v1/viewports/${VP}/sections/tasks/rows/find?where=priority=high`);
    expect(r.status).toBe(401);
  });

  test('happy · forwards where + limit · injects tenant in signed path', async () => {
    let capturedUrl = null;
    const { server, baseUrl } = await startPlatformStub((req, res) => {
      capturedUrl = req.url;
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'no-store');
      res.end(JSON.stringify({
        ok: true, viewport_id: VP, section_id: 'tasks',
        viewport_name: 'tasks', app_name: 'tasks',
        where: { priority: 'high' },
        rows: [
          { id: 'r1', row: { title: 'A', priority: 'high' }, row_id_hash: 'sha256:1',
            row_version: 'sha256:v1', created_at: new Date(), updated_at: new Date() },
        ],
        count: 1, limit: 10, truncated: false,
      }));
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const tenant = 'tenant-find-' + Date.now();
      const issued = await issueKey(app, tenant);
      const res = await request(app)
        .get(`/v1/viewports/${VP}/sections/tasks/rows/find?where=priority%3Dhigh&limit=10`)
        .set('Authorization', 'Bearer ' + issued.api_key);
      expect(res.status).toBe(200);
      expect(res.body.count).toBe(1);
      expect(res.body.rows[0].row.priority).toBe('high');
      expect(res.headers['cache-control']).toBe('no-store');
      // tenant injected into the signed canonical path
      expect(capturedUrl).toContain(`tenant=${encodeURIComponent(tenant)}`);
      // where + limit forwarded
      expect(capturedUrl).toContain('where=priority%3Dhigh');
      expect(capturedUrl).toContain('limit=10');
    } finally {
      server.close();
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });

  test('client cannot override tenant in query · stripped + re-injected', async () => {
    let capturedUrl = null;
    const { server, baseUrl } = await startPlatformStub((req, res) => {
      capturedUrl = req.url;
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ ok: true, rows: [], count: 0 }));
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const myTenant = 'tenant-find-strip-' + Date.now();
      const issued = await issueKey(app, myTenant);
      await request(app)
        .get(`/v1/viewports/${VP}/sections/tasks/rows/find?tenant=other-tenant&where=x%3D1`)
        .set('Authorization', 'Bearer ' + issued.api_key);
      expect(capturedUrl).toContain(encodeURIComponent(myTenant));
      expect(capturedUrl).not.toContain('other-tenant');
    } finally {
      server.close();
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });

  test('platform 400 (where_required) forwarded as-is', async () => {
    const { server, baseUrl } = await startPlatformStub((_req, res) => {
      res.statusCode = 400;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ ok: false, error: 'where_required' }));
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const issued = await issueKey(app, 'tenant-find-noargs-' + Date.now());
      const res = await request(app)
        .get(`/v1/viewports/${VP}/sections/tasks/rows/find`)
        .set('Authorization', 'Bearer ' + issued.api_key);
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('where_required');
    } finally {
      server.close();
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });

  test('connection refused → 503', async () => {
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = 'http://127.0.0.1:1';
    try {
      const app = createApp();
      const issued = await issueKey(app, 'tenant-find-down-' + Date.now());
      const res = await request(app)
        .get(`/v1/viewports/${VP}/sections/tasks/rows/find?where=x%3D1`)
        .set('Authorization', 'Bearer ' + issued.api_key);
      expect(res.status).toBe(503);
    } finally {
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });
});
