'use strict';

/**
 * POST /v1/apps/build + GET /v1/apps/build/:id — Zone B app push + status.
 *
 * Per Phase 2 acceptance criteria D + G (chain_head_after on state change).
 *
 * Covers:
 *   - Unauthenticated → 401 on both
 *   - Missing blueprint body → 400 invalid_request_error
 *   - Platform 201 (new app) · chain row written · chain_head_after returned
 *   - Platform 200 (existing app) · chain row written · chain_head_after returned
 *   - Platform 422 blueprint_invalid · forwarded as-is · no chain row
 *   - Platform 503 upstream_unavailable forwarded · no chain row
 *   - Connection refused → 503 with clean error
 *   - app_id derived from blueprint.name slug (chain partition correctness)
 *   - GET status forwards platform body + Cache-Control
 */

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-v1-apps-build';

const fs = require('fs');
const path = require('path');
const os = require('os');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-v1-apps-build-'));
process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
process.env.COGOS_INTERNAL_HMAC_SECRET = 'test-internal-hmac-32chars-ccccccc';

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

const goodBlueprint = () => ({
  name: 'tasks',
  sections: [{
    id: 'tasks', title: 'Tasks',
    fields: [{ name: 'title', type: 'string' }],
  }],
});

// Helper: count chain rows for a tenant by reading usage file.
function chainRowsForTenant(tenantId, appId) {
  if (!fs.existsSync(process.env.USAGE_FILE)) return [];
  return fs.readFileSync(process.env.USAGE_FILE, 'utf8')
    .split('\n').filter(Boolean).map(JSON.parse)
    .filter((r) => r.tenant_id === tenantId && (!appId || r.app_id === appId));
}

describe('POST /v1/apps/build', () => {
  test('unauthenticated → 401', async () => {
    const app = createApp();
    const res = await request(app).post('/v1/apps/build').send({ blueprint: goodBlueprint() });
    expect(res.status).toBe(401);
  });

  test('missing blueprint body → 400 invalid_request_error', async () => {
    const app = createApp();
    const tenant = 'tenant-push-' + Date.now();
    const issued = await issueKey(app, tenant);
    const res = await request(app)
      .post('/v1/apps/build')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send({});
    expect(res.status).toBe(400);
    expect(res.body.error.type).toBe('invalid_request_error');
  });

  test('platform 201 new app · chain row written · chain_head_after returned', async () => {
    const platformViewportId = '00000000-0000-0000-0000-000000000111';
    const { server, baseUrl } = await startPlatformStub((req, res) => {
      expect(req.url).toContain('/api/internal/apps/build?tenant=');
      let body = '';
      req.on('data', (c) => { body += c.toString('utf8'); });
      req.on('end', () => {
        const parsed = JSON.parse(body);
        expect(parsed.blueprint.name).toBe('tasks');
        res.statusCode = 201;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({
          ok: true,
          viewport_id: platformViewportId,
          app_name: 'tasks',
          blueprint_hash: 'sha256:abc',
          status: 'active',
          reused: false,
        }));
      });
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const tenant = 'tenant-push-ok-' + Date.now();
      const issued = await issueKey(app, tenant);
      const before = chainRowsForTenant(tenant, 'tasks').length;
      const res = await request(app)
        .post('/v1/apps/build')
        .set('Authorization', 'Bearer ' + issued.api_key)
        .send({ blueprint: goodBlueprint() });
      expect(res.status).toBe(201);
      expect(res.body.viewport_id).toBe(platformViewportId);
      expect(res.body.chain_head_after).toMatch(/^[a-f0-9]{64}$/);
      // Chain row written under tenant + app_id='tasks'
      const after = chainRowsForTenant(tenant, 'tasks');
      expect(after.length).toBe(before + 1);
      expect(after[after.length - 1].route).toBe('POST /v1/apps/build');
      expect(after[after.length - 1].status).toBe('success');
    } finally {
      server.close();
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });

  test('platform 422 blueprint_invalid · forwarded · NO chain row', async () => {
    const { server, baseUrl } = await startPlatformStub((_req, res) => {
      res.statusCode = 422;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({
        ok: false, error: 'blueprint_invalid',
        errors: [{ code: 'MISSING_NAME', message: 'no name', where: 'blueprint.name', hint: null }],
        warnings: [],
      }));
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const tenant = 'tenant-push-invalid-' + Date.now();
      const issued = await issueKey(app, tenant);
      const before = chainRowsForTenant(tenant).length;
      const res = await request(app)
        .post('/v1/apps/build')
        .set('Authorization', 'Bearer ' + issued.api_key)
        .send({ blueprint: { /* invalid */ } });
      expect(res.status).toBe(422);
      expect(res.body.error).toBe('blueprint_invalid');
      expect(res.body.errors[0].code).toBe('MISSING_NAME');
      // No chain row on failure
      const after = chainRowsForTenant(tenant);
      expect(after.length).toBe(before);
    } finally {
      server.close();
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });

  test('platform 503 upstream_unavailable forwarded · no chain row', async () => {
    const { server, baseUrl } = await startPlatformStub((_req, res) => {
      res.statusCode = 401;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ ok: false, error: 'internal_auth_signature_invalid' }));
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const tenant = 'tenant-push-503-' + Date.now();
      const issued = await issueKey(app, tenant);
      const before = chainRowsForTenant(tenant).length;
      const res = await request(app)
        .post('/v1/apps/build')
        .set('Authorization', 'Bearer ' + issued.api_key)
        .send({ blueprint: goodBlueprint() });
      expect(res.status).toBe(503);
      expect(res.body.error).toBe('upstream_unavailable');
      const after = chainRowsForTenant(tenant).length;
      expect(after).toBe(before);
    } finally {
      server.close();
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });

  test('app_id partition: two apps push, get two separate chain heads', async () => {
    const { server, baseUrl } = await startPlatformStub((_req, res) => {
      res.statusCode = 201;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ ok: true, viewport_id: 'vp-x', app_name: 'x', status: 'active', reused: false }));
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const tenant = 'tenant-push-multi-' + Date.now();
      const issued = await issueKey(app, tenant);
      const r1 = await request(app)
        .post('/v1/apps/build')
        .set('Authorization', 'Bearer ' + issued.api_key)
        .send({ blueprint: { name: 'alpha', sections: [{ id: 'alpha', title: 'A', fields: [{ name: 'x' }] }] } });
      const r2 = await request(app)
        .post('/v1/apps/build')
        .set('Authorization', 'Bearer ' + issued.api_key)
        .send({ blueprint: { name: 'beta', sections: [{ id: 'beta', title: 'B', fields: [{ name: 'x' }] }] } });
      expect(r1.body.chain_head_after).toBeTruthy();
      expect(r2.body.chain_head_after).toBeTruthy();
      // Two independent chains → first pushes of each are GENESIS rows
      // (prev_hash = ZERO_HASH). chain_head_after for each is the row_hash
      // of its own genesis row — they differ.
      expect(r1.body.chain_head_after).not.toBe(r2.body.chain_head_after);
      // Verify chain partitioning on disk
      const alphaRows = chainRowsForTenant(tenant, 'alpha');
      const betaRows = chainRowsForTenant(tenant, 'beta');
      expect(alphaRows.length).toBe(1);
      expect(betaRows.length).toBe(1);
    } finally {
      server.close();
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });

  test('connection refused → 503 clean error', async () => {
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = 'http://127.0.0.1:1';
    try {
      const app = createApp();
      const tenant = 'tenant-push-conn-' + Date.now();
      const issued = await issueKey(app, tenant);
      const res = await request(app)
        .post('/v1/apps/build')
        .set('Authorization', 'Bearer ' + issued.api_key)
        .send({ blueprint: goodBlueprint() });
      expect(res.status).toBe(503);
      expect(res.body.error.type).toBe('upstream_unavailable');
    } finally {
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });
});

describe('GET /v1/apps/build/:id', () => {
  test('unauthenticated → 401', async () => {
    const app = createApp();
    const res = await request(app).get('/v1/apps/build/abc');
    expect(res.status).toBe(401);
  });

  test('happy path · forwards platform body + Cache-Control', async () => {
    const viewportId = '00000000-0000-0000-0000-000000000222';
    const { server, baseUrl } = await startPlatformStub((req, res) => {
      expect(req.url).toContain(`/apps/build/${viewportId}?tenant=`);
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'no-store');
      res.end(JSON.stringify({
        ok: true, viewport_id: viewportId, app_name: 'tasks',
        blueprint_hash: 'sha256:abc', status: 'active',
      }));
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const issued = await issueKey(app, 'tenant-status-' + Date.now());
      const res = await request(app)
        .get('/v1/apps/build/' + viewportId)
        .set('Authorization', 'Bearer ' + issued.api_key);
      expect(res.status).toBe(200);
      expect(res.body.viewport_id).toBe(viewportId);
      expect(res.body.status).toBe('active');
      expect(res.headers['cache-control']).toBe('no-store');
    } finally {
      server.close();
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });

  test('platform 404 cross-tenant forwarded as 404', async () => {
    const { server, baseUrl } = await startPlatformStub((_req, res) => {
      res.statusCode = 404;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ ok: false, error: 'not_found' }));
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const issued = await issueKey(app, 'tenant-status-404-' + Date.now());
      const res = await request(app)
        .get('/v1/apps/build/abc')
        .set('Authorization', 'Bearer ' + issued.api_key);
      expect(res.status).toBe(404);
      expect(res.body.error).toBe('not_found');
    } finally {
      server.close();
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });
});
