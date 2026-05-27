'use strict';

/**
 * GET /v1/viewports[/:id[/rows]] — Zone B viewport reads · HTTP boundary.
 *
 * Per Phase 2 acceptance criteria D (commands) + H (cross-tenant 404).
 *
 * Stub platform via local HTTP server; assert:
 *   - Unauthenticated → 401
 *   - Tenant from req.apiKey.tenant_id injected into query string
 *   - Platform 404 forwarded as 404 not_found (cross-tenant criterion H)
 *   - Platform 200 forwarded with Cache-Control passthrough
 *   - Platform 503 internal_auth_* mapped → 503 upstream_unavailable
 *   - Network errors → 503 with clean message
 */

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-v1-viewports';

const fs = require('fs');
const path = require('path');
const os = require('os');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-v1-viewports-'));
process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
process.env.COGOS_INTERNAL_HMAC_SECRET = 'test-internal-hmac-32chars-bbbbbb';

const http = require('http');
const request = require('supertest');
const { createApp } = require('../src/index');

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

describe('GET /v1/viewports · list', () => {
  test('unauthenticated → 401', async () => {
    const app = createApp();
    const res = await request(app).get('/v1/viewports');
    expect(res.status).toBe(401);
  });

  test('authenticated · tenant injected in path · happy path', async () => {
    let capturedUrl = null;
    const { server, baseUrl } = await startPlatformStub((req, res) => {
      capturedUrl = req.url;
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'max-age=60');
      res.end(JSON.stringify({ ok: true, viewports: [] }));
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const tenant = 'tenant-vp-' + Date.now();
      const issued = await issueKey(app, tenant);
      const res = await request(app)
        .get('/v1/viewports')
        .set('Authorization', 'Bearer ' + issued.api_key);
      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
      expect(res.headers['cache-control']).toBe('max-age=60');
      // The tenant slug for this test was minted via /admin/keys above;
      // the platform stub should have seen ?tenant=<slug>
      expect(capturedUrl).toMatch(/^\/api\/internal\/viewports\?tenant=/);
      expect(capturedUrl).toContain(encodeURIComponent(tenant));
    } finally {
      server.close();
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });

  test('list with --app filter forwarded', async () => {
    let capturedUrl = null;
    const { server, baseUrl } = await startPlatformStub((req, res) => {
      capturedUrl = req.url;
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ ok: true, viewports: [] }));
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const issued = await issueKey(app, 'tenant-vp-app-' + Date.now());
      const res = await request(app)
        .get('/v1/viewports?app=tasks')
        .set('Authorization', 'Bearer ' + issued.api_key);
      expect(res.status).toBe(200);
      expect(capturedUrl).toContain('app=tasks');
      // tenant query param must NOT be tunnel-able from outside (we strip & re-inject)
      const cnt = (capturedUrl.match(/tenant=/g) || []).length;
      expect(cnt).toBe(1);
    } finally {
      server.close();
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });

  test('client cannot override tenant query param', async () => {
    let capturedUrl = null;
    const { server, baseUrl } = await startPlatformStub((req, res) => {
      capturedUrl = req.url;
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ ok: true, viewports: [] }));
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const myTenant = 'tenant-vp-noclient-' + Date.now();
      const issued = await issueKey(app, myTenant);
      // Try to inject ?tenant=somebody-else; cogos-api must strip + re-inject
      const res = await request(app)
        .get('/v1/viewports?tenant=somebody-else')
        .set('Authorization', 'Bearer ' + issued.api_key);
      expect(res.status).toBe(200);
      expect(capturedUrl).toContain(encodeURIComponent(myTenant));
      expect(capturedUrl).not.toContain('somebody-else');
    } finally {
      server.close();
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });
});

describe('GET /v1/viewports/:id · inspect', () => {
  test('unauthenticated → 401', async () => {
    const app = createApp();
    const res = await request(app).get('/v1/viewports/abc');
    expect(res.status).toBe(401);
  });

  test('platform 404 forwarded as 404 (criterion H)', async () => {
    const { server, baseUrl } = await startPlatformStub((_req, res) => {
      res.statusCode = 404;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ ok: false, error: 'not_found' }));
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const issued = await issueKey(app, 'tenant-vp-404-' + Date.now());
      const res = await request(app)
        .get('/v1/viewports/00000000-0000-0000-0000-000000000001')
        .set('Authorization', 'Bearer ' + issued.api_key);
      expect(res.status).toBe(404);
      expect(res.body.error).toBe('not_found');
    } finally {
      server.close();
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });

  test('happy path · forwards Cache-Control: no-store', async () => {
    const viewportId = '00000000-0000-0000-0000-000000000001';
    const { server, baseUrl } = await startPlatformStub((req, res) => {
      expect(req.url).toContain(`/viewports/${viewportId}?tenant=`);
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'no-store');
      res.end(JSON.stringify({
        ok: true,
        viewport: { viewport_id: viewportId, name: 'tasks', status: 'active', sections: [] },
      }));
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const issued = await issueKey(app, 'tenant-vp-ok-' + Date.now());
      const res = await request(app)
        .get('/v1/viewports/' + viewportId)
        .set('Authorization', 'Bearer ' + issued.api_key);
      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
      expect(res.headers['cache-control']).toBe('no-store');
    } finally {
      server.close();
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });
});

describe('GET /v1/viewports/:id/rows · export', () => {
  test('unauthenticated → 401', async () => {
    const app = createApp();
    const res = await request(app).get('/v1/viewports/abc/rows');
    expect(res.status).toBe(401);
  });

  test('happy path · forwards joined response', async () => {
    const viewportId = '00000000-0000-0000-0000-000000000001';
    const { server, baseUrl } = await startPlatformStub((req, res) => {
      expect(req.url).toContain(`/viewports/${viewportId}/rows?tenant=`);
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({
        ok: true,
        viewport: { viewport_id: viewportId, name: 'tasks' },
        rows: [{ row_id: 'r1', row_data: { title: 'A' } }],
        row_count: 1,
      }));
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const issued = await issueKey(app, 'tenant-vp-exp-' + Date.now());
      const res = await request(app)
        .get('/v1/viewports/' + viewportId + '/rows')
        .set('Authorization', 'Bearer ' + issued.api_key);
      expect(res.status).toBe(200);
      expect(res.body.rows.length).toBe(1);
      expect(res.body.row_count).toBe(1);
    } finally {
      server.close();
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });
});

describe('upstream failure modes', () => {
  test('platform 401 internal_auth_* mapped → 503 upstream_unavailable', async () => {
    const { server, baseUrl } = await startPlatformStub((_req, res) => {
      res.statusCode = 401;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ ok: false, error: 'internal_auth_signature_invalid' }));
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const issued = await issueKey(app, 'tenant-vp-fail-' + Date.now());
      const res = await request(app)
        .get('/v1/viewports')
        .set('Authorization', 'Bearer ' + issued.api_key);
      expect(res.status).toBe(503);
      expect(res.body.error).toBe('upstream_unavailable');
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
      const issued = await issueKey(app, 'tenant-vp-conn-' + Date.now());
      const res = await request(app)
        .get('/v1/viewports')
        .set('Authorization', 'Bearer ' + issued.api_key);
      expect(res.status).toBe(503);
      expect(res.body.error.type).toBe('upstream_unavailable');
    } finally {
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });
});
