'use strict';

/**
 * GET /v1/intents — Zone B primitive catalog · HTTP-boundary tests.
 *
 * Per Phase 2 acceptance criterion D (Zone B CLI commands surface)
 * + project_cli_zone_b_artifact_doctrine_2026_05_27.
 *
 * Covers:
 *   - Unauthenticated request → 401 (customerAuth blocks)
 *   - Authenticated · platform 200 → forwards body + max-age=300
 *   - Authenticated · platform 503 upstream_unavailable → forwards as-is
 *   - Authenticated · platform connection error → 503 with clean message
 *
 * Platform endpoint stubbed via a local HTTP server. proxyToPlatform()
 * is the unit under test on the cogos-api side; full cross-side wire
 * compat lives on the platform repo's internal-intents.test.js.
 */

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-v1-intents';

const fs = require('fs');
const path = require('path');
const os = require('os');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-v1-intents-'));
process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
process.env.COGOS_INTERNAL_HMAC_SECRET = 'test-internal-hmac-32chars-aaaaaa';

const http = require('http');
const request = require('supertest');
const { createApp } = require('../src/index');

afterAll(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

async function issueKey(app, tenantId, tier = 'starter') {
  const res = await request(app)
    .post('/admin/keys')
    .set('X-Admin-Key', process.env.ADMIN_KEY)
    .send({ tenant_id: tenantId, tier });
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

describe('GET /v1/intents', () => {
  test('unauthenticated → 401', async () => {
    const app = createApp();
    const res = await request(app).get('/v1/intents');
    expect(res.status).toBe(401);
  });

  test('authenticated · platform 200 → forwards intents + max-age=300', async () => {
    const { server, baseUrl } = await startPlatformStub((req, res) => {
      expect(req.url).toBe('/api/internal/intents');
      expect(req.method).toBe('GET');
      expect(req.headers['x-cogos-internal-auth']).toMatch(/^[a-f0-9]{64}$/);
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({
        ok: true,
        intents: [
          { id: 'kanban', label: 'Kanban Board', layout: 'kanban' },
          { id: 'crm', label: 'CRM / Sales Pipeline', layout: 'dashboard' },
        ],
      }));
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const issued = await issueKey(app, 'tenant-intents-' + Date.now());
      const res = await request(app)
        .get('/v1/intents')
        .set('Authorization', 'Bearer ' + issued.api_key);
      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
      expect(Array.isArray(res.body.intents)).toBe(true);
      expect(res.body.intents.length).toBe(2);
      expect(res.headers['cache-control']).toBe('max-age=300');
    } finally {
      server.close();
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });

  test('platform 503 upstream_unavailable forwarded as-is (internal-auth failure mapped)', async () => {
    const { server, baseUrl } = await startPlatformStub((_req, res) => {
      // Platform returns 401 internal_auth_signature_invalid; proxyToPlatform
      // maps to 503 upstream_unavailable so subscriber never sees HMAC details.
      res.statusCode = 401;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ ok: false, error: 'internal_auth_signature_invalid' }));
    });
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = baseUrl;
    try {
      const app = createApp();
      const issued = await issueKey(app, 'tenant-intents-503-' + Date.now());
      const res = await request(app)
        .get('/v1/intents')
        .set('Authorization', 'Bearer ' + issued.api_key);
      expect(res.status).toBe(503);
      expect(res.body.ok).toBe(false);
      expect(res.body.error).toBe('upstream_unavailable');
    } finally {
      server.close();
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });

  test('platform connection refused → 503 with clean error', async () => {
    // Point at a port nobody listens on
    const oldBase = process.env.PLATFORM_INTERNAL_BASE;
    process.env.PLATFORM_INTERNAL_BASE = 'http://127.0.0.1:1';
    try {
      const app = createApp();
      const issued = await issueKey(app, 'tenant-intents-conn-' + Date.now());
      const res = await request(app)
        .get('/v1/intents')
        .set('Authorization', 'Bearer ' + issued.api_key);
      expect(res.status).toBe(503);
      expect(res.body.error.type).toBe('upstream_unavailable');
    } finally {
      if (oldBase) process.env.PLATFORM_INTERNAL_BASE = oldBase;
      else delete process.env.PLATFORM_INTERNAL_BASE;
    }
  });
});
