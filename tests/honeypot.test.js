'use strict';

// Honeypot middleware tests.
//
// Two distinct guarantees we want to prove:
//   1. Scanner-target paths return canary-tagged responses (not 404).
//   2. The middleware does NOT shadow real routes — the landing page
//      and /v1/* still answer with their normal handlers.

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-hp-test-'));
process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
process.env.HONEYPOTS_FILE = path.join(tmpDir, 'honeypots.jsonl');

const request = require('supertest');
const { createApp } = require('../src/index');

afterAll(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

describe('honeypot middleware', () => {
  test('GET /.env → 200 with canary-tagged content', async () => {
    const app = createApp();
    const res = await request(app).get('/.env');
    expect(res.status).toBe(200);
    // Canary tokens should be unmissable in the body.
    expect(res.text).toMatch(/HONEYPOT|EXAMPLE/i);
  });

  test('GET /wp-admin → 200 with WordPress-flavored HTML', async () => {
    const app = createApp();
    const res = await request(app).get('/wp-admin');
    expect(res.status).toBe(200);
    expect(res.text.toLowerCase()).toMatch(/wordpress/);
  });

  test('GET /api/v0/foo → 401 invalid token', async () => {
    const app = createApp();
    const res = await request(app).get('/api/v0/foo');
    expect(res.status).toBe(401);
    // Body matches the OpenAI-style "invalid token" shape, JSON.
    expect(res.body).toEqual({ error: 'invalid token' });
  });

  test('GET /v1/models without auth still returns 401 (real route, not honeypot)', async () => {
    const app = createApp();
    const res = await request(app).get('/v1/models');
    // Real bearer-auth path: must NOT be a 200 honeypot body. The
    // shape here is the real cogos-api auth error.
    expect(res.status).toBe(401);
    expect(res.body.error && res.body.error.type).toBe('invalid_request_error');
  });

  test('GET / still returns the real landing page (not eaten)', async () => {
    const app = createApp();
    const res = await request(app).get('/');
    expect(res.status).toBe(200);
    // Landing page is real HTML — should not carry the honeypot canary.
    expect(res.text).not.toMatch(/HONEYPOT_TOKEN_REPORT_TO_SECURITY/);
  });

  // Pentest finding 2026-05-14: scanners try trivial path variations
  // (mixed-case, trailing slash) and were getting a real 404, leaking
  // signal. Normalize before lookup so the trap fires consistently.
  test.each([
    '/.ENV',
    '/.Env',
    '/.env/',
    '/WP-ADMIN',
    '/wp-Admin',
    '/Backup.SQL',
    '/.AWS/credentials',
    '/.Git/Config',
  ])('honeypot variant %s still trips the trap (200)', async (p) => {
    const app = createApp();
    const res = await request(app).get(p);
    expect(res.status).toBe(200);
  });

  test.each([
    '/API/v0/foo',
    '/api/V2/anything',
  ])('honeypot API-version variant %s returns 401', async (p) => {
    const app = createApp();
    const res = await request(app).get(p);
    expect(res.status).toBe(401);
  });

  // Persistence: every hit appends one structured row to HONEYPOTS_FILE
  // so /admin/analytics/honeypots can surface real time-series numbers.
  test('GET /.env appends a row to HONEYPOTS_FILE with the expected schema', async () => {
    // Start from a clean file — prior tests in this suite already hit
    // the same env-var-pointed location, so this assertion is about
    // SHAPE not COUNT.
    try { fs.unlinkSync(process.env.HONEYPOTS_FILE); } catch (_e) {}
    const app = createApp();
    const res = await request(app).get('/.env').set('User-Agent', 'curl/8.0');
    expect(res.status).toBe(200);
    expect(fs.existsSync(process.env.HONEYPOTS_FILE)).toBe(true);
    const lines = fs.readFileSync(process.env.HONEYPOTS_FILE, 'utf8')
      .split('\n')
      .filter((l) => l.trim());
    expect(lines.length).toBe(1);
    const row = JSON.parse(lines[0]);
    expect(typeof row.ts).toBe('string');
    expect(row.path).toBe('/.env');
    expect(row.normalized_path).toBe('/.env');
    expect(row.method).toBe('GET');
    expect(typeof row.ip).toBe('string');
    expect(row.ua).toBe('curl/8.0');
    expect(row.country).toBe(null);
  });
});
