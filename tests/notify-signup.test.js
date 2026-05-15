'use strict';

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-notify-test-'));
process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
process.env.NOTIFY_SIGNUPS_FILE = path.join(tmpDir, 'notify-signups.jsonl');

const request = require('supertest');
const { createApp } = require('../src/index');
const notifySignup = require('../src/notify-signup');

afterAll(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

describe('notify-signup', () => {
  test('isValidEmail accepts common shapes, rejects garbage', () => {
    expect(notifySignup.isValidEmail('a@b.co')).toBe(true);
    expect(notifySignup.isValidEmail('first.last+tag@sub.example.com')).toBe(true);
    expect(notifySignup.isValidEmail('no-at-sign')).toBe(false);
    expect(notifySignup.isValidEmail('two@@signs.com')).toBe(false);
    expect(notifySignup.isValidEmail('')).toBe(false);
    expect(notifySignup.isValidEmail(null)).toBe(false);
    expect(notifySignup.isValidEmail('a'.repeat(260) + '@b.co')).toBe(false);
  });

  test('POST /notify-signup with valid email → 200 HTML + row persisted', async () => {
    const app = createApp();
    const res = await request(app)
      .post('/notify-signup')
      .type('form')
      .send({ email: 'foo@example.com' });
    expect(res.status).toBe(200);
    expect(res.text).toMatch(/on the list/i);
    expect(res.text).toContain('foo@example.com');
    const rows = notifySignup.list();
    expect(rows.find((r) => r.email === 'foo@example.com')).toBeTruthy();
  });

  test('POST /notify-signup with invalid email → 400', async () => {
    const app = createApp();
    const res = await request(app)
      .post('/notify-signup')
      .type('form')
      .send({ email: 'not-an-email' });
    expect(res.status).toBe(400);
    expect(res.text).toMatch(/did not look right/i);
  });

  test('GET /admin/notify-signups without admin key → 401', async () => {
    const app = createApp();
    const res = await request(app).get('/admin/notify-signups');
    expect(res.status).toBe(401);
  });

  test('GET /admin/notify-signups with admin key → JSON list', async () => {
    const app = createApp();
    await request(app).post('/notify-signup').type('form').send({ email: 'a@b.co' });
    const res = await request(app)
      .get('/admin/notify-signups')
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.signups)).toBe(true);
    expect(res.body.signups.some((r) => r.email === 'a@b.co')).toBe(true);
  });

  test('email is normalized to lowercase + trimmed', async () => {
    const app = createApp();
    await request(app)
      .post('/notify-signup')
      .type('form')
      .send({ email: '  MixedCase@Example.COM  ' });
    const rows = notifySignup.list();
    expect(rows.some((r) => r.email === 'mixedcase@example.com')).toBe(true);
  });
});
