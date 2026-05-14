'use strict';

// Constant-time admin-key compare. The interesting cases are:
//   - correct key                       → 200/201
//   - same-length wrong bytes           → 401  (timingSafeEqual rejected)
//   - different-length wrong bytes      → 401  (length-check FIRST so
//                                                timingSafeEqual is never
//                                                called with mismatched
//                                                buffers — must NOT throw)
//   - missing header                    → 401
//
// We use the /admin/keys POST endpoint as the gate because it's the
// canonical admin-write surface. Bearer auth is untouched (already safe
// via hash lookup) and is not retested here.

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

// Isolate keys + usage files per test run so we don't poison neighbouring
// suites that share the same /tmp prefix.
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-auth-test-'));
process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');

const request = require('supertest');
const { createApp } = require('../src/index');

afterAll(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

describe('adminAuth: constant-time compare', () => {
  test('correct admin key → 201 (key issued)', async () => {
    const app = createApp();
    const res = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'denny', tier: 'starter' });
    expect(res.status).toBe(201);
    expect(res.body.api_key).toMatch(/^sk-cogos-/);
  });

  test('wrong admin key, SAME length → 401 (no throw)', async () => {
    const app = createApp();
    const expected = process.env.ADMIN_KEY;
    // Build a same-length string that differs in every byte position.
    const wrongSameLen = 'x'.repeat(expected.length);
    expect(wrongSameLen.length).toBe(expected.length);
    const res = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', wrongSameLen)
      .send({ tenant_id: 'denny' });
    expect(res.status).toBe(401);
    expect(res.body.error.message).toBe('Invalid admin key');
  });

  test('wrong admin key, DIFFERENT length → 401 (does NOT throw)', async () => {
    const app = createApp();
    // Both shorter and longer must be safe — timingSafeEqual throws on
    // mismatched buffer lengths, so the length-check must run FIRST.
    const shorter = 'short';
    const longer = process.env.ADMIN_KEY + '-extra-bytes-on-the-end';
    const shortRes = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', shorter)
      .send({ tenant_id: 'denny' });
    expect(shortRes.status).toBe(401);
    expect(shortRes.body.error.message).toBe('Invalid admin key');

    const longRes = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', longer)
      .send({ tenant_id: 'denny' });
    expect(longRes.status).toBe(401);
    expect(longRes.body.error.message).toBe('Invalid admin key');
  });

  test('missing admin key header → 401', async () => {
    const app = createApp();
    const res = await request(app)
      .post('/admin/keys')
      .send({ tenant_id: 'denny' });
    expect(res.status).toBe(401);
    expect(res.body.error.message).toBe('Invalid admin key');
  });
});
