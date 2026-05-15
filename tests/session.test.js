'use strict';

// Tests for src/session.js — HMAC-signed customer dashboard cookie.
//
// Covers:
//   - sign + verify roundtrip with the same secret
//   - signature mismatch (different secret) → null
//   - expired session payload → null
//   - tampered payload bytes → null
//   - tampered signature bytes → null
//   - constant-time comparison length guard (short input → null, no throw)
//   - createSession + parseSession agree on the triple (tenant, key, app)
//   - Cookie header parser handles common shapes
//
// We pin the secret via COGOS_SESSION_SECRET so each test is hermetic;
// _test._reset() flushes the in-memory cache between describes.

process.env.NODE_ENV = 'test';

const fs = require('fs');
const path = require('path');
const os = require('os');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-session-test-'));
process.env.SESSION_SECRET_FILE = path.join(tmpDir, '.session-secret');

afterAll(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

const SECRET_A = '11'.repeat(32); // 64 hex chars
const SECRET_B = '22'.repeat(32);

describe('session — createSession + parseSession roundtrip', () => {
  let session;

  beforeEach(() => {
    process.env.COGOS_SESSION_SECRET = SECRET_A;
    jest.resetModules();
    session = require('../src/session');
    session._test._reset();
  });

  test('roundtrip preserves tenant_id, key_id, app_id', () => {
    const cookie = session.createSession({
      tenant_id: 'tenant-abc',
      key_id: 'key-uuid-1',
      app_id: '_default',
    });
    const parsed = session.parseSession(cookie);
    expect(parsed).not.toBeNull();
    expect(parsed.tenant_id).toBe('tenant-abc');
    expect(parsed.key_id).toBe('key-uuid-1');
    expect(parsed.app_id).toBe('_default');
    expect(typeof parsed.exp_ms).toBe('number');
    expect(parsed.exp_ms).toBeGreaterThan(Date.now());
  });

  test('cookie value is base64url.base64url (no slashes or plus signs)', () => {
    const cookie = session.createSession({
      tenant_id: 'tenant-abc',
      key_id: 'key-uuid-1',
      app_id: '_default',
    });
    expect(cookie).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  });

  test('createSetCookie produces flag string with HttpOnly + Secure + SameSite=Lax + Path=/dashboard + Max-Age=604800', () => {
    const cookie = session.createSession({
      tenant_id: 't', key_id: 'k', app_id: 'a',
    });
    const header = session.createSetCookie(cookie);
    expect(header).toMatch(/^cogos_session=/);
    expect(header).toContain('HttpOnly');
    expect(header).toContain('Secure');
    expect(header).toContain('SameSite=Lax');
    expect(header).toContain('Path=/dashboard');
    expect(header).toContain('Max-Age=604800');
  });

  test('clearSetCookie produces Max-Age=0 delete header', () => {
    const header = session.clearSetCookie();
    expect(header).toContain('cogos_session=');
    expect(header).toContain('Max-Age=0');
    expect(header).toContain('Path=/dashboard');
  });
});

describe('session — failure modes', () => {
  let session;

  beforeEach(() => {
    process.env.COGOS_SESSION_SECRET = SECRET_A;
    jest.resetModules();
    session = require('../src/session');
    session._test._reset();
  });

  test('cookie signed with a different secret → null', () => {
    const cookie = session.createSession({
      tenant_id: 't1', key_id: 'k1', app_id: 'a1',
    });
    // Switch the secret. _test._reset() drops the cached buffer so the
    // module re-reads COGOS_SESSION_SECRET on the next parse.
    process.env.COGOS_SESSION_SECRET = SECRET_B;
    session._test._reset();
    expect(session.parseSession(cookie)).toBeNull();
  });

  test('tampered payload byte → null', () => {
    const cookie = session.createSession({
      tenant_id: 't1', key_id: 'k1', app_id: 'a1',
    });
    const dot = cookie.indexOf('.');
    const payload = cookie.slice(0, dot);
    const sig = cookie.slice(dot + 1);
    // Flip the last character of the payload to a different base64url
    // alphabet character — keeps the alphabet check passing but
    // changes the payload bytes.
    const last = payload[payload.length - 1];
    const replacement = last === 'A' ? 'B' : 'A';
    const tampered = `${payload.slice(0, -1)}${replacement}.${sig}`;
    expect(session.parseSession(tampered)).toBeNull();
  });

  test('tampered signature byte → null', () => {
    const cookie = session.createSession({
      tenant_id: 't1', key_id: 'k1', app_id: 'a1',
    });
    const dot = cookie.indexOf('.');
    const payload = cookie.slice(0, dot);
    const sig = cookie.slice(dot + 1);
    const last = sig[sig.length - 1];
    const replacement = last === 'A' ? 'B' : 'A';
    const tampered = `${payload}.${sig.slice(0, -1)}${replacement}`;
    expect(session.parseSession(tampered)).toBeNull();
  });

  test('expired session → null', () => {
    // We can't easily backdate createSession (it uses Date.now()), but
    // we can mock the canonical builder by signing a payload ourselves
    // using the same secret. Forge a payload with exp_ms in the past
    // and sign it with the real secret to confirm parseSession rejects
    // on the expiration check (post-signature-verify).
    const crypto = require('crypto');
    const past = Date.now() - 60_000;
    const payloadJson = JSON.stringify({
      tenant_id: 't1', key_id: 'k1', app_id: 'a1', exp_ms: past,
    });
    const payloadBytes = Buffer.from(payloadJson, 'utf8');
    const secret = Buffer.from(SECRET_A, 'hex');
    const sig = crypto.createHmac('sha256', secret).update(payloadBytes).digest();
    const cookie = `${payloadBytes.toString('base64url')}.${sig.toString('base64url')}`;
    expect(session.parseSession(cookie)).toBeNull();
  });

  test('no dot separator → null', () => {
    expect(session.parseSession('abcdef')).toBeNull();
    expect(session.parseSession('')).toBeNull();
    expect(session.parseSession(null)).toBeNull();
    expect(session.parseSession(undefined)).toBeNull();
  });

  test('signature shorter than 32 bytes → null (length guard before timingSafeEqual)', () => {
    // payload-shaped valid base64url + signature that decodes to
    // fewer than 32 bytes. parseSession must not throw — the length
    // check must come first.
    const fakePayload = Buffer.from('{"x":1}', 'utf8').toString('base64url');
    const shortSig = Buffer.alloc(8).toString('base64url'); // 8 bytes
    const cookie = `${fakePayload}.${shortSig}`;
    expect(() => session.parseSession(cookie)).not.toThrow();
    expect(session.parseSession(cookie)).toBeNull();
  });

  test('payload with non-base64url chars → null', () => {
    expect(session.parseSession('not!base64.abc')).toBeNull();
  });

  test('payload that decodes to non-JSON → null', () => {
    const crypto = require('crypto');
    const garbage = Buffer.from('not json at all', 'utf8');
    const secret = Buffer.from(SECRET_A, 'hex');
    const sig = crypto.createHmac('sha256', secret).update(garbage).digest();
    const cookie = `${garbage.toString('base64url')}.${sig.toString('base64url')}`;
    expect(session.parseSession(cookie)).toBeNull();
  });

  test('payload missing tenant_id → null', () => {
    const crypto = require('crypto');
    const payloadJson = JSON.stringify({
      key_id: 'k1', app_id: 'a1', exp_ms: Date.now() + 60_000,
    });
    const payloadBytes = Buffer.from(payloadJson, 'utf8');
    const secret = Buffer.from(SECRET_A, 'hex');
    const sig = crypto.createHmac('sha256', secret).update(payloadBytes).digest();
    const cookie = `${payloadBytes.toString('base64url')}.${sig.toString('base64url')}`;
    expect(session.parseSession(cookie)).toBeNull();
  });
});

describe('session — parseCookieHeader', () => {
  let session;
  beforeEach(() => {
    process.env.COGOS_SESSION_SECRET = SECRET_A;
    jest.resetModules();
    session = require('../src/session');
    session._test._reset();
  });

  test('parses single cookie', () => {
    const out = session.parseCookieHeader('cogos_session=abc.def');
    expect(out.cogos_session).toBe('abc.def');
  });

  test('parses multiple cookies', () => {
    const out = session.parseCookieHeader('a=1; b=2; cogos_session=xyz');
    expect(out.a).toBe('1');
    expect(out.b).toBe('2');
    expect(out.cogos_session).toBe('xyz');
  });

  test('empty / missing header → {}', () => {
    expect(session.parseCookieHeader('')).toEqual({});
    expect(session.parseCookieHeader(null)).toEqual({});
    expect(session.parseCookieHeader(undefined)).toEqual({});
  });

  test('malformed pairs are skipped', () => {
    const out = session.parseCookieHeader('badPair; a=1; =empty; b=2');
    expect(out.a).toBe('1');
    expect(out.b).toBe('2');
    expect(Object.keys(out).sort()).toEqual(['a', 'b']);
  });

  test('first occurrence wins on duplicate names', () => {
    const out = session.parseCookieHeader('x=first; x=second');
    expect(out.x).toBe('first');
  });
});

describe('session — secret resolution source priority', () => {
  test('env secret wins over file', () => {
    process.env.COGOS_SESSION_SECRET = SECRET_A;
    // Write a different secret to disk; env must override.
    fs.writeFileSync(process.env.SESSION_SECRET_FILE, SECRET_B, { mode: 0o600 });
    jest.resetModules();
    const session = require('../src/session');
    session._test._reset();
    const hex = session._test._peekSecretHex();
    expect(hex).toBe(SECRET_A);
  });

  test('file used when env unset', () => {
    delete process.env.COGOS_SESSION_SECRET;
    fs.writeFileSync(process.env.SESSION_SECRET_FILE, SECRET_B, { mode: 0o600 });
    jest.resetModules();
    const session = require('../src/session');
    session._test._reset();
    expect(session._test._peekSecretHex()).toBe(SECRET_B);
  });

  test('generated when neither env nor file present', () => {
    delete process.env.COGOS_SESSION_SECRET;
    try { fs.unlinkSync(process.env.SESSION_SECRET_FILE); } catch (_e) {}
    jest.resetModules();
    const session = require('../src/session');
    session._test._reset();
    const hex = session._test._peekSecretHex();
    expect(hex).toMatch(/^[0-9a-f]{64}$/);
    // The secret should have been persisted for next boot.
    const onDisk = fs.readFileSync(process.env.SESSION_SECRET_FILE, 'utf8').trim();
    expect(onDisk).toBe(hex);
  });
});
