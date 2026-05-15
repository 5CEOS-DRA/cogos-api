'use strict';

// Tests for the /dashboard customer surface.
//
// Covers:
//   - GET /dashboard with no cookie → 200 HTML with login form
//   - GET /dashboard with valid cookie → 303 to /dashboard/home
//   - POST /dashboard/login with valid key → 303 + Set-Cookie + Location
//   - POST /dashboard/login with invalid key → 400 + form-with-error
//   - GET /dashboard/home without cookie → 302 to /dashboard?error=login_required
//   - GET /dashboard/home with valid cookie → 200 + html contains tenant_id
//   - POST /dashboard/keys/:id/revoke same-tenant → 303 + key.active=false
//   - POST /dashboard/keys/:id/revoke cross-tenant → 403
//   - POST /dashboard/keys/:id/revoke self → 303 to home?error=self_revoke
//   - POST /dashboard/logout → 303 + Set-Cookie deletion
//   - GET /dashboard/forgot → 200 HTML stub
//   - Cookie tamper → next request redirects to /dashboard?error=login_required

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';
process.env.COGOS_SESSION_SECRET = 'a1'.repeat(32);

const fs = require('fs');
const path = require('path');
const os = require('os');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-dash-test-'));
process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
process.env.STRIPE_EVENTS_FILE = path.join(tmpDir, 'stripe-events.json');
process.env.SESSION_SECRET_FILE = path.join(tmpDir, '.session-secret');
process.env.MAGIC_LINK_SECRET_FILE = path.join(tmpDir, '.magic-link-secret');
process.env.COGOS_MAGIC_LINK_SECRET = 'a1'.repeat(32);
process.env.ATTESTATION_KEY_FILE = path.join(tmpDir, 'attestation-key.pem');
process.env.DEK_FILE = path.join(tmpDir, '.dek');
process.env.OLLAMA_URL = 'http://ollama.test';
process.env.DEFAULT_MODEL = 'qwen2.5:3b-instruct';

const request = require('supertest');

afterAll(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

function resetState() {
  for (const file of [
    process.env.PACKAGES_FILE,
    process.env.KEYS_FILE,
    process.env.USAGE_FILE,
    process.env.STRIPE_EVENTS_FILE,
  ]) {
    try { fs.unlinkSync(file); } catch (_e) {}
  }
  jest.resetModules();
}

function seedPackages(records) {
  fs.writeFileSync(process.env.PACKAGES_FILE, JSON.stringify(records), { mode: 0o600 });
}

function defaultPackages() {
  return [{
    id: 'starter',
    display_name: 'Starter',
    description: '100K reqs/mo',
    monthly_usd: 25,
    monthly_request_quota: 100000,
    allowed_model_tiers: ['cogos-tier-b'],
    is_default: true,
    active: true,
    stripe_product_id: null,
    stripe_price_id: null,
    public_signup: false,
  }];
}

// Helper: extract the cogos_session cookie value from a Set-Cookie header.
function extractCookieValue(setCookieHeader) {
  if (!setCookieHeader) return null;
  const headers = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
  for (const h of headers) {
    const m = /cogos_session=([^;]+)/.exec(h);
    if (m && m[1]) return m[1];
  }
  return null;
}

// =============================================================================
describe('GET /dashboard — login form', () => {
  let app;
  beforeEach(() => {
    resetState();
    seedPackages(defaultPackages());
    app = require('../src/index').createApp();
  });

  test('no cookie → 200 HTML with paste-key form', async () => {
    const res = await request(app).get('/dashboard');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/html/);
    expect(res.text).toMatch(/Paste your API key/i);
    expect(res.text).toMatch(/<input[^>]*type="password"[^>]*name="api_key"/);
    expect(res.text).toMatch(/<form[^>]*action="\/dashboard\/login"[^>]*method="POST"/);
  });

  test('?error=invalid_api_key renders error block via closed map', async () => {
    const res = await request(app).get('/dashboard?error=invalid_api_key');
    expect(res.status).toBe(200);
    expect(res.text).toMatch(/not recognized/i);
  });

  test('?error=<unknown> does NOT reflect into the page', async () => {
    // Defense: the error map is closed; an unknown error code shouldn't
    // produce an error block at all (no oracle, no reflected XSS surface).
    const res = await request(app).get('/dashboard?error=%3Cscript%3E');
    expect(res.status).toBe(200);
    expect(res.text).not.toMatch(/<script>/);
  });
});

// =============================================================================
describe('POST /dashboard/login', () => {
  let app;
  let keys;
  let issued;

  beforeEach(() => {
    resetState();
    seedPackages(defaultPackages());
    app = require('../src/index').createApp();
    keys = require('../src/keys');
    issued = keys.issue({
      tenantId: 'tenant-login-test',
      app_id: '_default',
      scheme: 'bearer',
      label: 'login test',
    });
  });

  test('valid key → 303 + Set-Cookie + Location /dashboard/home', async () => {
    const res = await request(app)
      .post('/dashboard/login')
      .type('form')
      .send({ api_key: issued.plaintext });
    expect(res.status).toBe(303);
    expect(res.headers.location).toBe('/dashboard/home');
    const setCookie = res.headers['set-cookie'];
    expect(setCookie).toBeTruthy();
    const cookieHeader = Array.isArray(setCookie) ? setCookie.join('\n') : setCookie;
    expect(cookieHeader).toMatch(/cogos_session=[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/);
    expect(cookieHeader).toMatch(/HttpOnly/);
    expect(cookieHeader).toMatch(/Secure/);
    expect(cookieHeader).toMatch(/SameSite=Lax/);
    expect(cookieHeader).toMatch(/Path=\/dashboard/);
    expect(cookieHeader).toMatch(/Max-Age=604800/);
  });

  test('invalid key → 400 HTML with error block', async () => {
    const res = await request(app)
      .post('/dashboard/login')
      .type('form')
      .send({ api_key: 'sk-cogos-deadbeefdeadbeefdeadbeefdeadbeef' });
    expect(res.status).toBe(400);
    expect(res.text).toMatch(/not recognized/i);
  });

  test('missing api_key field → 400', async () => {
    const res = await request(app)
      .post('/dashboard/login')
      .type('form')
      .send({});
    expect(res.status).toBe(400);
    expect(res.text).toMatch(/not recognized/i);
  });

  test('revoked key → 400 (verify returns null)', async () => {
    keys.revoke(issued.record.id);
    const res = await request(app)
      .post('/dashboard/login')
      .type('form')
      .send({ api_key: issued.plaintext });
    expect(res.status).toBe(400);
    expect(res.text).toMatch(/not recognized/i);
  });
});

// =============================================================================
describe('GET /dashboard/home — session gating', () => {
  let app;
  let keys;
  let session;
  let issued;

  beforeEach(() => {
    resetState();
    seedPackages(defaultPackages());
    app = require('../src/index').createApp();
    keys = require('../src/keys');
    session = require('../src/session');
    session._test._reset();
    issued = keys.issue({
      tenantId: 'tenant-home-test',
      app_id: '_default',
      scheme: 'bearer',
      label: 'home test',
    });
  });

  test('no cookie → 302 to /dashboard?error=login_required', async () => {
    const res = await request(app).get('/dashboard/home');
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/dashboard?error=login_required');
  });

  test('valid cookie → 200 HTML containing tenant_id', async () => {
    // Mint a session for this issued key.
    const cookieValue = session.createSession({
      tenant_id: 'tenant-home-test',
      key_id: issued.record.id,
      app_id: '_default',
    });
    const res = await request(app)
      .get('/dashboard/home')
      .set('Cookie', `cogos_session=${cookieValue}`);
    expect(res.status).toBe(200);
    expect(res.text).toContain('tenant-home-test');
    // Keys table should list the issued key
    expect(res.text).toMatch(/<table/);
    // Current session row should be marked
    expect(res.text).toMatch(/\(this session\)/);
    // Audit table headers should be present even if empty
    expect(res.text).toMatch(/Audit/i);
  });

  test('tampered signature byte → 302 to /dashboard?error=login_required', async () => {
    const cookieValue = session.createSession({
      tenant_id: 'tenant-home-test',
      key_id: issued.record.id,
      app_id: '_default',
    });
    const dot = cookieValue.indexOf('.');
    const tampered = `${cookieValue.slice(0, dot + 1)}${
      cookieValue[dot + 1] === 'A' ? 'B' : 'A'
    }${cookieValue.slice(dot + 2)}`;
    const res = await request(app)
      .get('/dashboard/home')
      .set('Cookie', `cogos_session=${tampered}`);
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/dashboard?error=login_required');
  });

  test('cookie for a revoked key → 302 to login', async () => {
    const cookieValue = session.createSession({
      tenant_id: 'tenant-home-test',
      key_id: issued.record.id,
      app_id: '_default',
    });
    keys.revoke(issued.record.id);
    const res = await request(app)
      .get('/dashboard/home')
      .set('Cookie', `cogos_session=${cookieValue}`);
    expect(res.status).toBe(302);
  });
});

// =============================================================================
describe('POST /dashboard/keys/:id/revoke — cross-tenant defense', () => {
  let app;
  let keys;
  let session;
  let myKey;
  let theirKey;

  beforeEach(() => {
    resetState();
    seedPackages(defaultPackages());
    app = require('../src/index').createApp();
    keys = require('../src/keys');
    session = require('../src/session');
    session._test._reset();
    myKey = keys.issue({
      tenantId: 'tenant-A',
      app_id: '_default',
      scheme: 'bearer',
      label: 'mine',
    });
    theirKey = keys.issue({
      tenantId: 'tenant-B',
      app_id: '_default',
      scheme: 'bearer',
      label: 'theirs',
    });
  });

  function myCookie() {
    return session.createSession({
      tenant_id: 'tenant-A',
      key_id: myKey.record.id,
      app_id: '_default',
    });
  }

  test('revoking a same-tenant non-self key → 303 to home + key marked inactive', async () => {
    // Issue a second key in my tenant so I can revoke it without
    // touching the one my session is bound to.
    const otherMine = keys.issue({
      tenantId: 'tenant-A',
      app_id: '_default',
      scheme: 'bearer',
      label: 'also mine',
    });
    const res = await request(app)
      .post(`/dashboard/keys/${otherMine.record.id}/revoke`)
      .set('Cookie', `cogos_session=${myCookie()}`);
    expect(res.status).toBe(303);
    expect(res.headers.location).toBe('/dashboard/home');
    const reread = keys.findById(otherMine.record.id);
    expect(reread.active).toBe(false);
  });

  test('revoking a cross-tenant key → 403 + key STAYS active', async () => {
    const res = await request(app)
      .post(`/dashboard/keys/${theirKey.record.id}/revoke`)
      .set('Cookie', `cogos_session=${myCookie()}`);
    expect(res.status).toBe(403);
    const reread = keys.findById(theirKey.record.id);
    expect(reread.active).toBe(true);
  });

  test('revoking the session\'s own key → 303 + key STAYS active (self-revoke blocked)', async () => {
    const res = await request(app)
      .post(`/dashboard/keys/${myKey.record.id}/revoke`)
      .set('Cookie', `cogos_session=${myCookie()}`);
    expect(res.status).toBe(303);
    expect(res.headers.location).toBe('/dashboard/home?error=self_revoke');
    const reread = keys.findById(myKey.record.id);
    expect(reread.active).toBe(true);
  });

  test('revoking with no cookie → 302 to login', async () => {
    const res = await request(app)
      .post(`/dashboard/keys/${myKey.record.id}/revoke`);
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/dashboard?error=login_required');
  });

  test('revoking a nonexistent id → 303 (idempotent, no crash)', async () => {
    const res = await request(app)
      .post('/dashboard/keys/nonexistent-id/revoke')
      .set('Cookie', `cogos_session=${myCookie()}`);
    expect(res.status).toBe(303);
    expect(res.headers.location).toBe('/dashboard/home');
  });
});

// =============================================================================
describe('POST /dashboard/keys/rotate', () => {
  let app;
  let keys;
  let session;
  let myKey;

  beforeEach(() => {
    resetState();
    seedPackages(defaultPackages());
    app = require('../src/index').createApp();
    keys = require('../src/keys');
    session = require('../src/session');
    session._test._reset();
    myKey = keys.issue({
      tenantId: 'tenant-rotate',
      app_id: '_default',
      scheme: 'bearer',
      label: 'rotate me',
    });
  });

  test('valid session → 200 HTML with new key material', async () => {
    const cookieValue = session.createSession({
      tenant_id: 'tenant-rotate',
      key_id: myKey.record.id,
      app_id: '_default',
    });
    const res = await request(app)
      .post('/dashboard/keys/rotate')
      .set('Cookie', `cogos_session=${cookieValue}`);
    expect(res.status).toBe(200);
    expect(res.text).toMatch(/Key rotated/i);
    // New api_key in the page
    expect(res.text).toMatch(/sk-cogos-[0-9a-f]{32}/);
    // Old key is still there but now has a grace window
    const all = keys.list().filter((k) => k.tenant_id === 'tenant-rotate');
    expect(all.length).toBe(2);
    const old = all.find((k) => k.id === myKey.record.id);
    expect(old.rotation_grace_until).toBeTruthy();
  });

  test('no cookie → 302 to login', async () => {
    const res = await request(app).post('/dashboard/keys/rotate');
    expect(res.status).toBe(302);
  });
});

// =============================================================================
describe('POST /dashboard/logout', () => {
  let app;
  beforeEach(() => {
    resetState();
    seedPackages(defaultPackages());
    app = require('../src/index').createApp();
  });

  test('clears cookie via Max-Age=0 + 303 to /dashboard', async () => {
    const res = await request(app).post('/dashboard/logout');
    expect(res.status).toBe(303);
    expect(res.headers.location).toBe('/dashboard');
    const setCookie = res.headers['set-cookie'];
    const flat = Array.isArray(setCookie) ? setCookie.join('\n') : setCookie;
    expect(flat).toMatch(/cogos_session=/);
    expect(flat).toMatch(/Max-Age=0/);
    expect(flat).toMatch(/Path=\/dashboard/);
  });
});

// =============================================================================
describe('GET /dashboard/forgot — magic-link recovery form', () => {
  let app;
  beforeEach(() => {
    resetState();
    seedPackages(defaultPackages());
    app = require('../src/index').createApp();
  });

  test('returns 200 HTML with email form + mailto fallback', async () => {
    const res = await request(app).get('/dashboard/forgot');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/html/);
    expect(res.text).toMatch(/Key recovery/i);
    expect(res.text).toMatch(/<form[^>]*action="\/dashboard\/forgot"[^>]*method="POST"/);
    expect(res.text).toMatch(/<input[^>]*type="email"[^>]*name="email"/);
    // Mailto fallback to support is still surfaced for edge cases.
    expect(res.text).toMatch(/support@5ceos\.com/);
    expect(res.text).toMatch(/%5BSECURITY%5D/);
  });
});

// =============================================================================
describe('POST /dashboard/forgot — non-enumeration contract', () => {
  let app;
  let keys;
  let notifySignup;

  beforeEach(() => {
    resetState();
    seedPackages(defaultPackages());
    app = require('../src/index').createApp();
    keys = require('../src/keys');
    notifySignup = require('../src/notify-signup');
    // Spy on forwardEmail so we can assert it's called for known emails.
    // resolved-promise return matches the real shape.
    jest.spyOn(notifySignup, 'forwardEmail').mockResolvedValue({
      sent: true, transport: 'ses', status: 200,
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  function postForgot(email) {
    return request(app)
      .post('/dashboard/forgot')
      .type('form')
      .send({ email });
  }

  test('existing-tenant email by customer_email → 200 + same body + SES call attempted', async () => {
    keys.issue({
      tenantId: 'tenant-recover-1',
      app_id: '_default',
      scheme: 'bearer',
      label: 'paid customer',
      stripe: { email: 'paid@example.com', customer_id: 'cus_x' },
    });
    const res = await postForgot('paid@example.com');
    expect(res.status).toBe(200);
    expect(res.text).toMatch(/Check your inbox/i);
    expect(res.text).toMatch(/if an account exists/i);
    // Fire-and-forget SES call happened.
    // (mock is a Promise, so the spy registers the invocation synchronously)
    expect(notifySignup.forwardEmail).toHaveBeenCalledTimes(1);
  });

  test('existing-tenant email by free-signup label → 200 + same body + SES call attempted', async () => {
    keys.issue({
      tenantId: 'tenant-recover-2',
      app_id: '_default',
      scheme: 'bearer',
      label: 'free-signup:alice@example.com',
    });
    const res = await postForgot('alice@example.com');
    expect(res.status).toBe(200);
    expect(res.text).toMatch(/Check your inbox/i);
    expect(notifySignup.forwardEmail).toHaveBeenCalledTimes(1);
  });

  test('unknown email → SAME 200 + SAME confirmation page (no enumeration)', async () => {
    const res = await postForgot('stranger@example.com');
    expect(res.status).toBe(200);
    expect(res.text).toMatch(/Check your inbox/i);
    // No SES call for unknowns — the mail-deliverability path is the
    // ONLY thing that distinguishes known vs unknown server-side; the
    // HTTP response itself is identical.
    expect(notifySignup.forwardEmail).not.toHaveBeenCalled();
  });

  test('non-enumeration: known + unknown emails return byte-equal HTML', async () => {
    keys.issue({
      tenantId: 'tenant-recover-3',
      app_id: '_default',
      scheme: 'bearer',
      label: 'free-signup:known@example.com',
    });
    const known = await postForgot('known@example.com');
    const unknown = await postForgot('totally-unknown@example.com');
    // Both responses share status code AND body shape (modulo the
    // echoed email, which is the only differentiator and intentionally
    // matches what the user typed).
    expect(known.status).toBe(unknown.status);
    expect(known.status).toBe(200);
    // Replace the user-echoed email in both bodies so we can compare
    // the chrome byte-for-byte.
    const norm = (s, e) => s.replace(new RegExp(e, 'g'), 'X@X');
    expect(norm(known.text, 'known@example.com'))
      .toBe(norm(unknown.text, 'totally-unknown@example.com'));
  });

  test('malformed email → SAME 200 (no validator-based oracle)', async () => {
    const res = await postForgot('not-an-email');
    expect(res.status).toBe(200);
    expect(res.text).toMatch(/Check your inbox/i);
    // We never call SES on a malformed email — same as "no match".
    expect(notifySignup.forwardEmail).not.toHaveBeenCalled();
  });

  test('revoked-only key for an email → no SES (treated as no match)', async () => {
    const issued = keys.issue({
      tenantId: 'tenant-revoked',
      app_id: '_default',
      scheme: 'bearer',
      label: 'free-signup:gone@example.com',
    });
    keys.revoke(issued.record.id);
    const res = await postForgot('gone@example.com');
    expect(res.status).toBe(200);
    expect(notifySignup.forwardEmail).not.toHaveBeenCalled();
  });
});

// =============================================================================
describe('GET /dashboard/auth — token verification + rotation', () => {
  let app;
  let keys;
  let session;
  let magicLink;
  let issued;

  beforeEach(() => {
    resetState();
    seedPackages(defaultPackages());
    app = require('../src/index').createApp();
    keys = require('../src/keys');
    session = require('../src/session');
    magicLink = require('../src/magic-link');
    session._test._reset();
    magicLink._test._reset();
    issued = keys.issue({
      tenantId: 'tenant-mlink',
      app_id: '_default',
      scheme: 'bearer',
      label: 'free-signup:carol@example.com',
    });
  });

  test('valid token → 303 to /dashboard/rotate-result + Set-Cookie (session+display) + new key issued + old key in grace', async () => {
    const { token } = magicLink.createToken({
      tenant_id: 'tenant-mlink',
      key_id: issued.record.id,
      email: 'carol@example.com',
    });
    const res = await request(app).get(`/dashboard/auth?token=${encodeURIComponent(token)}`);
    expect(res.status).toBe(303);
    expect(res.headers.location).toBe('/dashboard/rotate-result');
    const setCookie = res.headers['set-cookie'];
    expect(setCookie).toBeTruthy();
    const flat = Array.isArray(setCookie) ? setCookie.join('\n') : setCookie;
    expect(flat).toMatch(/cogos_session=[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/);
    expect(flat).toMatch(/cogos_recovery_display=/);
    expect(flat).toMatch(/HttpOnly/);
    expect(flat).toMatch(/SameSite=Strict/);

    // New key issued under same tenant
    const tenantKeys = keys.list().filter((k) => k.tenant_id === 'tenant-mlink');
    expect(tenantKeys.length).toBe(2);
    const old = tenantKeys.find((k) => k.id === issued.record.id);
    const fresh = tenantKeys.find((k) => k.id !== issued.record.id);
    expect(old.rotation_grace_until).toBeTruthy();
    expect(fresh.active).toBe(true);
    // 24h grace window (approx — ms-precision)
    const graceMs = old.rotation_grace_until - Date.now();
    expect(graceMs).toBeGreaterThan(23 * 60 * 60 * 1000);
    expect(graceMs).toBeLessThan(25 * 60 * 60 * 1000);
  });

  test('invalid token → 400 + form-with-error', async () => {
    const res = await request(app).get('/dashboard/auth?token=garbage');
    expect(res.status).toBe(400);
    expect(res.text).toMatch(/invalid, expired, or already used/i);
    // No new key minted on failure
    const tenantKeys = keys.list().filter((k) => k.tenant_id === 'tenant-mlink');
    expect(tenantKeys.length).toBe(1);
  });

  test('expired token → 400 + form-with-error', async () => {
    const { token } = magicLink.createToken({
      tenant_id: 'tenant-mlink',
      key_id: issued.record.id,
      email: 'carol@example.com',
      ttlMs: -1000, // already expired
    });
    const res = await request(app).get(`/dashboard/auth?token=${encodeURIComponent(token)}`);
    expect(res.status).toBe(400);
    expect(res.text).toMatch(/invalid, expired, or already used/i);
  });

  test('replayed token → first call succeeds, second call 400', async () => {
    const { token } = magicLink.createToken({
      tenant_id: 'tenant-mlink',
      key_id: issued.record.id,
      email: 'carol@example.com',
    });
    const first = await request(app).get(`/dashboard/auth?token=${encodeURIComponent(token)}`);
    expect(first.status).toBe(303);
    const second = await request(app).get(`/dashboard/auth?token=${encodeURIComponent(token)}`);
    expect(second.status).toBe(400);
    expect(second.text).toMatch(/invalid, expired, or already used/i);
    // Only ONE new key minted (the second attempt didn't rotate again)
    const tenantKeys = keys.list().filter((k) => k.tenant_id === 'tenant-mlink');
    expect(tenantKeys.length).toBe(2);
  });

  test('token for a revoked key → 400 (rotate refused at re-check)', async () => {
    const { token } = magicLink.createToken({
      tenant_id: 'tenant-mlink',
      key_id: issued.record.id,
      email: 'carol@example.com',
    });
    keys.revoke(issued.record.id);
    const res = await request(app).get(`/dashboard/auth?token=${encodeURIComponent(token)}`);
    expect(res.status).toBe(400);
    expect(res.text).toMatch(/no longer active/i);
  });

  test('audit-log marker is written under the new key id', async () => {
    const usage = require('../src/usage');
    const { token } = magicLink.createToken({
      tenant_id: 'tenant-mlink',
      key_id: issued.record.id,
      email: 'carol@example.com',
    });
    await request(app).get(`/dashboard/auth?token=${encodeURIComponent(token)}`);
    const rows = usage.readSlice({ tenant_id: 'tenant-mlink', limit: 10 });
    const marker = rows.find((r) => r.route === '/dashboard/auth');
    expect(marker).toBeTruthy();
    expect(marker.status).toBe('magic_link_recovery');
  });
});

// =============================================================================
describe('GET /dashboard/rotate-result — show-once page', () => {
  let app;
  let keys;
  let magicLink;
  let issued;

  beforeEach(() => {
    resetState();
    seedPackages(defaultPackages());
    app = require('../src/index').createApp();
    keys = require('../src/keys');
    magicLink = require('../src/magic-link');
    magicLink._test._reset();
    issued = keys.issue({
      tenantId: 'tenant-result',
      app_id: '_default',
      scheme: 'bearer',
      label: 'free-signup:dave@example.com',
    });
  });

  function recoveryDisplayCookie(authResponse) {
    const setCookie = authResponse.headers['set-cookie'];
    const headers = Array.isArray(setCookie) ? setCookie : [setCookie];
    for (const h of headers) {
      const m = /cogos_recovery_display=([^;]+)/.exec(h);
      if (m && m[1]) return m[1];
    }
    return null;
  }

  test('with display cookie set by /dashboard/auth → 200 + new key visible ONCE', async () => {
    const { token } = magicLink.createToken({
      tenant_id: 'tenant-result',
      key_id: issued.record.id,
      email: 'dave@example.com',
    });
    const auth = await request(app).get(`/dashboard/auth?token=${encodeURIComponent(token)}`);
    expect(auth.status).toBe(303);
    const display = recoveryDisplayCookie(auth);
    expect(display).toBeTruthy();

    // First read: material visible
    const first = await request(app)
      .get('/dashboard/rotate-result')
      .set('Cookie', `cogos_recovery_display=${display}`);
    expect(first.status).toBe(200);
    expect(first.text).toMatch(/Recovery complete/i);
    expect(first.text).toMatch(/sk-cogos-[0-9a-f]{32}/);

    // Second read with the same display token: nothing to show.
    const second = await request(app)
      .get('/dashboard/rotate-result')
      .set('Cookie', `cogos_recovery_display=${display}`);
    expect(second.status).toBe(200);
    expect(second.text).not.toMatch(/sk-cogos-[0-9a-f]{32}/);
  });

  test('without display cookie → 200 + friendly "nothing to show" page', async () => {
    const res = await request(app).get('/dashboard/rotate-result');
    expect(res.status).toBe(200);
    expect(res.text).toMatch(/Nothing to display/i);
    expect(res.text).not.toMatch(/sk-cogos-[0-9a-f]{32}/);
  });
});

// =============================================================================
describe('GET /dashboard — already-signed-in redirect', () => {
  let app;
  let keys;
  let session;

  beforeEach(() => {
    resetState();
    seedPackages(defaultPackages());
    app = require('../src/index').createApp();
    keys = require('../src/keys');
    session = require('../src/session');
    session._test._reset();
  });

  test('valid cookie on /dashboard → 303 to /dashboard/home', async () => {
    const issued = keys.issue({
      tenantId: 'tenant-redir',
      app_id: '_default',
      scheme: 'bearer',
    });
    const cookieValue = session.createSession({
      tenant_id: 'tenant-redir',
      key_id: issued.record.id,
      app_id: '_default',
    });
    const res = await request(app)
      .get('/dashboard')
      .set('Cookie', `cogos_session=${cookieValue}`);
    expect(res.status).toBe(303);
    expect(res.headers.location).toBe('/dashboard/home');
  });
});

// =============================================================================
describe('landing page footer integration', () => {
  let app;
  beforeEach(() => {
    resetState();
    seedPackages(defaultPackages());
    app = require('../src/index').createApp();
  });

  test('GET / footer includes a /dashboard link', async () => {
    const res = await request(app).get('/');
    expect(res.status).toBe(200);
    expect(res.text).toMatch(/<footer[\s\S]*<a href="\/dashboard">dashboard<\/a>[\s\S]*<\/footer>/);
  });
});
