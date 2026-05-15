'use strict';

// Tests for POST /signup/free — the no-Stripe, public, free-tier signup
// route. Sibling of the Stripe-gated /signup; uses keys.issue() directly
// + packages.list() to gate on package presence + public_signup flag.
//
// Each describe gets its own packages registry shape so the gating
// behavior (free missing → 503, free present but public_signup=false →
// 503, free present + public_signup=true → 200) can be exercised
// without cross-test contamination.

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-free-test-'));
process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
process.env.STRIPE_EVENTS_FILE = path.join(tmpDir, 'stripe-events.json');
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

// Seed packages.json directly so we control the public_signup flag per
// describe block. Bypasses packages.create() which would also try to
// reach Stripe (stub mode is fine here, but the file shape is the
// canonical disk shape so direct-write is the cleanest seed).
function seedPackages(records) {
  fs.writeFileSync(process.env.PACKAGES_FILE, JSON.stringify(records), { mode: 0o600 });
}

// =============================================================================
describe('POST /signup/free — happy path (public_signup=true)', () => {
  let app;
  let keys;

  beforeEach(() => {
    resetState();
    delete process.env.STRIPE_SECRET_KEY;
    seedPackages([
      {
        id: 'free',
        display_name: 'Free',
        description: 'Free tier — 100 requests/day, 1000 fallback tokens/day, Tier B (3B) only.',
        monthly_usd: 0,
        monthly_request_quota: 3000,
        allowed_model_tiers: ['cogos-tier-b'],
        is_default: false,
        active: true,
        stripe_product_id: null,
        stripe_price_id: null,
        public_signup: true,
      },
    ]);
    app = require('../src/index').createApp();
    keys = require('../src/keys');
  });

  test('POST /signup/free with no email → 200 HTML with api_key + hmac_secret in body', async () => {
    const res = await request(app).post('/signup/free').type('form').send({});
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/html/);
    // sk-cogos-<32 hex> is the bearer plaintext shape
    expect(res.text).toMatch(/sk-cogos-[0-9a-f]{32}/);
    // hmac_secret is 64 hex chars (32 bytes)
    // Anchored to data-copy attribute on the HMAC button to avoid
    // false-match on the api-key copy button.
    expect(res.text).toMatch(/Copy HMAC secret/);
    // Daily-caps callout from the task spec
    expect(res.text).toMatch(/100 requests\/day/);
    expect(res.text).toMatch(/1000 fallback tokens\/day/);
  });

  test('POST /signup/free with email → 200 HTML, key issued with label "free-signup:${email}"', async () => {
    const email = 'visitor@example.com';
    const res = await request(app).post('/signup/free').type('form').send({ email });
    expect(res.status).toBe(200);
    expect(res.text).toMatch(/sk-cogos-[0-9a-f]{32}/);

    // Verify the key was issued and labeled.
    const allKeys = keys.list();
    const match = allKeys.find((k) => k.label === `free-signup:${email}`);
    expect(match).toBeTruthy();
    expect(match.package_id).toBe('free');
    expect(match.tier).toBe('free');
    expect(match.scheme).toBe('bearer');
    expect(match.tenant_id).toMatch(/^free-[0-9a-f]{16}$/);
  });

  test('POST /signup/free twice with same email → second response is the already-exists page', async () => {
    const email = 'dupe@example.com';
    const first = await request(app).post('/signup/free').type('form').send({ email });
    expect(first.status).toBe(200);
    expect(first.text).toMatch(/sk-cogos-[0-9a-f]{32}/);

    const second = await request(app).post('/signup/free').type('form').send({ email });
    expect(second.status).toBe(200);
    expect(second.text).toMatch(/already/i);
    // Second response MUST NOT contain a freshly-minted key
    expect(second.text).not.toMatch(/sk-cogos-[0-9a-f]{32}/);

    // Only ONE key on disk for that label.
    const matches = keys.list().filter((k) => k.label === `free-signup:${email}`);
    expect(matches).toHaveLength(1);
  });

  test('POST /signup/free with email — key has package_id="free" and tier="free"', async () => {
    const email = 'shape-check@example.com';
    await request(app).post('/signup/free').type('form').send({ email });
    const match = keys.list().find((k) => k.label === `free-signup:${email}`);
    expect(match).toBeTruthy();
    expect(match.package_id).toBe('free');
    expect(match.tier).toBe('free');
  });

  test('two anonymous (no-email) POSTs issue two distinct keys (NOT deduped)', async () => {
    // Anonymous signups are explicitly not idempotent — see route comment.
    const before = keys.list().length;
    await request(app).post('/signup/free').type('form').send({});
    await request(app).post('/signup/free').type('form').send({});
    const after = keys.list().length;
    expect(after - before).toBe(2);
  });

  test('accepts JSON body shape as well as form-urlencoded', async () => {
    const email = 'json-shape@example.com';
    const res = await request(app)
      .post('/signup/free')
      .set('Content-Type', 'application/json')
      .send({ email });
    expect(res.status).toBe(200);
    expect(res.text).toMatch(/sk-cogos-[0-9a-f]{32}/);
    const match = keys.list().find((k) => k.label === `free-signup:${email}`);
    expect(match).toBeTruthy();
  });
});

// =============================================================================
describe('POST /signup/free — gating', () => {
  beforeEach(() => {
    resetState();
    delete process.env.STRIPE_SECRET_KEY;
  });

  test('returns 503 when packages.json has no "free" entry', async () => {
    seedPackages([
      // starter only, no free
      {
        id: 'starter',
        display_name: 'Operator Starter',
        description: '...',
        monthly_usd: 25,
        monthly_request_quota: 100000,
        allowed_model_tiers: ['cogos-tier-b'],
        is_default: true,
        active: true,
        stripe_product_id: 'prod_stub_starter',
        stripe_price_id: 'price_stub_starter_25',
      },
    ]);
    const app = require('../src/index').createApp();
    const res = await request(app).post('/signup/free').type('form').send({});
    expect(res.status).toBe(503);
    expect(res.body.error).toMatch(/Free tier not enabled/i);
  });

  test('returns 503 when "free" entry exists but public_signup=false', async () => {
    seedPackages([
      {
        id: 'free',
        display_name: 'Free',
        description: '...',
        monthly_usd: 0,
        monthly_request_quota: 3000,
        allowed_model_tiers: ['cogos-tier-b'],
        is_default: false,
        active: true,
        stripe_product_id: null,
        stripe_price_id: null,
        public_signup: false, // <-- gate disabled
      },
    ]);
    const app = require('../src/index').createApp();
    const res = await request(app).post('/signup/free').type('form').send({});
    expect(res.status).toBe(503);
    expect(res.body.error).toMatch(/Free tier not enabled/i);
  });

  test('returns 503 when "free" entry exists but public_signup is missing entirely', async () => {
    // Default-absent semantics: a package without public_signup is NOT
    // signupable. Belt-and-suspenders against the regression where a
    // future migration drops the field.
    seedPackages([
      {
        id: 'free',
        display_name: 'Free',
        description: '...',
        monthly_usd: 0,
        monthly_request_quota: 3000,
        allowed_model_tiers: ['cogos-tier-b'],
        is_default: false,
        active: true,
        stripe_product_id: null,
        stripe_price_id: null,
        // public_signup omitted
      },
    ]);
    const app = require('../src/index').createApp();
    const res = await request(app).post('/signup/free').type('form').send({});
    expect(res.status).toBe(503);
  });
});
