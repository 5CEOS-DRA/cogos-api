'use strict';

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';
process.env.STRIPE_SECRET_KEY = 'sk_test_FAKE_SECRET_FOR_TESTS';
process.env.STRIPE_WEBHOOK_SECRET = 'whsec_test_secret_for_signature_verification';
process.env.STRIPE_PRICE_ID = 'price_FAKE_TEST_PRICE';

// jest.mock must run BEFORE requiring src/index.js (which transitively
// requires stripe). Stub the Checkout Sessions create + retain the real
// webhooks.constructEvent / generateTestHeaderString for signature tests.
jest.mock('stripe', () => {
  const real = jest.requireActual('stripe');
  const mockCreate = jest.fn(async () => ({
    id: 'cs_test_mocked_abc',
    url: 'https://checkout.stripe.com/c/pay/cs_test_mocked_abc',
    object: 'checkout.session',
  }));
  // Products + Prices used by packages.js Stripe sync. Idempotent stubs.
  const mockProductCreate = jest.fn(async (p) => ({
    id: 'prod_test_' + p.metadata.cogos_package_id, ...p,
  }));
  const mockProductUpdate = jest.fn(async (id, p) => ({ id, ...p }));
  const mockPriceCreate = jest.fn(async (p) => ({
    id: 'price_test_' + p.metadata.cogos_package_id + '_' + p.unit_amount, ...p,
  }));
  const mockPriceUpdate = jest.fn(async (id, p) => ({ id, ...p }));
  const factory = function (_key, _opts) {
    return {
      checkout: { sessions: { create: mockCreate } },
      products: { create: mockProductCreate, update: mockProductUpdate },
      prices: { create: mockPriceCreate, update: mockPriceUpdate },
      webhooks: real.webhooks,
    };
  };
  factory.webhooks = real.webhooks;
  factory.__mockCreate = mockCreate;
  factory.__mockProductCreate = mockProductCreate;
  factory.__mockPriceCreate = mockPriceCreate;
  return factory;
});

const fs = require('fs');
const path = require('path');
const os = require('os');

// Isolated stores per test run
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-stripe-test-'));
process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
process.env.STRIPE_EVENTS_FILE = path.join(tmpDir, 'stripe-events.json');
process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
process.env.OLLAMA_URL = 'http://ollama.test';

const request = require('supertest');
const nock = require('nock');
const Stripe = require('stripe');
const { createApp } = require('../src/index');

beforeAll(() => {
  nock.disableNetConnect();
  nock.enableNetConnect(/127\.0\.0\.1|localhost/);
});
afterEach(() => { nock.cleanAll(); });
afterAll(() => {
  nock.enableNetConnect();
  nock.restore();
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

function buildApp() { return createApp(); }

// Seed the default package once before suites that depend on it.
// (createApp() doesn't auto-seed in tests; seedIfEmpty is wired only into
// the live listen() path so unit tests can control state explicitly.)
async function seedDefaultPackage() {
  const packages = require('../src/packages');
  if (packages.list().length === 0) {
    await packages.seedIfEmpty();
  }
}

// Stripe library exposes a helper to construct a properly-signed webhook header.
function signedWebhook(payloadObj) {
  const payload = JSON.stringify(payloadObj);
  const sig = Stripe.webhooks.generateTestHeaderString({
    payload,
    secret: process.env.STRIPE_WEBHOOK_SECRET,
  });
  return { rawBody: payload, signature: sig };
}

// ===========================================================================
describe('public landing + cancel pages', () => {
  beforeAll(async () => {
    await seedDefaultPackage();
  });

  test('GET / renders the landing page with seeded package', async () => {
    const res = await request(buildApp()).get('/');
    expect(res.status).toBe(200);
    expect(res.text).toMatch(/CogOS/);
    expect(res.text).toMatch(/\$25\/mo/);
    // Signup form now carries the package id as a query param so the
    // server-side handler knows which package to bill.
    expect(res.text).toMatch(/<form action="\/signup\?package=starter"/);
  });

  test('GET /cancel renders the cancel page', async () => {
    const res = await request(buildApp()).get('/cancel');
    expect(res.status).toBe(200);
    expect(res.text).toMatch(/cancelled/i);
  });
});

// ===========================================================================
describe('POST /signup creates Stripe Checkout Session', () => {
  beforeAll(async () => {
    await seedDefaultPackage();
  });

  test('happy path → 303 redirect to Stripe-hosted URL', async () => {
    const res = await request(buildApp()).post('/signup');
    expect(res.status).toBe(303);
    expect(res.headers.location).toMatch(/checkout\.stripe\.com/);
    // STRIPE_SECRET_KEY is set in this test file → live-mode mocks run.
    // The mocked stripe.prices.create returns price_test_<pkg>_<cents>.
    expect(Stripe.__mockCreate).toHaveBeenCalledWith(
      expect.objectContaining({
        mode: 'subscription',
        line_items: expect.arrayContaining([
          expect.objectContaining({ price: 'price_test_starter_2500', quantity: 1 }),
        ]),
        metadata: expect.objectContaining({
          cogos_package_id: 'starter',
        }),
      }),
    );
  });

  test('no packages configured → 500 with explanatory message', async () => {
    // Wipe packages.json so the registry is empty for this test.
    const fs = require('fs');
    try { fs.unlinkSync(process.env.PACKAGES_FILE); } catch (_e) {}
    jest.resetModules();
    const { createApp: freshCreateApp } = require('../src/index');
    const res = await request(freshCreateApp()).post('/signup');
    expect(res.status).toBe(500);
    expect(res.text).toMatch(/No packages configured/);
    // Restore default for downstream tests
    await seedDefaultPackage();
  });
});

// ===========================================================================
describe('POST /stripe/webhook — signature + idempotency', () => {
  test('missing signature → 400', async () => {
    const res = await request(buildApp())
      .post('/stripe/webhook')
      .set('content-type', 'application/json')
      .send('{}');
    expect(res.status).toBe(400);
    expect(res.text).toMatch(/signature/i);
  });

  test('invalid signature → 400', async () => {
    const res = await request(buildApp())
      .post('/stripe/webhook')
      .set('stripe-signature', 'sha256=not-a-real-sig')
      .set('content-type', 'application/json')
      .send('{}');
    expect(res.status).toBe(400);
  });

  test('valid checkout.session.completed → issues key, stores session_id link', async () => {
    const event = {
      id: 'evt_test_completed_1',
      object: 'event',
      type: 'checkout.session.completed',
      data: {
        object: {
          id: 'cs_test_abc',
          object: 'checkout.session',
          customer: 'cus_test_XYZ',
          subscription: 'sub_test_ABC',
          customer_details: { email: 'alice@example.com' },
        },
      },
    };
    const { rawBody, signature } = signedWebhook(event);

    const app = buildApp();
    const res = await request(app)
      .post('/stripe/webhook')
      .set('stripe-signature', signature)
      .set('content-type', 'application/json')
      .send(rawBody);
    expect(res.status).toBe(200);
    expect(res.body.received).toBe(true);

    // Now hit /success and confirm the key is shown ONCE
    const success = await request(app).get('/success?session_id=cs_test_abc');
    expect(success.status).toBe(200);
    expect(success.text).toMatch(/sk-cogos-[a-f0-9]{32}/);
    expect(success.text).toMatch(/welcome/i);
  });

  test('duplicate event id → {received: true, duplicate: true}', async () => {
    const event = {
      id: 'evt_test_dup_only',
      object: 'event',
      type: 'checkout.session.completed',
      data: { object: { id: 'cs_dup', customer: 'cus_dup', subscription: 'sub_dup', customer_details: { email: 'b@x.com' } } },
    };
    const { rawBody, signature } = signedWebhook(event);
    const app = buildApp();
    await request(app).post('/stripe/webhook').set('stripe-signature', signature).set('content-type', 'application/json').send(rawBody);
    // Send again — same event id
    const res2 = await request(app).post('/stripe/webhook').set('stripe-signature', signature).set('content-type', 'application/json').send(rawBody);
    expect(res2.status).toBe(200);
    expect(res2.body.duplicate).toBe(true);
  });

  test('subscription.deleted → revokes the key', async () => {
    // First issue a key via checkout.session.completed
    const issueEvent = {
      id: 'evt_issue_for_revoke',
      object: 'event',
      type: 'checkout.session.completed',
      data: { object: { id: 'cs_revoke_test', customer: 'cus_revoke', subscription: 'sub_revoke', customer_details: { email: 'c@x.com' } } },
    };
    const sig1 = signedWebhook(issueEvent);
    const app = buildApp();
    await request(app).post('/stripe/webhook').set('stripe-signature', sig1.signature).set('content-type', 'application/json').send(sig1.rawBody);

    // Then send a subscription cancellation for the same customer
    const cancelEvent = {
      id: 'evt_cancel',
      object: 'event',
      type: 'customer.subscription.deleted',
      data: { object: { id: 'sub_revoke', customer: 'cus_revoke', status: 'canceled' } },
    };
    const sig2 = signedWebhook(cancelEvent);
    const res = await request(app).post('/stripe/webhook').set('stripe-signature', sig2.signature).set('content-type', 'application/json').send(sig2.rawBody);
    expect(res.status).toBe(200);

    // Confirm the key is no longer in active list (auth probe should now 401)
    const admin = await request(app)
      .get('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    const revoked = admin.body.keys.find((k) => k.stripe_customer_id === 'cus_revoke');
    expect(revoked).toBeDefined();
    expect(revoked.active).toBe(false);
    expect(revoked.stripe_subscription_status).toBe('canceled');
  });
});

// ===========================================================================
describe('GET /success', () => {
  test('missing session_id → 400', async () => {
    const res = await request(buildApp()).get('/success');
    expect(res.status).toBe(400);
  });

  test('unknown session_id → success page with expired warning', async () => {
    const res = await request(buildApp()).get('/success?session_id=cs_nonexistent');
    expect(res.status).toBe(200);
    expect(res.text).toMatch(/expired|contact support/i);
  });
});
