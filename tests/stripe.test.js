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
  const factory = function (_key, _opts) {
    // Instance must also expose .webhooks for signature verification calls.
    return {
      checkout: { sessions: { create: mockCreate } },
      webhooks: real.webhooks,
    };
  };
  factory.webhooks = real.webhooks; // keep static module access too
  factory.__mockCreate = mockCreate; // expose for assertions
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
  test('GET / renders the landing page', async () => {
    const res = await request(buildApp()).get('/');
    expect(res.status).toBe(200);
    expect(res.text).toMatch(/CogOS/);
    expect(res.text).toMatch(/\$25\/mo/);
    expect(res.text).toMatch(/<form action="\/signup"/);
  });

  test('GET /cancel renders the cancel page', async () => {
    const res = await request(buildApp()).get('/cancel');
    expect(res.status).toBe(200);
    expect(res.text).toMatch(/cancelled/i);
  });
});

// ===========================================================================
describe('POST /signup creates Stripe Checkout Session', () => {
  test('happy path → 303 redirect to Stripe-hosted URL', async () => {
    const res = await request(buildApp()).post('/signup');
    expect(res.status).toBe(303);
    expect(res.headers.location).toMatch(/checkout\.stripe\.com/);
    expect(Stripe.__mockCreate).toHaveBeenCalledWith(
      expect.objectContaining({
        mode: 'subscription',
        line_items: expect.arrayContaining([
          expect.objectContaining({ price: 'price_FAKE_TEST_PRICE', quantity: 1 }),
        ]),
      }),
    );
  });

  test('STRIPE_PRICE_ID missing → 500 with error message', async () => {
    const saved = process.env.STRIPE_PRICE_ID;
    delete process.env.STRIPE_PRICE_ID;
    const res = await request(buildApp()).post('/signup');
    expect(res.status).toBe(500);
    expect(res.text).toMatch(/STRIPE_PRICE_ID/);
    process.env.STRIPE_PRICE_ID = saved;
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
