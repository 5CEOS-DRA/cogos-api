'use strict';

// Tests for src/packages.js and the /admin/packages routes + quota
// enforcement middleware. Two sub-environments:
//
//   describe('stub mode')  → STRIPE_SECRET_KEY unset; CRUD operates locally,
//                            stripe_* fields get deterministic stub values.
//   describe('live mode')  → STRIPE_SECRET_KEY set; the stripe SDK is mocked
//                            so we can verify create + update + archive flows
//                            without hitting Stripe.

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

// Per-suite tmpdir isolation
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-pkg-test-'));
process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
process.env.STRIPE_EVENTS_FILE = path.join(tmpDir, 'stripe-events.json');
process.env.OLLAMA_URL = 'http://ollama.test';
process.env.UPSTREAM_URL = 'http://ollama.test';
process.env.DEFAULT_MODEL = 'qwen2.5:3b-instruct';

const request = require('supertest');
const nock = require('nock');

// Mock stripe so live-mode tests don't actually hit Stripe.
jest.mock('stripe', () => {
  return jest.fn(() => ({
    products: {
      create: jest.fn(async (params) => ({
        id: 'prod_mock_' + params.metadata.cogos_package_id,
        name: params.name,
        description: params.description,
        metadata: params.metadata,
      })),
      update: jest.fn(async (id, params) => ({ id, ...params })),
    },
    prices: {
      create: jest.fn(async (params) => ({
        id: 'price_mock_' + params.metadata.cogos_package_id + '_' + params.unit_amount,
        product: params.product,
        unit_amount: params.unit_amount,
        currency: params.currency,
        recurring: params.recurring,
        lookup_key: params.lookup_key,
        metadata: params.metadata,
        active: true,
      })),
      update: jest.fn(async (id, params) => ({ id, ...params })),
    },
  }));
});

beforeAll(() => {
  nock.disableNetConnect();
  nock.enableNetConnect(/127\.0\.0\.1|localhost/);
});

afterEach(() => {
  nock.cleanAll();
});

afterAll(() => {
  nock.enableNetConnect();
  nock.restore();
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

// =============================================================================
describe('packages: stub mode (no Stripe)', () => {
  let packages, app, request;

  beforeEach(() => {
    resetState();
    delete process.env.STRIPE_SECRET_KEY;
    packages = require('../src/packages');
    request = require('supertest');
    app = require('../src/index').createApp();
  });

  test('list() returns empty on fresh store', () => {
    expect(packages.list()).toEqual([]);
  });

  test('seedIfEmpty() creates the default Operator Starter package', async () => {
    await packages.seedIfEmpty();
    const list = packages.list();
    expect(list).toHaveLength(1);
    expect(list[0].id).toBe('starter');
    expect(list[0].display_name).toBe('Operator Starter');
    expect(list[0].monthly_usd).toBe(25);
    expect(list[0].monthly_request_quota).toBe(100000);
    expect(list[0].allowed_model_tiers).toEqual(['cogos-tier-b']);
    expect(list[0].is_default).toBe(true);
    expect(list[0].stripe_product_id).toMatch(/^prod_stub_starter$/);
    expect(list[0].stripe_price_id).toMatch(/^price_stub_starter_25$/);
  });

  test('seedIfEmpty() is idempotent', async () => {
    await packages.seedIfEmpty();
    await packages.seedIfEmpty();
    expect(packages.list()).toHaveLength(1);
  });

  test('create() rejects bad ids', async () => {
    await expect(packages.create({
      id: 'BAD ID', display_name: 'x', monthly_usd: 1,
      monthly_request_quota: 1, allowed_model_tiers: ['cogos-tier-b'],
    })).rejects.toThrow(/lowercase-kebab/);
  });

  test('create() rejects unknown tier', async () => {
    await expect(packages.create({
      id: 'foo', display_name: 'Foo', monthly_usd: 1,
      monthly_request_quota: 1, allowed_model_tiers: ['cogos-tier-z'],
    })).rejects.toThrow(/unknown tier/);
  });

  test('create() then update() then softDelete()', async () => {
    const created = await packages.create({
      id: 'pro', display_name: 'Operator Pro', monthly_usd: 99,
      monthly_request_quota: 1000000, allowed_model_tiers: ['cogos-tier-a', 'cogos-tier-b'],
    });
    expect(created.id).toBe('pro');
    expect(created.stripe_price_id).toBe('price_stub_pro_99');

    const updated = await packages.update('pro', { monthly_usd: 79 });
    expect(updated.monthly_usd).toBe(79);
    // Price changed → new stub ID
    expect(updated.stripe_price_id).toBe('price_stub_pro_79');

    const deleted = await packages.softDelete('pro');
    expect(deleted).toBe(true);
    expect(packages.list({ includeInactive: false })).toEqual([]);
    expect(packages.list({ includeInactive: true })).toHaveLength(1);
  });

  test('softDelete() refuses on the default package', async () => {
    await packages.seedIfEmpty();
    await expect(packages.softDelete('starter')).rejects.toThrow(/cannot delete the default/);
  });

  test('duplicate id is rejected', async () => {
    await packages.seedIfEmpty();
    await expect(packages.create({
      id: 'starter', display_name: 'X', monthly_usd: 1,
      monthly_request_quota: 1, allowed_model_tiers: ['cogos-tier-b'],
    })).rejects.toThrow(/already exists/);
  });

  test('setting is_default on a new package un-defaults the old one', async () => {
    await packages.seedIfEmpty();
    await packages.create({
      id: 'pro', display_name: 'Operator Pro', monthly_usd: 99,
      monthly_request_quota: 1000000, allowed_model_tiers: ['cogos-tier-a', 'cogos-tier-b'],
      is_default: true,
    });
    const all = packages.list();
    const defaults = all.filter((p) => p.is_default);
    expect(defaults).toHaveLength(1);
    expect(defaults[0].id).toBe('pro');
  });
});

// =============================================================================
describe('packages: admin HTTP routes', () => {
  let app;

  beforeEach(() => {
    resetState();
    delete process.env.STRIPE_SECRET_KEY;
    app = require('../src/index').createApp();
  });

  test('GET /admin/packages requires X-Admin-Key', async () => {
    const res = await request(app).get('/admin/packages');
    expect(res.status).toBe(401);
  });

  test('full CRUD round-trip over HTTP', async () => {
    // 1. Create
    const create = await request(app)
      .post('/admin/packages')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({
        id: 'team',
        display_name: 'Team',
        description: 'For small teams',
        monthly_usd: 199,
        monthly_request_quota: 500000,
        allowed_model_tiers: ['cogos-tier-b'],
      });
    expect(create.status).toBe(201);
    expect(create.body.package.id).toBe('team');

    // 2. List
    const list = await request(app)
      .get('/admin/packages')
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(list.status).toBe(200);
    expect(list.body.packages).toHaveLength(1);

    // 3. Update
    const update = await request(app)
      .put('/admin/packages/team')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ monthly_usd: 249 });
    expect(update.status).toBe(200);
    expect(update.body.package.monthly_usd).toBe(249);

    // 4. Delete
    const del = await request(app)
      .delete('/admin/packages/team')
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(del.status).toBe(200);
    expect(del.body.deactivated).toBe(true);

    // 5. Final list excludes inactive by default
    const listAgain = await request(app)
      .get('/admin/packages')
      .set('X-Admin-Key', process.env.ADMIN_KEY);
    expect(listAgain.body.packages).toHaveLength(0);
  });

  test('validation errors return 400', async () => {
    const res = await request(app)
      .post('/admin/packages')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ id: 'X X', display_name: '', monthly_usd: -1, allowed_model_tiers: [] });
    expect(res.status).toBe(400);
    expect(res.body.error.type).toBe('validation_failed');
  });
});

// =============================================================================
describe('quota enforcement middleware', () => {
  let app;
  const ADMIN_KEY = process.env.ADMIN_KEY;

  beforeEach(async () => {
    resetState();
    delete process.env.STRIPE_SECRET_KEY;
    app = require('../src/index').createApp();
    // Seed a 2-call quota for the default Operator Starter package — easy to
    // exhaust without writing 100K rows.
    const packages = require('../src/packages');
    await packages.seedIfEmpty();
    await packages.update('starter', { monthly_request_quota: 2 });
  });

  async function issueKey(tenant = 'denny') {
    const res = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', ADMIN_KEY)
      .send({ tenant_id: tenant, tier: 'starter' });
    return res.body.api_key;
  }

  test('403 when customer requests a tier their package does not grant', async () => {
    const sk = await issueKey();
    const res = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', 'Bearer ' + sk)
      .send({
        model: 'cogos-tier-a',  // starter only grants cogos-tier-b
        messages: [{ role: 'user', content: 'hi' }],
      });
    expect(res.status).toBe(403);
    expect(res.body.error.type).toBe('model_tier_denied');
  });

  test('429 when monthly quota is exhausted', async () => {
    const sk = await issueKey();
    // Mock the upstream so two calls actually appear in usage.jsonl as successful.
    nock('http://ollama.test')
      .post('/api/chat')
      .twice()
      .reply(200, {
        message: { role: 'assistant', content: 'hi' },
        prompt_eval_count: 5,
        eval_count: 2,
        done_reason: 'stop',
      });
    const body = {
      model: 'cogos-tier-b',
      messages: [{ role: 'user', content: 'hi' }],
    };
    // Header semantics: remaining is BEFORE the current call is counted —
    // it's "what's left in your budget" at the moment of the check.
    const a = await request(app).post('/v1/chat/completions')
      .set('Authorization', 'Bearer ' + sk).send(body);
    expect(a.status).toBe(200);
    expect(a.headers['x-cogos-quota-remaining']).toBe('2');

    const b = await request(app).post('/v1/chat/completions')
      .set('Authorization', 'Bearer ' + sk).send(body);
    expect(b.status).toBe(200);
    expect(b.headers['x-cogos-quota-remaining']).toBe('1');

    const c = await request(app).post('/v1/chat/completions')
      .set('Authorization', 'Bearer ' + sk).send(body);
    expect(c.status).toBe(429);
    expect(c.body.error.type).toBe('quota_exceeded');
    expect(c.body.error.limit).toBe(2);
    expect(c.body.error.used).toBe(2);
  });
});

// =============================================================================
describe('packages: live mode (mocked Stripe SDK)', () => {
  let packages;

  beforeEach(() => {
    resetState();
    process.env.STRIPE_SECRET_KEY = 'sk_test_FAKE';
    packages = require('../src/packages');
  });

  afterAll(() => {
    delete process.env.STRIPE_SECRET_KEY;
  });

  test('create() calls Stripe products.create + prices.create', async () => {
    const pkg = await packages.create({
      id: 'live-test',
      display_name: 'Live Test',
      monthly_usd: 49,
      monthly_request_quota: 250000,
      allowed_model_tiers: ['cogos-tier-b'],
    });
    expect(pkg.stripe_product_id).toBe('prod_mock_live-test');
    expect(pkg.stripe_price_id).toBe('price_mock_live-test_4900');
  });

  test('update() with price change creates new Stripe price + archives old', async () => {
    await packages.create({
      id: 'live-test',
      display_name: 'Live Test',
      monthly_usd: 49,
      monthly_request_quota: 250000,
      allowed_model_tiers: ['cogos-tier-b'],
    });
    const updated = await packages.update('live-test', { monthly_usd: 79 });
    // New price id reflects new unit_amount (7900 cents)
    expect(updated.stripe_price_id).toBe('price_mock_live-test_7900');
  });

  test('findByStripePriceId() lookup works after create', async () => {
    const pkg = await packages.create({
      id: 'lookup-test',
      display_name: 'Lookup Test',
      monthly_usd: 10,
      monthly_request_quota: 1000,
      allowed_model_tiers: ['cogos-tier-b'],
    });
    const found = packages.findByStripePriceId(pkg.stripe_price_id);
    expect(found).not.toBeNull();
    expect(found.id).toBe('lookup-test');
  });
});
