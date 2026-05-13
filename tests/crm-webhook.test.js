'use strict';

// Tests for src/crm-webhook.js — outbound CRM webhook emitter.

process.env.NODE_ENV = 'test';

const fs = require('fs');
const path = require('path');
const os = require('os');
const nock = require('nock');

// Isolated queue file per test run
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-crm-test-'));
process.env.CRM_WEBHOOK_QUEUE_FILE = path.join(tmpDir, 'crm-events.jsonl');

beforeAll(() => {
  nock.disableNetConnect();
});

afterEach(() => {
  nock.cleanAll();
  delete process.env.CRM_WEBHOOK_URL;
  delete process.env.CRM_WEBHOOK_SECRET;
  try { fs.unlinkSync(process.env.CRM_WEBHOOK_QUEUE_FILE); } catch (_e) {}
});

afterAll(() => {
  nock.enableNetConnect();
  nock.restore();
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

function freshModule() {
  jest.resetModules();
  return require('../src/crm-webhook');
}

// =============================================================================
describe('CRM webhook: no-op when unconfigured', () => {
  test('emit() returns {delivered:false, configured:false} when no URL', async () => {
    const crm = freshModule();
    const res = await crm.emit('customer.created', { test: true });
    expect(res.delivered).toBe(false);
    expect(res.configured).toBe(false);
  });

  test('no event is queued when unconfigured', async () => {
    const crm = freshModule();
    await crm.emit('customer.created', { test: true });
    expect(crm.readQueue()).toEqual([]);
  });
});

// =============================================================================
describe('CRM webhook: delivery + signature', () => {
  test('emit() POSTs body, signed header, and 2xx returns delivered=true', async () => {
    process.env.CRM_WEBHOOK_URL = 'https://receiver.test/api/cogos/customer-events';
    process.env.CRM_WEBHOOK_SECRET = 'test-secret-very-long-please-rotate';
    const crm = freshModule();

    let capturedHeaders = null;
    let capturedBody = null;
    nock('https://receiver.test')
      .post('/api/cogos/customer-events', (body) => {
        capturedBody = body;
        return true;
      })
      .reply(function (uri, requestBody) {
        capturedHeaders = this.req.headers;
        return [200, { ok: true }];
      });

    const res = await crm.emit('customer.created', { foo: 'bar' });
    expect(res.delivered).toBe(true);
    expect(res.status).toBe(200);
    expect(capturedHeaders['x-cogos-webhook-signature']).toMatch(/^t=\d+,v1=[a-f0-9]+$/);
    expect(capturedHeaders['x-cogos-webhook-event-id']).toMatch(/^[a-f0-9-]{36}$/);
    expect(capturedHeaders['x-cogos-webhook-event-type']).toBe('customer.created');
    expect(capturedBody.event_type).toBe('customer.created');
    expect(capturedBody.data).toEqual({ foo: 'bar' });
  });

  test('signature uses HMAC-SHA256 of "<timestamp>.<body>"', () => {
    const crm = freshModule();
    const body = '{"a":1}';
    const fixedNow = 1700000000000;
    const sig = crm.signatureHeader('shh', body, fixedNow);
    const match = /^t=(\d+),v1=([a-f0-9]{64})$/.exec(sig);
    expect(match).not.toBeNull();
    const ts = match[1];
    const v1 = match[2];
    expect(ts).toBe('1700000000');
    // Manual recompute for proof
    const expected = crm.sign('shh', ts, body);
    expect(v1).toBe(expected);
  });
});

// =============================================================================
describe('CRM webhook: queueing on failure', () => {
  test('5xx response queues the event', async () => {
    process.env.CRM_WEBHOOK_URL = 'https://receiver.test/x';
    process.env.CRM_WEBHOOK_SECRET = 'secret';
    const crm = freshModule();

    nock('https://receiver.test').post('/x').reply(503, { error: 'down' });

    const res = await crm.emit('customer.created', { foo: 'bar' });
    expect(res.delivered).toBe(false);
    expect(res.queued).toBe(true);
    const queue = crm.readQueue();
    expect(queue).toHaveLength(1);
    expect(queue[0].event_type).toBe('customer.created');
    expect(queue[0].status).toBe('pending');
    expect(queue[0].last_status).toBe(503);
  });

  test('network error queues the event with error message', async () => {
    process.env.CRM_WEBHOOK_URL = 'https://receiver.test/x';
    process.env.CRM_WEBHOOK_SECRET = 'secret';
    const crm = freshModule();

    nock('https://receiver.test').post('/x').replyWithError('ECONNREFUSED');

    const res = await crm.emit('customer.created', { foo: 'bar' });
    expect(res.delivered).toBe(false);
    expect(res.queued).toBe(true);
    expect(res.error).toMatch(/ECONNREFUSED/);
    const queue = crm.readQueue();
    expect(queue).toHaveLength(1);
    expect(queue[0].last_error).toMatch(/ECONNREFUSED/);
  });
});

// =============================================================================
describe('CRM webhook: payload builders', () => {
  test('buildCustomerCreatedPayload pulls fields off the key+package records', () => {
    const crm = freshModule();
    const payload = crm.buildCustomerCreatedPayload({
      keyRecord: {
        id: 'key-abc',
        tenant_id: 'cus_test_123',
        key_prefix: 'sk-cogos-XXXX',
        issued_at: '2026-05-13T00:00:00Z',
        stripe_customer_id: 'cus_test_123',
        stripe_subscription_id: 'sub_test_456',
        stripe_subscription_status: 'active',
        customer_email: 'denny@example.com',
        package_id: 'starter',
      },
      packageRecord: {
        id: 'starter',
        display_name: 'Operator Starter',
        monthly_usd: 29,
        monthly_request_quota: 100000,
        allowed_model_tiers: ['cogos-tier-b'],
      },
      stripeData: { email: 'denny@example.com', customer_id: 'cus_test_123', subscription_id: 'sub_test_456' },
    });
    expect(payload.cogos_tenant_id).toBe('cus_test_123');
    expect(payload.plan_id).toBe('starter');
    expect(payload.plan_name).toBe('Operator Starter');
    expect(payload.monthly_usd).toBe(29);
    expect(payload.allowed_model_tiers).toEqual(['cogos-tier-b']);
    expect(payload.key_prefix).toBe('sk-cogos-XXXX');
    expect(payload).not.toHaveProperty('key_hash'); // never leak the hash
    expect(payload).not.toHaveProperty('api_key'); // never leak plaintext
  });
});
