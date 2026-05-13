'use strict';

// CRM webhook emitter.
//
// cogos-api emits a signed HTTPS webhook to the 5CEOs platform whenever a
// commerce-relevant event happens (customer created, plan changed,
// subscription state changed, key rotated). The 5CEOs platform 5RM module
// consumes these events to maintain a customer-facing record with:
//   - email, stripe_customer_id, cogos_tenant_id
//   - plan_id / plan_name / monthly_usd
//   - subscription_status
//   - key_id + key_prefix (NEVER plaintext)
//   - usage thresholds (80%, 100% crossed)
//
// Configuration:
//   CRM_WEBHOOK_URL     — full HTTPS endpoint (no trailing slash). When
//                         unset, all emit() calls are no-ops (safe to
//                         deploy ahead of the receiver).
//   CRM_WEBHOOK_SECRET  — shared secret used to HMAC-sign payloads.
//                         Required when CRM_WEBHOOK_URL is set.
//
// Wire protocol:
//   POST <CRM_WEBHOOK_URL>
//     Content-Type: application/json
//     X-Cogos-Webhook-Signature: t=<unix_ts>,v1=<hmac_sha256_hex>
//     X-Cogos-Webhook-Event-Id: <uuid>
//     X-Cogos-Webhook-Event-Type: customer.created | customer.plan_changed | ...
//     body: { event_id, event_type, occurred_at, data: { ... } }
//
// Signature verification (receiver side):
//   signed_payload = `${timestamp}.${raw_body}`
//   expected_sig = hmac_sha256(secret, signed_payload).hex()
//   compare expected_sig with v1=<...> from header (constant-time)
//   reject if abs(now - timestamp) > 5 minutes (replay protection)
//
// Idempotency:
//   Each event has a unique event_id (uuid). Receiver should dedupe by
//   event_id so duplicate deliveries (from retries) don't double-write.
//
// Retry buffer:
//   On delivery failure (network, 5xx, timeout), the event is appended
//   to data/crm-webhook-events.jsonl with status=pending. A periodic
//   redrain (not yet wired) re-attempts pending events. Until then,
//   the operator can replay manually via /admin/crm-webhook-replay
//   (admin endpoint TODO).

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const axios = require('axios');

const logger = require('./logger');

const QUEUE_FILE = process.env.CRM_WEBHOOK_QUEUE_FILE
  || path.join(__dirname, '..', 'data', 'crm-webhook-events.jsonl');

const TIMEOUT_MS = Number(process.env.CRM_WEBHOOK_TIMEOUT_MS || 5000);
const SIGNATURE_TOLERANCE_SECONDS = 300;

function isConfigured() {
  return Boolean(process.env.CRM_WEBHOOK_URL && process.env.CRM_WEBHOOK_SECRET);
}

function ensureQueueFile() {
  const dir = path.dirname(QUEUE_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (!fs.existsSync(QUEUE_FILE)) {
    fs.writeFileSync(QUEUE_FILE, '', { mode: 0o600 });
  }
}

function appendToQueue(entry) {
  ensureQueueFile();
  fs.appendFileSync(QUEUE_FILE, JSON.stringify(entry) + '\n');
}

function sign(secret, timestamp, body) {
  const payload = `${timestamp}.${body}`;
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

// Construct the signature header in the same scheme Stripe uses.
function signatureHeader(secret, body, now = Date.now()) {
  const timestamp = Math.floor(now / 1000);
  const v1 = sign(secret, timestamp, body);
  return `t=${timestamp},v1=${v1}`;
}

// Public API: fire a webhook for the given event. Best-effort.
// Returns { delivered: bool, status?: number, queued?: bool }.
async function emit(eventType, data) {
  if (!isConfigured()) {
    // No-op when not configured. The events are not even queued because
    // there's no receiver to drain to. Operator turns on the feature by
    // setting CRM_WEBHOOK_URL + CRM_WEBHOOK_SECRET.
    return { delivered: false, configured: false };
  }
  const url = process.env.CRM_WEBHOOK_URL;
  const secret = process.env.CRM_WEBHOOK_SECRET;

  const event = {
    event_id: crypto.randomUUID(),
    event_type: eventType,
    occurred_at: new Date().toISOString(),
    data,
  };
  const body = JSON.stringify(event);
  const sig = signatureHeader(secret, body);

  try {
    const res = await axios.post(url, body, {
      headers: {
        'Content-Type': 'application/json',
        'X-Cogos-Webhook-Signature': sig,
        'X-Cogos-Webhook-Event-Id': event.event_id,
        'X-Cogos-Webhook-Event-Type': eventType,
      },
      timeout: TIMEOUT_MS,
      validateStatus: () => true,
    });
    const ok = res.status >= 200 && res.status < 300;
    if (ok) {
      logger.info('crm_webhook_delivered', { event_id: event.event_id, event_type: eventType, status: res.status });
      return { delivered: true, status: res.status };
    }
    logger.warn('crm_webhook_non_2xx', { event_id: event.event_id, event_type: eventType, status: res.status });
    appendToQueue({ ...event, status: 'pending', last_status: res.status, last_attempt: new Date().toISOString() });
    return { delivered: false, status: res.status, queued: true };
  } catch (e) {
    logger.warn('crm_webhook_delivery_failed', { event_id: event.event_id, event_type: eventType, error: e.message });
    appendToQueue({ ...event, status: 'pending', last_error: e.message, last_attempt: new Date().toISOString() });
    return { delivered: false, queued: true, error: e.message };
  }
}

// Convenience constructors — keep event payloads consistent across
// the call sites in stripe.js / keys.js / chat-api.js.
function buildCustomerCreatedPayload({ keyRecord, packageRecord, stripeData }) {
  return {
    cogos_tenant_id: keyRecord.tenant_id,
    customer_email: stripeData.email || keyRecord.customer_email || null,
    stripe_customer_id: keyRecord.stripe_customer_id || (stripeData && stripeData.customer_id) || null,
    stripe_subscription_id: keyRecord.stripe_subscription_id || (stripeData && stripeData.subscription_id) || null,
    stripe_subscription_status: keyRecord.stripe_subscription_status || 'active',
    plan_id: packageRecord ? packageRecord.id : keyRecord.package_id,
    plan_name: packageRecord ? packageRecord.display_name : null,
    monthly_usd: packageRecord ? packageRecord.monthly_usd : null,
    monthly_request_quota: packageRecord ? packageRecord.monthly_request_quota : null,
    allowed_model_tiers: packageRecord ? packageRecord.allowed_model_tiers : null,
    key_id: keyRecord.id,
    key_prefix: keyRecord.key_prefix,
    issued_at: keyRecord.issued_at,
    source: 'stripe_checkout', // vs 'admin_issued' or 'platform_5developer'
  };
}

function buildSubscriptionStatusChangedPayload({ keyRecord, oldStatus, newStatus }) {
  return {
    cogos_tenant_id: keyRecord.tenant_id,
    stripe_customer_id: keyRecord.stripe_customer_id,
    stripe_subscription_id: keyRecord.stripe_subscription_id,
    old_status: oldStatus,
    new_status: newStatus,
    key_id: keyRecord.id,
    key_prefix: keyRecord.key_prefix,
    plan_id: keyRecord.package_id || keyRecord.tier,
    revoked: keyRecord.active === false,
  };
}

function buildUsageThresholdPayload({ keyRecord, packageRecord, used, threshold }) {
  return {
    cogos_tenant_id: keyRecord.tenant_id,
    stripe_customer_id: keyRecord.stripe_customer_id,
    plan_id: packageRecord.id,
    plan_name: packageRecord.display_name,
    monthly_request_quota: packageRecord.monthly_request_quota,
    used,
    threshold,
    percent: Math.round((used / packageRecord.monthly_request_quota) * 100),
    key_id: keyRecord.id,
  };
}

// Exposed for the (future) admin replay endpoint and tests.
function readQueue() {
  ensureQueueFile();
  return fs.readFileSync(QUEUE_FILE, 'utf8')
    .split('\n')
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l));
}

module.exports = {
  isConfigured,
  emit,
  signatureHeader,
  sign,
  buildCustomerCreatedPayload,
  buildSubscriptionStatusChangedPayload,
  buildUsageThresholdPayload,
  readQueue,
  SIGNATURE_TOLERANCE_SECONDS,
};
