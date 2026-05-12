'use strict';

// Stripe Checkout self-serve signup.
//
// Flow:
//   1. GET  /                       — landing page with [Start] button → POST /signup
//   2. POST /signup                 — creates Checkout Session, redirects to Stripe-hosted checkout
//   3. (customer pays on Stripe)
//   4. Stripe → POST /stripe/webhook — `checkout.session.completed` fires
//   5. Webhook handler issues the API key, links to Stripe customer
//   6. Stripe redirects customer → GET /success?session_id=...
//   7. /success fetches the key from server (by session_id) and shows it ONCE
//
// Idempotency: every Stripe event has an event.id. We persist processed IDs
// to data/stripe-events.json so duplicate deliveries don't double-issue keys.

const fs = require('fs');
const path = require('path');

const logger = require('./logger');
const keys = require('./keys');

const EVENTS_FILE = process.env.STRIPE_EVENTS_FILE
  || path.join(__dirname, '..', 'data', 'stripe-events.json');

let _stripe = null;
function getStripe() {
  if (_stripe) return _stripe;
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) throw new Error('STRIPE_SECRET_KEY not set');
  _stripe = require('stripe')(key, { apiVersion: '2024-10-28.acacia' });
  return _stripe;
}

function ensureEventsFile() {
  const dir = path.dirname(EVENTS_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (!fs.existsSync(EVENTS_FILE)) {
    fs.writeFileSync(EVENTS_FILE, JSON.stringify([]), { mode: 0o600 });
  }
}

function readProcessedEvents() {
  ensureEventsFile();
  return JSON.parse(fs.readFileSync(EVENTS_FILE, 'utf8'));
}

function markEventProcessed(eventId, kind, extra = {}) {
  const list = readProcessedEvents();
  list.push({ event_id: eventId, type: kind, processed_at: new Date().toISOString(), ...extra });
  fs.writeFileSync(EVENTS_FILE, JSON.stringify(list, null, 2), { mode: 0o600 });
}

function isEventProcessed(eventId) {
  return readProcessedEvents().some((e) => e.event_id === eventId);
}

function findKeyBySession(sessionId) {
  // Each session_id is stored on the issued key record as metadata.
  // We persist it via the webhook handler.
  const records = keys.list().filter((r) => r.stripe_checkout_session_id === sessionId);
  return records[0] || null;
}

// ---------------------------------------------------------------------------
// /signup — create a Stripe Checkout Session
// ---------------------------------------------------------------------------
async function createCheckoutSession({ origin }) {
  const priceId = process.env.STRIPE_PRICE_ID;
  if (!priceId) throw new Error('STRIPE_PRICE_ID not set');
  const session = await getStripe().checkout.sessions.create({
    mode: 'subscription',
    payment_method_types: ['card'],
    line_items: [{ price: priceId, quantity: 1 }],
    success_url: `${origin}/success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${origin}/cancel`,
    allow_promotion_codes: true,
    billing_address_collection: 'auto',
    customer_creation: 'always',
    metadata: { product: 'cogos-api', tier: 'starter' },
  });
  return session;
}

// ---------------------------------------------------------------------------
// Webhook signature verification + event handler
// ---------------------------------------------------------------------------
function verifyAndParseEvent(rawBody, signatureHeader) {
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!webhookSecret) throw new Error('STRIPE_WEBHOOK_SECRET not set');
  return getStripe().webhooks.constructEvent(rawBody, signatureHeader, webhookSecret);
}

// Issue the API key + link to Stripe customer + record session_id for
// the /success page to look up.
async function handleCheckoutCompleted(event) {
  const session = event.data.object;
  const customerId = session.customer;
  const subscriptionId = session.subscription;
  const email = (session.customer_details && session.customer_details.email)
    || session.customer_email
    || null;
  const tenantId = customerId; // use Stripe customer ID as tenant ID — stable, unique

  const { plaintext, record } = keys.issue({
    tenantId,
    label: 'self-serve via Stripe',
    tier: 'starter',
    stripe: {
      customer_id: customerId,
      subscription_id: subscriptionId,
      status: 'active',
      email,
    },
  });

  // Persist session_id → key linkage so /success can look it up
  // (extends the record without breaking the issue() return shape).
  const all = keys.list();
  const target = all.find((r) => r.id === record.id);
  if (target) {
    const records = JSON.parse(fs.readFileSync(
      process.env.KEYS_FILE || path.join(__dirname, '..', 'data', 'keys.json'),
      'utf8',
    ));
    const full = records.find((r) => r.id === record.id);
    if (full) {
      full.stripe_checkout_session_id = session.id;
      fs.writeFileSync(
        process.env.KEYS_FILE || path.join(__dirname, '..', 'data', 'keys.json'),
        JSON.stringify(records, null, 2),
        { mode: 0o600 },
      );
    }
  }

  // Also persist the plaintext temporarily in the event log so /success
  // can fetch it within ~10 minutes (until rotation/expiry).
  markEventProcessed(event.id, event.type, {
    session_id: session.id,
    key_id: record.id,
    plaintext_short_lived: plaintext,
    plaintext_expires_at: new Date(Date.now() + 10 * 60_000).toISOString(),
  });

  logger.info('stripe_checkout_completed', {
    event_id: event.id,
    session_id: session.id,
    customer_id: customerId,
    subscription_id: subscriptionId,
    key_id: record.id,
    email,
  });
  return { plaintext, key_id: record.id };
}

async function handleSubscriptionUpdated(event) {
  const sub = event.data.object;
  const customerId = sub.customer;
  const status = sub.status; // active | past_due | canceled | unpaid | ...
  const existing = keys.findByStripeCustomer(customerId);
  if (!existing) {
    logger.warn('stripe_subscription_no_matching_key', { customer_id: customerId, status });
    markEventProcessed(event.id, event.type, { unmatched: true });
    return;
  }
  const shouldRevoke = ['canceled', 'incomplete_expired', 'unpaid'].includes(status);
  keys.updateStripeStatus(existing.id, {
    status,
    active: shouldRevoke ? false : undefined,
  });
  logger.info('stripe_subscription_updated', {
    event_id: event.id,
    customer_id: customerId,
    status,
    key_id: existing.id,
    revoked: shouldRevoke,
  });
  markEventProcessed(event.id, event.type, { key_id: existing.id, status });
}

// ---------------------------------------------------------------------------
// /success — show the API key ONCE (read from short-lived event-log entry)
// ---------------------------------------------------------------------------
function getNewlyIssuedKey(sessionId) {
  const events = readProcessedEvents();
  const evt = events.find((e) => e.session_id === sessionId);
  if (!evt) return null;
  if (!evt.plaintext_short_lived) return null;
  if (evt.plaintext_expires_at && Date.parse(evt.plaintext_expires_at) < Date.now()) return null;
  return {
    api_key: evt.plaintext_short_lived,
    key_id: evt.key_id,
    expires_at: evt.plaintext_expires_at,
  };
}

module.exports = {
  createCheckoutSession,
  verifyAndParseEvent,
  handleCheckoutCompleted,
  handleSubscriptionUpdated,
  isEventProcessed,
  getNewlyIssuedKey,
  findKeyBySession,
};
