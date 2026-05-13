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
const packages = require('./packages');
const crmWebhook = require('./crm-webhook');

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
// Selects which package to sell:
//   1. Explicit packageId param (e.g. /signup?package=operator-pro)
//   2. The package whose stripe_price_id matches STRIPE_PRICE_ID env (legacy)
//   3. The default package
// The chosen package's stripe_price_id is what Stripe charges; its id is
// stored in session.metadata so the webhook can issue a key bound to it.
async function createCheckoutSession({ origin, packageId = null }) {
  let pkg = null;
  if (packageId) pkg = packages.get(packageId);
  if (!pkg && process.env.STRIPE_PRICE_ID) {
    pkg = packages.findByStripePriceId(process.env.STRIPE_PRICE_ID);
  }
  if (!pkg) pkg = packages.getDefault();
  if (!pkg) throw new Error('No packages configured — visit /admin/packages first');
  if (!pkg.stripe_price_id) throw new Error(`Package "${pkg.id}" has no stripe_price_id (Stripe sync not yet run)`);

  // NOTE: `customer_creation` is invalid in subscription mode — Stripe
  // auto-creates customers for subscriptions, so the field is rejected
  // with "customer_creation can only be used in payment mode."
  const session = await getStripe().checkout.sessions.create({
    mode: 'subscription',
    payment_method_types: ['card'],
    line_items: [{ price: pkg.stripe_price_id, quantity: 1 }],
    success_url: `${origin}/success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${origin}/cancel`,
    allow_promotion_codes: true,
    billing_address_collection: 'auto',
    metadata: {
      product: 'cogos-api',
      cogos_package_id: pkg.id,
      tier: pkg.id, // legacy field; kept for back-compat with admin/usage UIs
    },
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

  // Pull the package id off the session metadata (set in createCheckoutSession).
  // Fall back to default package if unset (legacy session or admin-created).
  const packageId = (session.metadata && session.metadata.cogos_package_id) || null;
  const pkg = packageId ? packages.get(packageId) : packages.getDefault();

  const { plaintext, record } = keys.issue({
    tenantId,
    label: 'self-serve via Stripe',
    tier: (pkg && pkg.id) || 'starter',
    package_id: pkg ? pkg.id : null,
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

  // Persist the plaintext temporarily in the event log so /success can
  // fetch it. Window was 10 minutes; real customers click the receipt
  // email link well after that, so extended to 24 hours. After expiry
  // the key remains valid in the database, but the plaintext cannot be
  // shown again — they have to manage from /portal (Stripe Customer
  // Portal) and contact support for a rotation if they lost it.
  markEventProcessed(event.id, event.type, {
    session_id: session.id,
    key_id: record.id,
    plaintext_short_lived: plaintext,
    plaintext_expires_at: new Date(Date.now() + 24 * 60 * 60_000).toISOString(),
  });

  logger.info('stripe_checkout_completed', {
    event_id: event.id,
    session_id: session.id,
    customer_id: customerId,
    subscription_id: subscriptionId,
    key_id: record.id,
    email,
  });

  // Fire CRM webhook for the 5RM bridge. Best-effort; no-op if
  // CRM_WEBHOOK_URL / CRM_WEBHOOK_SECRET aren't configured yet.
  try {
    const fullKey = keys.list().find((r) => r.id === record.id) || record;
    await crmWebhook.emit('customer.created', crmWebhook.buildCustomerCreatedPayload({
      keyRecord: fullKey,
      packageRecord: pkg,
      stripeData: { email, customer_id: customerId, subscription_id: subscriptionId },
    }));
  } catch (e) {
    logger.warn('crm_webhook_customer_created_failed', { error: e.message, key_id: record.id });
  }

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
  const oldStatus = existing.stripe_subscription_status;
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

  // CRM webhook — relay subscription state change to 5RM.
  try {
    const fullKey = keys.list().find((r) => r.id === existing.id) || existing;
    await crmWebhook.emit('customer.subscription_status_changed',
      crmWebhook.buildSubscriptionStatusChangedPayload({
        keyRecord: fullKey,
        oldStatus,
        newStatus: status,
      }),
    );
  } catch (e) {
    logger.warn('crm_webhook_subscription_changed_failed', { error: e.message, key_id: existing.id });
  }
}

// ---------------------------------------------------------------------------
// /portal — customer self-serve subscription management
// ---------------------------------------------------------------------------
// Stripe-hosted billing portal. The customer manages payment method,
// downloads invoices, and cancels their subscription. The portal must
// be enabled in the Stripe dashboard (Settings → Billing → Customer
// Portal → Activate) once per account. The function below creates a
// portal session bound to the customer; the caller redirects to the
// returned URL.
async function createCustomerPortalSession({ customerId, returnUrl }) {
  if (!customerId) throw new Error('customerId required');
  const session = await getStripe().billingPortal.sessions.create({
    customer: customerId,
    return_url: returnUrl || 'https://cogos.5ceos.com/',
  });
  return session;
}

// Resolve a checkout session_id (which the customer holds via their
// success URL) to the Stripe customer ID we issued their key against.
// Used by GET /portal?session_id=... so the customer self-authenticates
// by holding their original receipt URL.
function findStripeCustomerBySession(sessionId) {
  const k = findKeyBySession(sessionId);
  return k && k.stripe_customer_id ? k.stripe_customer_id : null;
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
  createCustomerPortalSession,
  findStripeCustomerBySession,
  verifyAndParseEvent,
  handleCheckoutCompleted,
  handleSubscriptionUpdated,
  isEventProcessed,
  getNewlyIssuedKey,
  findKeyBySession,
};
