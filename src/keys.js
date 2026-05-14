'use strict';

// API key store. Keys are issued with prefix `sk-cogos-` followed by 32
// hex chars. The plaintext is shown to the customer exactly once at issue
// time; only the sha256 hash is stored.
//
// Storage: JSON file (data/keys.json), mode 0600. Good enough for v1;
// swap for Postgres when the customer count justifies it.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const KEYS_FILE = process.env.KEYS_FILE
  || path.join(__dirname, '..', 'data', 'keys.json');

const PREFIX = 'sk-cogos-';

function ensureStore() {
  const dir = path.dirname(KEYS_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (!fs.existsSync(KEYS_FILE)) {
    fs.writeFileSync(KEYS_FILE, JSON.stringify([]), { mode: 0o600 });
  }
}

function readAll() {
  ensureStore();
  return JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8'));
}

function writeAll(records) {
  fs.writeFileSync(KEYS_FILE, JSON.stringify(records, null, 2), { mode: 0o600 });
}

function hashKey(plaintext) {
  return crypto.createHash('sha256').update(plaintext).digest('hex');
}

function newKeyPlaintext() {
  return PREFIX + crypto.randomBytes(16).toString('hex');
}

// HMAC secret for response signing. 32 bytes (256 bits) hex-encoded —
// same strength as the API key. Customers use it to verify
// X-Cogos-Signature on every /v1/* response. Stored in the record so the
// gateway can sign responses; shown to the customer ONCE at issue time
// alongside the API key (and never re-displayed).
function newHmacSecret() {
  return crypto.randomBytes(32).toString('hex');
}

// Issue a new API key for a tenant. Returns the plaintext (show once).
// `stripe` is optional metadata: { customer_id, subscription_id, status, email }
// `package_id` (optional) links the key to a package in packages.json for
// quota + tier enforcement. Falls back to default package at request time
// if unset (keeps backward compat with pre-packages keys).
function issue({ tenantId, label = '', tier = 'starter', package_id = null, stripe = null } = {}) {
  if (!tenantId) throw new Error('tenantId required');
  const plaintext = newKeyPlaintext();
  const hmac_secret = newHmacSecret();
  const record = {
    id: crypto.randomUUID(),
    key_hash: hashKey(plaintext),
    key_prefix: plaintext.slice(0, 16), // sk-cogos-XXXXXXXX — display hint, NOT auth
    hmac_secret, // used to sign /v1/* responses; surfaced to caller below
    tenant_id: tenantId,
    label,
    tier,
    package_id,
    active: true,
    issued_at: new Date().toISOString(),
    last_used_at: null,
    stripe_customer_id: (stripe && stripe.customer_id) || null,
    stripe_subscription_id: (stripe && stripe.subscription_id) || null,
    stripe_subscription_status: (stripe && stripe.status) || null,
    customer_email: (stripe && stripe.email) || null,
  };
  const records = readAll();
  records.push(record);
  writeAll(records);
  return {
    plaintext,
    hmac_secret,
    record: { ...record, key_hash: undefined, hmac_secret: undefined },
  };
}

// Find an existing record by Stripe customer ID (used by webhook handlers to
// update subscription status / revoke on cancellation).
function findByStripeCustomer(stripeCustomerId) {
  if (!stripeCustomerId) return null;
  const records = readAll();
  const found = records.find((r) => r.stripe_customer_id === stripeCustomerId && r.active);
  if (!found) return null;
  return { ...found, key_hash: undefined };
}

// Update an existing record's Stripe metadata + optionally toggle active.
function updateStripeStatus(keyId, { status, active }) {
  const records = readAll();
  const r = records.find((x) => x.id === keyId);
  if (!r) return false;
  if (status !== undefined) r.stripe_subscription_status = status;
  if (active !== undefined) {
    r.active = active;
    if (!active) r.revoked_at = new Date().toISOString();
  }
  r.stripe_updated_at = new Date().toISOString();
  writeAll(records);
  return true;
}

// Verify a presented bearer string. Returns the record if valid+active.
function verify(plaintext) {
  if (typeof plaintext !== 'string' || !plaintext.startsWith(PREFIX)) return null;
  const records = readAll();
  const hash = hashKey(plaintext);
  const found = records.find((r) => r.key_hash === hash && r.active);
  if (!found) return null;
  // Best-effort last_used_at touch + lazy hmac_secret backfill for keys
  // issued before HMAC signing was introduced. The customer can never
  // see the backfilled secret (not on success page anymore), but the
  // gateway can still sign responses for it. To get a verifiable
  // signature, the customer rotates to a new key.
  try {
    found.last_used_at = new Date().toISOString();
    if (!found.hmac_secret) found.hmac_secret = newHmacSecret();
    writeAll(records);
  } catch (_e) { /* no-op */ }
  return { ...found, key_hash: undefined };
}

function list() {
  return readAll().map((r) => ({ ...r, key_hash: undefined }));
}

function revoke(id) {
  const records = readAll();
  const r = records.find((x) => x.id === id);
  if (!r) return false;
  r.active = false;
  r.revoked_at = new Date().toISOString();
  writeAll(records);
  return true;
}

module.exports = { issue, verify, list, revoke, findByStripeCustomer, updateStripeStatus, PREFIX };
