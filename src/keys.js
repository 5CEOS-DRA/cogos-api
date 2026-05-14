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

// Generate a stable ed25519 key id for the Authorization header `keyId=`
// field. Public, customer-visible; not authoritative (the signature is).
// Format: `kid-` + 16 hex chars (8 bytes of entropy = 64 bits; collision
// space is fine for the customer-count horizon, and a server-side index
// on this string is the lookup path).
function newEd25519KeyId() {
  return 'kid-' + crypto.randomBytes(8).toString('hex');
}

// Issue a new API key for a tenant. Returns the plaintext (show once).
// `stripe` is optional metadata: { customer_id, subscription_id, status, email }
// `package_id` (optional) links the key to a package in packages.json for
// quota + tier enforcement. Falls back to default package at request time
// if unset (keeps backward compat with pre-packages keys).
//
// `scheme` selects the auth substrate. Default 'bearer' is the legacy
// hash-of-plaintext model (we store sha256(plaintext); customer holds the
// plaintext). 'ed25519' generates a fresh keypair server-side, returns
// the private key PEM to the caller ONCE, and persists only the public
// key PEM + a stable keyId. After issuance the server has no reusable
// customer auth material at rest for that record — the private key never
// lands on disk.
//
// A bearer-scheme record retains its bearer fields untouched (so existing
// callers keep working). An ed25519-scheme record sets key_hash/key_prefix
// to null and instead carries { scheme:'ed25519', ed25519_key_id, pubkey_pem }.
// hmac_secret is issued for both schemes so the response-signing path
// stays uniform.
function issue({
  tenantId,
  label = '',
  tier = 'starter',
  package_id = null,
  stripe = null,
  scheme = 'bearer',
} = {}) {
  if (!tenantId) throw new Error('tenantId required');
  if (scheme !== 'bearer' && scheme !== 'ed25519') {
    throw new Error(`unknown scheme: ${scheme}`);
  }
  const hmac_secret = newHmacSecret();

  // Branch on scheme. Both branches produce a record + a return payload
  // that mirrors the bearer one (plaintext-equivalent shown ONCE).
  let plaintext = null;
  let private_pem = null;
  let pubkey_pem = null;
  let ed25519_key_id = null;
  let key_hash = null;
  let key_prefix = null;

  if (scheme === 'bearer') {
    plaintext = newKeyPlaintext();
    key_hash = hashKey(plaintext);
    key_prefix = plaintext.slice(0, 16); // sk-cogos-XXXXXXXX — display hint, NOT auth
  } else {
    // Ed25519: server generates the pair, exports both as PEM, and only
    // the public PEM is persisted. private_pem is returned to the caller
    // and must not be retained server-side after this function returns.
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    pubkey_pem = publicKey.export({ type: 'spki', format: 'pem' });
    private_pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    ed25519_key_id = newEd25519KeyId();
  }

  const record = {
    id: crypto.randomUUID(),
    scheme,                      // 'bearer' | 'ed25519' — dispatcher hint
    key_hash,                    // bearer-only; null for ed25519
    key_prefix,                  // bearer-only; null for ed25519
    ed25519_key_id,              // ed25519-only; null for bearer
    pubkey_pem,                  // ed25519-only; null for bearer
    hmac_secret,                 // used to sign /v1/* responses; surfaced to caller below
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
    plaintext,                    // null for ed25519
    private_pem,                  // null for bearer
    pubkey_pem,                   // null for bearer
    ed25519_key_id,               // null for bearer
    hmac_secret,
    record: { ...record, key_hash: undefined, hmac_secret: undefined },
  };
}

// Look up an ed25519 record by the public keyId from the Authorization
// header. Returns the full record (sans key_hash) or null. Active flag
// is NOT filtered here so the middleware can distinguish "doesn't exist"
// from "revoked" and return a clearer 401 reason.
function findByEd25519KeyId(keyId) {
  if (typeof keyId !== 'string' || !keyId) return null;
  const records = readAll();
  const found = records.find((r) => r.ed25519_key_id === keyId);
  if (!found) return null;
  return { ...found, key_hash: undefined };
}

// Touch last_used_at for an ed25519 record after a successful verification.
// Mirrors the in-place mutation that `verify()` does for bearer keys, but
// kept out of findByEd25519KeyId() so reads are clean and writes only
// happen on the success path in the middleware.
function touchLastUsed(recordId) {
  if (!recordId) return;
  try {
    const records = readAll();
    const r = records.find((x) => x.id === recordId);
    if (!r) return;
    r.last_used_at = new Date().toISOString();
    writeAll(records);
  } catch (_e) { /* no-op */ }
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

module.exports = {
  issue,
  verify,
  list,
  revoke,
  findByStripeCustomer,
  updateStripeStatus,
  findByEd25519KeyId,
  touchLastUsed,
  PREFIX,
};
