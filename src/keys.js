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

// ---------------------------------------------------------------------------
// Multi-app namespace (round 1 of customer-sealed audit).
// ---------------------------------------------------------------------------
// Every key carries an `app_id` tag. The (tenant_id, app_id) tuple is the
// new partition key — each app gets its own audit chain head, its own
// anomaly bucket, and its own slice of /v1/audit. Backward compatibility:
// pre-multi-app records lack app_id; readers MUST treat NULL/missing as
// the default app `_default`. There is NO migration to backfill — absent
// is interpreted, not rewritten.
const DEFAULT_APP_ID = '_default';
const APP_ID_PATTERN = /^[a-z0-9_-]+$/;
const APP_ID_MAX_LEN = 64;

// Validate + normalize an app_id input. Returns DEFAULT_APP_ID for
// null/undefined/empty. Throws on shape violations (slug-style only,
// matches the same constraint we put on tenant_id implicitly throughout
// the gateway). The DEFAULT_APP_ID leading underscore is allowed by the
// regex; no further special-case needed.
function normalizeAppId(input) {
  if (input == null || input === '') return DEFAULT_APP_ID;
  if (typeof input !== 'string') {
    throw new Error('app_id must be a string');
  }
  if (input.length > APP_ID_MAX_LEN) {
    throw new Error(`app_id exceeds ${APP_ID_MAX_LEN} chars`);
  }
  if (!APP_ID_PATTERN.test(input)) {
    throw new Error('app_id must match [a-z0-9_-]+');
  }
  return input;
}

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
//
// SEALING KEYPAIR (customer-sealed audit, sibling of ed25519 scheme).
// At ed25519 issuance time we ALSO generate an independent X25519
// keypair. We persist only the X25519 public PEM (so usage.record can
// seal new rows for this customer) and return the X25519 private PEM
// to the caller ONCE alongside the ed25519 private. Ed25519 and X25519
// are different curves — auth signing uses ed25519, audit decryption
// uses x25519. Node 20 stdlib does NOT expose
// crypto.convertEd25519PublicKey, and the seed-level convertibility
// trick is fragile across minor versions, so we ship two independent
// keypairs. The cost is one extra PEM in the issuance response; the
// benefit is no fragile curve-conversion shim.
//
// Bearer-scheme keys are NOT issued an x25519 keypair. A bearer
// customer's audit rows stay cleartext (sealed:false), which matches
// the doctrine that sealing is opt-in via the ed25519 scheme.
function issue({
  tenantId,
  app_id = null,
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
  // Validate-and-normalize. Null/undefined/empty all collapse to
  // DEFAULT_APP_ID so callers who never pass app_id still get a sane tag.
  const resolvedAppId = normalizeAppId(app_id);
  const hmac_secret = newHmacSecret();

  // Branch on scheme. Both branches produce a record + a return payload
  // that mirrors the bearer one (plaintext-equivalent shown ONCE).
  let plaintext = null;
  let private_pem = null;
  let pubkey_pem = null;
  let ed25519_key_id = null;
  let key_hash = null;
  let key_prefix = null;
  // Sealing keypair (x25519). Only generated for ed25519-scheme keys.
  let x25519_private_pem = null;
  let x25519_pubkey_pem = null;

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

    // X25519: independent sealing keypair (see header comment). Only
    // the public PEM is persisted; the private is returned to the
    // caller ONCE and is never reachable from the server afterward.
    const x = crypto.generateKeyPairSync('x25519');
    x25519_pubkey_pem = x.publicKey.export({ type: 'spki', format: 'pem' });
    x25519_private_pem = x.privateKey.export({ type: 'pkcs8', format: 'pem' });
  }

  const record = {
    id: crypto.randomUUID(),
    scheme,                      // 'bearer' | 'ed25519' — dispatcher hint
    key_hash,                    // bearer-only; null for ed25519
    key_prefix,                  // bearer-only; null for ed25519
    ed25519_key_id,              // ed25519-only; null for bearer
    pubkey_pem,                  // ed25519-only; null for bearer
    x25519_pubkey_pem,           // ed25519-only sealing pubkey; null for bearer
    hmac_secret,                 // used to sign /v1/* responses; surfaced to caller below
    tenant_id: tenantId,
    app_id: resolvedAppId,       // partition key for audit chain + anomaly + future RBAC
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
    private_pem,                  // null for bearer (ed25519 auth-signing private)
    pubkey_pem,                   // null for bearer (ed25519 auth-signing public)
    ed25519_key_id,               // null for bearer
    x25519_private_pem,           // null for bearer (sealing/decryption private)
    x25519_pubkey_pem,            // null for bearer (sealing/encryption public)
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
  // app_id read-time backfill: pre-multi-app records have no app_id.
  // Treat absent as DEFAULT_APP_ID so downstream auth + audit logic
  // never has to special-case null. We do NOT rewrite the file — the
  // record on disk stays untagged, which keeps the original snapshot
  // recoverable if the migration semantics ever need to change.
  const out = { ...found, key_hash: undefined };
  if (out.app_id == null) out.app_id = DEFAULT_APP_ID;
  return out;
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
  const out = { ...found, key_hash: undefined };
  // app_id read-time backfill: pre-multi-app records have no app_id.
  // Treat absent as DEFAULT_APP_ID so chat-api can always pass a
  // concrete app_id to usage.record() without a null-coalesce on every
  // hot-path request.
  if (out.app_id == null) out.app_id = DEFAULT_APP_ID;
  return out;
}

function list({ tenant_id, app_id } = {}) {
  // Optional (tenant_id, app_id) filter for the multi-app browse story.
  // app_id alone is rejected (would cross-tenant) — callers must scope
  // to a tenant first. tenant_id alone returns every app for that tenant.
  // No-arg call keeps the original "list everything" semantics for the
  // operator-only /admin/keys surface.
  let rows = readAll();
  if (tenant_id) {
    rows = rows.filter((r) => r.tenant_id === tenant_id);
    if (app_id != null) {
      const wanted = normalizeAppId(app_id);
      rows = rows.filter((r) => (r.app_id || DEFAULT_APP_ID) === wanted);
    }
  } else if (app_id != null) {
    throw new Error('app_id filter requires tenant_id');
  }
  return rows.map((r) => {
    const out = { ...r, key_hash: undefined };
    if (out.app_id == null) out.app_id = DEFAULT_APP_ID;
    return out;
  });
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
  normalizeAppId,
  PREFIX,
  DEFAULT_APP_ID,
};
