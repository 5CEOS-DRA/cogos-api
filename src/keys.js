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
const dek = require('./dek');

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
//
// AT-REST REPRESENTATION (revised 2026-05-14, sec-encrypt-at-rest card):
// the on-disk record carries `hmac_secret_sealed: {ciphertext_b64,
// nonce_b64, tag_b64}` instead of cleartext `hmac_secret`. See src/dek.js
// for the envelope-encryption substrate. Backward compatible: legacy
// records with cleartext `hmac_secret` keep working — readers fall back
// to the cleartext field when `hmac_secret_sealed` is absent, and the
// next touch of the record (verify's last_used_at write, etc.) will
// migrate it to the sealed shape.
function newHmacSecret() {
  return crypto.randomBytes(32).toString('hex');
}

// Seal a cleartext HMAC secret (hex string) under the DEK. Returns the
// envelope object suitable for direct embedding in a record under
// `hmac_secret_sealed`.
function _sealHmacSecret(secretHex) {
  return dek.seal(Buffer.from(String(secretHex), 'utf8'));
}

// Decrypt a record's HMAC secret. Returns:
//   - record.hmac_secret_sealed → opened cleartext hex string
//   - record.hmac_secret (legacy cleartext fallback) → as-is
//   - neither present → null (caller decides whether to lazy-generate)
// Never throws on shape errors; returns null instead so the caller can
// take the lazy-backfill branch.
function _decryptHmacSecret(record) {
  if (!record) return null;
  if (dek.isSealed(record.hmac_secret_sealed)) {
    try {
      return dek.open(record.hmac_secret_sealed).toString('utf8');
    } catch (_e) {
      // Wrong DEK or tampered ciphertext. Treat as missing so the caller
      // can decide whether to fail the request or backfill. Surfacing as
      // null avoids leaking the wrong-DEK signal through the auth path.
      return null;
    }
  }
  if (typeof record.hmac_secret === 'string' && record.hmac_secret) {
    return record.hmac_secret;
  }
  return null;
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
// Default key expiration: 1 year from issuance. Long-lived secrets get
// stolen; an explicit ceiling forces a rotation/renewal cadence. Tunable
// per-tier in the future; for v1 every tier gets the same window.
const DEFAULT_KEY_LIFETIME_MS = 365 * 24 * 60 * 60_000;

function issue({
  tenantId,
  app_id = null,
  label = '',
  tier = 'starter',
  package_id = null,
  stripe = null,
  scheme = 'bearer',
  expires_at_iso = null,
  // Channel attribution: who/where did this key originate from? Captured
  // at /signup/free POST (referer + UTM params + user-agent). Operator
  // reads this via /admin/keys to answer "which distribution channel
  // brings developers." Shape: { referer, ua, utm_source, utm_medium,
  // utm_campaign, utm_content, utm_term, ip, ts } — all fields optional.
  // Null = no attribution captured (e.g. operator-issued admin keys).
  signup_source = null,
} = {}) {
  if (!tenantId) throw new Error('tenantId required');
  if (scheme !== 'bearer' && scheme !== 'ed25519') {
    throw new Error(`unknown scheme: ${scheme}`);
  }
  // Resolve expires_at. Caller-provided ISO wins; otherwise default to
  // now + DEFAULT_KEY_LIFETIME_MS. We accept and re-serialize so a malformed
  // string fails LOUDLY at issue time, not later at verify time. A past
  // ISO is allowed (operator may issue an already-expired key for testing
  // / negative scenarios); auth path treats it as expired.
  let resolvedExpiresAt = null;
  if (expires_at_iso != null && expires_at_iso !== '') {
    if (typeof expires_at_iso !== 'string') {
      throw new Error('expires_at_iso must be a string');
    }
    const parsed = Date.parse(expires_at_iso);
    if (!Number.isFinite(parsed)) {
      throw new Error('expires_at_iso must be a parseable ISO-8601 timestamp');
    }
    resolvedExpiresAt = new Date(parsed).toISOString();
  } else {
    resolvedExpiresAt = new Date(Date.now() + DEFAULT_KEY_LIFETIME_MS).toISOString();
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

  // At rest the HMAC secret is sealed under the DEK. Cleartext is held
  // only on this function's stack + the return payload (so the caller can
  // show it to the customer ONCE). The on-disk record carries only the
  // sealed envelope. See src/dek.js + the _decryptHmacSecret() helper.
  const hmac_secret_sealed = _sealHmacSecret(hmac_secret);

  const record = {
    id: crypto.randomUUID(),
    scheme,                      // 'bearer' | 'ed25519' — dispatcher hint
    key_hash,                    // bearer-only; null for ed25519
    key_prefix,                  // bearer-only; null for ed25519
    ed25519_key_id,              // ed25519-only; null for bearer
    pubkey_pem,                  // ed25519-only; null for bearer
    x25519_pubkey_pem,           // ed25519-only sealing pubkey; null for bearer
    hmac_secret_sealed,          // sealed envelope; replaces cleartext hmac_secret at rest
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
    // Lifecycle: expires_at is set at issue time and never extended.
    // Auth path rejects with `expired_api_key` past this point.
    expires_at: resolvedExpiresAt,
    // rotation_grace_until — ms-epoch on the OLD record at rotation
    // time. During the grace window the old key still authenticates and
    // the response carries X-Cogos-Key-Deprecated. After grace,
    // verify() auto-revokes on next touch.
    rotation_grace_until: null,
    // quarantined_at — ms-epoch; non-null = key is held for review.
    // Auth path rejects with `key_quarantined_for_review`. Cleared by
    // operator via /admin/keys/:id/clear-quarantine. Trigger is
    // anomaly-driven (scanner_active + recent valid auth from same IP
    // within 60s, fail-closed mode only).
    quarantined_at: null,
    quarantine_reason: null,
    signup_source: signup_source || null,
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
    record: {
      ...record,
      key_hash: undefined,
      hmac_secret: undefined,
      hmac_secret_sealed: undefined,
    },
  };
}

// Look up an ed25519 record by the public keyId from the Authorization
// header. Returns the full record (sans key_hash) or null. Active flag
// is NOT filtered here so the middleware can distinguish "doesn't exist"
// from "revoked" and return a clearer 401 reason.
//
// Rotation grace: if the record's rotation_grace_until has elapsed,
// auto-revoke in place (mirrors verify() for the bearer path). If the
// grace window is still open, surface `_rotation_grace=true` on the
// returned record so the auth middleware can emit X-Cogos-Key-Deprecated.
function findByEd25519KeyId(keyId) {
  if (typeof keyId !== 'string' || !keyId) return null;
  const records = readAll();
  const found = records.find((r) => r.ed25519_key_id === keyId);
  if (!found) return null;
  const nowMs = Date.now();
  if (found.active && found.rotation_grace_until
      && nowMs > found.rotation_grace_until) {
    found.active = false;
    found.revoked_at = new Date().toISOString();
    found.revoke_reason = 'rotation_grace_expired';
    try { writeAll(records); } catch (_e) { /* no-op */ }
  }
  // app_id read-time backfill: pre-multi-app records have no app_id.
  // Treat absent as DEFAULT_APP_ID so downstream auth + audit logic
  // never has to special-case null. We do NOT rewrite the file — the
  // record on disk stays untagged, which keeps the original snapshot
  // recoverable if the migration semantics ever need to change.
  //
  // HMAC secret read-time decrypt: downstream chat-api.js reads
  // req.apiKey.hmac_secret to sign /v1/* responses. Materialize the
  // cleartext here from the sealed envelope (or the legacy cleartext
  // field on pre-migration records). Disk record stays sealed.
  const out = { ...found, key_hash: undefined };
  const hmacCleartext = _decryptHmacSecret(found);
  if (hmacCleartext) out.hmac_secret = hmacCleartext;
  if (out.app_id == null) out.app_id = DEFAULT_APP_ID;
  if (found.active && found.rotation_grace_until
      && nowMs <= found.rotation_grace_until) {
    out._rotation_grace = true;
  }
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
  // Strip all HMAC material — this path is for webhook status updates
  // (subscription change → toggle active) and downstream callers should
  // not be handling cleartext secrets here.
  return {
    ...found,
    key_hash: undefined,
    hmac_secret: undefined,
    hmac_secret_sealed: undefined,
  };
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

// Stamp first_call_at exactly once per key. Caller is expected to gate
// with an in-memory Set so we don't pay the readAll/writeAll round-trip
// on every chat-completion — see src/early-adopter.js. Returns the
// previous value (null if this was the first stamp; ISO string if it
// was already set, in which case the in-memory cache was stale).
function markFirstCallAt(keyId, isoTs) {
  const records = readAll();
  const r = records.find((x) => x.id === keyId);
  if (!r) return null;
  const prev = r.first_call_at || null;
  if (prev) return prev;
  r.first_call_at = isoTs;
  writeAll(records);
  return null;
}

// Verify a presented bearer string. Returns the record if valid+active.
//
// Rotation grace (2026-05-15):
//   - If `rotation_grace_until` has elapsed, auto-revoke the record in
//     place and return null so downstream sees a clean revoke (no
//     zombie key linger).
//   - If `rotation_grace_until > now`, the OLD key is in active grace:
//     mark `_rotation_grace=true` on the returned record so auth.js can
//     append the X-Cogos-Key-Deprecated response header. The new key
//     was issued by rotate() with no grace flag.
function verify(plaintext) {
  if (typeof plaintext !== 'string' || !plaintext.startsWith(PREFIX)) return null;
  const records = readAll();
  const hash = hashKey(plaintext);
  const found = records.find((r) => r.key_hash === hash && r.active);
  if (!found) return null;
  // Auto-revoke if rotation grace window has expired. After rotation,
  // the old record stays auth-able for 24h via rotation_grace_until; once
  // past, the verify path retires it. Belt-and-suspenders against the
  // edge case where the customer never actually rotated to the new key.
  const nowMs = Date.now();
  if (found.rotation_grace_until && nowMs > found.rotation_grace_until) {
    found.active = false;
    found.revoked_at = new Date().toISOString();
    found.revoke_reason = 'rotation_grace_expired';
    try { writeAll(records); } catch (_e) { /* no-op */ }
    return null;
  }
  // Resolve the cleartext HMAC secret. Order:
  //   1. found.hmac_secret_sealed → open under DEK (the new shape).
  //   2. found.hmac_secret (legacy cleartext) → use as-is.
  //   3. neither present → lazy-generate a fresh one (keys issued before
  //      HMAC signing was introduced). The customer can never see the
  //      backfilled secret (not on the success page anymore), but the
  //      gateway can still sign responses for it. To get a verifiable
  //      signature, the customer rotates to a new key.
  let hmacCleartext = _decryptHmacSecret(found);
  let didMigrate = false;
  if (!hmacCleartext) {
    hmacCleartext = newHmacSecret();
    didMigrate = true;
  }
  // Best-effort last_used_at touch + lazy migration to the sealed shape.
  // Any record that gets touched on the verify path is rewritten with
  // hmac_secret_sealed and cleartext hmac_secret stripped — the disk
  // moves toward fully-sealed-at-rest one verify at a time.
  try {
    found.last_used_at = new Date().toISOString();
    if (!found.hmac_secret_sealed || didMigrate) {
      found.hmac_secret_sealed = _sealHmacSecret(hmacCleartext);
    }
    if ('hmac_secret' in found) delete found.hmac_secret;
    writeAll(records);
  } catch (_e) { /* no-op */ }
  // Materialize an in-memory record for the request path. Downstream
  // chat-api.js reads req.apiKey.hmac_secret, so we attach the cleartext
  // hex here. The on-disk record stays sealed.
  const out = { ...found, key_hash: undefined, hmac_secret: hmacCleartext };
  // app_id read-time backfill: pre-multi-app records have no app_id.
  // Treat absent as DEFAULT_APP_ID so chat-api can always pass a
  // concrete app_id to usage.record() without a null-coalesce on every
  // hot-path request.
  if (out.app_id == null) out.app_id = DEFAULT_APP_ID;
  if (found.rotation_grace_until && nowMs <= found.rotation_grace_until) {
    out._rotation_grace = true;
  }
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
    // Strip both key_hash AND any HMAC secret material (sealed envelope
    // or legacy cleartext). The /admin/keys list surface should never
    // surface either — operators see metadata only.
    const out = {
      ...r,
      key_hash: undefined,
      hmac_secret: undefined,
      hmac_secret_sealed: undefined,
    };
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

// ---------------------------------------------------------------------------
// Rotation (2026-05-15 — key lifecycle card, commit 2/3).
// ---------------------------------------------------------------------------
//
// 24h grace window — long enough that a customer running rotation from a
// CI pipeline can roll their app's deploys at their own cadence; short
// enough that a leaked credential isn't valid for weeks. 24h is the
// smallest window that comfortably accommodates a once-a-day deploy.
const ROTATION_GRACE_MS = 24 * 60 * 60_000;

// Rotate a key. The OLD record is stamped with rotation_grace_until =
// now + 24h and stays active during the grace window — verify() returns
// it with `_rotation_grace=true` so auth.js can append a deprecation
// header. After the grace window, verify() auto-revokes on next touch.
//
// The NEW record inherits tenant_id, app_id, tier, package_id, and
// CRUCIALLY the OLD record's expires_at — a rotation is not a renewal.
// Operator-policy decision: rotation is for "this key may be leaked,"
// not "I want another year." Renewal is a separate (future) flow.
//
// `callerRecord` is the verified record from the auth middleware. We
// re-read it from disk here to get the canonical state.
//
// Returns the same shape as issue() so the route handler can reuse the
// display logic. Throws if the record doesn't exist or has been revoked
// between auth and rotate (rare; clear error beats a silent partial).
function rotate(callerRecord) {
  if (!callerRecord || !callerRecord.id) {
    throw new Error('rotate requires the authenticated caller record');
  }
  const records = readAll();
  const old = records.find((r) => r.id === callerRecord.id);
  if (!old) throw new Error('caller record not found in store');
  if (!old.active) throw new Error('cannot rotate a revoked key');

  // Issue the new record. We DO NOT call issue() directly because issue()
  // would mint a fresh expires_at; rotation carries the parent's window
  // forward. We replicate the issue() shape inline so the new record is
  // identical in every other field.
  const hmac_secret = newHmacSecret();
  let plaintext = null;
  let private_pem = null;
  let pubkey_pem = null;
  let ed25519_key_id = null;
  let key_hash = null;
  let key_prefix = null;
  let x25519_private_pem = null;
  let x25519_pubkey_pem = null;

  if (old.scheme === 'bearer') {
    plaintext = newKeyPlaintext();
    key_hash = hashKey(plaintext);
    key_prefix = plaintext.slice(0, 16);
  } else if (old.scheme === 'ed25519') {
    const kp = crypto.generateKeyPairSync('ed25519');
    pubkey_pem = kp.publicKey.export({ type: 'spki', format: 'pem' });
    private_pem = kp.privateKey.export({ type: 'pkcs8', format: 'pem' });
    ed25519_key_id = newEd25519KeyId();
    const x = crypto.generateKeyPairSync('x25519');
    x25519_pubkey_pem = x.publicKey.export({ type: 'spki', format: 'pem' });
    x25519_private_pem = x.privateKey.export({ type: 'pkcs8', format: 'pem' });
  } else {
    throw new Error(`cannot rotate unknown scheme: ${old.scheme}`);
  }

  const newRecord = {
    id: crypto.randomUUID(),
    scheme: old.scheme,
    key_hash,
    key_prefix,
    ed25519_key_id,
    pubkey_pem,
    x25519_pubkey_pem,
    hmac_secret,
    tenant_id: old.tenant_id,
    app_id: old.app_id || DEFAULT_APP_ID,
    label: old.label || '',
    tier: old.tier,
    package_id: old.package_id || null,
    active: true,
    issued_at: new Date().toISOString(),
    last_used_at: null,
    stripe_customer_id: old.stripe_customer_id || null,
    stripe_subscription_id: old.stripe_subscription_id || null,
    stripe_subscription_status: old.stripe_subscription_status || null,
    customer_email: old.customer_email || null,
    // expires_at carries forward — rotation is not renewal.
    expires_at: old.expires_at || null,
    rotation_grace_until: null,
    // Provenance — links new key back to its parent for the audit story.
    rotated_from_key_id: old.id,
  };

  // Stamp the OLD record's grace window. It stays active=true; verify()
  // auto-revokes on first touch past the deadline.
  old.rotation_grace_until = Date.now() + ROTATION_GRACE_MS;
  old.rotated_to_key_id = newRecord.id;

  records.push(newRecord);
  writeAll(records);

  return {
    plaintext,
    private_pem,
    pubkey_pem,
    ed25519_key_id,
    x25519_private_pem,
    x25519_pubkey_pem,
    hmac_secret,
    record: { ...newRecord, key_hash: undefined, hmac_secret: undefined },
    rotation_grace_until_iso: new Date(old.rotation_grace_until).toISOString(),
    rotated_from_key_id: old.id,
  };
}

// ---------------------------------------------------------------------------
// Quarantine (2026-05-15 — key lifecycle card, commit 3/3).
// ---------------------------------------------------------------------------
//
// Quarantine a key. Idempotent — calling on an already-quarantined key
// is a no-op (preserves the original quarantine timestamp + reason).
// Quarantine is fail-closed: auth.js returns 401
// `key_quarantined_for_review` until the operator clears it explicitly.
function quarantine(id, reason) {
  if (!id) return false;
  const records = readAll();
  const r = records.find((x) => x.id === id);
  if (!r) return false;
  if (r.quarantined_at) return true; // already quarantined; no rewrite
  r.quarantined_at = Date.now();
  r.quarantine_reason = String(reason || 'unspecified');
  writeAll(records);
  return true;
}

// Operator-driven clear. Reverse of quarantine(). Preserves the original
// quarantine timestamp+reason as quarantine_history so a key bouncing
// in/out of quarantine leaves a trail (that itself is a signal).
function clearQuarantine(id) {
  if (!id) return false;
  const records = readAll();
  const r = records.find((x) => x.id === id);
  if (!r) return false;
  if (!r.quarantined_at) return false; // nothing to clear
  if (!Array.isArray(r.quarantine_history)) r.quarantine_history = [];
  r.quarantine_history.push({
    quarantined_at: r.quarantined_at,
    quarantine_reason: r.quarantine_reason || null,
    cleared_at: Date.now(),
  });
  r.quarantined_at = null;
  r.quarantine_reason = null;
  writeAll(records);
  return true;
}

// Return every record currently quarantined. Operator visibility surface
// for /admin/keys/quarantined.
function listQuarantined() {
  return readAll()
    .filter((r) => r.quarantined_at)
    .map((r) => {
      const out = { ...r, key_hash: undefined };
      if (out.app_id == null) out.app_id = DEFAULT_APP_ID;
      return out;
    });
}

// Internal lookup used by the admin clear-quarantine route to disambig-
// uate 404 (no such key) from 409 (key exists but isn't quarantined).
// Returns the record sans key_hash, or null.
function findById(id) {
  if (!id) return null;
  const records = readAll();
  const r = records.find((x) => x.id === id);
  if (!r) return null;
  const out = { ...r, key_hash: undefined };
  if (out.app_id == null) out.app_id = DEFAULT_APP_ID;
  return out;
}

module.exports = {
  issue,
  verify,
  list,
  revoke,
  rotate,
  quarantine,
  clearQuarantine,
  listQuarantined,
  findById,
  findByStripeCustomer,
  updateStripeStatus,
  markFirstCallAt,
  findByEd25519KeyId,
  touchLastUsed,
  normalizeAppId,
  PREFIX,
  DEFAULT_APP_ID,
  DEFAULT_KEY_LIFETIME_MS,
  ROTATION_GRACE_MS,
};
