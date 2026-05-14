'use strict';

// ---------------------------------------------------------------------------
// Customer-sealed audit content (Security Hardening Card — invent track).
// ---------------------------------------------------------------------------
// PROBLEM. Every SaaS — including Salesforce — stores audit log content
// fields in cleartext on the vendor's side. Encrypted-at-rest with
// vendor-managed keys checks the SOC2 box but the vendor still holds
// the keys, so a sufficiently privileged breach (rogue ops, stolen
// HSM access, exfiltrated KMS material) yields plaintext for every
// customer. The doctrine "we cant sell against integration tax and be
// guilty of it" applies here too: we sell determinism + sovereignty,
// so we must not be the vendor with the master key.
//
// INVENTION. Each audit row's content-sensitive fields are wrapped in
// an envelope: a per-row random AES-256-GCM content key, that key
// derived via X25519 ECDH against the customer's X25519 public key +
// HKDF-SHA256. We persist: ciphertext + nonce + ephemeral pubkey +
// auth tag + the per-row context (tenant_id, app_id, ts) bound through
// AEAD AAD. The customer (who holds the X25519 private key, returned
// to them ONCE at issuance) can derive the same shared secret and
// decrypt. The server CANNOT — the ephemeral private key was random,
// never persisted, and the customer's private key never crossed the
// wire after issuance. A full breach of cogos-api therefore yields
// ciphertext only.
//
// SEPARATE FROM AUTH. The customer's ed25519 keypair (Card #7) signs
// requests. Ed25519 and X25519 are different curves, and key reuse
// across signing + ECDH is a documented footgun (the math is
// "convertible" via low-level seed manipulation but Node 20 stdlib
// does not expose `crypto.convertEd25519PublicKey` — that API name
// from the design sketch does not exist). Rather than ship fragile
// curve-conversion code, we generate TWO independent keypairs at
// issuance time: ed25519 for AUTH SIGNING, x25519 for SEALING. The
// customer holds two private PEMs; both are shown once at issue and
// never re-displayable. The cost is one extra PEM in the issuance
// response; the benefit is that we do not lean on a fragile API that
// may or may not exist across Node minor versions.
//
// FIELDS SEALED. Only customer-content-sensitive fields ride inside
// the envelope: request_id, prompt_fingerprint, schema_name, and any
// future "context" fields. Metadata that the operator needs for
// billing + the chain to function (ts, tenant_id, app_id, key_id,
// route, status, prompt_tokens, completion_tokens, latency_ms,
// prev_hash, row_hash) STAYS CLEARTEXT. This is deliberate: the chain
// hashes the row WITH its sealed fields (because the on-disk shape is
// what gets hashed), so chain integrity is independent of whether the
// content fields are sealed or cleartext.
//
// AAD BINDING. The GCM auth tag covers `ciphertext` (built-in) PLUS
// `tenant_id || app_id || ts` (supplied as AAD). That binding means an
// attacker who lifts a sealed blob from one row cannot paste it onto a
// different row (different tenant, different app, or different
// timestamp) and have it decrypt — the AAD mismatch trips the GCM tag
// check and `unsealForPrivkey` throws. Without AAD binding the
// envelope would be context-free and the blob would be tenant-portable
// in the worst case.
//
// NEVERS. (1) The server MUST NOT call `unsealForPrivkey` in any
// production code path — it's exported for tests + future cookbook
// recipes only. (2) We never log the ephemeral private key (we don't
// retain it after the seal returns). (3) HKDF info string is
// versioned `cogos/seal/v1` so we can rotate the KDF without
// re-sealing old rows.
//
// ---------------------------------------------------------------------------
// On-disk envelope shape (added to a usage row when sealed === true):
//
//   sealed: true,
//   sealed_content: {
//     v: 1,                       // envelope version (bump on KDF/AEAD change)
//     alg: 'x25519-hkdf-aes-256-gcm',
//     ciphertext_b64: '...',      // base64 of GCM ciphertext
//     nonce_b64: '...',           // base64 of 12-byte GCM nonce
//     ephemeral_pub_b64: '...',   // base64 of raw 32-byte X25519 pubkey
//     tag_b64: '...',             // base64 of 16-byte GCM tag
//   }
//
// When sealed === false, the customer-content fields stay in their
// usual cleartext slots on the row (request_id, prompt_fingerprint,
// schema_name, ...). That's the legacy shape — backward compatible.

const crypto = require('crypto');

// HKDF parameters. SHA-256, info string is versioned, salt is empty
// (HKDF without salt is fine because the shared-secret is the
// high-entropy material; salt would help only against rainbow-table
// attacks against weak shared secrets — irrelevant here).
const HKDF_HASH = 'sha256';
const HKDF_INFO = Buffer.from('cogos/seal/v1', 'utf8');
const HKDF_SALT = Buffer.alloc(0);
const HKDF_KEY_LEN = 32; // AES-256

const GCM_NONCE_LEN = 12; // 96-bit nonce — GCM standard
const GCM_TAG_LEN = 16;   // 128-bit tag — GCM standard

const ENVELOPE_VERSION = 1;
const ENVELOPE_ALG = 'x25519-hkdf-aes-256-gcm';

// Build the AAD buffer that the GCM tag covers in addition to the
// ciphertext. Order is fixed (tenant_id || '|' || app_id || '|' || ts)
// and the separator is a byte that cannot appear in a tenant_id or
// app_id slug (we restrict those to [a-z0-9_-] elsewhere in the
// codebase; ts is an ISO-8601 string and contains no '|'). Using a
// non-collision separator means two distinct AAD tuples can never
// produce the same AAD byte sequence — a classic concatenation pitfall
// we deliberately avoid.
function buildAad({ tenant_id, app_id, ts }) {
  if (typeof tenant_id !== 'string' || tenant_id.length === 0) {
    throw new Error('buildAad: tenant_id required');
  }
  if (typeof app_id !== 'string' || app_id.length === 0) {
    throw new Error('buildAad: app_id required');
  }
  if (typeof ts !== 'string' || ts.length === 0) {
    throw new Error('buildAad: ts required');
  }
  return Buffer.from(`${tenant_id}|${app_id}|${ts}`, 'utf8');
}

// Derive the AES-256 content key from an ECDH shared secret. HKDF info
// is versioned `cogos/seal/v1` so a future rev (different AEAD, larger
// key, different nonce schedule) bumps the info string and old rows
// remain decryptable under v1 by inspecting envelope.v.
function deriveContentKey(sharedSecret) {
  const out = crypto.hkdfSync(HKDF_HASH, sharedSecret, HKDF_SALT, HKDF_INFO, HKDF_KEY_LEN);
  return Buffer.from(out);
}

// Seal `plaintext` (string or Buffer) for a customer holding the
// X25519 private key whose public PEM is `pubkeyPem`. The AAD object
// binds the envelope to a specific (tenant, app, ts) — a sealed blob
// lifted to a different row will fail to decrypt.
//
// Returns the envelope object that gets persisted alongside the row.
// The ephemeral private key is GENERATED HERE, USED ONCE, AND DROPPED
// when this function returns — Node's GC reclaims it. It is never
// logged, never persisted.
function sealForPubkey(pubkeyPem, plaintext, aad) {
  if (typeof pubkeyPem !== 'string' || !/BEGIN PUBLIC KEY/.test(pubkeyPem)) {
    throw new Error('sealForPubkey: pubkeyPem must be an X25519 SPKI PEM');
  }
  const ptBuf = Buffer.isBuffer(plaintext)
    ? plaintext
    : Buffer.from(String(plaintext), 'utf8');

  const customerPub = crypto.createPublicKey(pubkeyPem);
  if (customerPub.asymmetricKeyType !== 'x25519') {
    throw new Error(
      `sealForPubkey: expected x25519 pubkey, got ${customerPub.asymmetricKeyType}`,
    );
  }

  // Fresh ephemeral keypair per row — this is the "envelope key" half.
  const { publicKey: ephPub, privateKey: ephPriv } =
    crypto.generateKeyPairSync('x25519');

  // ECDH: derive the 32-byte shared secret from our ephemeral private
  // and the customer's persistent X25519 public. The customer will
  // recompute it from their persistent X25519 private + our ephemeral
  // public (which we store on the row in the clear — it's a public key).
  const sharedSecret = crypto.diffieHellman({
    privateKey: ephPriv,
    publicKey: customerPub,
  });

  const aesKey = deriveContentKey(sharedSecret);
  const nonce = crypto.randomBytes(GCM_NONCE_LEN);

  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, nonce, {
    authTagLength: GCM_TAG_LEN,
  });
  const aadBuf = buildAad(aad);
  cipher.setAAD(aadBuf);
  const ct = Buffer.concat([cipher.update(ptBuf), cipher.final()]);
  const tag = cipher.getAuthTag();

  // Extract raw 32-byte X25519 public from the JWK so we can ship it
  // as base64 (more compact + portable than PEM). The customer's
  // unseal step rebuilds the KeyObject from the raw bytes.
  const ephPubRaw = Buffer.from(ephPub.export({ format: 'jwk' }).x, 'base64url');

  return {
    v: ENVELOPE_VERSION,
    alg: ENVELOPE_ALG,
    ciphertext_b64: ct.toString('base64'),
    nonce_b64: nonce.toString('base64'),
    ephemeral_pub_b64: ephPubRaw.toString('base64'),
    tag_b64: tag.toString('base64'),
  };
}

// Decrypt an envelope using the customer's X25519 private PEM.
// PRODUCTION SERVER MUST NEVER CALL THIS — it's the customer's
// side of the protocol. Exported so the test suite + future cookbook
// recipes can round-trip envelopes.
//
// Throws if the envelope version/alg is unknown, if AAD doesn't match,
// or if the GCM tag fails (tamper detection).
function unsealForPrivkey(privkeyPem, envelope, aad) {
  if (!envelope || typeof envelope !== 'object') {
    throw new Error('unsealForPrivkey: envelope object required');
  }
  if (envelope.v !== ENVELOPE_VERSION) {
    throw new Error(`unsealForPrivkey: unknown envelope version ${envelope.v}`);
  }
  if (envelope.alg !== ENVELOPE_ALG) {
    throw new Error(`unsealForPrivkey: unknown envelope alg ${envelope.alg}`);
  }
  const customerPriv = crypto.createPrivateKey(privkeyPem);
  if (customerPriv.asymmetricKeyType !== 'x25519') {
    throw new Error(
      `unsealForPrivkey: expected x25519 privkey, got ${customerPriv.asymmetricKeyType}`,
    );
  }

  // Rebuild the ephemeral public KeyObject from the raw bytes.
  const ephPubRaw = Buffer.from(envelope.ephemeral_pub_b64, 'base64');
  if (ephPubRaw.length !== 32) {
    throw new Error('unsealForPrivkey: ephemeral_pub_b64 must decode to 32 bytes');
  }
  const ephPub = crypto.createPublicKey({
    key: { kty: 'OKP', crv: 'X25519', x: ephPubRaw.toString('base64url') },
    format: 'jwk',
  });

  const sharedSecret = crypto.diffieHellman({
    privateKey: customerPriv,
    publicKey: ephPub,
  });
  const aesKey = deriveContentKey(sharedSecret);

  const nonce = Buffer.from(envelope.nonce_b64, 'base64');
  const ct = Buffer.from(envelope.ciphertext_b64, 'base64');
  const tag = Buffer.from(envelope.tag_b64, 'base64');

  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, nonce, {
    authTagLength: GCM_TAG_LEN,
  });
  decipher.setAAD(buildAad(aad));
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return pt;
}

// Canonicalize the content payload before sealing. Keys are ordered;
// missing fields are omitted (so the envelope size is minimal). Two
// callers passing the same logical content produce the same bytes.
function canonicalContent(content) {
  const obj = {};
  if (content && typeof content === 'object') {
    if (content.request_id != null) obj.request_id = String(content.request_id);
    if (content.prompt_fingerprint != null) obj.prompt_fingerprint = String(content.prompt_fingerprint);
    if (content.schema_name != null) obj.schema_name = String(content.schema_name);
  }
  return JSON.stringify(obj);
}

// True if `pubkeyPem` looks like an X25519 SPKI PEM the seal path can
// accept. Used by callers (usage.record) to branch on
// sealed-vs-cleartext without try/catching the seal function.
function isSealablePubkey(pubkeyPem) {
  if (typeof pubkeyPem !== 'string' || !/BEGIN PUBLIC KEY/.test(pubkeyPem)) {
    return false;
  }
  try {
    const k = crypto.createPublicKey(pubkeyPem);
    return k.asymmetricKeyType === 'x25519';
  } catch (_e) {
    return false;
  }
}

module.exports = {
  sealForPubkey,
  unsealForPrivkey,
  canonicalContent,
  isSealablePubkey,
  ENVELOPE_VERSION,
  ENVELOPE_ALG,
  // exported for tests
  _internal: { buildAad, deriveContentKey, HKDF_INFO },
};
