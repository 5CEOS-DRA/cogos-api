'use strict';

// Data Encryption Key (DEK) — envelope encryption for at-rest secrets.
//
// PROBLEM THIS PRIMITIVE SOLVES
// -----------------------------------------------------------------------------
// Two cryptographic secrets sit on the writable Azure Files volume:
//   1. HMAC secrets (`hmac_secret` per customer record in `data/keys.json`).
//      The server NEEDS the cleartext to sign every /v1/* response body. If
//      `keys.json` leaks, an attacker can forge `X-Cogos-Signature` headers
//      for any customer.
//   2. The attestation signing private PEM (`data/attestation-key.pem`).
//      Persisted across container restarts so previously-issued receipts
//      stay verifiable. If the file leaks, an attacker can forge attestation
//      tokens.
//
// Both of these need to live on disk in some form. The fix is envelope
// encryption: an out-of-band Data Encryption Key (DEK) decrypts the at-rest
// blobs into memory at startup or on-demand. Disk breach yields ciphertext
// only. KV breach OR memory breach OR runtime-process compromise is still
// bad — those are different threat models and are handled by other primitives
// (managed identity, distroless runtime, attestation receipts).
//
// DEK SOURCE PRIORITY (first match wins):
//   1. `COGOS_DEK_HEX` env — 64-char hex string (32 raw bytes).
//      In production this is set on the Container App via a Key Vault secret
//      reference (operator-managed; out of scope for this module).
//   2. `COGOS_DEK_FILE` env — path to a file containing the 64-char hex string
//      OR 32 raw bytes. Used by operator scripts that mount a secret file.
//   3. On-disk fallback at `data/.dek` (mode 0600). Generated lazily on first
//      access so dev + early-prod runs work without KV wiring. Production
//      operators flip to source #1 once Key Vault is wired.
//
// AT-REST CIPHER: AES-256-GCM (Node stdlib `crypto`, no new deps).
//   - 32-byte key
//   - 12-byte random nonce per seal (NIST SP 800-38D recommendation)
//   - 16-byte auth tag
//   - no AAD (the records have their own integrity via the audit chain +
//     HMAC response signatures + attestation receipts)
//
// THE NONCE IS RANDOM, NOT A COUNTER. GCM allows ~2^32 random nonces under
// the same key before collision risk becomes meaningful (~10 billion seals).
// For this workload (one seal per HMAC secret + one per attestation key
// rotation) that ceiling is unreachable.
//
// CACHED IN-PROCESS. Re-read on `_internal._reset()` for tests.

const crypto = require('crypto');
const fs = require('node:fs');
const path = require('node:path');

const KEY_BYTES = 32;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;

let _dekCache = null;
let _sourceCache = null; // 'env' | 'file' | 'generated' — for startup logging

function _defaultGeneratedPath() {
  return path.join(process.cwd(), 'data', '.dek');
}

// Parse a hex string OR raw 32 bytes from a Buffer. Throws on shape mismatch.
function _parseKeyMaterial(buf, sourceLabel) {
  // hex shape: 64 ASCII chars (a-fA-F0-9), with optional trailing whitespace.
  const trimmed = buf.toString('utf8').trim();
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    return Buffer.from(trimmed, 'hex');
  }
  // raw 32-byte shape: the file IS the key.
  if (buf.length === KEY_BYTES) {
    return Buffer.from(buf);
  }
  throw new Error(
    `${sourceLabel} must be a 64-char hex string or a 32-byte raw key (got ${buf.length} bytes)`,
  );
}

function _loadFromEnv() {
  const hex = process.env.COGOS_DEK_HEX;
  if (!hex) return null;
  const trimmed = String(hex).trim();
  if (!/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    throw new Error('COGOS_DEK_HEX must be a 64-char hex string (32 bytes)');
  }
  _sourceCache = 'env';
  return Buffer.from(trimmed, 'hex');
}

function _loadFromFile() {
  const filePath = process.env.COGOS_DEK_FILE;
  if (!filePath) return null;
  let raw;
  try {
    raw = fs.readFileSync(filePath);
  } catch (e) {
    throw new Error(`COGOS_DEK_FILE unreadable at ${filePath}: ${e.message}`);
  }
  _sourceCache = 'file';
  return _parseKeyMaterial(raw, 'COGOS_DEK_FILE contents');
}

function _loadOrGenerateOnDisk() {
  const filePath = _defaultGeneratedPath();
  try {
    const raw = fs.readFileSync(filePath);
    _sourceCache = 'generated';
    return _parseKeyMaterial(raw, `${filePath}`);
  } catch (_e) { /* fall through and generate */ }
  // Generate fresh + persist (best-effort; if dir not writable, throw — a
  // process that can't persist its DEK will produce records that the NEXT
  // process can't decrypt, which is worse than failing loudly here).
  const key = crypto.randomBytes(KEY_BYTES);
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(filePath, key.toString('hex'), { mode: 0o600 });
  _sourceCache = 'generated';
  return key;
}

// Resolve the DEK in priority order. Caches the result in-process.
function getDek() {
  if (_dekCache) return _dekCache;
  let key = _loadFromEnv();
  if (!key) key = _loadFromFile();
  if (!key) key = _loadOrGenerateOnDisk();
  if (!key || key.length !== KEY_BYTES) {
    throw new Error('DEK resolution failed: no 32-byte key available');
  }
  _dekCache = key;
  return _dekCache;
}

// Return the source label for the currently-cached DEK. Used at startup to
// emit one INFO log line so the operator can see which path resolved. Does
// NOT trigger DEK resolution — call getDek() first if you want it warmed.
function getSource() {
  return _sourceCache;
}

// Seal a plaintext (Buffer or string) into {ciphertext_b64, nonce_b64, tag_b64}.
// All three fields are RFC 4648 §4 standard base64 (with padding) for
// straightforward JSON.stringify round-tripping.
function seal(plaintext) {
  const key = getDek();
  const nonce = crypto.randomBytes(NONCE_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce, { authTagLength: TAG_BYTES });
  const ptBuf = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(String(plaintext), 'utf8');
  const ct = Buffer.concat([cipher.update(ptBuf), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    ciphertext_b64: ct.toString('base64'),
    nonce_b64: nonce.toString('base64'),
    tag_b64: tag.toString('base64'),
  };
}

// Open a sealed envelope. Returns a Buffer of the plaintext bytes. Throws on
// shape errors or GCM auth-tag mismatch (the latter is a wrong-DEK signal).
function open(envelope) {
  if (!envelope || typeof envelope !== 'object') {
    throw new Error('open: envelope must be {ciphertext_b64, nonce_b64, tag_b64}');
  }
  const { ciphertext_b64, nonce_b64, tag_b64 } = envelope;
  // Note: ciphertext_b64 may be the empty string (zero-length plaintext is
  // a legal seal); require all three keys to be present-as-strings rather
  // than truthy.
  if (typeof ciphertext_b64 !== 'string'
      || typeof nonce_b64 !== 'string'
      || typeof tag_b64 !== 'string') {
    throw new Error('open: envelope missing one of ciphertext_b64 / nonce_b64 / tag_b64');
  }
  const key = getDek();
  const nonce = Buffer.from(nonce_b64, 'base64');
  const tag = Buffer.from(tag_b64, 'base64');
  const ct = Buffer.from(ciphertext_b64, 'base64');
  if (nonce.length !== NONCE_BYTES) {
    throw new Error(`open: nonce must be ${NONCE_BYTES} bytes`);
  }
  if (tag.length !== TAG_BYTES) {
    throw new Error(`open: tag must be ${TAG_BYTES} bytes`);
  }
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: TAG_BYTES });
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

// Detect whether a JSON object looks like a sealed envelope. Used by callers
// to dispatch between cleartext-fallback and decrypt paths during migration.
function isSealed(value) {
  return !!(value
    && typeof value === 'object'
    && typeof value.ciphertext_b64 === 'string'
    && typeof value.nonce_b64 === 'string'
    && typeof value.tag_b64 === 'string');
}

module.exports = {
  getDek,
  getSource,
  seal,
  open,
  isSealed,
  _internal: {
    _reset() {
      _dekCache = null;
      _sourceCache = null;
    },
    KEY_BYTES,
    NONCE_BYTES,
    TAG_BYTES,
  },
};
