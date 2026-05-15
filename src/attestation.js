'use strict';

// Per-response attestation tokens — the "X-Cogos-Attestation" header.
//
// PROBLEM THIS PRIMITIVE SOLVES
// -----------------------------------------------------------------------------
// Every modern SaaS — Salesforce, OpenAI, Anthropic — gives the customer a
// request and a response, signed at the TLS layer ONLY. The customer cannot
// prove to a regulator months later that a SPECIFIC response actually came
// from a SPECIFIC build of the vendor's substrate, against a SPECIFIC request,
// at a SPECIFIC position in the vendor's audit chain. The only existing
// primitive is "we keep an audit log; trust us." A determined vendor could
// rewrite that audit log after the fact and the customer has no way to detect
// it. Even cosigned container images only prove "an image with this digest
// once existed" — they don't bind any individual response to that image.
//
// X-Cogos-Attestation closes the gap. Every /v1/* response carries a small
// signed token that cryptographically binds five things together:
//   - the SHA-256 of the canonical request bytes (method, path, ts, body)
//   - the SHA-256 of the response body bytes
//   - the cogos-api source revision SHA
//   - the audit chain head AFTER this row was appended (= the new row_hash)
//   - the timestamp of issuance
// signed with an Ed25519 key bound to this running process. The customer
// recomputes req_hash + resp_hash on their side, fetches /attestation.pub,
// verifies the signature, and from that point holds a court-defensible
// receipt: "this exact response came from a process running revision <rev>
// and was the n-th appended row in tenant chain <chain_head>." If we ever
// rewrite the audit log, the chain_head in the customer's token no longer
// matches any path through our new log — the rewrite is detectable from
// the outside, by any single customer who kept their receipts.
//
// KEY-STRATEGY DECISION: EPHEMERAL ED25519 ON STARTUP
// -----------------------------------------------------------------------------
// We deliberately do NOT load a long-lived signing key from
// COSIGN_PRIVATE_KEY_PEM at runtime. Two reasons:
//
//   1. Reading the cosign offline-signing key into a customer-facing API
//      process would directly defeat cosign's posture. Cosign's threat model
//      assumes the signing key is HSM/airgapped and the running container
//      never touches it. A runtime-accessible long-lived signing key is a
//      first-class exposure surface — exactly the property cosign exists
//      to prevent.
//
//   2. The attestation token doesn't need to outlive the process. Its job
//      is to bind a specific response to a specific running build. A new
//      keypair per process restart is the correct unit: it scopes the
//      blast radius of any key compromise to "exactly the responses that
//      process emitted," and it removes the operational risk of key
//      rotation entirely (rotation == restart).
//
// OPERATOR TRADEOFF: customers must fetch /attestation.pub LIVE from the
// same deployment they hit for /v1/*. They cannot pre-pin a long-lived pubkey
// in their CI — every container restart rotates the keypair. We accept that
// because it's the same operational shape as TLS cert rotation (which already
// works fine for everyone), and because operator-side persistence of a
// signing key was the threat we wanted to avoid in the first place. Document
// this in the cookbook recipe.
//
// FALLBACK FOR DETERMINISTIC TESTS: setKeyPairForTest(privPem, pubPem) lets
// the test suite pin a stable keypair across calls. Never call this in
// production code — there is no production caller.
//
// CANONICAL PAYLOAD: explicit fixed-key-order JSON object literal. Mirrors
// the choice in src/usage.js: source code IS the spec, no sort-keys
// canonicalization library required. The field order is LOAD-BEARING for
// signature verification — bench-side clients in any language must
// re-serialize the same fields in the same order.
//
// FIELD ORDER (LOAD-BEARING):
//   v, req_hash, resp_hash, rev, chain_head, signer, signer_kid, ts
//
// TOKEN WIRE FORMAT: <payload_b64>.<signature_b64>
//   - payload_b64 = base64url of the canonical JSON string (no padding)
//   - signature_b64 = base64url of the raw Ed25519 signature (no padding)
//   - separator = '.' (JWT-style, but we deliberately skip the JWT header —
//     algorithm is fixed at Ed25519 and the format is operator-defined).
//
// WHY NOT A FULL JWT: JWT adds a header that lets the client choose the
// signature algorithm. That's a known attack surface (alg=none, alg
// confusion). Our format pins Ed25519 by spec; there is nothing to negotiate.
//
// TODOs (intentionally NOT addressed in this branch):
//   - Key rotation across container restarts: today every restart breaks
//     pre-restart receipts' verifiability against the live /attestation.pub.
//     A historical pubkey index (signed by cosign at release time) would let
//     a customer verify a stale receipt against the corresponding past
//     deploy. Not blocking — restarts are infrequent and customers who care
//     can re-verify within the first few seconds of receipt.
//   - Attestation on non-/v1 endpoints: today only /v1/chat/completions
//     and /v1/models call sign(). /admin/* and /v1/audit don't. The chain
//     head exposure case is /v1; auditing the audit endpoint is a future
//     wrinkle.
//   - Chain-head binding when usage.record() fails: in the error paths
//     (upstream_error, upstream_5xx) we still attestation-sign the error
//     response but the chain_head is the head BEFORE this request because
//     no row was appended. Customer can detect "this request did not enter
//     the audit chain" from chain_head not advancing across consecutive
//     receipts. Future work: add a separate "chain_head_at_failure" marker
//     so the customer doesn't have to compare receipts to spot it.

const crypto = require('crypto');
const fs = require('node:fs');
const path = require('node:path');
const dek = require('./dek');

// -- attestation keypair --------------------------------------------------------
// Persist the keypair across container restarts so previously-issued receipts
// stay verifiable. Without persistence, every revision rollover invalidates
// every receipt customers captured before it — a real operational hole.
//
// Storage: ATTESTATION_KEY_FILE env (full PEM path) or default
// data/attestation-key.pem on the writable volume. File mode 0600. Threat
// model: a disk-level compromise leaks the attestation signing key (attacker
// can forge receipts going forward). It does NOT leak the audit cipher (those
// are separate per-customer keys we cannot decrypt). Pragmatic middle vs.
// either ephemeral (breaks old receipts) or long-term-shared-secret-in-KV.
//
// Generated lazily so test code that wants to pin a keypair via
// setKeyPairForTest() can do so before the first sign() call.

let _priv = null;
let _pub = null;
let _pubPem = null;
let _kid = null;

function _keyFilePath() {
  return process.env.ATTESTATION_KEY_FILE
    || path.join(process.cwd(), 'data', 'attestation-key.pem');
}

// Load the persisted private PEM from disk. Detects the at-rest shape:
//   - sealed envelope: JSON object with {ciphertext_b64, nonce_b64, tag_b64}
//     (the new default — see src/dek.js). Detected by `data[0] === '{'`.
//   - cleartext PEM: starts with `-----BEGIN ` (legacy, pre-encrypt-at-rest).
// Returns the cleartext PEM string. Throws on read/decrypt failure so the
// caller can fall through to generate-fresh.
function _readPersistedPem(filePath) {
  const data = fs.readFileSync(filePath, 'utf8');
  const trimmed = data.trimStart();
  if (trimmed[0] === '{') {
    // Sealed envelope. Open under the DEK.
    const env = JSON.parse(trimmed);
    return dek.open(env).toString('utf8');
  }
  // Legacy cleartext PEM. Pass through unchanged.
  return data;
}

// Persist the private PEM. Always sealed under the DEK going forward —
// disk breach yields ciphertext only. See src/dek.js for the substrate
// + DEK source priority. Best-effort: if the dir isn't writable we
// fall back to ephemeral (caller logs once).
function _writePersistedPem(filePath, privPem) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const env = dek.seal(Buffer.from(privPem, 'utf8'));
  // Pretty-printed for operator-grep ergonomics; the JSON wrapper isn't
  // load-bearing for crypto, only for the at-rest detection prefix check.
  fs.writeFileSync(filePath, JSON.stringify(env, null, 2), { mode: 0o600 });
}

function _ensureKeyPair() {
  if (_priv && _pub) return;
  const filePath = _keyFilePath();
  // 1) Try to load an existing persisted key (sealed or legacy PEM).
  try {
    const pem = _readPersistedPem(filePath);
    const priv = crypto.createPrivateKey(pem);
    const pub = crypto.createPublicKey(priv);
    _priv = priv;
    _pub = pub;
    _pubPem = pub.export({ type: 'spki', format: 'pem' });
    _kid = _computeKid(_pubPem);
    return;
  } catch (_e) { /* fall through to generate */ }
  // 2) Generate fresh + persist (best-effort; if the dir isn't writable we
  //    fall back to ephemeral and log once — receipts still work for this
  //    process lifetime).
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  _priv = privateKey;
  _pub = publicKey;
  _pubPem = publicKey.export({ type: 'spki', format: 'pem' });
  _kid = _computeKid(_pubPem);
  try {
    const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    _writePersistedPem(filePath, privPem);
  } catch (e) {
    if (!process.env.ATTESTATION_QUIET) {
      console.warn(`[attestation] could not persist key at ${filePath}: ${e.message} — receipts will not survive restart`);
    }
  }
}

function _computeKid(pubPem) {
  // sha256 of the PEM string, first 16 hex chars. Matches the spec.
  return crypto.createHash('sha256').update(pubPem).digest('hex').slice(0, 16);
}

// Resolve the running revision SHA. Order: COGOS_REVISION env (set at build
// time / by the deploy pipeline) > package.json version. Never falls back
// to 'unknown' — the contract is that the receipt always cites a concrete
// build. If neither is set we emit '0.0.0' so the customer can still verify
// the attestation, but the binding to source revision is weak. The deploy
// pipeline should always set COGOS_REVISION.
function getRevision() {
  if (process.env.COGOS_REVISION) return String(process.env.COGOS_REVISION);
  try {
    const pkg = require('../package.json');
    if (pkg && pkg.version) return String(pkg.version);
  } catch (_e) { /* ignore */ }
  return '0.0.0';
}

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

// Base64url without padding. Matches RFC 7515 base64url for compactness on
// the wire and zero ambiguity in tokenizers.
function b64urlEncode(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/=+$/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function b64urlDecode(str) {
  // Restore padding so Buffer.from base64 handles it.
  const pad = str.length % 4 === 0 ? 0 : 4 - (str.length % 4);
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(pad), 'base64');
}

// Compute req_hash deterministically. Input fields:
//   method  — HTTP verb (uppercased on the wire; caller must pass as-is)
//   path    — req.originalUrl (includes query string) for maximum bind
//   ts      — unix-ms timestamp string of when we observed the request
//   body    — Buffer or string of the raw request body bytes
// Format: METHOD + '\n' + path + '\n' + ts + '\n' + sha256_hex(body_bytes)
// Then hash THAT string with sha256. The double-hash isolates the body from
// the rest of the input (so a body-replay with adjusted ts can't collide).
function computeReqHash({ method, path, ts, body }) {
  const bodyBuf = body == null
    ? Buffer.alloc(0)
    : (Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8'));
  const bodyHash = sha256Hex(bodyBuf);
  const canonical = `${method}\n${path}\n${ts}\n${bodyHash}`;
  return sha256Hex(Buffer.from(canonical, 'utf8'));
}

// Compute resp_hash over the raw response body bytes. Caller is responsible
// for passing the EXACT bytes the customer will receive — that's the bind
// that lets the customer detect transit tampering.
function computeRespHash(respBodyBytes) {
  const buf = Buffer.isBuffer(respBodyBytes)
    ? respBodyBytes
    : Buffer.from(String(respBodyBytes), 'utf8');
  return sha256Hex(buf);
}

// Build the canonical payload object. EXPLICIT FIXED-KEY-ORDER — see header
// comment for why this order is load-bearing.
function buildPayload({ req_hash, resp_hash, chain_head, ts }) {
  _ensureKeyPair();
  return {
    v: 1,
    req_hash,
    resp_hash,
    rev: getRevision(),
    chain_head: chain_head || '0'.repeat(64),
    signer: 'cogos-api',
    signer_kid: _kid,
    ts: typeof ts === 'number' ? ts : Date.now(),
  };
}

// Canonical JSON serialization of the payload. Fixed-key-order object
// literal — JSON.stringify preserves insertion order on plain objects in
// every modern engine. Mirrors the choice in src/usage.js.
function canonicalPayloadJson(payload) {
  // Reconstruct in fixed order so a payload object passed in any field
  // order still serializes identically. THIS ORDER IS LOAD-BEARING.
  return JSON.stringify({
    v: payload.v,
    req_hash: payload.req_hash,
    resp_hash: payload.resp_hash,
    rev: payload.rev,
    chain_head: payload.chain_head,
    signer: payload.signer,
    signer_kid: payload.signer_kid,
    ts: payload.ts,
  });
}

// Sign a request/response pair, producing the X-Cogos-Attestation token
// string. Returns null only if the caller's inputs are unusable; never
// throws on missing-but-optional fields (the token just records what was
// available).
//
// Token format: <payload_b64url>.<signature_b64url>
function sign({ method, path, ts, reqBody, respBody, chainHead }) {
  _ensureKeyPair();
  const issuedTs = typeof ts === 'number' ? ts : Date.now();
  const reqHash = computeReqHash({
    method: String(method || 'GET').toUpperCase(),
    path: String(path || '/'),
    ts: String(issuedTs),
    body: reqBody,
  });
  const respHash = computeRespHash(respBody);
  const payload = buildPayload({
    req_hash: reqHash,
    resp_hash: respHash,
    chain_head: chainHead,
    ts: issuedTs,
  });
  const payloadJson = canonicalPayloadJson(payload);
  const payloadB64 = b64urlEncode(Buffer.from(payloadJson, 'utf8'));
  const sigBuf = crypto.sign(null, Buffer.from(payloadJson, 'utf8'), _priv);
  const sigB64 = b64urlEncode(sigBuf);
  return `${payloadB64}.${sigB64}`;
}

// Decode + verify a token against a given public PEM. Returns the decoded
// payload on success, or null on any signature/format failure. Exposed for
// in-process tests and as a reference implementation customers can crib.
function verify(token, pubPem = null) {
  if (typeof token !== 'string' || !token.includes('.')) return null;
  const [payloadB64, sigB64] = token.split('.', 2);
  if (!payloadB64 || !sigB64) return null;
  let payloadJson;
  let payload;
  try {
    payloadJson = b64urlDecode(payloadB64).toString('utf8');
    payload = JSON.parse(payloadJson);
  } catch (_e) {
    return null;
  }
  const sigBuf = b64urlDecode(sigB64);
  const pubKey = pubPem
    ? crypto.createPublicKey(pubPem)
    : (_ensureKeyPair(), _pub);
  let ok;
  try {
    ok = crypto.verify(null, Buffer.from(payloadJson, 'utf8'), pubKey, sigBuf);
  } catch (_e) {
    return null;
  }
  return ok ? payload : null;
}

// Return the current attestation public key as PEM. Served at
// /attestation.pub. Generated lazily so test pinning still works.
function getAttestationPubkey() {
  _ensureKeyPair();
  return _pubPem;
}

function getAttestationKid() {
  _ensureKeyPair();
  return _kid;
}

// Test hook only. Pin a deterministic keypair for tests that need to verify
// signatures against a stable pubkey. Never called from src/.
function setKeyPairForTest(privPem, pubPem) {
  _priv = crypto.createPrivateKey(privPem);
  _pub = crypto.createPublicKey(pubPem);
  _pubPem = _pub.export({ type: 'spki', format: 'pem' });
  _kid = _computeKid(_pubPem);
}

// Test hook only. Force regeneration of the ephemeral keypair (e.g. between
// test suites that want isolation).
function resetForTest() {
  _priv = null;
  _pub = null;
  _pubPem = null;
  _kid = null;
}

module.exports = {
  sign,
  verify,
  getAttestationPubkey,
  getAttestationKid,
  getRevision,
  // exported for tests + customer-side reference implementations
  _internal: {
    computeReqHash,
    computeRespHash,
    canonicalPayloadJson,
    buildPayload,
    b64urlEncode,
    b64urlDecode,
    sha256Hex,
    setKeyPairForTest,
    resetForTest,
  },
};
