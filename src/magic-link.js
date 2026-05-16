'use strict';

// Signed magic-link tokens for "I lost my API key" recovery.
//
// PURPOSE
// -----------------------------------------------------------------------------
// The dashboard surface at /dashboard authenticates via API key — paste-and-go
// like Stripe/Vercel/Cloudflare. When a customer has lost every key they hold,
// they need a self-service way back in. The substrate can't recover the lost
// key (we only persist sha256(plaintext)) — recovery means "prove you own the
// email associated with a key, then we rotate to a fresh key for that same
// tenant." This module produces + verifies the signed bearer token that
// carries the customer through the email round-trip.
//
// TOKEN WIRE FORMAT
// -----------------------------------------------------------------------------
//   token = <base64url(payload_json)>.<base64url(hmac_sha256)>
//
// payload_json = JSON.stringify({
//                  kind, tenant_id, key_id, email, nonce, exp_ms
//                }) in EXPLICIT FIXED FIELD ORDER (load-bearing for the HMAC).
//
// signature   = HMAC-SHA256(MAGIC_LINK_SECRET, payload_bytes) → base64url.
//
// `kind` is always 'magic-link' on emitted tokens; verifyToken rejects any
// other value. The constant lets future token kinds (recovery-pin, billing-
// link, ...) share the same chassis without a wire-format ambiguity.
//
// `nonce` is 16 random bytes hex-encoded. Single-use enforcement keeps a Set
// of consumed nonces in memory: a successful verifyToken() that passes every
// other check ALSO records the nonce, and any subsequent verifyToken() with
// the same nonce returns null even when the signature is otherwise valid.
//
// SECRET RESOLUTION (defense in depth)
// -----------------------------------------------------------------------------
// Same shape as src/session.js, but DISTINCT secret. Compromising the
// session secret doesn't compromise the magic-link secret (or vice versa) —
// an attacker who steals the session-cookie secret can mint cookies but
// can't mint password-reset emails. Source priority:
//   1. COGOS_MAGIC_LINK_SECRET env (64 hex chars) — preferred for prod.
//   2. data/.magic-link-secret file (mode 0600, generated on first boot).
//   3. Lazy-generate + persist when neither is present.
// First call logs the resolution source once (env / file / generated)
// but never the secret value itself.
//
// TTL + REPLAY
// -----------------------------------------------------------------------------
// 15 minutes. Short enough that a leaked link (forwarded email, archived
// inbox) is mostly dead-on-arrival; long enough for a real customer to
// open the email and click. exp_ms is bound INSIDE the signed payload so
// a stale token cached at the edge can't be re-presented past expiration
// even if the URL is preserved.
//
// SINGLE-USE NONCE STORE (in-memory LRU)
// -----------------------------------------------------------------------------
// Consumed nonces live in a Map with insertion-order eviction at
// MAX_CONSUMED_NONCES (10k entries — same MAX_BUCKETS pattern as
// src/anomaly.js). A process restart re-allows any nonce that hadn't
// yet been pruned — acceptable for v1 because the 15-minute TTL is the
// stronger defense (a token whose exp_ms passed during the restart
// window is still rejected by verifyToken on signature-then-exp check).
//
// TODO(future): persist consumed nonces in Azure Files (or whatever
// per-process shared substrate we land on) so single-use survives a
// rolling restart in a multi-replica deploy. Today this is single-replica
// + ephemeral, which matches the rest of the secrets in this repo.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const logger = require('./logger');

// --- constants ---------------------------------------------------------------

const TOKEN_KIND = 'magic-link';
const TOKEN_TTL_MS = 15 * 60 * 1000; // 15 minutes
const SIGNATURE_BYTE_LEN = 32;       // sha256 output
const MAX_CONSUMED_NONCES = 10_000;  // LRU cap — same shape as anomaly.js MAX_BUCKETS

// FIELD ORDER IS LOAD-BEARING. The HMAC is over the exact byte sequence
// JSON.stringify produces; any reorder would invalidate every signed token.
// Matches the same fixed-key-order pattern src/session.js + src/usage.js use.
const PAYLOAD_FIELDS = ['kind', 'tenant_id', 'key_id', 'email', 'nonce', 'exp_ms'];

// --- secret resolution -------------------------------------------------------

let _secretBuf = null;
let _secretSourceLogged = false;

function _secretFilePath() {
  return process.env.MAGIC_LINK_SECRET_FILE
    || path.join(process.cwd(), 'data', '.magic-link-secret');
}

function _isHex64(s) {
  return typeof s === 'string' && /^[0-9a-fA-F]{64}$/.test(s);
}

function _logSourceOnce(source) {
  if (_secretSourceLogged) return;
  _secretSourceLogged = true;
  try { logger.info('magic_link_secret_resolved', { source }); }
  catch (_e) { /* logger should never throw, but be defensive */ }
}

function _resolveSecret() {
  if (_secretBuf) return _secretBuf;

  // 1) env
  const envSecret = process.env.COGOS_MAGIC_LINK_SECRET;
  if (_isHex64(envSecret)) {
    _secretBuf = Buffer.from(envSecret, 'hex');
    _logSourceOnce('env');
    return _secretBuf;
  }

  // 2) persisted file
  const filePath = _secretFilePath();
  try {
    const onDisk = fs.readFileSync(filePath, 'utf8').trim();
    if (_isHex64(onDisk)) {
      _secretBuf = Buffer.from(onDisk, 'hex');
      _logSourceOnce('file');
      return _secretBuf;
    }
  } catch (_e) { /* fall through to generate */ }

  // 3) lazy-generate + persist (best-effort write)
  const fresh = crypto.randomBytes(32);
  _secretBuf = fresh;
  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
    fs.writeFileSync(filePath, fresh.toString('hex'), { mode: 0o600 });
    _logSourceOnce('generated');
  } catch (e) {
    // Read-only FS / no permission — accept ephemeral. Tokens minted by
    // this process won't survive a restart; tokens in-flight at the time
    // of restart die — same property TLS-ephemeral has, acceptable for
    // a 15-minute-TTL recovery flow.
    _logSourceOnce('generated_ephemeral');
    try { logger.warn('magic_link_secret_persist_failed', { error: e.message }); }
    catch (_e2) { /* no-op */ }
  }
  return _secretBuf;
}

// --- base64url helpers -------------------------------------------------------

function _b64urlEncode(buf) {
  return Buffer.from(buf).toString('base64url');
}

function _b64urlDecode(str) {
  // Buffer.from('base64url') silently accepts stray characters by
  // ignoring them, which means a tampered payload could round-trip
  // past us. Reject anything outside the base64url alphabet.
  if (typeof str !== 'string' || !/^[A-Za-z0-9_-]*$/.test(str)) {
    return null;
  }
  try { return Buffer.from(str, 'base64url'); }
  catch (_e) { return null; }
}

// --- canonical payload -------------------------------------------------------

// Build the canonical JSON bytes used by both createToken (to sign) and
// verifyToken (to recompute the expected signature). Field order is the
// load-bearing contract.
function _canonicalPayloadJson({ kind, tenant_id, key_id, email, nonce, exp_ms }) {
  const obj = { kind, tenant_id, key_id, email, nonce, exp_ms };
  const ordered = {};
  for (const f of PAYLOAD_FIELDS) ordered[f] = obj[f];
  return JSON.stringify(ordered);
}

// --- consumed-nonce LRU + disk snapshot --------------------------------------

// Map<nonce, exp_ms>. The value is the token's expiration epoch-ms so
// load-time pruning can drop entries past their replay window. Map
// preserves insertion order for LRU cap eviction.
//
// Persisted to data/magic-link-consumed.json on every consumption +
// hydrated on first verifyToken() call. Without persistence a process
// restart re-opens the replay window: a token already used could be
// re-presented and accepted. The 15-min TTL still bounds the danger,
// but a deploy + restart inside that window IS the attack scenario.
const _consumed = new Map();

function _consumedFile() {
  return process.env.MAGIC_LINK_CONSUMED_FILE
    || path.join(process.cwd(), 'data', 'magic-link-consumed.json');
}

let _consumedLoaded = false;
function _lazyLoadConsumed() {
  if (_consumedLoaded) return;
  _consumedLoaded = true;
  const f = _consumedFile();
  if (!fs.existsSync(f)) return;
  let raw;
  try { raw = fs.readFileSync(f, 'utf8'); }
  catch (e) {
    try { logger.warn('magic_link_consumed_load_failed', { error: e.message }); } catch (_e) {}
    return;
  }
  let parsed;
  try { parsed = JSON.parse(raw); }
  catch (e) {
    try { logger.warn('magic_link_consumed_parse_failed', { error: e.message }); } catch (_e) {}
    return;
  }
  if (!parsed || !Array.isArray(parsed.entries)) return;
  const now = Date.now();
  let restored = 0;
  for (const entry of parsed.entries) {
    if (!entry || typeof entry !== 'object') continue;
    if (typeof entry.nonce !== 'string' || !/^[0-9a-f]{32}$/.test(entry.nonce)) continue;
    if (typeof entry.exp_ms !== 'number' || !Number.isFinite(entry.exp_ms)) continue;
    // Past-expiry entries can't replay anyway (verifyToken's exp check
    // rejects them first), so dropping them at load time shrinks the
    // working set without changing semantics.
    if (entry.exp_ms <= now) continue;
    _consumed.set(entry.nonce, entry.exp_ms);
    restored += 1;
  }
  try { logger.info('magic_link_consumed_loaded', { restored }); } catch (_e) {}
}

function _persistConsumed() {
  const f = _consumedFile();
  const tmp = `${f}.${process.pid}.tmp`;
  const payload = {
    version: 1,
    ts: new Date().toISOString(),
    entries: Array.from(_consumed.entries()).map(([nonce, exp_ms]) => ({ nonce, exp_ms })),
  };
  try {
    fs.mkdirSync(path.dirname(f), { recursive: true });
    fs.writeFileSync(tmp, JSON.stringify(payload), { mode: 0o600 });
    fs.renameSync(tmp, f);
  } catch (e) {
    try { logger.warn('magic_link_consumed_persist_failed', { error: e.message }); } catch (_e) {}
  }
}

function _markConsumed(nonce, exp_ms) {
  // Re-insert if already present so a successful verification refreshes
  // its LRU position. In practice the second-call path returns null
  // before reaching here, so this is mostly defensive.
  if (_consumed.has(nonce)) _consumed.delete(nonce);
  // Evict oldest until under cap. Map.keys().next().value is the
  // insertion-order-oldest entry — O(1) per eviction.
  while (_consumed.size >= MAX_CONSUMED_NONCES) {
    const oldestKey = _consumed.keys().next().value;
    if (!oldestKey) break;
    _consumed.delete(oldestKey);
  }
  _consumed.set(nonce, exp_ms);
  _persistConsumed();
}

function _isConsumed(nonce) {
  _lazyLoadConsumed();
  return _consumed.has(nonce);
}

// --- public API --------------------------------------------------------------

// Mint a magic-link token + the URL the customer should click.
// Returns { token, url, exp_ms, nonce } so callers can log the nonce
// (NOT the token) for forensic tracing without leaking the bearer secret.
function createToken({ tenant_id, key_id, email, baseUrl, ttlMs }) {
  if (!tenant_id || !key_id || !email) {
    throw new Error('createToken requires tenant_id, key_id, email');
  }
  const nonce = crypto.randomBytes(16).toString('hex');
  const exp_ms = Date.now() + (Number.isFinite(ttlMs) ? ttlMs : TOKEN_TTL_MS);
  const payloadJson = _canonicalPayloadJson({
    kind: TOKEN_KIND, tenant_id, key_id, email, nonce, exp_ms,
  });
  const payloadBytes = Buffer.from(payloadJson, 'utf8');
  const secret = _resolveSecret();
  const sig = crypto.createHmac('sha256', secret).update(payloadBytes).digest();
  const token = `${_b64urlEncode(payloadBytes)}.${_b64urlEncode(sig)}`;

  // The URL is the customer-clickable form. The route at /dashboard/auth
  // verifies the token and triggers rotation. The base URL is supplied by
  // the route handler (proto + host from the request) — that lets the
  // exact same code emit a localhost link in dev and a public link in prod
  // without an environment variable.
  const base = (typeof baseUrl === 'string' && baseUrl)
    ? baseUrl.replace(/\/+$/, '')
    : '';
  const url = `${base}/dashboard/auth?token=${encodeURIComponent(token)}`;
  return { token, url, exp_ms, nonce };
}

// Verify a token. Returns the decoded payload subset
// { tenant_id, key_id, email } on success, or null on ANY failure mode:
// bad encoding, wrong signature, wrong kind, expired, already-consumed
// nonce. Failures are deliberately indistinguishable to the caller — the
// route handler maps every flavor to the same 400 error page so a poking
// attacker can't tell whether a guessed token was structurally valid.
//
// CONSUME ON SUCCESS: a successful verification records the nonce in the
// in-memory LRU. The very next call with the same token returns null.
// Pass { consume: false } to peek without marking (test-only).
function verifyToken(token, { consume = true } = {}) {
  if (typeof token !== 'string' || token.length === 0) return null;
  const dot = token.indexOf('.');
  if (dot <= 0 || dot === token.length - 1) return null;
  const payloadB64 = token.slice(0, dot);
  const sigB64 = token.slice(dot + 1);
  const payloadBytes = _b64urlDecode(payloadB64);
  const presentedSig = _b64urlDecode(sigB64);
  if (!payloadBytes || !presentedSig) return null;
  if (presentedSig.length !== SIGNATURE_BYTE_LEN) return null;

  const secret = _resolveSecret();
  const expectedSig = crypto.createHmac('sha256', secret).update(payloadBytes).digest();
  if (!crypto.timingSafeEqual(presentedSig, expectedSig)) return null;

  // Signature good — parse + check fields.
  let parsed;
  try { parsed = JSON.parse(payloadBytes.toString('utf8')); }
  catch (_e) { return null; }
  if (!parsed || typeof parsed !== 'object') return null;
  const { kind, tenant_id, key_id, email, nonce, exp_ms } = parsed;
  if (kind !== TOKEN_KIND) return null;
  if (typeof tenant_id !== 'string' || !tenant_id) return null;
  if (typeof key_id !== 'string' || !key_id) return null;
  if (typeof email !== 'string' || !email) return null;
  if (typeof nonce !== 'string' || !/^[0-9a-f]{32}$/.test(nonce)) return null;
  if (typeof exp_ms !== 'number' || !Number.isFinite(exp_ms)) return null;
  if (Date.now() >= exp_ms) return null;

  // Single-use enforcement. Check BEFORE marking so a token reused twice
  // in rapid succession can't slip through under a race (single-threaded
  // Node lets us treat this as atomic).
  if (_isConsumed(nonce)) return null;
  if (consume) _markConsumed(nonce, exp_ms);

  return { tenant_id, key_id, email, nonce, exp_ms };
}

// --- test hooks --------------------------------------------------------------

const _test = {
  _reset() {
    _secretBuf = null;
    _secretSourceLogged = false;
    _consumed.clear();
    _consumedLoaded = false;
    try { fs.unlinkSync(_consumedFile()); } catch (_e) { /* missing is fine */ }
  },
  _resetConsumed() {
    _consumed.clear();
    _consumedLoaded = false;
    try { fs.unlinkSync(_consumedFile()); } catch (_e) { /* missing is fine */ }
  },
  _peekSecretHex() {
    const buf = _resolveSecret();
    return buf.toString('hex');
  },
  _consumedSize() { return _consumed.size; },
  TOKEN_KIND,
  TOKEN_TTL_MS,
  MAX_CONSUMED_NONCES,
};

module.exports = {
  createToken,
  verifyToken,
  TOKEN_TTL_MS,
  TOKEN_KIND,
  _test,
};
