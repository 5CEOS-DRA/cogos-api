'use strict';

// HMAC-signed customer session cookie + customerSessionAuth middleware.
//
// PURPOSE
// -----------------------------------------------------------------------------
// The customer-facing dashboard at /dashboard uses the customer's API key
// as a password — same login model as Stripe / Vercel / Cloudflare / Fly
// developer dashboards. After a successful POST /dashboard/login the
// server mints a short-lived HMAC-signed session cookie so subsequent
// dashboard requests don't have to re-present the API key on every page
// load. The session cookie is bound to a specific (tenant_id, key_id,
// app_id) triple; if the underlying key is revoked or expires the next
// request fails closed.
//
// COOKIE WIRE FORMAT
// -----------------------------------------------------------------------------
//   cookie value = <base64url(payload_json)>.<base64url(hmac_sha256)>
//
// payload_json = JSON.stringify({tenant_id, key_id, app_id, exp_ms})
//                in EXPLICIT FIXED FIELD ORDER (load-bearing for the
//                HMAC — see the field-order note below).
//
// signature   = HMAC-SHA256(SESSION_SECRET, payload_bytes)
//               → 32 raw bytes → base64url (no padding).
//
// Cookie flags written by createSession:
//   HttpOnly; Secure; SameSite=Lax; Path=/dashboard; Max-Age=604800
//
// Path=/dashboard means the cookie is NOT sent on /v1/*, /admin/*, etc —
// the dashboard surface is a sandboxed namespace. SameSite=Lax allows
// top-level navigation (a customer clicking a link in a verification
// email lands on /dashboard with the cookie attached) while blocking
// cross-origin POSTs — combined with HttpOnly that gives most of the
// CSRF protection a state-changing form needs, without an explicit
// CSRF token. A future card can layer a per-request token on top.
//
// SECRET RESOLUTION
// -----------------------------------------------------------------------------
// Source priority (mirrors src/attestation.js + src/dek.js):
//   1. COGOS_SESSION_SECRET env (64 hex chars) — preferred for prod.
//   2. data/.session-secret file (mode 0600, generated on first boot).
//   3. Lazy-generate + persist when neither is present.
//
// On startup the FIRST call to a secret-consuming function logs once
// with the source (env / file / generated) but never the secret value.
// _test._reset() flushes the in-memory cache so tests can simulate a
// cold start without rebuilding the worktree.
//
// EXPIRATION
// -----------------------------------------------------------------------------
// exp_ms is the wall-clock millisecond at which the session is no
// longer valid. We deliberately bind expiration INSIDE the signed
// payload (not just the cookie Max-Age) so a stale cookie a customer
// has cached in a browser session can't be re-presented past its
// expiration even if the cookie itself was never deleted by the
// browser. parseSession() rejects expired payloads as cleanly as it
// rejects tampered ones.
//
// CONSTANT-TIME COMPARISON
// -----------------------------------------------------------------------------
// crypto.timingSafeEqual requires equal-length buffers. We check the
// signature length first (the expected length is always 32 bytes) and
// short-circuit on mismatch before reaching timingSafeEqual — that's
// the correct shape, but the LENGTH check is itself not timing-safe.
// That's acceptable because the length-check arm leaks only "the
// caller didn't even produce a 32-byte signature," not anything about
// the secret.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const logger = require('./logger');

// --- constants ---------------------------------------------------------------

const COOKIE_NAME = 'cogos_session';
const COOKIE_PATH = '/dashboard';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const MAX_AGE_S = Math.floor(SESSION_TTL_MS / 1000);
const SIGNATURE_BYTE_LEN = 32; // sha256 output

// FIELD ORDER IS LOAD-BEARING. The HMAC is over the exact byte
// sequence JSON.stringify produces; any reorder would invalidate
// every signed cookie. Fixed-key-order matches the same pattern
// src/usage.js and src/attestation.js use.
const PAYLOAD_FIELDS = ['tenant_id', 'key_id', 'app_id', 'exp_ms'];

// --- secret resolution -------------------------------------------------------

let _secretBuf = null;       // Buffer holding the 32-byte secret (decoded hex)
let _secretSourceLogged = false;

function _secretFilePath() {
  return process.env.SESSION_SECRET_FILE
    || path.join(process.cwd(), 'data', '.session-secret');
}

function _isHex64(s) {
  return typeof s === 'string' && /^[0-9a-fA-F]{64}$/.test(s);
}

function _logSourceOnce(source) {
  if (_secretSourceLogged) return;
  _secretSourceLogged = true;
  try { logger.info('session_secret_resolved', { source }); }
  catch (_e) { /* logger should never throw, but be defensive */ }
}

function _resolveSecret() {
  if (_secretBuf) return _secretBuf;

  // 1) env
  const envSecret = process.env.COGOS_SESSION_SECRET;
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
    // Filesystem read-only / no permission — accept ephemeral for this
    // process lifetime. Cookies signed by this process won't survive
    // a restart, which is the same property TLS-ephemeral has and is
    // acceptable for a dashboard surface.
    _logSourceOnce('generated_ephemeral');
    try { logger.warn('session_secret_persist_failed', { error: e.message }); }
    catch (_e2) { /* no-op */ }
  }
  return _secretBuf;
}

// --- base64url helpers (Node 16+ supports 'base64url' natively) --------------

function _b64urlEncode(buf) {
  return Buffer.from(buf).toString('base64url');
}

function _b64urlDecode(str) {
  // Buffer.from('base64url') silently accepts strings with stray
  // characters by ignoring them, which means a tampered payload could
  // round-trip past us. Reject anything outside the base64url alphabet.
  if (typeof str !== 'string' || !/^[A-Za-z0-9_-]*$/.test(str)) {
    return null;
  }
  try { return Buffer.from(str, 'base64url'); }
  catch (_e) { return null; }
}

// --- canonical payload -------------------------------------------------------

// Build the canonical JSON bytes used by both createSession (to sign)
// and parseSession (to recompute the expected signature). The field
// order here is the load-bearing contract.
function _canonicalPayloadJson({ tenant_id, key_id, app_id, exp_ms }) {
  const obj = { tenant_id, key_id, app_id, exp_ms };
  // Defensive: rebuild explicitly in the PAYLOAD_FIELDS order so a
  // caller passing extra fields can't reorder the serialization.
  const ordered = {};
  for (const f of PAYLOAD_FIELDS) ordered[f] = obj[f];
  return JSON.stringify(ordered);
}

// --- public API --------------------------------------------------------------

// Mint a session cookie value (the string after `cogos_session=`).
// Caller composes the full Set-Cookie header — see createSetCookie()
// for the convenience helper that adds the flags.
function createSession({ tenant_id, key_id, app_id }) {
  if (!tenant_id || !key_id || !app_id) {
    throw new Error('createSession requires tenant_id, key_id, app_id');
  }
  const exp_ms = Date.now() + SESSION_TTL_MS;
  const payloadJson = _canonicalPayloadJson({ tenant_id, key_id, app_id, exp_ms });
  const payloadBytes = Buffer.from(payloadJson, 'utf8');
  const secret = _resolveSecret();
  const sig = crypto.createHmac('sha256', secret).update(payloadBytes).digest();
  return `${_b64urlEncode(payloadBytes)}.${_b64urlEncode(sig)}`;
}

// Parse a cookie value back into the original payload. Returns the
// payload object on success, or null on any failure mode (no dot,
// bad base64, bad JSON, wrong-length signature, signature mismatch,
// expired). Failures are deliberately indistinguishable to the
// caller — the middleware translates every flavor into the same
// 302-to-login response so a poking attacker can't tell whether a
// guessed cookie was structurally valid or just had a bad signature.
function parseSession(cookieValue) {
  if (typeof cookieValue !== 'string' || cookieValue.length === 0) return null;
  const dot = cookieValue.indexOf('.');
  if (dot <= 0 || dot === cookieValue.length - 1) return null;
  const payloadB64 = cookieValue.slice(0, dot);
  const sigB64 = cookieValue.slice(dot + 1);
  const payloadBytes = _b64urlDecode(payloadB64);
  const presentedSig = _b64urlDecode(sigB64);
  if (!payloadBytes || !presentedSig) return null;
  // Length check before timingSafeEqual — that function throws on a
  // length mismatch, and we want a clean null instead.
  if (presentedSig.length !== SIGNATURE_BYTE_LEN) return null;

  const secret = _resolveSecret();
  const expectedSig = crypto.createHmac('sha256', secret).update(payloadBytes).digest();
  if (!crypto.timingSafeEqual(presentedSig, expectedSig)) return null;

  // Signature good — parse the payload and check the expiration.
  let parsed;
  try { parsed = JSON.parse(payloadBytes.toString('utf8')); }
  catch (_e) { return null; }
  if (!parsed || typeof parsed !== 'object') return null;
  const { tenant_id, key_id, app_id, exp_ms } = parsed;
  if (typeof tenant_id !== 'string' || !tenant_id) return null;
  if (typeof key_id !== 'string' || !key_id) return null;
  if (typeof app_id !== 'string' || !app_id) return null;
  if (typeof exp_ms !== 'number' || !Number.isFinite(exp_ms)) return null;
  if (Date.now() >= exp_ms) return null;
  return { tenant_id, key_id, app_id, exp_ms };
}

// Build a Set-Cookie header string with the full flag set. Exposed so
// the route handlers don't have to know the flag string in two places.
function createSetCookie(cookieValue) {
  return `${COOKIE_NAME}=${cookieValue}; HttpOnly; Secure; SameSite=Lax; Path=${COOKIE_PATH}; Max-Age=${MAX_AGE_S}`;
}

// Build a Set-Cookie header that deletes the cookie. Same Path + flags
// (browsers match Set-Cookie deletion on path+name) with Max-Age=0.
function clearSetCookie() {
  return `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Path=${COOKIE_PATH}; Max-Age=0`;
}

// Parse the Cookie request header inline — avoids the cookie-parser
// dependency. The header format is `name=value; name2=value2 ...`.
// Returns an object map; missing/empty header → {}. Unknown shape
// (no equals sign in a pair, etc) → skipped silently.
function parseCookieHeader(headerValue) {
  const out = {};
  if (typeof headerValue !== 'string' || !headerValue) return out;
  const parts = headerValue.split(';');
  for (const raw of parts) {
    const eq = raw.indexOf('=');
    if (eq < 0) continue;
    const name = raw.slice(0, eq).trim();
    const value = raw.slice(eq + 1).trim();
    if (!name) continue;
    // Don't overwrite a prior value — first occurrence wins. This
    // makes a duplicate cookie name (browser bug / proxy quirk)
    // behave deterministically.
    if (!(name in out)) out[name] = value;
  }
  return out;
}

// Express middleware. Reads the session cookie, validates it, confirms
// the key is still active in the keys store, and attaches req.session.
// On any failure → 302 to /dashboard?error=login_required.
//
// We re-validate the key against the store on every request so a
// revoked key can't continue to use a still-valid session cookie.
// keys is loaded lazily to keep the require graph one-way (this file
// can be required from index.js even if keys hasn't been initialized
// yet, which matters during tests that swap KEYS_FILE per describe).
function customerSessionAuth(req, res, next) {
  const cookieHeader = req.headers.cookie || '';
  const cookies = parseCookieHeader(cookieHeader);
  const session = parseSession(cookies[COOKIE_NAME]);
  if (!session) {
    return res.redirect(302, '/dashboard?error=login_required');
  }
  // Re-verify the key against the store. findById returns the canonical
  // record sans key_hash; an inactive or quarantined record fails
  // closed. We DON'T require the record to match scheme — both bearer
  // and ed25519 keys can hold a dashboard session.
  let keys;
  try { keys = require('./keys'); }
  catch (_e) {
    // Shouldn't happen in normal operation; log + fail closed.
    return res.redirect(302, '/dashboard?error=login_required');
  }
  const record = keys.findById(session.key_id);
  if (!record || record.active === false) {
    return res.redirect(302, '/dashboard?error=login_required');
  }
  if (record.quarantined_at) {
    return res.redirect(302, '/dashboard?error=login_required');
  }
  if (record.tenant_id !== session.tenant_id) {
    // Stale cookie referencing a key that's been re-issued to a
    // different tenant (shouldn't happen with random UUID key_ids,
    // but the defensive check costs nothing).
    return res.redirect(302, '/dashboard?error=login_required');
  }
  // Check expiration on the key itself. A key whose expires_at has
  // passed gets a fresh login flow — the customer can paste a key
  // that's still in the keys.json but is otherwise dead.
  if (record.expires_at) {
    const expMs = Date.parse(record.expires_at);
    if (Number.isFinite(expMs) && Date.now() >= expMs) {
      return res.redirect(302, '/dashboard?error=login_required');
    }
  }
  req.session = session;
  req.sessionRecord = record;
  return next();
}

// --- test hooks --------------------------------------------------------------

const _test = {
  _reset() {
    _secretBuf = null;
    _secretSourceLogged = false;
  },
  _peekSecretHex() {
    // For test-only introspection. Never call from production code.
    const buf = _resolveSecret();
    return buf.toString('hex');
  },
  SESSION_TTL_MS,
  COOKIE_NAME,
  COOKIE_PATH,
};

module.exports = {
  createSession,
  parseSession,
  createSetCookie,
  clearSetCookie,
  parseCookieHeader,
  customerSessionAuth,
  COOKIE_NAME,
  COOKIE_PATH,
  SESSION_TTL_MS,
  _test,
};
