'use strict';

const crypto = require('node:crypto');
const { verify, findByEd25519KeyId, touchLastUsed, PREFIX } = require('./keys');

// Bearer auth for customer API calls. On success, attaches req.apiKey =
// the key record (without hash).
function bearerAuth(req, res, next) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) {
    return res.status(401).json({
      error: { message: 'Missing Bearer token', type: 'invalid_request_error' },
    });
  }
  const token = header.slice(7).trim();
  if (!token.startsWith(PREFIX)) {
    return res.status(401).json({
      error: { message: `API key must start with "${PREFIX}"`, type: 'invalid_api_key' },
    });
  }
  const record = verify(token);
  if (!record) {
    return res.status(401).json({
      error: { message: 'Invalid or revoked API key', type: 'invalid_api_key' },
    });
  }
  req.apiKey = record;
  next();
}

// Ed25519 customer auth (Security Hardening Card #7).
//
// Wire format:
//   Authorization: CogOS-Ed25519 keyId=<id>,sig=<base64>,ts=<unix_ms>
//
// Signed bytes:
//   <METHOD>\n<path-including-query>\n<ts>\n<body_sha256_hex>
//
// where:
//   - METHOD is uppercase HTTP method
//   - path is req.originalUrl (includes query string)
//   - ts is the same unix-ms string from the header
//   - body_sha256_hex is hex sha256 of raw request body bytes; empty body
//     uses the empty-string sha256
//     (e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)
//
// Signature is Ed25519, base64-encoded (standard, not URL-safe). Replay
// window is REPLAY_WINDOW_MS (default 300_000 = 5 min) on each side of
// server wall-clock.
//
// IMPORTANT BEHAVIOR: this middleware DETECTS the CogOS-Ed25519 scheme.
//   - If no Authorization header OR it doesn't start with `CogOS-Ed25519 `,
//     it calls next() WITHOUT setting req.apiKey. This lets a chained
//     `customerAuth` wrapper fall through to bearerAuth for legacy callers.
//   - If the scheme IS present but malformed / signature fails / replay /
//     revoked, it returns 401 with a clear error code. The bearer path is
//     NOT consulted as a fallback — once a caller picks ed25519, they own
//     that outcome (otherwise we'd leak a downgrade oracle).
const REPLAY_WINDOW_MS = 300_000;
const ED25519_SCHEME = 'CogOS-Ed25519 ';
const EMPTY_BODY_SHA256 = crypto.createHash('sha256').update('').digest('hex');

function parseEd25519Header(value) {
  // Expected: keyId=<id>,sig=<base64>,ts=<digits>
  // Order-insensitive on purpose so a hand-typed client doesn't trip.
  const out = {};
  const parts = String(value).split(',');
  for (const part of parts) {
    const eq = part.indexOf('=');
    if (eq < 0) return null;
    const k = part.slice(0, eq).trim();
    const v = part.slice(eq + 1).trim();
    if (!k || !v) return null;
    if (k === 'keyId' || k === 'sig' || k === 'ts') {
      out[k] = v;
    }
  }
  if (!out.keyId || !out.sig || !out.ts) return null;
  return out;
}

function ed25519Auth(req, res, next) {
  const header = req.headers.authorization || '';
  if (!header.startsWith(ED25519_SCHEME)) {
    // Not an ed25519 request — fall through. customerAuth will try bearer.
    return next();
  }
  const params = parseEd25519Header(header.slice(ED25519_SCHEME.length));
  if (!params) {
    return res.status(401).json({
      error: {
        message: 'Malformed CogOS-Ed25519 Authorization header (expected keyId=...,sig=...,ts=...)',
        type: 'invalid_request_error',
      },
    });
  }

  // Replay window. ts is unix-ms; allow ±REPLAY_WINDOW_MS skew either way
  // so callers in different timezones / on lagging clocks still verify.
  const ts = Number(params.ts);
  if (!Number.isFinite(ts) || !Number.isInteger(ts) || ts <= 0) {
    return res.status(401).json({
      error: { message: 'Invalid ts (must be unix-ms integer)', type: 'invalid_api_key' },
    });
  }
  const now = Date.now();
  if (Math.abs(now - ts) > REPLAY_WINDOW_MS) {
    return res.status(401).json({
      error: {
        message: `Request timestamp outside ${REPLAY_WINDOW_MS / 1000}s replay window`,
        type: 'invalid_api_key',
      },
    });
  }

  // Key lookup. Use a stable not-found vs revoked distinction so customers
  // can tell when they're holding a stale keyId.
  const record = findByEd25519KeyId(params.keyId);
  if (!record) {
    return res.status(401).json({
      error: { message: 'Unknown ed25519 keyId', type: 'invalid_api_key' },
    });
  }
  if (record.scheme !== 'ed25519' || !record.pubkey_pem) {
    return res.status(401).json({
      error: { message: 'Key is not ed25519-issued', type: 'invalid_api_key' },
    });
  }
  if (!record.active) {
    return res.status(401).json({
      error: { message: 'Key has been revoked', type: 'invalid_api_key' },
    });
  }

  // Reconstruct signed bytes. req.rawBody is set by the json parser's
  // verify callback in src/index.js. Empty body → empty-string sha256.
  const bodyHex = req.rawBody && req.rawBody.length > 0
    ? crypto.createHash('sha256').update(req.rawBody).digest('hex')
    : EMPTY_BODY_SHA256;
  const method = String(req.method || '').toUpperCase();
  // originalUrl preserves the query string; req.path strips it. The
  // customer signs the URL they wrote, which always includes the query.
  const pathWithQuery = req.originalUrl || req.url || '';
  const signedBytes = `${method}\n${pathWithQuery}\n${params.ts}\n${bodyHex}`;

  // Decode sig (base64, standard). On malformed base64, node returns a
  // shorter buffer — verify() then fails closed which is what we want.
  let sigBytes;
  try {
    sigBytes = Buffer.from(params.sig, 'base64');
  } catch (_e) {
    return res.status(401).json({
      error: { message: 'Malformed signature (expected standard base64)', type: 'invalid_api_key' },
    });
  }

  let ok = false;
  try {
    ok = crypto.verify(
      null, // ed25519 has no separate digest; algorithm = null per Node docs
      Buffer.from(signedBytes, 'utf8'),
      record.pubkey_pem,
      sigBytes,
    );
  } catch (_e) {
    ok = false;
  }
  if (!ok) {
    return res.status(401).json({
      error: { message: 'Signature verification failed', type: 'invalid_api_key' },
    });
  }

  // Strip pubkey_pem from req.apiKey to keep the downstream shape tight —
  // it's persisted state, not request state. tenant_id / tier / package_id
  // / id are what downstream cares about.
  req.apiKey = { ...record, pubkey_pem: undefined };
  touchLastUsed(record.id);
  next();
}

// Chained customer auth. ed25519 first (so customers who opted into the
// signed scheme always get its semantics), then bearer for legacy callers.
// Note: ed25519Auth ONLY falls through when the CogOS-Ed25519 scheme is
// absent from Authorization. If the scheme IS present and verification
// fails, the response is 401 immediately — no bearer fallback. This is
// deliberate: a fallback would let a network attacker downgrade a
// stronger scheme to a weaker one by mangling the header.
function customerAuth(req, res, next) {
  ed25519Auth(req, res, (err) => {
    if (err) return next(err);
    if (req.apiKey) return next();  // ed25519 succeeded
    return bearerAuth(req, res, next);
  });
}

// Admin auth for issuance/revocation endpoints. Single shared ADMIN_KEY
// in env; rotate by changing the env var.
//
// Comparison is constant-time via crypto.timingSafeEqual to keep the 256-bit
// admin key out of timing-oracle reach once the repo is public. We do the
// length check FIRST because timingSafeEqual throws on length mismatch; the
// mismatch itself can leak the expected length, but the same length is
// already implicit in any header-parsing path and we accept that.
function adminAuth(req, res, next) {
  const header = req.headers['x-admin-key'] || '';
  const expected = process.env.ADMIN_KEY;
  if (!expected) {
    return res.status(503).json({ error: { message: 'ADMIN_KEY not configured' } });
  }
  const a = Buffer.from(String(header));
  const b = Buffer.from(String(expected));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ error: { message: 'Invalid admin key' } });
  }
  next();
}

module.exports = { bearerAuth, ed25519Auth, customerAuth, adminAuth };
