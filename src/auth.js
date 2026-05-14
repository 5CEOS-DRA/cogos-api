'use strict';

const crypto = require('node:crypto');
const { verify, PREFIX } = require('./keys');

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

module.exports = { bearerAuth, adminAuth };
