'use strict';

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
function adminAuth(req, res, next) {
  const header = req.headers['x-admin-key'] || '';
  const expected = process.env.ADMIN_KEY;
  if (!expected) {
    return res.status(503).json({ error: { message: 'ADMIN_KEY not configured' } });
  }
  if (header !== expected) {
    return res.status(401).json({ error: { message: 'Invalid admin key' } });
  }
  next();
}

module.exports = { bearerAuth, adminAuth };
