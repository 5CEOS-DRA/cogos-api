'use strict';

// Response signing for /v1/* endpoints.
//
// Design:
//   1. Customer is issued an api_key + an hmac_secret at the same time.
//   2. Both are shown ONCE on the /success page. Customer saves both.
//   3. Every /v1/* response from the gateway carries an X-Cogos-Signature
//      header = HMAC-SHA256(hmac_secret, <exact response body bytes>).
//   4. Customer-side: verify the signature by recomputing the HMAC over
//      the bytes they received. If it matches, the response was not
//      tampered with in transit (TLS + signature = belt-and-suspenders).
//
// The signature is over the exact bytes on the wire — no canonicalization
// needed. Customer captures the raw response body before parsing JSON.
// Same shape as Stripe's webhook signature scheme.

const crypto = require('crypto');

function sign(hmac_secret, bodyBytes) {
  if (!hmac_secret) return null;
  const buf = Buffer.isBuffer(bodyBytes) ? bodyBytes : Buffer.from(bodyBytes, 'utf8');
  return crypto.createHmac('sha256', hmac_secret).update(buf).digest('hex');
}

// Verify a signature. Constant-time compare to defeat timing attacks.
function verify(hmac_secret, bodyBytes, signatureHex) {
  if (!hmac_secret || !signatureHex) return false;
  const expected = sign(hmac_secret, bodyBytes);
  if (!expected || expected.length !== signatureHex.length) return false;
  return crypto.timingSafeEqual(
    Buffer.from(expected, 'hex'),
    Buffer.from(signatureHex, 'hex'),
  );
}

module.exports = { sign, verify };
