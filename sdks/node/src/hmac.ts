// HMAC-SHA256 response signing — verifier side.
//
// Mirrors src/crypto-sign.js on the gateway:
//   X-Cogos-Signature: hex(HMAC-SHA256(hmac_secret, <exact response body bytes>))
//
// Customer captures the raw response body BEFORE parsing JSON. Verification
// recomputes the HMAC over the exact bytes and timing-safe-compares.

import { createHmac, timingSafeEqual } from 'node:crypto';

export function computeHmac(hmacSecret: string, bodyBytes: Buffer | string): string {
  const buf = Buffer.isBuffer(bodyBytes) ? bodyBytes : Buffer.from(bodyBytes, 'utf8');
  return createHmac('sha256', hmacSecret).update(buf).digest('hex');
}

export function verifyHmac(
  hmacSecret: string,
  bodyBytes: Buffer | string,
  signatureHex: string,
): boolean {
  if (!hmacSecret || !signatureHex) return false;
  const expected = computeHmac(hmacSecret, bodyBytes);
  // Length check first so timingSafeEqual never throws on mismatched
  // buffers — matches the gateway's defense in src/crypto-sign.js.
  if (expected.length !== signatureHex.length) return false;
  let a: Buffer;
  let b: Buffer;
  try {
    a = Buffer.from(expected, 'hex');
    b = Buffer.from(signatureHex, 'hex');
  } catch {
    return false;
  }
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
