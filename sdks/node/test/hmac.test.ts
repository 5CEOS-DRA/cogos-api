// HMAC roundtrip — compute on one side, verify on the other.
// Mirrors the bytes-on-the-wire test the gateway runs against src/crypto-sign.js.

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { computeHmac, verifyHmac } from '../src/hmac';

test('hmac: roundtrip verifies', () => {
  const secret = 'a'.repeat(64);
  const body = JSON.stringify({ hello: 'world' });
  const sig = computeHmac(secret, body);
  assert.ok(verifyHmac(secret, body, sig));
});

test('hmac: rejects tampered body', () => {
  const secret = 'a'.repeat(64);
  const body = JSON.stringify({ hello: 'world' });
  const sig = computeHmac(secret, body);
  assert.ok(!verifyHmac(secret, body + 'x', sig));
});

test('hmac: rejects wrong secret', () => {
  const secret = 'a'.repeat(64);
  const body = 'payload';
  const sig = computeHmac(secret, body);
  assert.ok(!verifyHmac('b'.repeat(64), body, sig));
});

test('hmac: length-mismatch returns false (no throw)', () => {
  assert.ok(!verifyHmac('a'.repeat(64), 'payload', 'deadbeef'));
});

test('hmac: empty signature returns false', () => {
  assert.ok(!verifyHmac('a'.repeat(64), 'payload', ''));
});

test('hmac: matches a known fixture', () => {
  // sha256-hmac('hello-world', 'cogos') checked against an independent
  // CLI run: `echo -n "cogos" | openssl dgst -sha256 -hmac hello-world`.
  const secret = 'hello-world';
  const body = 'cogos';
  const expected = '2674f06bfdc53e622f25d8a10fc9b8571fe1dd06da3d140886d2280ab1010d7d';
  assert.equal(computeHmac(secret, body), expected);
});
