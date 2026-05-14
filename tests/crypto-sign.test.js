'use strict';

const { sign, verify } = require('../src/crypto-sign');

const SECRET = 'a'.repeat(64); // 32 bytes hex

describe('crypto-sign', () => {
  test('sign + verify roundtrips on a JSON string body', () => {
    const body = JSON.stringify({ id: 'chatcmpl-x', model: 'cogos-tier-b', choices: [] });
    const sig = sign(SECRET, body);
    expect(typeof sig).toBe('string');
    expect(sig.length).toBe(64); // sha256 hex
    expect(verify(SECRET, body, sig)).toBe(true);
  });

  test('sign returns null without a secret', () => {
    expect(sign(null, 'anything')).toBeNull();
    expect(sign(undefined, 'anything')).toBeNull();
    expect(sign('', 'anything')).toBeNull();
  });

  test('verify rejects a tampered body', () => {
    const body = JSON.stringify({ id: 'a', val: 1 });
    const tampered = JSON.stringify({ id: 'a', val: 2 });
    const sig = sign(SECRET, body);
    expect(verify(SECRET, tampered, sig)).toBe(false);
  });

  test('verify rejects a flipped signature bit', () => {
    const body = 'hello';
    const sig = sign(SECRET, body);
    const flipped = (sig[0] === '0' ? '1' : '0') + sig.slice(1);
    expect(verify(SECRET, body, flipped)).toBe(false);
  });

  test('verify rejects wrong-length signatures without throwing', () => {
    const body = 'hello';
    expect(verify(SECRET, body, 'short')).toBe(false);
    expect(verify(SECRET, body, 'a'.repeat(63))).toBe(false);
  });

  test('verify rejects a wrong secret', () => {
    const body = 'hello';
    const sig = sign(SECRET, body);
    const wrongSecret = 'b'.repeat(64);
    expect(verify(wrongSecret, body, sig)).toBe(false);
  });

  test('sign accepts a Buffer body', () => {
    const body = Buffer.from('binary data \x00\xff', 'utf8');
    const sig = sign(SECRET, body);
    expect(verify(SECRET, body, sig)).toBe(true);
  });
});
