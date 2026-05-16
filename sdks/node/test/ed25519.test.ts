// Ed25519 signed-request roundtrip. The gateway's auth.js reconstructs:
//   `${METHOD}\n${path-with-query}\n${ts}\n${sha256_hex(body)}`
// and verifies with crypto.verify(null, signedBytes, pubkey, sigBuf).
// We mint a fresh keypair, sign with the SDK signer, and call
// crypto.verify on the public side — same shape as the gateway.

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { createHash, generateKeyPairSync, verify } from 'node:crypto';
import { Ed25519Signer } from '../src/ed25519';

function emptyBodySha256(): string {
  return createHash('sha256').update('').digest('hex');
}

test('ed25519: signRequest produces gateway-verifiable signature (empty body)', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  const signer = new Ed25519Signer(privPem, 'kid-test01');
  const ts = 1717250000000;
  const headerValue = signer.signRequest({ method: 'GET', path: '/v1/models', ts, body: null });
  // Parse out keyId, sig, ts
  const parts: Record<string, string> = {};
  for (const p of headerValue.split(',')) {
    const eq = p.indexOf('=');
    parts[p.slice(0, eq).trim()] = p.slice(eq + 1).trim();
  }
  assert.equal(parts.keyId, 'kid-test01');
  assert.equal(parts.ts, String(ts));
  assert.ok(parts.sig.length > 0);

  // Reconstruct the same signed bytes server-side and verify.
  const bodyHex = emptyBodySha256();
  const signedBytes = `GET\n/v1/models\n${ts}\n${bodyHex}`;
  const sigBuf = Buffer.from(parts.sig, 'base64');
  const ok = verify(null, Buffer.from(signedBytes, 'utf8'), publicKey, sigBuf);
  assert.ok(ok, 'signature should verify against fresh keypair');
});

test('ed25519: signRequest binds body sha256', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  const signer = new Ed25519Signer(privPem, 'kid-test02');
  const ts = 1717250001000;
  const body = JSON.stringify({ messages: [{ role: 'user', content: 'hi' }] });
  const headerValue = signer.signRequest({
    method: 'POST',
    path: '/v1/chat/completions',
    ts,
    body,
  });
  const sigB64 = headerValue.split(',').find((s) => s.startsWith('sig='))!.slice(4);
  const bodyHex = createHash('sha256').update(body).digest('hex');
  const signedBytes = `POST\n/v1/chat/completions\n${ts}\n${bodyHex}`;
  assert.ok(verify(null, Buffer.from(signedBytes, 'utf8'), publicKey, Buffer.from(sigB64, 'base64')));
  // Tampered body fails.
  const wrongBodyHex = createHash('sha256').update(body + 'x').digest('hex');
  const wrongBytes = `POST\n/v1/chat/completions\n${ts}\n${wrongBodyHex}`;
  assert.ok(!verify(null, Buffer.from(wrongBytes, 'utf8'), publicKey, Buffer.from(sigB64, 'base64')));
});

test('ed25519: authorizationHeader prepends scheme', () => {
  const { privateKey } = generateKeyPairSync('ed25519');
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  const signer = new Ed25519Signer(privPem, 'kid-test03');
  const header = signer.authorizationHeader({
    method: 'GET',
    path: '/v1/models',
    ts: Date.now(),
  });
  assert.ok(header.startsWith('CogOS-Ed25519 keyId='));
});

test('ed25519: rejects non-ed25519 key with clear error', () => {
  const { privateKey } = generateKeyPairSync('ed25519');
  // Generate an RSA key, exported as PKCS8 PEM, to verify the asymmetricKeyType check.
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const rsaPem = rsa.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  assert.throws(() => new Ed25519Signer(rsaPem, 'kid-x'), /expected ed25519/);
  // Sanity — ed25519 still works.
  const okPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  const s = new Ed25519Signer(okPem, 'kid-ok');
  assert.equal(s.keyId, 'kid-ok');
});
