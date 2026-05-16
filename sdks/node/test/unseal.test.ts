// unsealAuditRow roundtrip. We reproduce the gateway's sealForPubkey
// math (src/sealed-audit.js) inline here so the test is self-contained
// and pins the wire format. If the gateway's KDF / AEAD / AAD shape
// ever changes, this test will fail and force a coordinated bump.

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  createCipheriv,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
} from 'node:crypto';
import { unsealAuditRow } from '../src/unseal';
import type { AuditRow } from '../src/types';

const HKDF_INFO = Buffer.from('cogos/seal/v1', 'utf8');

function sealMirror(
  customerPubPem: string,
  plaintext: string,
  aad: { tenant_id: string; app_id: string; ts: string },
): { sealed_content: AuditRow['sealed_content'] } {
  const customerPub = createPublicKey(customerPubPem);
  const { publicKey: ephPub, privateKey: ephPriv } = generateKeyPairSync('x25519');
  const shared = diffieHellman({ privateKey: ephPriv, publicKey: customerPub });
  const aesKey = Buffer.from(hkdfSync('sha256', shared, Buffer.alloc(0), HKDF_INFO, 32) as ArrayBuffer);
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', aesKey, nonce, { authTagLength: 16 });
  cipher.setAAD(Buffer.from(`${aad.tenant_id}|${aad.app_id}|${aad.ts}`, 'utf8'));
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  const ephPubRaw = Buffer.from(ephPub.export({ format: 'jwk' }).x as string, 'base64url');
  return {
    sealed_content: {
      v: 1,
      alg: 'x25519-hkdf-aes-256-gcm',
      ciphertext_b64: ct.toString('base64'),
      nonce_b64: nonce.toString('base64'),
      ephemeral_pub_b64: ephPubRaw.toString('base64'),
      tag_b64: tag.toString('base64'),
    },
  };
}

test('unseal: roundtrip recovers content', () => {
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;

  const payload = JSON.stringify({
    request_id: 'chatcmpl-abc123',
    prompt_fingerprint: 'sha256:deadbeef',
    schema_name: 'sentiment',
  });

  const sealed = sealMirror(pubPem, payload, {
    tenant_id: 'tenant-x',
    app_id: 'app-y',
    ts: '2026-05-14T00:00:00.000Z',
  });

  const row: AuditRow = {
    ts: '2026-05-14T00:00:00.000Z',
    tenant_id: 'tenant-x',
    app_id: 'app-y',
    sealed: true,
    sealed_content: sealed.sealed_content,
  };

  const out = unsealAuditRow(row, privPem);
  assert.equal(out.request_id, 'chatcmpl-abc123');
  assert.equal(out.prompt_fingerprint, 'sha256:deadbeef');
  assert.equal(out.schema_name, 'sentiment');
});

test('unseal: AAD mismatch fails closed', () => {
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  const sealed = sealMirror(pubPem, '{"request_id":"x"}', {
    tenant_id: 'tenant-x',
    app_id: 'app-y',
    ts: '2026-05-14T00:00:00.000Z',
  });
  // Move the blob onto a row with a different ts → AAD mismatch.
  const row: AuditRow = {
    ts: '2026-05-14T00:00:00.001Z',
    tenant_id: 'tenant-x',
    app_id: 'app-y',
    sealed: true,
    sealed_content: sealed.sealed_content,
  };
  assert.throws(() => unsealAuditRow(row, privPem));
});

test('unseal: wrong key fails', () => {
  const { publicKey } = generateKeyPairSync('x25519');
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
  const wrongPair = generateKeyPairSync('x25519');
  const wrongPriv = wrongPair.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  const sealed = sealMirror(pubPem, '{"request_id":"x"}', {
    tenant_id: 'tenant-x',
    app_id: 'app-y',
    ts: '2026-05-14T00:00:00.000Z',
  });
  const row: AuditRow = {
    ts: '2026-05-14T00:00:00.000Z',
    tenant_id: 'tenant-x',
    app_id: 'app-y',
    sealed: true,
    sealed_content: sealed.sealed_content,
  };
  assert.throws(() => unsealAuditRow(row, wrongPriv));
});

test('unseal: rejects unknown envelope version', () => {
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  const sealed = sealMirror(pubPem, '{"request_id":"x"}', {
    tenant_id: 'tenant-x',
    app_id: 'app-y',
    ts: '2026-05-14T00:00:00.000Z',
  });
  const row: AuditRow = {
    ts: '2026-05-14T00:00:00.000Z',
    tenant_id: 'tenant-x',
    app_id: 'app-y',
    sealed: true,
    sealed_content: { ...sealed.sealed_content!, v: 99 as unknown as 1 },
  };
  assert.throws(() => unsealAuditRow(row, privPem), /envelope version/);
});
