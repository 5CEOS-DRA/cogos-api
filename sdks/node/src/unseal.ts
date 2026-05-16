// Unseal a customer-sealed audit row.
//
// Mirrors src/sealed-audit.js on the gateway:
//   - alg = 'x25519-hkdf-aes-256-gcm', envelope v=1
//   - HKDF-SHA256, info = "cogos/seal/v1", empty salt, 32-byte key
//   - AES-256-GCM, 12-byte nonce, 16-byte tag
//   - AAD = `${tenant_id}|${app_id}|${ts}`
//
// The shared secret is X25519 ECDH between the customer's persistent
// private key (the x25519_private_pem returned ONCE at ed25519-scheme
// issuance) and the per-row ephemeral public key the gateway stored on
// the row.
//
// PRODUCTION SERVER MUST NEVER CALL THIS — it's the customer side of
// the protocol. Wrong way to use this primitive is to ship the customer's
// x25519 private key to the server. The only correct location is in the
// customer's process.

import {
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  hkdfSync,
} from 'node:crypto';
import type { AuditRow, SealedEnvelope } from './types';

const HKDF_INFO = Buffer.from('cogos/seal/v1', 'utf8');
const HKDF_SALT = Buffer.alloc(0);
const HKDF_KEY_LEN = 32;
const GCM_TAG_LEN = 16;
const ENVELOPE_VERSION = 1;
const ENVELOPE_ALG = 'x25519-hkdf-aes-256-gcm';

export interface UnsealedContent {
  request_id?: string;
  prompt_fingerprint?: string;
  schema_name?: string;
}

function deriveContentKey(sharedSecret: Buffer): Buffer {
  const out = hkdfSync('sha256', sharedSecret, HKDF_SALT, HKDF_INFO, HKDF_KEY_LEN);
  return Buffer.from(out as ArrayBuffer);
}

function buildAad(row: Pick<AuditRow, 'tenant_id' | 'app_id' | 'ts'>): Buffer {
  if (typeof row.tenant_id !== 'string' || row.tenant_id.length === 0) {
    throw new Error('unsealAuditRow: row.tenant_id required');
  }
  if (typeof row.app_id !== 'string' || row.app_id.length === 0) {
    throw new Error('unsealAuditRow: row.app_id required');
  }
  if (typeof row.ts !== 'string' || row.ts.length === 0) {
    throw new Error('unsealAuditRow: row.ts required');
  }
  return Buffer.from(`${row.tenant_id}|${row.app_id}|${row.ts}`, 'utf8');
}

// Unseal a single sealed audit row. Returns the parsed content payload.
// Throws on any decryption failure (wrong key, tampered ciphertext, AAD
// mismatch, unknown envelope version/alg).
//
// `x25519PrivatePem` is the SAME PEM the gateway returned in the issuance
// response under x25519_private_pem. Save it; never re-displayable.
export function unsealAuditRow(row: AuditRow, x25519PrivatePem: string): UnsealedContent {
  if (!row || !row.sealed_content) {
    throw new Error('unsealAuditRow: row.sealed_content missing — was the row sealed?');
  }
  const env: SealedEnvelope = row.sealed_content;
  if (env.v !== ENVELOPE_VERSION) {
    throw new Error(`unsealAuditRow: unknown envelope version ${env.v}`);
  }
  if (env.alg !== ENVELOPE_ALG) {
    throw new Error(`unsealAuditRow: unknown envelope alg ${env.alg}`);
  }
  const customerPriv = createPrivateKey(x25519PrivatePem);
  if (customerPriv.asymmetricKeyType !== 'x25519') {
    throw new Error(`unsealAuditRow: expected x25519 privkey, got ${customerPriv.asymmetricKeyType}`);
  }
  const ephPubRaw = Buffer.from(env.ephemeral_pub_b64, 'base64');
  if (ephPubRaw.length !== 32) {
    throw new Error('unsealAuditRow: ephemeral_pub_b64 must decode to 32 bytes');
  }
  const ephPub = createPublicKey({
    key: { kty: 'OKP', crv: 'X25519', x: ephPubRaw.toString('base64url') },
    format: 'jwk',
  });
  const sharedSecret = diffieHellman({ privateKey: customerPriv, publicKey: ephPub });
  const aesKey = deriveContentKey(sharedSecret);

  const nonce = Buffer.from(env.nonce_b64, 'base64');
  const ct = Buffer.from(env.ciphertext_b64, 'base64');
  const tag = Buffer.from(env.tag_b64, 'base64');

  const decipher = createDecipheriv('aes-256-gcm', aesKey, nonce, { authTagLength: GCM_TAG_LEN });
  decipher.setAAD(
    buildAad({
      tenant_id: row.tenant_id,
      app_id: row.app_id,
      ts: row.ts,
    }),
  );
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  const obj = JSON.parse(pt.toString('utf8')) as UnsealedContent;
  return obj;
}
