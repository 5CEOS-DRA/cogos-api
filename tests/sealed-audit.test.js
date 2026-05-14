'use strict';

// Customer-sealed audit content tests.
//
// Coverage matrix:
//   1. Round-trip: seal with pubkey, unseal with privkey, recover plaintext.
//   2. Wrong privkey can't decrypt (GCM auth tag fails).
//   3. Tampering with the ciphertext invalidates the tag (decrypt throws).
//   4. Tampering with the AAD (changing ts) invalidates.
//   5. Customer with bearer-only auth → rows are NOT sealed (`sealed: false`).
//   6. Customer with ed25519+x25519 auth → rows ARE sealed.
//   7. Chain verification (verifyChain) works whether row is sealed or not.
//   8. /v1/audit response surfaces ciphertext bytes for sealed rows;
//      cleartext fields are absent.
//   9. AAD binding: a sealed blob lifted to a different (tenant, app, ts)
//      cannot be decrypted (extension of #4 covering tenant + app).
//  10. Envelope versioning: unknown v / unknown alg → unseal throws.

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

let tmpDir;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-sealed-test-'));
  process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
  process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
  jest.resetModules();
});

afterEach(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

function freshSealed() {
  jest.resetModules();
  return require('../src/sealed-audit');
}

function freshUsage() {
  jest.resetModules();
  return require('../src/usage');
}

function freshKeys() {
  jest.resetModules();
  return require('../src/keys');
}

// Make an X25519 keypair the way src/keys.js does at ed25519+x25519
// issuance time. The test files don't need the rest of the issuance
// scaffolding for the pure crypto round-trip tests.
function makeX25519Pair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  return {
    pubPem: publicKey.export({ type: 'spki', format: 'pem' }),
    privPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

// =============================================================================
// 1. Round-trip
// =============================================================================

describe('sealed-audit — round trip', () => {
  test('seal then unseal recovers the original plaintext', () => {
    const sealed = freshSealed();
    const { pubPem, privPem } = makeX25519Pair();
    const aad = { tenant_id: 'alice', app_id: '_default', ts: '2026-05-14T00:00:00.000Z' };
    const pt = 'request_id=chatcmpl-abc;prompt_fp=sha256:deadbeef';
    const env = sealed.sealForPubkey(pubPem, pt, aad);
    expect(env.v).toBe(1);
    expect(env.alg).toBe('x25519-hkdf-aes-256-gcm');
    expect(typeof env.ciphertext_b64).toBe('string');
    expect(typeof env.nonce_b64).toBe('string');
    expect(typeof env.ephemeral_pub_b64).toBe('string');
    expect(typeof env.tag_b64).toBe('string');
    const recovered = sealed.unsealForPrivkey(privPem, env, aad).toString('utf8');
    expect(recovered).toBe(pt);
  });

  test('two seals of the same plaintext produce different ciphertext (random ephemeral)', () => {
    const sealed = freshSealed();
    const { pubPem } = makeX25519Pair();
    const aad = { tenant_id: 't', app_id: 'a', ts: '2026-01-01T00:00:00Z' };
    const env1 = sealed.sealForPubkey(pubPem, 'hello', aad);
    const env2 = sealed.sealForPubkey(pubPem, 'hello', aad);
    expect(env1.ciphertext_b64).not.toBe(env2.ciphertext_b64);
    expect(env1.ephemeral_pub_b64).not.toBe(env2.ephemeral_pub_b64);
    expect(env1.nonce_b64).not.toBe(env2.nonce_b64);
  });
});

// =============================================================================
// 2. Wrong privkey can't decrypt
// =============================================================================

describe('sealed-audit — wrong privkey rejection', () => {
  test('a DIFFERENT customer privkey cannot unseal', () => {
    const sealed = freshSealed();
    const { pubPem } = makeX25519Pair();
    const { privPem: otherPriv } = makeX25519Pair();
    const aad = { tenant_id: 't', app_id: 'a', ts: '2026-05-14T00:00:00Z' };
    const env = sealed.sealForPubkey(pubPem, 'secret', aad);
    expect(() => sealed.unsealForPrivkey(otherPriv, env, aad)).toThrow();
  });
});

// =============================================================================
// 3. Tampered ciphertext invalidates tag
// =============================================================================

describe('sealed-audit — tamper detection', () => {
  test('flipping a byte in ciphertext_b64 → unseal throws', () => {
    const sealed = freshSealed();
    const { pubPem, privPem } = makeX25519Pair();
    const aad = { tenant_id: 't', app_id: 'a', ts: '2026-05-14T00:00:00Z' };
    const env = sealed.sealForPubkey(pubPem, 'hello world', aad);
    const ctBuf = Buffer.from(env.ciphertext_b64, 'base64');
    ctBuf[0] ^= 0x01;
    const tampered = { ...env, ciphertext_b64: ctBuf.toString('base64') };
    expect(() => sealed.unsealForPrivkey(privPem, tampered, aad)).toThrow();
  });

  test('flipping a byte in tag_b64 → unseal throws', () => {
    const sealed = freshSealed();
    const { pubPem, privPem } = makeX25519Pair();
    const aad = { tenant_id: 't', app_id: 'a', ts: '2026-05-14T00:00:00Z' };
    const env = sealed.sealForPubkey(pubPem, 'hello world', aad);
    const tagBuf = Buffer.from(env.tag_b64, 'base64');
    tagBuf[0] ^= 0x01;
    const tampered = { ...env, tag_b64: tagBuf.toString('base64') };
    expect(() => sealed.unsealForPrivkey(privPem, tampered, aad)).toThrow();
  });

  test('flipping a byte in nonce_b64 → unseal throws', () => {
    const sealed = freshSealed();
    const { pubPem, privPem } = makeX25519Pair();
    const aad = { tenant_id: 't', app_id: 'a', ts: '2026-05-14T00:00:00Z' };
    const env = sealed.sealForPubkey(pubPem, 'hello world', aad);
    const nonceBuf = Buffer.from(env.nonce_b64, 'base64');
    nonceBuf[0] ^= 0x01;
    const tampered = { ...env, nonce_b64: nonceBuf.toString('base64') };
    expect(() => sealed.unsealForPrivkey(privPem, tampered, aad)).toThrow();
  });
});

// =============================================================================
// 4. AAD tampering invalidates (covers ts, tenant_id, app_id)
// =============================================================================

describe('sealed-audit — AAD binding', () => {
  test('changing ts in AAD → unseal throws', () => {
    const sealed = freshSealed();
    const { pubPem, privPem } = makeX25519Pair();
    const aad = { tenant_id: 't', app_id: 'a', ts: '2026-05-14T00:00:00Z' };
    const env = sealed.sealForPubkey(pubPem, 'hello', aad);
    const wrongAad = { ...aad, ts: '2026-05-15T00:00:00Z' };
    expect(() => sealed.unsealForPrivkey(privPem, env, wrongAad)).toThrow();
  });

  test('changing tenant_id in AAD → unseal throws (cross-tenant blob lift)', () => {
    const sealed = freshSealed();
    const { pubPem, privPem } = makeX25519Pair();
    const aad = { tenant_id: 't1', app_id: 'a', ts: '2026-05-14T00:00:00Z' };
    const env = sealed.sealForPubkey(pubPem, 'hello', aad);
    const wrongAad = { ...aad, tenant_id: 't2' };
    expect(() => sealed.unsealForPrivkey(privPem, env, wrongAad)).toThrow();
  });

  test('changing app_id in AAD → unseal throws (cross-app blob lift)', () => {
    const sealed = freshSealed();
    const { pubPem, privPem } = makeX25519Pair();
    const aad = { tenant_id: 't', app_id: 'a1', ts: '2026-05-14T00:00:00Z' };
    const env = sealed.sealForPubkey(pubPem, 'hello', aad);
    const wrongAad = { ...aad, app_id: 'a2' };
    expect(() => sealed.unsealForPrivkey(privPem, env, wrongAad)).toThrow();
  });
});

// =============================================================================
// 5 + 6. Sealing behavior at usage.record() integration point
// =============================================================================

describe('usage.record — sealing dispatch', () => {
  test('bearer-only customer → row stored cleartext, sealed:false', () => {
    const usage = freshUsage();
    usage.record({
      key_id: 'kid',
      tenant_id: 'bob',
      app_id: '_default',
      model: 'm',
      status: 'success',
      request_id: 'req-abc',
      // No x25519_pubkey_pem present → sealing must be skipped.
    });
    const rows = usage.readByTenant('bob');
    expect(rows.length).toBe(1);
    expect(rows[0].sealed).toBe(false);
    expect(rows[0].request_id).toBe('req-abc');
    expect(rows[0].sealed_content).toBeUndefined();
  });

  test('customer with x25519_pubkey_pem → row stored sealed, cleartext absent', () => {
    const sealed = freshSealed();
    const usage = freshUsage();
    const { pubPem, privPem } = makeX25519Pair();
    usage.record({
      key_id: 'kid',
      tenant_id: 'alice',
      app_id: '_default',
      model: 'm',
      status: 'success',
      request_id: 'req-xyz',
      prompt_fingerprint: 'sha256:abc',
      x25519_pubkey_pem: pubPem,
    });
    const rows = usage.readByTenant('alice');
    expect(rows.length).toBe(1);
    expect(rows[0].sealed).toBe(true);
    expect(rows[0].sealed_content).toBeDefined();
    // The on-disk row MUST NOT carry the cleartext content fields.
    expect(rows[0].request_id == null || rows[0].request_id === '').toBe(true);
    expect(rows[0].prompt_fingerprint == null).toBe(true);
    // Customer round-trips it back.
    const aad = {
      tenant_id: rows[0].tenant_id,
      app_id: rows[0].app_id,
      ts: rows[0].ts,
    };
    const plain = sealed.unsealForPrivkey(privPem, rows[0].sealed_content, aad)
      .toString('utf8');
    const parsed = JSON.parse(plain);
    expect(parsed.request_id).toBe('req-xyz');
    expect(parsed.prompt_fingerprint).toBe('sha256:abc');
  });
});

// =============================================================================
// 7. Chain verification holds across sealed + unsealed rows
// =============================================================================

describe('usage.verifyChain — sealing-agnostic', () => {
  test('mixed sealed + unsealed rows in one chain still verify', () => {
    const usage = freshUsage();
    const { pubPem } = makeX25519Pair();
    // Append in order: unsealed, sealed, unsealed, sealed.
    usage.record({
      key_id: 'k', tenant_id: 'T', app_id: '_default', model: 'm',
      status: 'success', request_id: 'r1',
    });
    usage.record({
      key_id: 'k', tenant_id: 'T', app_id: '_default', model: 'm',
      status: 'success', request_id: 'r2', x25519_pubkey_pem: pubPem,
    });
    usage.record({
      key_id: 'k', tenant_id: 'T', app_id: '_default', model: 'm',
      status: 'success', request_id: 'r3',
    });
    usage.record({
      key_id: 'k', tenant_id: 'T', app_id: '_default', model: 'm',
      status: 'success', request_id: 'r4', x25519_pubkey_pem: pubPem,
    });
    const rows = usage.readByTenant('T');
    expect(rows.length).toBe(4);
    const result = usage.verifyChain(rows);
    expect(result.ok).toBe(true);
    // Check sealed flags landed as expected.
    expect(rows.map((r) => r.sealed)).toEqual([false, true, false, true]);
  });

  test('all-sealed chain verifies independent of envelope contents', () => {
    const usage = freshUsage();
    const { pubPem } = makeX25519Pair();
    for (let i = 0; i < 5; i += 1) {
      usage.record({
        key_id: 'k', tenant_id: 'T', app_id: 'a1', model: 'm',
        status: 'success', request_id: `r${i}`, x25519_pubkey_pem: pubPem,
      });
    }
    const rows = usage.readByTenant('T');
    expect(rows.length).toBe(5);
    expect(rows.every((r) => r.sealed === true)).toBe(true);
    expect(usage.verifyChain(rows).ok).toBe(true);
  });
});

// =============================================================================
// 8. /v1/audit projection — integration test lives in tests/sealed-audit-integration.test.js
//    (added in the follow-on commit that wires x25519 issuance into keys.issue).
//    Module-level seal/unseal + usage.record() dispatch are exercised above.
// =============================================================================

// =============================================================================
// 10. Envelope versioning rejects unknown shapes
// =============================================================================

describe('sealed-audit — envelope versioning', () => {
  test('unknown v → unseal throws', () => {
    const sealed = freshSealed();
    const { pubPem, privPem } = makeX25519Pair();
    const aad = { tenant_id: 't', app_id: 'a', ts: '2026-01-01T00:00:00Z' };
    const env = sealed.sealForPubkey(pubPem, 'hello', aad);
    const future = { ...env, v: 999 };
    expect(() => sealed.unsealForPrivkey(privPem, future, aad))
      .toThrow(/unknown envelope version/);
  });

  test('unknown alg → unseal throws', () => {
    const sealed = freshSealed();
    const { pubPem, privPem } = makeX25519Pair();
    const aad = { tenant_id: 't', app_id: 'a', ts: '2026-01-01T00:00:00Z' };
    const env = sealed.sealForPubkey(pubPem, 'hello', aad);
    const bogus = { ...env, alg: 'rsa-please' };
    expect(() => sealed.unsealForPrivkey(privPem, bogus, aad))
      .toThrow(/unknown envelope alg/);
  });
});

// =============================================================================
// isSealablePubkey gate
// =============================================================================

describe('sealed-audit — isSealablePubkey gate', () => {
  test('valid x25519 SPKI PEM → true', () => {
    const sealed = freshSealed();
    const { pubPem } = makeX25519Pair();
    expect(sealed.isSealablePubkey(pubPem)).toBe(true);
  });

  test('ed25519 SPKI PEM → false (wrong curve)', () => {
    const sealed = freshSealed();
    const { publicKey } = crypto.generateKeyPairSync('ed25519');
    const edPem = publicKey.export({ type: 'spki', format: 'pem' });
    expect(sealed.isSealablePubkey(edPem)).toBe(false);
  });

  test('null / garbage → false', () => {
    const sealed = freshSealed();
    expect(sealed.isSealablePubkey(null)).toBe(false);
    expect(sealed.isSealablePubkey('not a pem')).toBe(false);
    expect(sealed.isSealablePubkey(undefined)).toBe(false);
  });
});
