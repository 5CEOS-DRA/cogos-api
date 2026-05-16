#!/usr/bin/env node
// Generate cross-implementation fixtures for the Python SDK tests.
// We import the SERVER's own crypto/attestation/sealed-audit primitives
// so any byte-exact divergence between the Python implementation and
// the Node server is caught by a Python unit test.
//
// Outputs JSON to stdout. Re-run when the wire format changes:
//   node sdks/python/tests/generate_fixtures.js > sdks/python/tests/fixtures.json
//
// The fixture is committed; tests don't shell out to node at run time.

'use strict';

const crypto = require('crypto');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const cryptoSign = require(path.join(ROOT, 'src/crypto-sign.js'));
const attestation = require(path.join(ROOT, 'src/attestation.js'));
const sealedAudit = require(path.join(ROOT, 'src/sealed-audit.js'));

// ---- HMAC fixture --------------------------------------------------------
const hmacSecret = 'hsec_test_DETERMINISTIC_32B_PADDED';
const bodyStr = '{"object":"list","data":[{"id":"cogos-tier-b"}]}';
const bodyBytes = Buffer.from(bodyStr, 'utf8');
const sigHex = cryptoSign.sign(hmacSecret, bodyBytes);

// ---- Ed25519 request-sign fixture ---------------------------------------
// Deterministic keypair from a fixed 32-byte seed so the Python test can
// hard-code the expected base64 signature byte-for-byte.
//
// Node accepts ed25519 keys via raw seed -> PKCS8 PEM via createPrivateKey.
// We construct the DER from a known wrapper.
const ed25519Seed = Buffer.from(
  '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
  'hex',
);
// PKCS8 DER prefix for Ed25519 keys (RFC 8410). Always 16 bytes followed by
// the 32-byte seed. We assemble it manually to avoid any randomness.
const PKCS8_ED25519_PREFIX = Buffer.from(
  '302e020100300506032b657004220420',
  'hex',
);
const ed25519PkBuf = Buffer.concat([PKCS8_ED25519_PREFIX, ed25519Seed]);
const ed25519PrivKey = crypto.createPrivateKey({
  key: ed25519PkBuf,
  format: 'der',
  type: 'pkcs8',
});
const ed25519PrivPem = ed25519PrivKey.export({ type: 'pkcs8', format: 'pem' });
const ed25519PubKey = crypto.createPublicKey(ed25519PrivKey);
const ed25519PubPem = ed25519PubKey.export({ type: 'spki', format: 'pem' });

const reqMethod = 'POST';
const reqPath = '/v1/chat/completions';
const reqTs = 1715706000000; // fixed
const reqBody = '{"model":"cogos-tier-b","messages":[{"role":"user","content":"hi"}]}';
const reqBodyHex = crypto.createHash('sha256').update(reqBody).digest('hex');
const signedBytes = `${reqMethod}\n${reqPath}\n${reqTs}\n${reqBodyHex}`;
const reqSigB64 = crypto
  .sign(null, Buffer.from(signedBytes, 'utf8'), ed25519PrivKey)
  .toString('base64');

// ---- Attestation token fixture (server-side sign + customer-side verify)
// Pin a deterministic attestation keypair via the test hook.
const attSeed = Buffer.from(
  'a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0',
  'hex',
);
const attPkBuf = Buffer.concat([PKCS8_ED25519_PREFIX, attSeed]);
const attPrivKey = crypto.createPrivateKey({
  key: attPkBuf, format: 'der', type: 'pkcs8',
});
const attPubKey = crypto.createPublicKey(attPrivKey);
const attPrivPem = attPrivKey.export({ type: 'pkcs8', format: 'pem' });
const attPubPem = attPubKey.export({ type: 'spki', format: 'pem' });
attestation._internal.setKeyPairForTest(attPrivPem, attPubPem);

// Pin a deterministic timestamp + chain head so the Python test can
// assert the full payload value.
const respBody = '{"object":"list","data":[{"id":"cogos-tier-b","object":"model"}]}';
const attReqBody = ''; // GET /v1/models
const fixedTs = 1715706000000;
const chainHead = 'deadbeef'.repeat(8); // 64 hex chars
// Force COGOS_REVISION so rev is stable.
process.env.COGOS_REVISION = 'test-revision-1';
const token = attestation.sign({
  method: 'GET',
  path: '/v1/models',
  ts: fixedTs,
  reqBody: attReqBody,
  respBody,
  chainHead,
});

// ---- Sealed audit fixture ------------------------------------------------
// Deterministic X25519 keypair via clamped raw seed.
const x25519SeedRaw = Buffer.from(
  '8888888888888888888888888888888888888888888888888888888888888888',
  'hex',
);
// X25519 PKCS8 PEM via the raw seed. clamp-on-load is handled by Node.
const PKCS8_X25519_PREFIX = Buffer.from(
  '302e020100300506032b656e04220420',
  'hex',
);
const x25519PkBuf = Buffer.concat([PKCS8_X25519_PREFIX, x25519SeedRaw]);
const x25519PrivKey = crypto.createPrivateKey({
  key: x25519PkBuf, format: 'der', type: 'pkcs8',
});
const x25519PubKey = crypto.createPublicKey(x25519PrivKey);
const x25519PrivPem = x25519PrivKey.export({ type: 'pkcs8', format: 'pem' });
const x25519PubPem = x25519PubKey.export({ type: 'spki', format: 'pem' });

const sealAad = {
  tenant_id: 'alice',
  app_id: '_default',
  ts: '2026-05-14T00:00:00.000Z',
};
const sealPlaintext = JSON.stringify({
  request_id: 'chatcmpl-abc123',
  prompt_fingerprint: 'sha256:deadbeefdeadbeef',
  schema_name: 'invoice_v1',
});
const envelope = sealedAudit.sealForPubkey(x25519PubPem, sealPlaintext, sealAad);

// One sealed audit ROW shape as the customer would see it from /v1/audit.
const sealedRow = {
  ts: sealAad.ts,
  tenant_id: sealAad.tenant_id,
  app_id: sealAad.app_id,
  key_id: 'kid-test',
  model: 'cogos-tier-b',
  status: 'success',
  sealed: true,
  sealed_content: envelope,
};

const out = {
  hmac: {
    hmac_secret: hmacSecret,
    body_utf8: bodyStr,
    expected_signature_hex: sigHex,
  },
  ed25519_request: {
    private_pem: ed25519PrivPem,
    public_pem: ed25519PubPem,
    method: reqMethod,
    path: reqPath,
    ts: reqTs,
    body_utf8: reqBody,
    expected_signature_base64: reqSigB64,
    expected_header_suffix: `keyId=kid-test,sig=${reqSigB64},ts=${reqTs}`,
  },
  attestation: {
    public_pem: attPubPem,
    revision: 'test-revision-1',
    chain_head: chainHead,
    ts: fixedTs,
    response_body_utf8: respBody,
    request_method: 'GET',
    request_path: '/v1/models',
    request_body_utf8: '',
    token,
  },
  sealed_audit: {
    x25519_private_pem: x25519PrivPem,
    x25519_public_pem: x25519PubPem,
    plaintext_utf8: sealPlaintext,
    aad: sealAad,
    row: sealedRow,
  },
};

process.stdout.write(JSON.stringify(out, null, 2));
process.stdout.write('\n');
