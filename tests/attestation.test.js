'use strict';

// Per-response attestation token tests.
//
// The attestation primitive cryptographically binds a /v1/* response to the
// running build, the request that produced it, the audit chain head after
// the row was appended, and the timestamp of issuance — signed by an
// ephemeral Ed25519 key bound to the process. See src/attestation.js for
// the threat model.

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';
process.env.COGOS_REVISION = 'test-rev-7c3a';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-api-attest-'));
process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
process.env.OLLAMA_URL = 'http://ollama.test';
process.env.DEFAULT_MODEL = 'qwen2.5:3b-instruct';
// Isolate the persisted attestation key in tmpDir so the sealed-shape
// assertion can read it back without polluting the repo's data/ dir.
process.env.ATTESTATION_KEY_FILE = path.join(tmpDir, 'attestation-key.pem');
// Pin a deterministic DEK for the at-rest-shape assertion below. The
// DEK is also used by src/keys.js for hmac_secret sealing — keys issued
// in this test file are sealed under the same key.
process.env.COGOS_DEK_HEX = crypto.randomBytes(32).toString('hex');

const request = require('supertest');
const nock = require('nock');
const { createApp } = require('../src/index');
const attestation = require('../src/attestation');

beforeAll(() => {
  nock.disableNetConnect();
  nock.enableNetConnect(/127\.0\.0\.1|localhost/);
});
afterEach(() => { nock.cleanAll(); });
afterAll(() => {
  nock.enableNetConnect();
  nock.restore();
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

async function issueKey(app, tenantId = 'denny-attest', tier = 'starter') {
  const res = await request(app)
    .post('/admin/keys')
    .set('X-Admin-Key', process.env.ADMIN_KEY)
    .send({ tenant_id: tenantId, tier });
  return res.body;
}

// Re-export the canonical helpers so the tests speak the same shape the
// production module speaks. Re-implementing them here would let a divergence
// between test and prod slip through.
const {
  computeReqHash, computeRespHash, b64urlDecode, canonicalPayloadJson,
} = attestation._internal;

function decodeToken(token) {
  const [payloadB64, sigB64] = token.split('.', 2);
  const payloadJson = b64urlDecode(payloadB64).toString('utf8');
  return {
    payloadJson,
    payload: JSON.parse(payloadJson),
    sigBuf: b64urlDecode(sigB64),
  };
}

describe('attestation: /attestation.pub endpoint', () => {
  test('GET /attestation.pub → 200 + a public key PEM', async () => {
    const app = createApp();
    const res = await request(app).get('/attestation.pub');
    expect(res.status).toBe(200);
    expect(res.text).toMatch(/-----BEGIN PUBLIC KEY-----/);
    expect(res.text).toMatch(/-----END PUBLIC KEY-----/);
    // PEM parses as an Ed25519 public key.
    const k = crypto.createPublicKey(res.text);
    expect(k.asymmetricKeyType).toBe('ed25519');
    // kid header echoes the first 16 hex of sha256(pem).
    expect(res.headers['x-cogos-attestation-kid']).toMatch(/^[a-f0-9]{16}$/);
  });
});

// at-rest-encrypt-attestation-key card (2026-05-14): when a DEK is
// configured, the persisted private PEM file is replaced by a JSON-shape
// sealed envelope. Disk breach yields ciphertext only.
describe('attestation: persisted key file is sealed (JSON-shape) under DEK', () => {
  test('data/attestation-key.pem on disk is a JSON envelope, NOT raw PEM', async () => {
    // Force the keypair to materialize so the persistence path runs.
    const app = createApp();
    const res = await request(app).get('/attestation.pub');
    expect(res.status).toBe(200);
    // Read what was actually written to disk.
    const raw = fs.readFileSync(process.env.ATTESTATION_KEY_FILE, 'utf8');
    // PEM shape would start with `-----BEGIN`. Sealed shape starts with `{`.
    expect(raw.trimStart()[0]).toBe('{');
    expect(raw).not.toMatch(/-----BEGIN /);
    // Parses as JSON with the dek envelope shape.
    const env = JSON.parse(raw);
    expect(env).toEqual(expect.objectContaining({
      ciphertext_b64: expect.any(String),
      nonce_b64: expect.any(String),
      tag_b64: expect.any(String),
    }));
  });
});

describe('attestation: header on /v1/models', () => {
  test('signed /v1/models response carries X-Cogos-Attestation with decodable payload', async () => {
    const app = createApp();
    const { api_key } = await issueKey(app);
    const res = await request(app)
      .get('/v1/models')
      .set('Authorization', `Bearer ${api_key}`);
    expect(res.status).toBe(200);
    const token = res.headers['x-cogos-attestation'];
    expect(typeof token).toBe('string');
    expect(token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    const { payload } = decodeToken(token);
    // Every required field present.
    expect(payload.v).toBe(1);
    expect(payload.req_hash).toMatch(/^[a-f0-9]{64}$/);
    expect(payload.resp_hash).toMatch(/^[a-f0-9]{64}$/);
    expect(payload.rev).toBe('test-rev-7c3a');
    expect(payload.chain_head).toMatch(/^[a-f0-9]{64}$/);
    expect(payload.signer).toBe('cogos-api');
    expect(payload.signer_kid).toMatch(/^[a-f0-9]{16}$/);
    expect(typeof payload.ts).toBe('number');
    expect(res.headers['x-cogos-attestation-algo']).toBe('ed25519');
  });
});

describe('attestation: req_hash bind is client-recomputable', () => {
  test('req_hash matches a client-side recomputation over (method, path, ts, body)', async () => {
    nock('http://ollama.test')
      .post('/api/chat')
      .reply(200, {
        message: { role: 'assistant', content: 'echo' },
        prompt_eval_count: 4,
        eval_count: 2,
        done_reason: 'stop',
      });
    const app = createApp();
    const { api_key } = await issueKey(app);
    const reqBody = { model: 'cogos-tier-b', messages: [{ role: 'user', content: 'hi' }] };
    const res = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${api_key}`)
      .send(reqBody);
    expect(res.status).toBe(200);
    const token = res.headers['x-cogos-attestation'];
    const { payload } = decodeToken(token);
    // Recompute client-side. supertest serializes the body as JSON.stringify;
    // we mirror that for the bind. The ts in the receipt is what the server
    // recorded — we use that to recompute, so the recomputation is a true
    // round-trip check (not an end-to-end signature verification, which is
    // tested separately below).
    const clientReqHash = computeReqHash({
      method: 'POST',
      path: '/v1/chat/completions',
      ts: String(payload.ts),
      body: JSON.stringify(reqBody),
    });
    expect(payload.req_hash).toBe(clientReqHash);
  });
});

describe('attestation: resp_hash bind matches actual body bytes', () => {
  test('resp_hash equals sha256(actual response body)', async () => {
    nock('http://ollama.test')
      .post('/api/chat')
      .reply(200, {
        message: { role: 'assistant', content: 'paris' },
        prompt_eval_count: 8,
        eval_count: 1,
        done_reason: 'stop',
      });
    const app = createApp();
    const { api_key } = await issueKey(app);
    const res = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${api_key}`)
      .send({ messages: [{ role: 'user', content: 'capital of france?' }] });
    expect(res.status).toBe(200);
    const token = res.headers['x-cogos-attestation'];
    const { payload } = decodeToken(token);
    // The customer reads r.text (raw bytes) — that's what we sign.
    const computed = computeRespHash(res.text);
    expect(payload.resp_hash).toBe(computed);
  });
});

describe('attestation: signature verifies under /attestation.pub', () => {
  test('end-to-end signature verifies; chain_head matches running findHead', async () => {
    nock('http://ollama.test')
      .post('/api/chat')
      .reply(200, {
        message: { role: 'assistant', content: 'hi back' },
        prompt_eval_count: 3,
        eval_count: 2,
        done_reason: 'stop',
      });
    const app = createApp();
    const { api_key } = await issueKey(app, 'denny-verify');
    const res = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${api_key}`)
      .send({ messages: [{ role: 'user', content: 'hi' }] });
    const token = res.headers['x-cogos-attestation'];

    // Fetch the pubkey the same way a customer would.
    const pubRes = await request(app).get('/attestation.pub');
    const pubPem = pubRes.text;

    // Recompute the payload bytes, verify the Ed25519 signature against
    // the published pubkey, end to end.
    const [payloadB64, sigB64] = token.split('.', 2);
    const payloadJson = b64urlDecode(payloadB64).toString('utf8');
    const sigBuf = b64urlDecode(sigB64);
    const pubKey = crypto.createPublicKey(pubPem);
    const ok = crypto.verify(null, Buffer.from(payloadJson, 'utf8'), pubKey, sigBuf);
    expect(ok).toBe(true);

    // chain_head in the receipt equals the row_hash that usage.record
    // wrote for this request — verifiable independently by reading
    // usage._internal.findHead().
    const usage = require('../src/usage');
    const expectedHead = usage._internal.findHead('denny-verify', '_default');
    const { payload } = decodeToken(token);
    expect(payload.chain_head).toBe(expectedHead);
    expect(payload.chain_head).not.toBe('0'.repeat(64));
  });
});

describe('attestation: tamper detection', () => {
  test('tampering the encoded payload (flipping resp_hash) invalidates the signature', async () => {
    const app = createApp();
    const { api_key } = await issueKey(app, 'denny-tamper-1');
    const res = await request(app)
      .get('/v1/models')
      .set('Authorization', `Bearer ${api_key}`);
    const token = res.headers['x-cogos-attestation'];

    // Decode, mutate resp_hash, re-encode under the SAME signature.
    // The signature is over the original payload bytes — any single-bit
    // change to the payload (including key order) flips verification.
    const { payload, sigBuf } = decodeToken(token);
    const tampered = { ...payload };
    // Flip one hex char of resp_hash.
    const first = tampered.resp_hash[0];
    tampered.resp_hash = (first === 'f' ? '0' : 'f') + tampered.resp_hash.slice(1);
    const tamperedJson = canonicalPayloadJson(tampered);
    const tamperedB64 = Buffer.from(tamperedJson, 'utf8').toString('base64')
      .replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const sigB64 = Buffer.from(sigBuf).toString('base64')
      .replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const tamperedToken = `${tamperedB64}.${sigB64}`;

    const pubRes = await request(app).get('/attestation.pub');
    const verified = attestation.verify(tamperedToken, pubRes.text);
    expect(verified).toBeNull();
  });

  test('tampering the response body (but not the token) — token verifies, resp_hash bind fails', async () => {
    // This is THE detection mechanism: the signature is over the token
    // payload, not over the body. A MITM that rewrites the body but keeps
    // the original token will leave the token signature-valid — BUT the
    // resp_hash inside the token will no longer match sha256(body), and
    // the customer's client-side recomputation surfaces the discrepancy.
    nock('http://ollama.test')
      .post('/api/chat')
      .reply(200, {
        message: { role: 'assistant', content: 'original' },
        prompt_eval_count: 1,
        eval_count: 1,
        done_reason: 'stop',
      });
    const app = createApp();
    const { api_key } = await issueKey(app, 'denny-tamper-2');
    const res = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${api_key}`)
      .send({ messages: [{ role: 'user', content: 'original?' }] });
    const token = res.headers['x-cogos-attestation'];

    // The token signature still verifies (we haven't touched the token).
    const pubRes = await request(app).get('/attestation.pub');
    const payload = attestation.verify(token, pubRes.text);
    expect(payload).not.toBeNull();

    // But if a MITM rewrote the body, the customer's sha256(received_body)
    // would diverge from payload.resp_hash. Simulate by hashing a tampered
    // body and confirming the payload's bound hash is the original one.
    const originalBodyHash = computeRespHash(res.text);
    expect(payload.resp_hash).toBe(originalBodyHash);

    const tamperedBody = res.text.replace('original', 'manipulated');
    expect(tamperedBody).not.toBe(res.text);
    const tamperedBodyHash = computeRespHash(tamperedBody);
    expect(tamperedBodyHash).not.toBe(payload.resp_hash);
    // This is the discrepancy the customer detects: tamper of body without
    // tamper of token still binds to the ORIGINAL response.
  });

  test('flipping a bit in the signature segment makes the token unverifiable', async () => {
    const app = createApp();
    const { api_key } = await issueKey(app, 'denny-tamper-3');
    const res = await request(app)
      .get('/v1/models')
      .set('Authorization', `Bearer ${api_key}`);
    const token = res.headers['x-cogos-attestation'];
    const [payloadB64, sigB64] = token.split('.', 2);
    // Flip a single character in the signature.
    const flipped = (sigB64[0] === 'A' ? 'B' : 'A') + sigB64.slice(1);
    const tamperedToken = `${payloadB64}.${flipped}`;
    const pubRes = await request(app).get('/attestation.pub');
    const verified = attestation.verify(tamperedToken, pubRes.text);
    expect(verified).toBeNull();
  });
});

describe('attestation: chain_head advances across consecutive requests', () => {
  test('two requests on same tenant produce chain_head values that link', async () => {
    nock('http://ollama.test')
      .post('/api/chat').times(2)
      .reply(200, {
        message: { role: 'assistant', content: 'ok' },
        prompt_eval_count: 1,
        eval_count: 1,
        done_reason: 'stop',
      });
    const app = createApp();
    const { api_key } = await issueKey(app, 'denny-chain');
    const r1 = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${api_key}`)
      .send({ messages: [{ role: 'user', content: 'one' }] });
    const r2 = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${api_key}`)
      .send({ messages: [{ role: 'user', content: 'two' }] });
    const head1 = decodeToken(r1.headers['x-cogos-attestation']).payload.chain_head;
    const head2 = decodeToken(r2.headers['x-cogos-attestation']).payload.chain_head;
    expect(head1).not.toBe(head2);
    expect(head1).toMatch(/^[a-f0-9]{64}$/);
    expect(head2).toMatch(/^[a-f0-9]{64}$/);
    // r2 was appended after r1, so r2's chain row had r1's hash as prev_hash.
    // We can't easily reconstruct without internal access to canonicalChainPayload,
    // but we can at minimum confirm the head moved forward in the file.
    const usage = require('../src/usage');
    const rows = usage.readSlice({ tenant_id: 'denny-chain', limit: 10 });
    expect(rows.length).toBeGreaterThanOrEqual(2);
    expect(rows[rows.length - 1].row_hash).toBe(head2);
  });
});
