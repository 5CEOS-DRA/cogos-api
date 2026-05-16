// Integration tests against a local http.createServer that mimics the
// gateway's signing surface. No nock — pure stdlib.

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { createServer, Server, IncomingMessage, ServerResponse } from 'node:http';
import { AddressInfo } from 'node:net';
import {
  createHash,
  createHmac,
  createPrivateKey,
  generateKeyPairSync,
  sign as cryptoSign,
} from 'node:crypto';
import { Cogos } from '../src/client';
import {
  AuthError,
  AttestationMismatchError,
  DailyQuotaError,
  RateLimitError,
  ServerError,
  SignatureMismatchError,
} from '../src/errors';

// Reusable fixture: a fresh attestation keypair the mock server uses to
// sign every response. The Cogos client is constructed with the pubkey
// pre-pinned so it doesn't try to fetch /attestation.pub.
function mintAttestationKeyPair(): { privPem: string; pubPem: string; sign: (bytes: Buffer) => Buffer } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
  const k = createPrivateKey(privPem);
  return {
    privPem,
    pubPem,
    sign: (bytes: Buffer) => cryptoSign(null, bytes, k),
  };
}

function b64url(buf: Buffer): string {
  return buf.toString('base64').replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

// Mint a full attestation token over `respBytes` exactly as the gateway
// would (src/attestation.js fixed key order). req_hash here is a stable
// fixture (we don't bind to req body in this test scaffold; the SDK only
// validates resp_hash + signature).
function mintAttestationToken(
  signer: ReturnType<typeof mintAttestationKeyPair>['sign'],
  respBytes: Buffer,
): string {
  const respHash = createHash('sha256').update(respBytes).digest('hex');
  const payload = {
    v: 1,
    req_hash: '0'.repeat(64),
    resp_hash: respHash,
    rev: 'test-0.0.0',
    chain_head: '0'.repeat(64),
    signer: 'cogos-api',
    signer_kid: 'testkid000000001',
    ts: Date.now(),
  };
  const canonical = JSON.stringify({
    v: payload.v,
    req_hash: payload.req_hash,
    resp_hash: payload.resp_hash,
    rev: payload.rev,
    chain_head: payload.chain_head,
    signer: payload.signer,
    signer_kid: payload.signer_kid,
    ts: payload.ts,
  });
  const sig = signer(Buffer.from(canonical, 'utf8'));
  return `${b64url(Buffer.from(canonical, 'utf8'))}.${b64url(sig)}`;
}

interface Fixture {
  baseUrl: string;
  close: () => Promise<void>;
}

async function startServer(
  handler: (req: IncomingMessage, res: ServerResponse, bodyBuf: Buffer) => void,
): Promise<Fixture> {
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const bodyBuf = Buffer.concat(chunks);
      handler(req, res, bodyBuf);
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const addr = server.address() as AddressInfo;
  return {
    baseUrl: `http://127.0.0.1:${addr.port}`,
    close: () =>
      new Promise<void>((r) => {
        server.close(() => r());
      }),
  };
}

test('integration: chat.completions.create verifies HMAC + attestation', async () => {
  const att = mintAttestationKeyPair();
  const hmacSecret = 'abcdef0123456789'.repeat(4);
  const respObj = {
    id: 'chatcmpl-x',
    object: 'chat.completion',
    created: 1700000000,
    model: 'cogos-tier-b',
    choices: [{ index: 0, message: { role: 'assistant', content: 'hi' }, finish_reason: 'stop' }],
    usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
  };
  const respBytes = Buffer.from(JSON.stringify(respObj), 'utf8');
  const sig = createHmac('sha256', hmacSecret).update(respBytes).digest('hex');
  const token = mintAttestationToken(att.sign, respBytes);

  const fixture = await startServer((req, res, _body) => {
    assert.equal(req.method, 'POST');
    assert.equal(req.url, '/v1/chat/completions');
    assert.equal(req.headers.authorization, 'Bearer sk-cogos-fakekey');
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('X-Cogos-Signature', sig);
    res.setHeader('X-Cogos-Signature-Algo', 'hmac-sha256');
    res.setHeader('X-Cogos-Attestation', token);
    res.setHeader('X-Cogos-Attestation-Algo', 'ed25519');
    res.end(respBytes);
  });

  try {
    const client = new Cogos({
      apiKey: 'sk-cogos-fakekey',
      hmacSecret,
      baseUrl: fixture.baseUrl,
      attestationPubPem: att.pubPem,
    });
    const r = await client.chat.completions.create({
      messages: [{ role: 'user', content: 'hi' }],
      model: 'cogos-tier-b',
    });
    assert.equal(r.choices[0].message.content, 'hi');
  } finally {
    await fixture.close();
  }
});

test('integration: SignatureMismatchError when HMAC wrong', async () => {
  const att = mintAttestationKeyPair();
  const hmacSecret = 'a'.repeat(64);
  const respObj = { object: 'list', data: [] };
  const respBytes = Buffer.from(JSON.stringify(respObj), 'utf8');
  const wrongSig = createHmac('sha256', 'WRONGSECRET').update(respBytes).digest('hex');
  const token = mintAttestationToken(att.sign, respBytes);

  const fixture = await startServer((_req, res) => {
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('X-Cogos-Signature', wrongSig);
    res.setHeader('X-Cogos-Attestation', token);
    res.end(respBytes);
  });

  try {
    const client = new Cogos({
      apiKey: 'sk-cogos-fakekey',
      hmacSecret,
      baseUrl: fixture.baseUrl,
      attestationPubPem: att.pubPem,
    });
    await assert.rejects(client.models.list(), SignatureMismatchError);
  } finally {
    await fixture.close();
  }
});

test('integration: AttestationMismatchError when resp_hash does not bind', async () => {
  const att = mintAttestationKeyPair();
  const realResp = Buffer.from(JSON.stringify({ object: 'list', data: [] }), 'utf8');
  const otherResp = Buffer.from(JSON.stringify({ object: 'list', data: [{ id: 'x' }] }), 'utf8');
  const token = mintAttestationToken(att.sign, realResp); // signed over OLD bytes
  const fixture = await startServer((_req, res) => {
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('X-Cogos-Attestation', token);
    res.end(otherResp); // but we send DIFFERENT bytes
  });

  try {
    const client = new Cogos({
      apiKey: 'sk-cogos-fakekey',
      baseUrl: fixture.baseUrl,
      attestationPubPem: att.pubPem,
    });
    await assert.rejects(client.models.list(), AttestationMismatchError);
  } finally {
    await fixture.close();
  }
});

test('integration: 401 → AuthError with errorType', async () => {
  const att = mintAttestationKeyPair();
  const fixture = await startServer((_req, res) => {
    res.statusCode = 401;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: { message: 'bad key', type: 'invalid_api_key' } }));
  });
  try {
    const client = new Cogos({
      apiKey: 'sk-cogos-fakekey',
      baseUrl: fixture.baseUrl,
      attestationPubPem: att.pubPem,
    });
    await assert.rejects(
      client.models.list(),
      (e: unknown) => {
        assert.ok(e instanceof AuthError);
        assert.equal((e as AuthError).status, 401);
        assert.equal((e as AuthError).errorType, 'invalid_api_key');
        return true;
      },
    );
  } finally {
    await fixture.close();
  }
});

test('integration: 429 daily_quota_exceeded → DailyQuotaError with retryAfter', async () => {
  const att = mintAttestationKeyPair();
  const fixture = await startServer((_req, res) => {
    res.statusCode = 429;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Retry-After', '3600');
    res.end(JSON.stringify({
      error: { message: 'daily quota', type: 'daily_quota_exceeded', retry_after_s: 3600 },
    }));
  });
  try {
    const client = new Cogos({
      apiKey: 'sk-cogos-fakekey',
      baseUrl: fixture.baseUrl,
      attestationPubPem: att.pubPem,
    });
    await assert.rejects(
      client.models.list(),
      (e: unknown) => {
        assert.ok(e instanceof DailyQuotaError);
        assert.equal((e as DailyQuotaError).retryAfterSeconds, 3600);
        assert.equal((e as DailyQuotaError).errorType, 'daily_quota_exceeded');
        return true;
      },
    );
  } finally {
    await fixture.close();
  }
});

test('integration: 429 plain → RateLimitError', async () => {
  const att = mintAttestationKeyPair();
  const fixture = await startServer((_req, res) => {
    res.statusCode = 429;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Retry-After', '7');
    res.end(JSON.stringify({ error: { message: 'slow down', type: 'rate_limit' } }));
  });
  try {
    const client = new Cogos({
      apiKey: 'sk-cogos-fakekey',
      baseUrl: fixture.baseUrl,
      attestationPubPem: att.pubPem,
    });
    await assert.rejects(
      client.models.list(),
      (e: unknown) => {
        assert.ok(e instanceof RateLimitError);
        assert.equal((e as RateLimitError).retryAfterSeconds, 7);
        return true;
      },
    );
  } finally {
    await fixture.close();
  }
});

test('integration: 502 → ServerError', async () => {
  const att = mintAttestationKeyPair();
  const fixture = await startServer((_req, res) => {
    res.statusCode = 502;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: { message: 'upstream is sad', type: 'upstream_error' } }));
  });
  try {
    const client = new Cogos({
      apiKey: 'sk-cogos-fakekey',
      baseUrl: fixture.baseUrl,
      attestationPubPem: att.pubPem,
    });
    await assert.rejects(
      client.models.list(),
      (e: unknown) => {
        assert.ok(e instanceof ServerError);
        assert.equal((e as ServerError).status, 502);
        return true;
      },
    );
  } finally {
    await fixture.close();
  }
});

test('integration: audit.read passes query params', async () => {
  const att = mintAttestationKeyPair();
  const respObj = {
    rows: [],
    next_cursor: null,
    chain_ok: true,
    chain_break: null,
    chain_ok_by_app: { _default: true },
    app_id: '_default',
    server_time_ms: 1700000000,
  };
  const respBytes = Buffer.from(JSON.stringify(respObj), 'utf8');
  const token = mintAttestationToken(att.sign, respBytes);
  let observedUrl = '';
  const fixture = await startServer((req, res) => {
    observedUrl = req.url || '';
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('X-Cogos-Attestation', token);
    res.end(respBytes);
  });
  try {
    const client = new Cogos({
      apiKey: 'sk-cogos-fakekey',
      baseUrl: fixture.baseUrl,
      attestationPubPem: att.pubPem,
    });
    const r = await client.audit.read({ sinceMs: 100, limit: 10, appId: '_default' });
    assert.equal(r.chain_ok, true);
    assert.ok(observedUrl.includes('since=100'));
    assert.ok(observedUrl.includes('limit=10'));
    assert.ok(observedUrl.includes('app_id=_default'));
  } finally {
    await fixture.close();
  }
});

test('integration: ed25519 client signs Authorization header', async () => {
  const att = mintAttestationKeyPair();
  const userKp = generateKeyPairSync('ed25519');
  const userPrivPem = userKp.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  const respObj = { object: 'list', data: [] };
  const respBytes = Buffer.from(JSON.stringify(respObj), 'utf8');
  const token = mintAttestationToken(att.sign, respBytes);
  let observedAuth = '';
  const fixture = await startServer((req, res) => {
    observedAuth = String(req.headers.authorization || '');
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('X-Cogos-Attestation', token);
    res.end(respBytes);
  });
  try {
    const { Ed25519Signer } = await import('../src/ed25519');
    const signer = new Ed25519Signer(userPrivPem, 'kid-int01');
    const client = new Cogos({
      ed25519Signer: signer,
      baseUrl: fixture.baseUrl,
      attestationPubPem: att.pubPem,
    });
    await client.models.list();
    assert.ok(observedAuth.startsWith('CogOS-Ed25519 keyId=kid-int01,'));
    // ts and sig present
    assert.ok(/,sig=[^,]+/.test(observedAuth));
    assert.ok(/,ts=\d+/.test(observedAuth));
  } finally {
    await fixture.close();
  }
});

test('integration: verifyAttestation=false skips attestation', async () => {
  const fixture = await startServer((_req, res) => {
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    // intentionally NO X-Cogos-Attestation
    res.end(JSON.stringify({ object: 'list', data: [] }));
  });
  try {
    const client = new Cogos({
      apiKey: 'sk-cogos-fakekey',
      baseUrl: fixture.baseUrl,
      verifyAttestation: false,
    });
    const r = await client.models.list();
    assert.equal(r.object, 'list');
  } finally {
    await fixture.close();
  }
});

test('integration: keys.rotate returns bearer rotation payload', async () => {
  const att = mintAttestationKeyPair();
  const respObj = {
    key_id: 'uuid-1',
    tenant_id: 't',
    app_id: '_default',
    tier: 'starter',
    scheme: 'bearer',
    issued_at: '2026-05-14T00:00:00.000Z',
    expires_at: '2027-05-14T00:00:00.000Z',
    rotated_from_key_id: 'uuid-0',
    rotation_grace_until: '2026-05-15T00:00:00.000Z',
    hmac_secret: 'b'.repeat(64),
    api_key: 'sk-cogos-newkey',
    warning: 'rotate fast',
  };
  const respBytes = Buffer.from(JSON.stringify(respObj), 'utf8');
  const token = mintAttestationToken(att.sign, respBytes);
  const fixture = await startServer((req, res) => {
    assert.equal(req.method, 'POST');
    assert.equal(req.url, '/v1/keys/rotate');
    res.statusCode = 201;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('X-Cogos-Attestation', token);
    res.end(respBytes);
  });
  try {
    const client = new Cogos({
      apiKey: 'sk-cogos-fakekey',
      baseUrl: fixture.baseUrl,
      attestationPubPem: att.pubPem,
    });
    const r = await client.keys.rotate();
    assert.equal(r.scheme, 'bearer');
    if (r.scheme === 'bearer') {
      assert.equal(r.api_key, 'sk-cogos-newkey');
    }
  } finally {
    await fixture.close();
  }
});
