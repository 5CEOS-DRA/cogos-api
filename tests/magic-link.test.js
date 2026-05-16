'use strict';

// Tests for src/magic-link.js — signed magic-link tokens.
//
// Covers:
//   - createToken + verifyToken roundtrip
//   - URL shape (host base + token query param)
//   - Expired token (exp_ms in past) → null
//   - Wrong signature → null
//   - Tampered payload (any byte) → null
//   - Wrong kind in payload → null
//   - Garbage / structurally-broken token → null
//   - Same nonce consumed twice → second call returns null
//   - Token tied to one tenant_id can't be replayed for another (changing
//     tenant_id is a tamper, which fails the signature check)
//   - Secret resolution priority: env → file → generated

process.env.NODE_ENV = 'test';
process.env.COGOS_MAGIC_LINK_SECRET = 'b2'.repeat(32);

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-magic-test-'));
process.env.MAGIC_LINK_SECRET_FILE = path.join(tmpDir, '.magic-link-secret');
process.env.MAGIC_LINK_CONSUMED_FILE = path.join(tmpDir, 'magic-link-consumed.json');

afterAll(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

function freshModule() {
  // Reset the require cache + in-memory state between tests so secret
  // resolution + consumed-nonce LRU are deterministic.
  jest.resetModules();
  const m = require('../src/magic-link');
  m._test._reset();
  return m;
}

// =============================================================================
describe('createToken + verifyToken roundtrip', () => {
  test('valid token → returns the original tenant_id/key_id/email', () => {
    const m = freshModule();
    const { token } = m.createToken({
      tenant_id: 'tenant-A',
      key_id: 'key-abc',
      email: 'alice@example.com',
    });
    const parsed = m.verifyToken(token);
    expect(parsed).toBeTruthy();
    expect(parsed.tenant_id).toBe('tenant-A');
    expect(parsed.key_id).toBe('key-abc');
    expect(parsed.email).toBe('alice@example.com');
    expect(parsed.nonce).toMatch(/^[0-9a-f]{32}$/);
    expect(typeof parsed.exp_ms).toBe('number');
  });

  test('createToken returns a base64url.base64url shape', () => {
    const m = freshModule();
    const { token } = m.createToken({
      tenant_id: 't', key_id: 'k', email: 'e@x.com',
    });
    expect(token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  });

  test('url field uses the supplied baseUrl + dashboard/auth path', () => {
    const m = freshModule();
    const { url, token } = m.createToken({
      tenant_id: 't', key_id: 'k', email: 'e@x.com',
      baseUrl: 'https://cogos.5ceos.com',
    });
    expect(url).toBe(`https://cogos.5ceos.com/dashboard/auth?token=${encodeURIComponent(token)}`);
  });

  test('url with no baseUrl falls back to a relative path', () => {
    const m = freshModule();
    const { url } = m.createToken({
      tenant_id: 't', key_id: 'k', email: 'e@x.com',
    });
    expect(url.startsWith('/dashboard/auth?token=')).toBe(true);
  });

  test('createToken refuses to mint without required fields', () => {
    const m = freshModule();
    expect(() => m.createToken({ key_id: 'k', email: 'e' })).toThrow();
    expect(() => m.createToken({ tenant_id: 't', email: 'e' })).toThrow();
    expect(() => m.createToken({ tenant_id: 't', key_id: 'k' })).toThrow();
  });
});

// =============================================================================
describe('verifyToken — failure modes (all return null, no oracle)', () => {
  test('expired token (ttl in the past) → null', () => {
    const m = freshModule();
    const { token } = m.createToken({
      tenant_id: 't', key_id: 'k', email: 'e@x.com',
      ttlMs: -1000, // already expired
    });
    expect(m.verifyToken(token)).toBeNull();
  });

  test('wrong signature → null', () => {
    const m = freshModule();
    const { token } = m.createToken({
      tenant_id: 't', key_id: 'k', email: 'e@x.com',
    });
    const dot = token.indexOf('.');
    const flipped = token[dot + 1] === 'A' ? 'B' : 'A';
    const tampered = `${token.slice(0, dot + 1)}${flipped}${token.slice(dot + 2)}`;
    expect(m.verifyToken(tampered)).toBeNull();
  });

  test('tampered payload (changing tenant_id) → null', () => {
    const m = freshModule();
    const { token } = m.createToken({
      tenant_id: 'tenant-A', key_id: 'k', email: 'e@x.com',
    });
    // Re-encode the payload with a different tenant_id but keep the
    // original signature. The HMAC won't match.
    const dot = token.indexOf('.');
    const payloadB64 = token.slice(0, dot);
    const sigB64 = token.slice(dot + 1);
    const payloadJson = Buffer.from(payloadB64, 'base64url').toString('utf8');
    const obj = JSON.parse(payloadJson);
    obj.tenant_id = 'tenant-B'; // attacker-controlled
    const tamperedPayloadB64 = Buffer.from(JSON.stringify(obj)).toString('base64url');
    const tampered = `${tamperedPayloadB64}.${sigB64}`;
    expect(m.verifyToken(tampered)).toBeNull();
  });

  test('wrong kind value (not magic-link) → null', () => {
    const m = freshModule();
    // Mint manually with kind='other' but a valid signature so we know
    // the kind check is what's rejecting (not the signature).
    const payload = {
      kind: 'other',
      tenant_id: 't', key_id: 'k', email: 'e@x.com',
      nonce: crypto.randomBytes(16).toString('hex'),
      exp_ms: Date.now() + 60_000,
    };
    const payloadJson = JSON.stringify(payload);
    const payloadBytes = Buffer.from(payloadJson, 'utf8');
    const secretHex = m._test._peekSecretHex();
    const sig = crypto.createHmac('sha256', Buffer.from(secretHex, 'hex'))
      .update(payloadBytes).digest();
    const token = `${payloadBytes.toString('base64url')}.${sig.toString('base64url')}`;
    expect(m.verifyToken(token)).toBeNull();
  });

  test('garbage strings → null (no exceptions)', () => {
    const m = freshModule();
    expect(m.verifyToken('')).toBeNull();
    expect(m.verifyToken('not-a-token')).toBeNull();
    expect(m.verifyToken('.')).toBeNull();
    expect(m.verifyToken('a.')).toBeNull();
    expect(m.verifyToken('.b')).toBeNull();
    expect(m.verifyToken(null)).toBeNull();
    expect(m.verifyToken(undefined)).toBeNull();
    expect(m.verifyToken(123)).toBeNull();
  });

  test('token with stray non-base64url characters → null', () => {
    const m = freshModule();
    const { token } = m.createToken({
      tenant_id: 't', key_id: 'k', email: 'e@x.com',
    });
    // Inject a character outside the base64url alphabet.
    const dot = token.indexOf('.');
    const dirty = `${token.slice(0, dot)}!${token.slice(dot)}`;
    expect(m.verifyToken(dirty)).toBeNull();
  });
});

// =============================================================================
describe('single-use nonce enforcement', () => {
  test('same token consumed twice → second call returns null', () => {
    const m = freshModule();
    const { token } = m.createToken({
      tenant_id: 't', key_id: 'k', email: 'e@x.com',
    });
    const first = m.verifyToken(token);
    expect(first).toBeTruthy();
    const second = m.verifyToken(token);
    expect(second).toBeNull();
  });

  test('consume:false lets a token be peeked without marking', () => {
    const m = freshModule();
    const { token } = m.createToken({
      tenant_id: 't', key_id: 'k', email: 'e@x.com',
    });
    const peek = m.verifyToken(token, { consume: false });
    expect(peek).toBeTruthy();
    // Subsequent default-consume call still works because the nonce
    // wasn't marked.
    const real = m.verifyToken(token);
    expect(real).toBeTruthy();
    // And NOW it's marked.
    expect(m.verifyToken(token)).toBeNull();
  });

  test('_test._resetConsumed flushes the consumed-nonce set', () => {
    const m = freshModule();
    const { token } = m.createToken({
      tenant_id: 't', key_id: 'k', email: 'e@x.com',
    });
    expect(m.verifyToken(token)).toBeTruthy();
    expect(m.verifyToken(token)).toBeNull();
    m._test._resetConsumed();
    expect(m.verifyToken(token)).toBeTruthy(); // nonce is forgotten
  });

  test('distinct tokens get distinct nonces', () => {
    const m = freshModule();
    const a = m.createToken({ tenant_id: 't', key_id: 'k', email: 'a@x.com' });
    const b = m.createToken({ tenant_id: 't', key_id: 'k', email: 'a@x.com' });
    expect(a.nonce).not.toBe(b.nonce);
    expect(m.verifyToken(a.token)).toBeTruthy();
    expect(m.verifyToken(b.token)).toBeTruthy();
  });
});

// =============================================================================
describe('cross-tenant replay defense', () => {
  test('a token minted for tenant A cannot be re-encoded for tenant B', () => {
    // Re-encoding the payload changes the bytes the HMAC was computed
    // over, so signature check fails. (Same as "tampered payload"
    // above but framed as the explicit replay-against-different-tenant
    // attack the spec calls out.)
    const m = freshModule();
    const { token } = m.createToken({
      tenant_id: 'tenant-A',
      key_id: 'key-A',
      email: 'shared@example.com',
    });
    const dot = token.indexOf('.');
    const payload = JSON.parse(Buffer.from(token.slice(0, dot), 'base64url').toString('utf8'));
    expect(payload.tenant_id).toBe('tenant-A');

    // Attacker swaps tenant_id and re-signs with their own (fake) key.
    // That's still rejected because they don't know our secret.
    const attackerKey = Buffer.from('00'.repeat(32), 'hex');
    payload.tenant_id = 'tenant-B';
    const newPayloadBytes = Buffer.from(JSON.stringify(payload), 'utf8');
    const attackerSig = crypto.createHmac('sha256', attackerKey)
      .update(newPayloadBytes).digest();
    const forged = `${newPayloadBytes.toString('base64url')}.${attackerSig.toString('base64url')}`;
    expect(m.verifyToken(forged)).toBeNull();
  });
});

// =============================================================================
describe('secret resolution priority', () => {
  // Each test below mutates env / fs then resets the module, which is why
  // every test in this describe uses jest.resetModules() directly rather
  // than freshModule() — we need to set state BEFORE the first require.

  test('env-set secret takes priority over file', () => {
    process.env.COGOS_MAGIC_LINK_SECRET = 'c3'.repeat(32);
    // Write a different secret to the file
    fs.writeFileSync(process.env.MAGIC_LINK_SECRET_FILE, 'd4'.repeat(32), { mode: 0o600 });
    jest.resetModules();
    const m = require('../src/magic-link');
    m._test._reset();
    expect(m._test._peekSecretHex()).toBe('c3'.repeat(32));
  });

  test('file-backed secret used when env is unset', () => {
    delete process.env.COGOS_MAGIC_LINK_SECRET;
    fs.writeFileSync(process.env.MAGIC_LINK_SECRET_FILE, 'e5'.repeat(32), { mode: 0o600 });
    jest.resetModules();
    const m = require('../src/magic-link');
    m._test._reset();
    expect(m._test._peekSecretHex()).toBe('e5'.repeat(32));
    // Restore env for any test that runs after this one.
    process.env.COGOS_MAGIC_LINK_SECRET = 'b2'.repeat(32);
  });

  test('lazy-generates + persists when env+file are absent', () => {
    delete process.env.COGOS_MAGIC_LINK_SECRET;
    try { fs.unlinkSync(process.env.MAGIC_LINK_SECRET_FILE); } catch (_e) {}
    jest.resetModules();
    const m = require('../src/magic-link');
    m._test._reset();
    const generated = m._test._peekSecretHex();
    expect(generated).toMatch(/^[0-9a-f]{64}$/);
    // The secret file now exists with the generated value.
    const onDisk = fs.readFileSync(process.env.MAGIC_LINK_SECRET_FILE, 'utf8').trim();
    expect(onDisk).toBe(generated);
    process.env.COGOS_MAGIC_LINK_SECRET = 'b2'.repeat(32);
  });
});

// =============================================================================
describe('consumed-nonce persistence', () => {
  test('a consumed nonce survives a process restart', () => {
    const m1 = freshModule();
    const { token, nonce } = m1.createToken({
      tenant_id: 'tenant-X',
      key_id: 'key-Y',
      email: 'persist@example.com',
    });
    expect(m1.verifyToken(token)).toBeTruthy(); // first use consumes
    expect(typeof nonce).toBe('string');
    // The snapshot file is now on disk.
    expect(fs.existsSync(process.env.MAGIC_LINK_CONSUMED_FILE)).toBe(true);

    // Simulate restart: jest.resetModules() flushes the require cache.
    // We deliberately do NOT call _test._reset() — that would unlink
    // the file. Instead we re-require fresh and verify hydration.
    jest.resetModules();
    const m2 = require('../src/magic-link');
    // Re-presenting the SAME token must now be rejected even though
    // this is a "fresh" process — the file was rehydrated on the
    // first verifyToken() call.
    expect(m2.verifyToken(token)).toBeNull();
  });

  test('expired nonces are pruned at load time', () => {
    // Hand-craft a snapshot file containing an already-expired nonce.
    const ancient = Date.now() - 60 * 60 * 1000; // 1h ago, well past TTL
    fs.writeFileSync(process.env.MAGIC_LINK_CONSUMED_FILE, JSON.stringify({
      version: 1,
      ts: new Date().toISOString(),
      entries: [
        { nonce: 'a'.repeat(32), exp_ms: ancient },
      ],
    }));
    jest.resetModules();
    const m = require('../src/magic-link');
    // Touch the consumed map by minting + consuming a different token.
    // After that touch, the stale entry should have been pruned.
    const { token } = m.createToken({
      tenant_id: 'tenant-prune',
      key_id: 'k1',
      email: 'prune@example.com',
    });
    expect(m.verifyToken(token)).toBeTruthy();
    // Read the file back: it should contain only the freshly-consumed
    // nonce, NOT the ancient one.
    const after = JSON.parse(fs.readFileSync(process.env.MAGIC_LINK_CONSUMED_FILE, 'utf8'));
    expect(after.entries.find((e) => e.nonce === 'a'.repeat(32))).toBeUndefined();
    expect(after.entries.length).toBe(1);
  });

  test('malformed snapshot file does not crash; starts empty', () => {
    fs.writeFileSync(process.env.MAGIC_LINK_CONSUMED_FILE, '{not json');
    jest.resetModules();
    const m = require('../src/magic-link');
    const { token } = m.createToken({
      tenant_id: 'tenant-corrupt',
      key_id: 'k1',
      email: 'c@example.com',
    });
    expect(m.verifyToken(token)).toBeTruthy();
  });
});
