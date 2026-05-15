'use strict';

// Data Encryption Key (DEK) round-trip + source-priority tests.
//
// `src/dek.js` is the envelope-encryption substrate that keeps HMAC secrets
// and the attestation signing key as ciphertext on disk. These tests prove:
//   - seal/open round-trips arbitrary plaintext bytes
//   - opening a sealed envelope with a different DEK fails with the
//     GCM auth-tag mismatch (NOT silent garbage plaintext)
//   - the DEK source (env > file > generated) is stable across
//     `_internal._reset()` when the source is held constant

process.env.NODE_ENV = 'test';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

// Each test resets module + env before exercising, so we can't share a
// long-lived require cache. Re-require per test in helpers below.
function freshDek() {
  // jest.resetModules() clears jest's per-test module registry so the next
  // require evaluates the module top-level fresh (module-scoped _dekCache
  // is null again).
  jest.resetModules();
  return require('../src/dek');
}

// Save the test runner's env so we can restore between cases.
let savedEnv;
let tmpDir;

beforeEach(() => {
  savedEnv = {
    COGOS_DEK_HEX: process.env.COGOS_DEK_HEX,
    COGOS_DEK_FILE: process.env.COGOS_DEK_FILE,
  };
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-dek-'));
  // Run inside the tmp dir so the default generated-on-disk path
  // (data/.dek) doesn't pollute the repo root.
  process.chdir(tmpDir);
});

afterEach(() => {
  for (const k of Object.keys(savedEnv)) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

describe('dek: round-trip seal/open', () => {
  test('seal then open returns the same plaintext bytes', () => {
    process.env.COGOS_DEK_HEX = crypto.randomBytes(32).toString('hex');
    delete process.env.COGOS_DEK_FILE;
    const dek = freshDek();
    const plaintext = Buffer.from('the HMAC secret — 64 hex chars in production', 'utf8');
    const env = dek.seal(plaintext);
    expect(env).toHaveProperty('ciphertext_b64');
    expect(env).toHaveProperty('nonce_b64');
    expect(env).toHaveProperty('tag_b64');
    // Sanity: ciphertext is NOT the plaintext. (Tighter than just != — we
    // assert the ciphertext doesn't even contain the recognizable prefix.)
    expect(Buffer.from(env.ciphertext_b64, 'base64').toString('utf8')).not.toContain('HMAC secret');
    const recovered = dek.open(env);
    expect(recovered.equals(plaintext)).toBe(true);
  });

  test('seal of empty buffer round-trips', () => {
    process.env.COGOS_DEK_HEX = crypto.randomBytes(32).toString('hex');
    const dek = freshDek();
    const env = dek.seal(Buffer.alloc(0));
    const recovered = dek.open(env);
    expect(recovered.length).toBe(0);
  });

  test('each seal produces a fresh random nonce (no nonce reuse)', () => {
    process.env.COGOS_DEK_HEX = crypto.randomBytes(32).toString('hex');
    const dek = freshDek();
    const plaintext = Buffer.from('same plaintext both times', 'utf8');
    const a = dek.seal(plaintext);
    const b = dek.seal(plaintext);
    expect(a.nonce_b64).not.toBe(b.nonce_b64);
    expect(a.ciphertext_b64).not.toBe(b.ciphertext_b64);
  });
});

describe('dek: wrong-key open fails with auth-tag mismatch', () => {
  test('opening a sealed envelope with a different DEK throws', () => {
    const keyA = crypto.randomBytes(32).toString('hex');
    const keyB = crypto.randomBytes(32).toString('hex');
    process.env.COGOS_DEK_HEX = keyA;
    let dek = freshDek();
    const env = dek.seal(Buffer.from('secret', 'utf8'));
    // Switch to a different DEK in a fresh module instance.
    process.env.COGOS_DEK_HEX = keyB;
    dek = freshDek();
    expect(() => dek.open(env)).toThrow(/auth(enticate|entication)|tag|unsupported/i);
  });
});

describe('dek: source priority + stability across _reset()', () => {
  test('env source — same hex produces same key after _reset()', () => {
    const hex = crypto.randomBytes(32).toString('hex');
    process.env.COGOS_DEK_HEX = hex;
    delete process.env.COGOS_DEK_FILE;
    const dek = freshDek();
    const k1 = dek.getDek();
    dek._internal._reset();
    const k2 = dek.getDek();
    expect(k1.equals(k2)).toBe(true);
    expect(dek.getSource()).toBe('env');
  });

  test('file source — overrides on-disk generated', () => {
    const hex = crypto.randomBytes(32).toString('hex');
    const dekPath = path.join(tmpDir, 'dek.hex');
    fs.writeFileSync(dekPath, hex);
    delete process.env.COGOS_DEK_HEX;
    process.env.COGOS_DEK_FILE = dekPath;
    const dek = freshDek();
    const k = dek.getDek();
    expect(k.toString('hex')).toBe(hex);
    expect(dek.getSource()).toBe('file');
  });

  test('generated source — persists across _reset() via data/.dek', () => {
    delete process.env.COGOS_DEK_HEX;
    delete process.env.COGOS_DEK_FILE;
    const dek = freshDek();
    const k1 = dek.getDek();
    expect(dek.getSource()).toBe('generated');
    // .dek file should now exist on disk with mode 0600.
    const generatedPath = path.join(tmpDir, 'data', '.dek');
    expect(fs.existsSync(generatedPath)).toBe(true);
    // Reset cache + re-resolve — same key comes back.
    dek._internal._reset();
    const k2 = dek.getDek();
    expect(k1.equals(k2)).toBe(true);
  });

  test('env beats file beats generated (priority order)', () => {
    const envHex = crypto.randomBytes(32).toString('hex');
    const fileHex = crypto.randomBytes(32).toString('hex');
    const dekFilePath = path.join(tmpDir, 'dek.hex');
    fs.writeFileSync(dekFilePath, fileHex);
    process.env.COGOS_DEK_HEX = envHex;
    process.env.COGOS_DEK_FILE = dekFilePath;
    const dek = freshDek();
    expect(dek.getDek().toString('hex')).toBe(envHex);
    expect(dek.getSource()).toBe('env');
  });
});

describe('dek: isSealed shape detection', () => {
  test('isSealed true on a sealed envelope, false on cleartext string', () => {
    process.env.COGOS_DEK_HEX = crypto.randomBytes(32).toString('hex');
    const dek = freshDek();
    const env = dek.seal(Buffer.from('x', 'utf8'));
    expect(dek.isSealed(env)).toBe(true);
    expect(dek.isSealed('plaintext-hex-string')).toBe(false);
    expect(dek.isSealed(null)).toBe(false);
    expect(dek.isSealed({})).toBe(false);
  });
});
