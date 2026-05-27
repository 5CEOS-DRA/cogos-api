'use strict';

/**
 * Phase 4 wedge 1: tenant_type field on key records.
 *
 * Per project_cli_phase_4_acceptance_criteria_v0_1_2026_05_27 A + B.
 *
 * Covers:
 *   - issue() defaults to 'subscriber'
 *   - issue() accepts explicit 'operator'
 *   - issue() rejects invalid tenant_type values
 *   - normalizeTenantType pure-function shape
 *   - Read-time backfill in verify(): legacy record (no tenant_type
 *     field on disk) reads as 'subscriber'
 *   - Read-time backfill in findByEd25519KeyId(): same posture for
 *     the ed25519 path
 *   - POST /admin/keys passes tenant_type through and returns it
 */

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-phase-4-tenant-type-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

let tmpDir;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-phase-4-tt-test-'));
  process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
  process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
  process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
  jest.resetModules();
});

afterEach(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

function freshKeysModule() {
  jest.resetModules();
  return require('../src/keys');
}

describe('normalizeTenantType', () => {
  test('null/undefined/empty → subscriber default', () => {
    const keys = freshKeysModule();
    expect(keys.normalizeTenantType(null)).toBe('subscriber');
    expect(keys.normalizeTenantType(undefined)).toBe('subscriber');
    expect(keys.normalizeTenantType('')).toBe('subscriber');
  });

  test('explicit "subscriber" passes through', () => {
    const keys = freshKeysModule();
    expect(keys.normalizeTenantType('subscriber')).toBe('subscriber');
  });

  test('explicit "operator" passes through', () => {
    const keys = freshKeysModule();
    expect(keys.normalizeTenantType('operator')).toBe('operator');
  });

  test('non-string throws', () => {
    const keys = freshKeysModule();
    expect(() => keys.normalizeTenantType(7)).toThrow(/must be a string/);
  });

  test('unknown value throws with enum hint', () => {
    const keys = freshKeysModule();
    expect(() => keys.normalizeTenantType('admin')).toThrow(/subscriber|operator/);
  });

  test('TENANT_TYPES set exposed for callers', () => {
    const keys = freshKeysModule();
    expect(keys.TENANT_TYPES.has('subscriber')).toBe(true);
    expect(keys.TENANT_TYPES.has('operator')).toBe(true);
    expect(keys.TENANT_TYPES.size).toBe(2);
  });
});

describe('keys.issue · tenant_type', () => {
  test('default to subscriber when not specified', () => {
    const keys = freshKeysModule();
    const issued = keys.issue({ tenantId: 'denny' });
    expect(issued.record.tenant_type).toBe('subscriber');
  });

  test('explicit operator stored', () => {
    const keys = freshKeysModule();
    const issued = keys.issue({ tenantId: 'denny', tenant_type: 'operator' });
    expect(issued.record.tenant_type).toBe('operator');
  });

  test('explicit subscriber stored', () => {
    const keys = freshKeysModule();
    const issued = keys.issue({ tenantId: 'acme', tenant_type: 'subscriber' });
    expect(issued.record.tenant_type).toBe('subscriber');
  });

  test('invalid tenant_type rejected at issue time', () => {
    const keys = freshKeysModule();
    expect(() => keys.issue({ tenantId: 'denny', tenant_type: 'admin' }))
      .toThrow(/tenant_type/);
  });
});

describe('keys.verify · read-time backfill', () => {
  test('legacy record (no tenant_type on disk) → reads as subscriber', () => {
    const keys = freshKeysModule();
    const issued = keys.issue({ tenantId: 'legacy-tenant' });
    // Hand-rewrite disk to strip the field (simulates pre-Phase-4 records)
    const raw = fs.readFileSync(process.env.KEYS_FILE, 'utf8');
    const arr = JSON.parse(raw);
    arr.forEach((r) => { delete r.tenant_type; });
    fs.writeFileSync(process.env.KEYS_FILE, JSON.stringify(arr));

    // verify() reads + backfills in-memory
    const verified = keys.verify(issued.plaintext);
    expect(verified).toBeTruthy();
    expect(verified.tenant_type).toBe('subscriber');

    // Disk record may have been re-touched by verify's last_used_at write;
    // post-touch the file will carry tenant_type going forward (the
    // write loop above wrote the stripped record, but verify writes back
    // the full found record which still has tenant_type undefined if not
    // re-attached — that's fine, backfill kicks in on next read).
  });

  test('operator record retained as operator across verify', () => {
    const keys = freshKeysModule();
    const issued = keys.issue({ tenantId: 'denny', tenant_type: 'operator' });
    const verified = keys.verify(issued.plaintext);
    expect(verified.tenant_type).toBe('operator');
  });
});

describe('keys.findByEd25519KeyId · read-time backfill', () => {
  test('legacy ed25519 record reads as subscriber', () => {
    const keys = freshKeysModule();
    const issued = keys.issue({ tenantId: 'legacy-ed', scheme: 'ed25519' });
    // Strip tenant_type
    const arr = JSON.parse(fs.readFileSync(process.env.KEYS_FILE, 'utf8'));
    arr.forEach((r) => { delete r.tenant_type; });
    fs.writeFileSync(process.env.KEYS_FILE, JSON.stringify(arr));

    const found = keys.findByEd25519KeyId(issued.ed25519_key_id);
    expect(found).toBeTruthy();
    expect(found.tenant_type).toBe('subscriber');
  });
});

describe('POST /admin/keys · tenant_type passthrough', () => {
  const request = require('supertest');

  test('default mint → tenant_type=subscriber in response', async () => {
    const { createApp } = require('../src/index');
    const app = createApp();
    const res = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'new-tenant', tier: 'starter' });
    expect(res.status).toBe(201);
    expect(res.body.tenant_type).toBe('subscriber');
  });

  test('explicit operator mint → tenant_type=operator in response', async () => {
    const { createApp } = require('../src/index');
    const app = createApp();
    const res = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'denny', tier: 'starter', tenant_type: 'operator' });
    expect(res.status).toBe(201);
    expect(res.body.tenant_type).toBe('operator');
  });

  test('invalid tenant_type rejected with 400', async () => {
    const { createApp } = require('../src/index');
    const app = createApp();
    const res = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'denny', tier: 'starter', tenant_type: 'admin' });
    expect(res.status).toBe(400);
    expect(res.body.error.message).toMatch(/tenant_type/);
  });
});
