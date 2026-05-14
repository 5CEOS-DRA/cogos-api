'use strict';

// Unit tests for the per-tenant hash chain in src/usage.js.
// Companion to tests/audit.test.js (the HTTP-level tests).

process.env.NODE_ENV = 'test';

const fs = require('fs');
const path = require('path');
const os = require('os');

let tmpDir;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-usage-test-'));
  process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
  // Re-require so the module picks up the fresh USAGE_FILE env.
  jest.resetModules();
});

afterEach(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

function freshUsage() {
  jest.resetModules();
  return require('../src/usage');
}

describe('usage hash chain — record + readByTenant', () => {
  test('genesis row has prev_hash = 64 zeros', () => {
    const usage = freshUsage();
    usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm', status: 'success' });
    const rows = usage.readByTenant('A');
    expect(rows.length).toBe(1);
    expect(rows[0].prev_hash).toBe('0'.repeat(64));
    expect(rows[0].row_hash).toMatch(/^[a-f0-9]{64}$/);
  });

  test('subsequent rows link to the previous row_hash for the same tenant', () => {
    const usage = freshUsage();
    usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm', status: 'success' });
    usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm', status: 'success' });
    usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm', status: 'success' });
    const rows = usage.readByTenant('A');
    expect(rows.length).toBe(3);
    expect(rows[0].prev_hash).toBe('0'.repeat(64));
    expect(rows[1].prev_hash).toBe(rows[0].row_hash);
    expect(rows[2].prev_hash).toBe(rows[1].row_hash);
  });

  test('tenant chains are independent — A and B each have their own genesis', () => {
    const usage = freshUsage();
    usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm', status: 'success' });
    usage.record({ key_id: 'k2', tenant_id: 'B', model: 'm', status: 'success' });
    usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm', status: 'success' });
    const a = usage.readByTenant('A');
    const b = usage.readByTenant('B');
    expect(a.length).toBe(2);
    expect(b.length).toBe(1);
    expect(a[0].prev_hash).toBe('0'.repeat(64));
    expect(b[0].prev_hash).toBe('0'.repeat(64));
    expect(a[1].prev_hash).toBe(a[0].row_hash);
    // B's genesis must NOT chain off A's row.
    expect(b[0].prev_hash).not.toBe(a[0].row_hash);
  });

  test('since= filter excludes rows with ts <= sinceMs', async () => {
    const usage = freshUsage();
    usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm', status: 'success' });
    await new Promise((r) => setTimeout(r, 10));
    const cutoff = Date.now();
    await new Promise((r) => setTimeout(r, 10));
    usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm', status: 'success' });
    const rows = usage.readByTenant('A', cutoff);
    expect(rows.length).toBe(1);
  });

  test('limit caps the returned rows', () => {
    const usage = freshUsage();
    for (let i = 0; i < 5; i += 1) {
      usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm', status: 'success' });
    }
    const rows = usage.readByTenant('A', 0, 3);
    expect(rows.length).toBe(3);
  });
});

describe('usage hash chain — verifyChain', () => {
  test('returns ok on a clean chain', () => {
    const usage = freshUsage();
    for (let i = 0; i < 4; i += 1) {
      usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm', status: 'success' });
    }
    const rows = usage.readByTenant('A');
    expect(usage.verifyChain(rows)).toEqual({ ok: true });
  });

  test('detects tamper in the middle of the chain', () => {
    const usage = freshUsage();
    for (let i = 0; i < 5; i += 1) {
      usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm', status: 'success' });
    }
    const rows = usage.readByTenant('A');
    // Tamper with row 2's payload but leave its row_hash intact —
    // simulates content-level corruption.
    rows[2] = { ...rows[2], status: 'tampered' };
    const result = usage.verifyChain(rows);
    expect(result.ok).toBe(false);
    expect(result.broke_at_index).toBe(2);
    expect(result.reason).toBe('row_hash_mismatch');
  });

  test('detects missing row (prev_hash break)', () => {
    const usage = freshUsage();
    for (let i = 0; i < 4; i += 1) {
      usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm', status: 'success' });
    }
    const rows = usage.readByTenant('A');
    // Drop row 1 — row 2's prev_hash will no longer match row 0's row_hash.
    const broken = [rows[0], rows[2], rows[3]];
    const result = usage.verifyChain(broken);
    expect(result.ok).toBe(false);
    expect(result.broke_at_index).toBe(1);
    expect(result.reason).toBe('prev_hash_mismatch');
    expect(result.expected_prev_hash).toBe(rows[0].row_hash);
    expect(result.found_prev_hash).toBe(rows[2].prev_hash);
  });

  test('detects rows missing chain fields (pre-chain history)', () => {
    const usage = freshUsage();
    // Manually write a pre-chain row directly to the file (simulates
    // pre-deploy history that lacks prev_hash/row_hash).
    fs.appendFileSync(process.env.USAGE_FILE,
      JSON.stringify({ ts: new Date().toISOString(), tenant_id: 'A', key_id: 'k1', status: 'success' }) + '\n');
    usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm', status: 'success' });
    const rows = usage.readByTenant('A');
    expect(rows.length).toBe(2);
    const result = usage.verifyChain(rows);
    expect(result.ok).toBe(false);
    expect(result.broke_at_index).toBe(0);
    expect(result.reason).toBe('row_missing_chain_fields');
  });

  test('empty slice verifies as ok', () => {
    const usage = freshUsage();
    expect(usage.verifyChain([])).toEqual({ ok: true });
  });

  test('partial slice verifies when expectedHeadBefore is supplied', () => {
    const usage = freshUsage();
    for (let i = 0; i < 4; i += 1) {
      usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm', status: 'success' });
    }
    const rows = usage.readByTenant('A');
    // Slice from index 2 onwards — without the head hint this would look
    // like a broken chain (its first prev_hash isn't ZERO_HASH); with the
    // hint it's a clean continuation.
    const tail = rows.slice(2);
    expect(usage.verifyChain(tail).ok).toBe(false); // no head hint
    expect(usage.verifyChain(tail, rows[1].row_hash)).toEqual({ ok: true });
  });
});

// ---------------------------------------------------------------------------
// Multi-app namespace — per-(tenant, app_id) chain semantics.
// ---------------------------------------------------------------------------
describe('usage hash chain — multi-app (tenant, app_id)', () => {
  test('two apps under one tenant chain independently', () => {
    const usage = freshUsage();
    usage.record({ key_id: 'k1', tenant_id: 'A', app_id: 'app1', model: 'm', status: 'success' });
    usage.record({ key_id: 'k2', tenant_id: 'A', app_id: 'app2', model: 'm', status: 'success' });
    usage.record({ key_id: 'k1', tenant_id: 'A', app_id: 'app1', model: 'm', status: 'success' });
    usage.record({ key_id: 'k2', tenant_id: 'A', app_id: 'app2', model: 'm', status: 'success' });

    const a1 = usage.readSlice({ tenant_id: 'A', app_id: 'app1' });
    const a2 = usage.readSlice({ tenant_id: 'A', app_id: 'app2' });
    expect(a1.length).toBe(2);
    expect(a2.length).toBe(2);
    // Each app starts at ZERO_HASH — independent genesis.
    expect(a1[0].prev_hash).toBe('0'.repeat(64));
    expect(a2[0].prev_hash).toBe('0'.repeat(64));
    // Within an app the chain links cleanly.
    expect(a1[1].prev_hash).toBe(a1[0].row_hash);
    expect(a2[1].prev_hash).toBe(a2[0].row_hash);
    // Cross-app row_hashes are distinct even though all other content
    // matches — the app_id is in the canonical payload so identical
    // tenant + key + ts (impossible in practice; spaced enough here)
    // would still distinguish.
    expect(a1[0].row_hash).not.toBe(a2[0].row_hash);
  });

  test('canonical payload includes app_id — two rows differing only by app_id produce different hashes', () => {
    const usage = freshUsage();
    const payload = {
      ts: '2026-05-14T00:00:00.000Z',
      tenant_id: 'A',
      key_id: 'k',
      route: '/v1/chat/completions',
      status: 'success',
      prompt_tokens: 1,
      completion_tokens: 1,
      latency_ms: 0,
      prev_hash: '0'.repeat(64),
    };
    const h1 = usage._internal.sha256Hex(
      usage._internal.canonicalChainPayload({ ...payload, app_id: 'app1' }));
    const h2 = usage._internal.sha256Hex(
      usage._internal.canonicalChainPayload({ ...payload, app_id: 'app2' }));
    expect(h1).not.toBe(h2);
    // Null/undefined/empty all normalize to '_default' — they MUST hash
    // identically to the explicit '_default' payload so back-compat rows
    // chain correctly.
    const hDefault = usage._internal.sha256Hex(
      usage._internal.canonicalChainPayload({ ...payload, app_id: '_default' }));
    const hNull = usage._internal.sha256Hex(
      usage._internal.canonicalChainPayload({ ...payload, app_id: null }));
    const hUndef = usage._internal.sha256Hex(
      usage._internal.canonicalChainPayload({ ...payload }));
    expect(hDefault).toBe(hNull);
    expect(hDefault).toBe(hUndef);
  });

  test('readSlice without app_id returns rows for all apps under the tenant', () => {
    const usage = freshUsage();
    usage.record({ key_id: 'k', tenant_id: 'A', app_id: 'app1', model: 'm', status: 'success' });
    usage.record({ key_id: 'k', tenant_id: 'A', app_id: 'app2', model: 'm', status: 'success' });
    usage.record({ key_id: 'k', tenant_id: 'B', app_id: 'app1', model: 'm', status: 'success' });
    const all = usage.readSlice({ tenant_id: 'A' });
    expect(all.length).toBe(2);
    expect(all.every((r) => r.tenant_id === 'A')).toBe(true);
    // Tenant B is excluded — cross-tenant isolation preserved.
  });

  test('verifyByApp returns per-app verdict on mixed slice', () => {
    const usage = freshUsage();
    usage.record({ key_id: 'k', tenant_id: 'A', app_id: 'app1', model: 'm', status: 'success' });
    usage.record({ key_id: 'k', tenant_id: 'A', app_id: 'app2', model: 'm', status: 'success' });
    usage.record({ key_id: 'k', tenant_id: 'A', app_id: 'app1', model: 'm', status: 'success' });
    const mixed = usage.readSlice({ tenant_id: 'A' });
    const result = usage.verifyByApp(mixed);
    expect(result.app1).toEqual({ ok: true });
    expect(result.app2).toEqual({ ok: true });
  });

  test('legacy rows on disk without app_id are surfaced as _default and chain consistently', () => {
    const usage = freshUsage();
    // Persist a row that pre-dates the multi-app code AND lacks any
    // chain fields — exercises both the chain epoch boundary
    // (row_missing_chain_fields) and the app_id projection. We append
    // raw JSON, not via record().
    const pre = {
      ts: new Date(Date.now() - 1000).toISOString(),
      key_id: 'old',
      tenant_id: 'A',
      model: 'm',
      status: 'success',
    };
    fs.appendFileSync(process.env.USAGE_FILE, JSON.stringify(pre) + '\n');
    // Now a fresh row via record() — should chain off ZERO_HASH because
    // findHead(A, _default) finds no row_hash in the pre-row.
    usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm', status: 'success' });

    // Read default-only — both rows surface under _default.
    const rows = usage.readSlice({ tenant_id: 'A', app_id: '_default' });
    expect(rows.length).toBe(2);
    expect(rows.every((r) => r.app_id === '_default')).toBe(true);
    // The new row starts at ZERO (the pre-row had no row_hash to chain off).
    const newRow = rows.find((r) => typeof r.row_hash === 'string');
    expect(newRow.prev_hash).toBe('0'.repeat(64));
  });
});
