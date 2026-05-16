'use strict';

// Unit + HTTP tests for the public hash-chain checkpoint primitive.
// Companion to tests/usage.test.js (the per-tenant chain) — this file
// covers the GLOBAL chain that aggregates every (tenant, app) head into
// an externally-verifiable witness.

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

let tmpDir;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-checkpoint-test-'));
  process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
  process.env.AUDIT_CHECKPOINTS_FILE = path.join(tmpDir, 'audit-checkpoints.jsonl');
  process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
  // Fresh module cache so the new env values take effect.
  jest.resetModules();
});

afterEach(() => {
  // Make sure no scheduler is left running between tests.
  try {
    const ac = require('../src/audit-checkpoint');
    if (ac && ac._internal) ac._internal._reset();
  } catch (_e) {}
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

function freshModules() {
  jest.resetModules();
  return {
    usage: require('../src/usage'),
    checkpoint: require('../src/audit-checkpoint'),
  };
}

describe('audit-checkpoint — computeAndAppend', () => {
  test('returns null when no usage rows exist yet (genesis-skip policy)', async () => {
    const { checkpoint } = freshModules();
    const row = await checkpoint.computeAndAppend();
    expect(row).toBeNull();
    // File should be empty (or only contain whitespace-free no-rows).
    const cpFile = process.env.AUDIT_CHECKPOINTS_FILE;
    const onDisk = fs.existsSync(cpFile) ? fs.readFileSync(cpFile, 'utf8') : '';
    expect(onDisk.trim()).toBe('');
  });

  test('first checkpoint with usage rows uses ZERO_HASH as prev_global_head', async () => {
    const { usage, checkpoint } = freshModules();
    usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm', status: 'success' });
    const row = await checkpoint.computeAndAppend();
    expect(row).not.toBeNull();
    expect(row.prev_global_head).toBe('0'.repeat(64));
    expect(row.global_head).toMatch(/^[a-f0-9]{64}$/);
    expect(row.row_hash).toMatch(/^[a-f0-9]{64}$/);
    expect(row.partition_count).toBe(1);
    expect(typeof row.ts).toBe('string');
  });

  test('second checkpoint chains off the first (prev_global_head == prior global_head)', async () => {
    const { usage, checkpoint } = freshModules();
    usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm', status: 'success' });
    const r1 = await checkpoint.computeAndAppend();
    usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm', status: 'success' });
    const r2 = await checkpoint.computeAndAppend();
    expect(r2.prev_global_head).toBe(r1.global_head);
    expect(r2.global_head).not.toBe(r1.global_head);
  });

  test('partition_count grows as new (tenant, app) pairs appear', async () => {
    const { usage, checkpoint } = freshModules();
    usage.record({ key_id: 'k1', tenant_id: 'A', app_id: 'truthpulse', model: 'm' });
    const r1 = await checkpoint.computeAndAppend();
    expect(r1.partition_count).toBe(1);
    usage.record({ key_id: 'k2', tenant_id: 'B', app_id: 'merger', model: 'm' });
    usage.record({ key_id: 'k3', tenant_id: 'A', app_id: 'central', model: 'm' });
    const r2 = await checkpoint.computeAndAppend();
    expect(r2.partition_count).toBe(3); // (A,truthpulse), (A,central), (B,merger)
  });

  test('canonical input sorts partitions lexicographically by (tenant_id, app_id)', async () => {
    const { usage, checkpoint } = freshModules();
    // Insert in reverse-alphabetical order; canonical must reorder.
    usage.record({ key_id: 'k1', tenant_id: 'Z', app_id: 'z-app', model: 'm' });
    usage.record({ key_id: 'k2', tenant_id: 'A', app_id: 'b-app', model: 'm' });
    usage.record({ key_id: 'k3', tenant_id: 'A', app_id: 'a-app', model: 'm' });
    const partitions = await checkpoint._internal.enumeratePartitions();
    expect(partitions.map((p) => `${p.tenant_id} ${p.app_id}`)).toEqual([
      'A a-app',
      'A b-app',
      'Z z-app',
    ]);
  });
});

describe('audit-checkpoint — latest / at / list', () => {
  test('latest() returns null when file is empty', async () => {
    const { checkpoint } = freshModules();
    expect(checkpoint.latest()).toBeNull();
  });

  test('latest() returns the most recent appended row', async () => {
    const { usage, checkpoint } = freshModules();
    usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm' });
    const r1 = await checkpoint.computeAndAppend();
    usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm' });
    const r2 = await checkpoint.computeAndAppend();
    expect(checkpoint.latest()).toEqual(r2);
    expect(checkpoint.latest()).not.toEqual(r1);
  });

  test('at(tsMs) returns the checkpoint nearest-before that ts', async () => {
    const { usage, checkpoint } = freshModules();
    usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm' });
    const r1 = await checkpoint.computeAndAppend();
    await new Promise((r) => setTimeout(r, 15));
    usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm' });
    const r2 = await checkpoint.computeAndAppend();
    const betweenMs = Date.parse(r1.ts) + 5;
    const got = checkpoint.at(betweenMs);
    expect(got).toEqual(r1); // strictly before r2
    // Future-ts returns the latest.
    expect(checkpoint.at(Date.now() + 1_000_000)).toEqual(r2);
    // Pre-genesis ts returns null.
    expect(checkpoint.at(0)).toBeNull();
  });

  test('list({limit, sinceMs}) returns most-recent first, paginated', async () => {
    const { usage, checkpoint } = freshModules();
    const rows = [];
    for (let i = 0; i < 5; i += 1) {
      usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm' });
      rows.push(await checkpoint.computeAndAppend());
      await new Promise((r) => setTimeout(r, 5));
    }
    const got = checkpoint.list({ limit: 3 });
    expect(got.length).toBe(3);
    // Most-recent first.
    expect(got[0]).toEqual(rows[4]);
    expect(got[1]).toEqual(rows[3]);
    expect(got[2]).toEqual(rows[2]);
  });
});

describe('audit-checkpoint — verifyChain', () => {
  test('returns ok with chain_length=0 on empty file', async () => {
    const { checkpoint } = freshModules();
    expect(checkpoint.verifyChain()).toEqual({
      ok: true, chain_length: 0, broke_at_index: null, reason: null,
    });
  });

  test('returns ok on a clean multi-row chain', async () => {
    const { usage, checkpoint } = freshModules();
    for (let i = 0; i < 4; i += 1) {
      usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm' });
      await checkpoint.computeAndAppend();
    }
    const v = checkpoint.verifyChain();
    expect(v.ok).toBe(true);
    expect(v.chain_length).toBe(4);
    expect(v.broke_at_index).toBeNull();
  });

  test('tampering with row #2 prev_global_head trips broke_at_index:2', async () => {
    const { usage, checkpoint } = freshModules();
    for (let i = 0; i < 3; i += 1) {
      usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm' });
      await checkpoint.computeAndAppend();
    }
    // Hand-edit row #2's prev_global_head on disk to a non-matching value.
    // Index in the verify() return is 0-based, so row #2 == index 2.
    const cpFile = process.env.AUDIT_CHECKPOINTS_FILE;
    const lines = fs.readFileSync(cpFile, 'utf8').trim().split('\n');
    const r2 = JSON.parse(lines[2]);
    r2.prev_global_head = 'f'.repeat(64); // garbage; not the prior head
    lines[2] = JSON.stringify(r2);
    fs.writeFileSync(cpFile, lines.join('\n') + '\n');

    const v = checkpoint.verifyChain();
    expect(v.ok).toBe(false);
    expect(v.broke_at_index).toBe(2);
    expect(v.reason).toBe('prev_global_head_mismatch');
    expect(v.chain_length).toBe(3);
  });

  test('row missing required fields trips row_missing_fields', async () => {
    const { usage, checkpoint } = freshModules();
    usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm' });
    await checkpoint.computeAndAppend();
    // Replace the single row with one missing global_head.
    const cpFile = process.env.AUDIT_CHECKPOINTS_FILE;
    fs.writeFileSync(cpFile, JSON.stringify({ ts: 'x', prev_global_head: '0'.repeat(64), row_hash: 'a' }) + '\n');
    const v = checkpoint.verifyChain();
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('row_missing_fields');
    expect(v.broke_at_index).toBe(0);
  });
});

describe('audit-checkpoint — scheduler', () => {
  test('startScheduler() with a small interval accrues checkpoints over time', async () => {
    // Tight loop interval — exercises the timer path without long test waits.
    process.env.CHECKPOINT_INTERVAL_MS = '40';
    const { usage, checkpoint } = freshModules();
    usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm' });
    const stop = checkpoint.startScheduler();
    try {
      // Wait long enough for several firings — first immediate, then
      // setInterval-paced. Counts vary by host load; we assert a floor.
      await new Promise((r) => setTimeout(r, 200));
      const cps = checkpoint.list({ limit: 100 });
      expect(cps.length).toBeGreaterThanOrEqual(2);
      // Chain stays consistent across rapid-fire runs.
      const v = checkpoint.verifyChain();
      expect(v.ok).toBe(true);
    } finally {
      stop();
    }
  });

  test('startScheduler() is idempotent — second call returns the same stop handle', async () => {
    process.env.CHECKPOINT_INTERVAL_MS = '60000'; // long enough not to fire
    const { checkpoint } = freshModules();
    const s1 = checkpoint.startScheduler();
    const s2 = checkpoint.startScheduler();
    expect(s2).toBe(s1);
    s1();
  });

  test('startScheduler() does not double-publish on restart (recent checkpoint defers)', async () => {
    // Pretend a previous process already wrote a checkpoint < interval ago.
    process.env.CHECKPOINT_INTERVAL_MS = '600000'; // 10 min
    const { usage, checkpoint } = freshModules();
    usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm' });
    await checkpoint.computeAndAppend();
    const before = checkpoint.list({ limit: 100 }).length;
    expect(before).toBe(1);

    const stop = checkpoint.startScheduler();
    try {
      // Wait a beat; with a 10-minute interval and a fresh checkpoint
      // already on disk, no new row should appear.
      await new Promise((r) => setTimeout(r, 80));
      const after = checkpoint.list({ limit: 100 }).length;
      expect(after).toBe(before);
    } finally {
      stop();
    }
  });
});

// ---- HTTP endpoint tests ----------------------------------------------------
//
// These mount the full Express app via createApp() and exercise each
// /audit/checkpoint/* route. Public endpoints — no auth header attached.

describe('GET /audit/checkpoint/* — HTTP surface', () => {
  test('/audit/checkpoint/latest returns 404 with explanatory body when no checkpoints exist', async () => {
    // Force the route to find nothing — fresh checkpoints file.
    const request = require('supertest');
    const { createApp } = require('../src/index');
    const app = createApp();
    const res = await request(app).get('/audit/checkpoint/latest');
    expect(res.status).toBe(404);
    expect(res.body && res.body.error && res.body.error.type).toBe('no_checkpoint_yet');
    expect(String(res.body.error.message)).toMatch(/no checkpoints recorded/);
  });

  test('/audit/checkpoint/latest returns 200 + row when checkpoints exist', async () => {
    const { usage, checkpoint } = freshModules();
    usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm' });
    const expected = await checkpoint.computeAndAppend();

    const request = require('supertest');
    const { createApp } = require('../src/index');
    const app = createApp();
    const res = await request(app).get('/audit/checkpoint/latest');
    expect(res.status).toBe(200);
    expect(res.body.global_head).toBe(expected.global_head);
    expect(res.body.prev_global_head).toBe(expected.prev_global_head);
    expect(res.body.partition_count).toBe(expected.partition_count);
  });

  test('/audit/checkpoint?ts=bogus returns 400', async () => {
    const request = require('supertest');
    const { createApp } = require('../src/index');
    const app = createApp();
    const res = await request(app).get('/audit/checkpoint?ts=not-a-number');
    expect(res.status).toBe(400);
    expect(res.body.error.type).toBe('bad_ts');
  });

  test('/audit/checkpoint?ts=<past> returns the nearest-before row', async () => {
    const { usage, checkpoint } = freshModules();
    usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm' });
    const r1 = await checkpoint.computeAndAppend();
    await new Promise((r) => setTimeout(r, 15));
    usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm' });
    await checkpoint.computeAndAppend();
    const tsBetween = Date.parse(r1.ts) + 5;

    const request = require('supertest');
    const { createApp } = require('../src/index');
    const app = createApp();
    const res = await request(app).get(`/audit/checkpoint?ts=${tsBetween}`);
    expect(res.status).toBe(200);
    expect(res.body.global_head).toBe(r1.global_head);
  });

  test('/audit/checkpoint?ts=0 returns 404 when no checkpoint at-or-before that ts', async () => {
    const { usage, checkpoint } = freshModules();
    usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm' });
    await checkpoint.computeAndAppend();

    const request = require('supertest');
    const { createApp } = require('../src/index');
    const app = createApp();
    const res = await request(app).get('/audit/checkpoint?ts=0');
    expect(res.status).toBe(404);
    expect(res.body.error.type).toBe('no_checkpoint_at_or_before');
  });

  test('/audit/checkpoints returns paginated list', async () => {
    const { usage, checkpoint } = freshModules();
    for (let i = 0; i < 3; i += 1) {
      usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm' });
      await checkpoint.computeAndAppend();
      await new Promise((r) => setTimeout(r, 5));
    }
    const request = require('supertest');
    const { createApp } = require('../src/index');
    const app = createApp();
    const res = await request(app).get('/audit/checkpoints?limit=2');
    expect(res.status).toBe(200);
    expect(res.body.count).toBe(2);
    expect(Array.isArray(res.body.checkpoints)).toBe(true);
    expect(res.body.checkpoints.length).toBe(2);
  });

  test('/audit/checkpoint/verify returns the chain status shape', async () => {
    const request = require('supertest');
    const { createApp } = require('../src/index');
    const app = createApp();
    const res = await request(app).get('/audit/checkpoint/verify');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('ok');
    expect(res.body).toHaveProperty('chain_length');
    expect(res.body).toHaveProperty('broke_at_index');
    expect(res.body).toHaveProperty('reason');
  });

  test('all /audit/checkpoint/* endpoints are public (no auth required)', async () => {
    const { usage, checkpoint } = freshModules();
    usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm' });
    await checkpoint.computeAndAppend();

    const request = require('supertest');
    const { createApp } = require('../src/index');
    const app = createApp();
    // No Authorization header on any of these.
    const paths = [
      '/audit/checkpoint/latest',
      '/audit/checkpoint?ts=' + Date.now(),
      '/audit/checkpoints?limit=10',
      '/audit/checkpoint/verify',
    ];
    for (const p of paths) {
      const res = await request(app).get(p);
      // None should 401/403. 200 or 404 (no data) are both fine.
      expect([200, 404]).toContain(res.status);
    }
  });
});

// ---- Trust dashboard integration -------------------------------------------

describe('/trust includes the checkpoint section', () => {
  test('trust page renders the checkpoint headline + endpoint links', async () => {
    const { usage, checkpoint } = freshModules();
    usage.record({ key_id: 'k1', tenant_id: 'A', model: 'm' });
    await checkpoint.computeAndAppend();

    const request = require('supertest');
    const { createApp } = require('../src/index');
    const app = createApp();
    const res = await request(app).get('/trust');
    expect(res.status).toBe(200);
    // The new section is mounted.
    expect(res.text).toContain('Public hash-chain checkpoint');
    // Either we render a checkpoint table (with last-checkpoint ts) OR
    // the placeholder. Both ship.
    expect(res.text).toMatch(/Last checkpoint|No public checkpoint recorded yet/);
  });
});
