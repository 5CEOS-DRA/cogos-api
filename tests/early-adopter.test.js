'use strict';

// Unit tests for src/early-adopter.js — verifies per-key dedup, on-disk
// first_call_at stamping, and that a hydration hit (prior stamp on disk
// before this process started) suppresses the notification.

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

describe('early-adopter.noteCall', () => {
  let tmpDir;
  let prevKeysFile;
  let earlyAdopter;
  let keys;
  let sendCalls;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-early-adopter-'));
    prevKeysFile = process.env.COGOS_KEYS_FILE;
    process.env.COGOS_KEYS_FILE = path.join(tmpDir, 'keys.json');
    // Fresh module load so the in-process Set + keys.json path bind to
    // the temp file. jest's resetModules makes this air-tight; without
    // it the second test's keys module would still point at the prior
    // tmp file.
    jest.resetModules();
    keys = require('../src/keys');
    earlyAdopter = require('../src/early-adopter');

    // Capture SES send invocations by mocking notify-signup at require
    // time. Done AFTER resetModules so the require cache for the freshly-
    // loaded early-adopter.js binds to our mock.
    sendCalls = [];
    const notifySignupPath = require.resolve('../src/notify-signup');
    require.cache[notifySignupPath].exports.sendOperatorEmail = async (msg) => {
      sendCalls.push(msg);
      return { sent: true, status: 200, transport: 'ses-mock' };
    };
  });

  afterEach(() => {
    if (prevKeysFile === undefined) delete process.env.COGOS_KEYS_FILE;
    else process.env.COGOS_KEYS_FILE = prevKeysFile;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('first call fires; subsequent calls suppress', async () => {
    const issued = keys.issue({
      tenantId: 'tenant-A',
      tier: 'free',
      label: 'test-early-adopter',
      scheme: 'bearer',
    });
    const rec = keys.findById(issued.record.id);

    const fired1 = earlyAdopter.noteCall(rec, 'qwen2.5:7b');
    expect(fired1).toBe(true);

    // Allow the fire-and-forget promise to resolve.
    await new Promise((r) => setImmediate(r));
    expect(sendCalls).toHaveLength(1);
    expect(sendCalls[0].subject).toContain('tenant-A');
    expect(sendCalls[0].body).toContain('tenant-A');
    expect(sendCalls[0].body).toContain('qwen2.5:7b');

    // first_call_at is stamped on disk.
    const stamped = keys.findById(rec.id);
    expect(typeof stamped.first_call_at).toBe('string');

    // Same key again → suppressed (in-memory Set short-circuit).
    const fired2 = earlyAdopter.noteCall(rec, 'qwen2.5:7b');
    expect(fired2).toBe(false);
    expect(sendCalls).toHaveLength(1);
  });

  test('process restart with prior stamp on disk: hydration suppresses', async () => {
    const issued = keys.issue({
      tenantId: 'tenant-B',
      tier: 'free',
      scheme: 'bearer',
    });
    // Simulate a prior process having already stamped this key.
    keys.markFirstCallAt(issued.record.id, '2026-01-01T00:00:00.000Z');
    const rec = keys.findById(issued.record.id);
    expect(rec.first_call_at).toBe('2026-01-01T00:00:00.000Z');

    earlyAdopter._resetForTest(); // simulate process restart

    const fired = earlyAdopter.noteCall(rec, 'qwen2.5:3b');
    expect(fired).toBe(false);
    await new Promise((r) => setImmediate(r));
    expect(sendCalls).toHaveLength(0);
  });

  test('missing keyRecord returns false without throwing', () => {
    expect(earlyAdopter.noteCall(null, 'm')).toBe(false);
    expect(earlyAdopter.noteCall({}, 'm')).toBe(false);
    expect(earlyAdopter.noteCall({ id: '' }, 'm')).toBe(false);
  });

  test('two distinct keys both fire', async () => {
    const a = keys.issue({ tenantId: 't1', scheme: 'bearer' });
    const b = keys.issue({ tenantId: 't2', scheme: 'bearer' });

    earlyAdopter.noteCall(keys.findById(a.record.id), 'm1');
    earlyAdopter.noteCall(keys.findById(b.record.id), 'm2');

    await new Promise((r) => setImmediate(r));
    expect(sendCalls).toHaveLength(2);
    expect(sendCalls.map((c) => c.subject).sort()).toEqual([
      expect.stringContaining('t1'),
      expect.stringContaining('t2'),
    ]);
  });
});
