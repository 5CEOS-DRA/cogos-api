'use strict';

// Tests for src/event-log.js — the shared append-only JSONL helper.
//
// We exercise the helper directly (no Express). Every test points at a
// fresh tmpdir so we never collide with the repo data/ directory.

process.env.NODE_ENV = 'test';

const fs = require('fs');
const path = require('path');
const os = require('os');

const eventLog = require('../src/event-log');

let tmpDir;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-event-log-test-'));
});

afterEach(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

describe('event-log: appendEvent', () => {
  test('creates the file with mode 0600 if missing', () => {
    const file = path.join(tmpDir, 'subdir', 'events.jsonl');
    expect(fs.existsSync(file)).toBe(false);
    const ok = eventLog.appendEvent(file, { ts: '2026-05-14T00:00:00Z', hello: 'world' });
    expect(ok).toBe(true);
    expect(fs.existsSync(file)).toBe(true);
    // Verify the file mode bits — UNIX-only assertion. Skip the masking
    // check on non-POSIX platforms (jest runs on macOS + Linux).
    const stat = fs.statSync(file);
    // Mask to the lower 9 mode bits and assert 0600 (owner rw, no group/other).
    // eslint-disable-next-line no-bitwise
    expect(stat.mode & 0o777).toBe(0o600);
    // Parent dir should be mode 0700 (owner rwx only).
    const dirStat = fs.statSync(path.dirname(file));
    // eslint-disable-next-line no-bitwise
    expect(dirStat.mode & 0o777).toBe(0o700);
  });

  test('appends rows as newline-delimited JSON', () => {
    const file = path.join(tmpDir, 'events.jsonl');
    eventLog.appendEvent(file, { a: 1 });
    eventLog.appendEvent(file, { b: 2 });
    eventLog.appendEvent(file, { c: 3 });
    const body = fs.readFileSync(file, 'utf8');
    const lines = body.split('\n').filter((l) => l.trim());
    expect(lines.length).toBe(3);
    expect(JSON.parse(lines[0])).toEqual({ a: 1 });
    expect(JSON.parse(lines[1])).toEqual({ b: 2 });
    expect(JSON.parse(lines[2])).toEqual({ c: 3 });
    // Every line ends with a newline; the file ends with one too.
    expect(body.endsWith('\n')).toBe(true);
  });

  test('fails closed (returns false, never throws) on disk error', () => {
    // Drop the parent directory permissions so mkdir + writeFile both fail.
    // We point at a path UNDER an unwritable directory so ensureFile()
    // hits the failure path.
    const lockedDir = path.join(tmpDir, 'locked');
    fs.mkdirSync(lockedDir);
    // 0500 = r-x for owner; can read+exec, cannot write/create.
    fs.chmodSync(lockedDir, 0o500);
    const file = path.join(lockedDir, 'subdir', 'events.jsonl');
    let threw = false;
    let ok;
    try {
      ok = eventLog.appendEvent(file, { hello: 'world' });
    } catch (_e) {
      threw = true;
    }
    // Restore so afterEach cleanup can rm the dir.
    try { fs.chmodSync(lockedDir, 0o700); } catch (_e) {}
    expect(threw).toBe(false);
    expect(ok).toBe(false);
  });
});
