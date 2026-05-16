'use strict';

// Tiny shared helper for append-only JSONL event logs.
//
// PURPOSE: src/usage.js, src/anomaly.js, and src/notify-signup.js each
// implemented the same pattern by hand — ensure parent dir at mode 0700,
// create the file at mode 0600 if missing, append one JSON-stringified
// row per line, and NEVER fail the request path on a disk error. This
// module concentrates that pattern in one place so honeypot, rate-limit,
// and daily-cap can opt into the same shape without duplicating the
// boilerplate.
//
// THREAT MODEL: the files this helper writes are operator-readable audit
// substrates (analytics aggregates them, /admin/analytics/* surfaces them
// to the Management Console). They are NOT customer-visible. They MUST
// NOT contain prompt content or request bodies — see the per-caller
// schemas in src/honeypot.js + src/rate-limit.js for what IS captured.
//
// FAIL-SAFE: every write goes through a try/catch. On failure we log via
// logger.warn and return — we NEVER throw into the caller. The substrate
// keeps serving requests regardless of disk health; a missing event row
// is preferable to a missed customer response. Tests verify this by
// exercising appendEvent against an unwritable path (e.g. a path under a
// 0500 directory) and asserting no exception escapes.
//
// MEMORY: in-process is just the function call. We append synchronously
// to disk per event — no in-memory buffer, no batching, no flush timer.
// The per-IP token bucket + the anomaly fail-closed ban already cap the
// volume an attacker can drive through these paths, so the cost is
// bounded.

const fs = require('fs');
const path = require('path');
const logger = require('./logger');

// Idempotent directory + file initialization. Matches the shape used by
// src/usage.js (dir mode 0700, file mode 0600). Safe to call on every
// append — fs.existsSync short-circuits before any mkdir/writeFile
// happens on the steady-state path. Throws on its own failure; callers
// MUST wrap in try/catch (appendEvent does).
function ensureFile(filePath) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, '', { mode: 0o600 });
  }
}

// Append one row to the JSONL file at filePath. Returns true on success,
// false on any disk error. Never throws — the request path that triggers
// the append MUST NOT die on disk health.
//
//   filePath  absolute path to the .jsonl file
//   row       plain JSON-serializable object (the caller picks the schema)
//
// Logging discipline: on failure we emit a single logger.warn with the
// error message + the target file. We deliberately do NOT log the row
// itself — the row may contain operator-sensitive fields (IP addresses,
// tenant ids) that already live inside the file we just failed to write;
// double-logging them at WARN level would inflate the noise without
// helping the operator diagnose the disk fault.
function appendEvent(filePath, row) {
  try {
    ensureFile(filePath);
    fs.appendFileSync(filePath, JSON.stringify(row) + '\n');
    return true;
  } catch (e) {
    logger.warn('event_log_append_failed', { file: filePath, error: e.message });
    return false;
  }
}

module.exports = {
  appendEvent,
  // ensureFile is exported for tests that want to verify the mode bits
  // without going through a successful append first. Not part of the
  // module's public surface for other src/* callers.
  _ensureFile: ensureFile,
};
