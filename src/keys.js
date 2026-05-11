'use strict';

// API key store. Keys are issued with prefix `sk-cogos-` followed by 32
// hex chars. The plaintext is shown to the customer exactly once at issue
// time; only the sha256 hash is stored.
//
// Storage: JSON file (data/keys.json), mode 0600. Good enough for v1;
// swap for Postgres when the customer count justifies it.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const KEYS_FILE = process.env.KEYS_FILE
  || path.join(__dirname, '..', 'data', 'keys.json');

const PREFIX = 'sk-cogos-';

function ensureStore() {
  const dir = path.dirname(KEYS_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (!fs.existsSync(KEYS_FILE)) {
    fs.writeFileSync(KEYS_FILE, JSON.stringify([]), { mode: 0o600 });
  }
}

function readAll() {
  ensureStore();
  return JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8'));
}

function writeAll(records) {
  fs.writeFileSync(KEYS_FILE, JSON.stringify(records, null, 2), { mode: 0o600 });
}

function hashKey(plaintext) {
  return crypto.createHash('sha256').update(plaintext).digest('hex');
}

function newKeyPlaintext() {
  return PREFIX + crypto.randomBytes(16).toString('hex');
}

// Issue a new API key for a tenant. Returns the plaintext (show once).
function issue({ tenantId, label = '', tier = 'starter' } = {}) {
  if (!tenantId) throw new Error('tenantId required');
  const plaintext = newKeyPlaintext();
  const record = {
    id: crypto.randomUUID(),
    key_hash: hashKey(plaintext),
    key_prefix: plaintext.slice(0, 16), // sk-cogos-XXXXXXXX — display hint, NOT auth
    tenant_id: tenantId,
    label,
    tier,
    active: true,
    issued_at: new Date().toISOString(),
    last_used_at: null,
  };
  const records = readAll();
  records.push(record);
  writeAll(records);
  return { plaintext, record: { ...record, key_hash: undefined } };
}

// Verify a presented bearer string. Returns the record if valid+active.
function verify(plaintext) {
  if (typeof plaintext !== 'string' || !plaintext.startsWith(PREFIX)) return null;
  const records = readAll();
  const hash = hashKey(plaintext);
  const found = records.find((r) => r.key_hash === hash && r.active);
  if (!found) return null;
  // Best-effort last_used_at touch (non-fatal if it races; usage log is authoritative).
  try {
    found.last_used_at = new Date().toISOString();
    writeAll(records);
  } catch (_e) { /* no-op */ }
  return { ...found, key_hash: undefined };
}

function list() {
  return readAll().map((r) => ({ ...r, key_hash: undefined }));
}

function revoke(id) {
  const records = readAll();
  const r = records.find((x) => x.id === id);
  if (!r) return false;
  r.active = false;
  r.revoked_at = new Date().toISOString();
  writeAll(records);
  return true;
}

module.exports = { issue, verify, list, revoke, PREFIX };
