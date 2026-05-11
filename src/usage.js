'use strict';

// Append-only usage log (JSONL). One line per chat completion call.
// Aggregation (daily, by tenant/key, etc.) is a downstream job; this
// file is the immutable substrate.

const fs = require('fs');
const path = require('path');

const USAGE_FILE = process.env.USAGE_FILE
  || path.join(__dirname, '..', 'data', 'usage.jsonl');

function ensureFile() {
  const dir = path.dirname(USAGE_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (!fs.existsSync(USAGE_FILE)) {
    fs.writeFileSync(USAGE_FILE, '', { mode: 0o600 });
  }
}

function record({
  key_id,
  tenant_id,
  model,
  prompt_tokens = 0,
  completion_tokens = 0,
  latency_ms = 0,
  status = 'success',
  schema_enforced = false,
  request_id,
}) {
  ensureFile();
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    key_id,
    tenant_id,
    model,
    prompt_tokens,
    completion_tokens,
    total_tokens: prompt_tokens + completion_tokens,
    latency_ms,
    status,
    schema_enforced,
    request_id,
  }) + '\n';
  fs.appendFileSync(USAGE_FILE, line);
}

function readAll() {
  ensureFile();
  return fs.readFileSync(USAGE_FILE, 'utf8')
    .split('\n')
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l));
}

module.exports = { record, readAll };
