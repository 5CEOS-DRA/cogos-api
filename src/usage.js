'use strict';

// Append-only usage log (JSONL). One line per chat completion call.
// Aggregation (daily, by tenant/key, etc.) is a downstream job; this
// file is the immutable substrate.
//
// ---------------------------------------------------------------------------
// Per-tenant hash chain (Security Hardening Card #3)
// ---------------------------------------------------------------------------
// Every appended row carries `prev_hash` + `row_hash` so each tenant's slice
// of the usage log forms a tamper-evident hash chain.
//
//   prev_hash = the row_hash of the most recent prior row for the SAME
//               tenant_id, OR 64 zeros if this is the tenant's genesis row.
//   row_hash  = sha256-hex( canonical-JSON({
//                 ts, tenant_id, key_id, route, status,
//                 prompt_tokens, completion_tokens, latency_ms, prev_hash
//               }) )
//
// CANONICAL JSON CHOICE: explicit fixed-key-order object literal. We rebuild
// the object below in the exact field order shown above and JSON.stringify
// it. We deliberately do NOT sort keys alphabetically — fixed-order is more
// auditable (the source code IS the spec), survives field renames cleanly
// (a rename is a chain reset, not a silent reorder), and matches what a
// bench-side verifier in a different language would naturally write.
//
// THIS ORDER IS LOAD-BEARING. Changing it invalidates every existing
// row_hash. If you need to extend the hashed payload, append fields at the
// end and document a chain epoch boundary.
//
// SCOPING NOTE: the chain here is per-tenant. A future card will publish a
// global head-hash (merkle aggregation of all tenant heads) to an Azure Blob
// public URL on an hourly cadence — see SECURITY_HARDENING_PLAN.md card #3.
// That public-checkpoint endpoint is intentionally NOT built in this branch.
//
// MIGRATION NOTE: pre-chain rows in an existing usage.jsonl are left as-is
// (no back-fill). They simply lack prev_hash/row_hash fields. The chain
// starts fresh from the first append after this code lands; readByTenant()
// returns pre-chain rows too, but verifyChain() will report them as
// unchained on the first row that has a `row_hash` field. Operators who
// want a clean chain can rotate the usage file before deploying this
// version.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const USAGE_FILE = process.env.USAGE_FILE
  || path.join(__dirname, '..', 'data', 'usage.jsonl');

const ZERO_HASH = '0'.repeat(64);

function ensureFile() {
  const dir = path.dirname(USAGE_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (!fs.existsSync(USAGE_FILE)) {
    fs.writeFileSync(USAGE_FILE, '', { mode: 0o600 });
  }
}

// Build the canonical hashed payload for a row. EXPLICIT FIXED-KEY ORDER —
// see the comment block above. Numeric fields are coerced to numbers so a
// row recorded as `0` and a row recorded as `undefined` never disagree.
function canonicalChainPayload({
  ts, tenant_id, key_id, route, status,
  prompt_tokens, completion_tokens, latency_ms, prev_hash,
}) {
  return JSON.stringify({
    ts,
    tenant_id: tenant_id || null,
    key_id: key_id || null,
    route: route || null,
    status: status || null,
    prompt_tokens: Number(prompt_tokens) || 0,
    completion_tokens: Number(completion_tokens) || 0,
    latency_ms: Number(latency_ms) || 0,
    prev_hash,
  });
}

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

// Walk the file backwards to find the most recent row_hash for a tenant.
// O(file-size) per append — fine while files are MB-scale. Swap for an
// in-memory head-cache when usage.jsonl grows past, say, 100MB.
function findTenantHead(tenantId) {
  ensureFile();
  const raw = fs.readFileSync(USAGE_FILE, 'utf8');
  if (!raw) return ZERO_HASH;
  const lines = raw.split('\n');
  for (let i = lines.length - 1; i >= 0; i -= 1) {
    const l = lines[i];
    if (!l || !l.trim()) continue;
    let row;
    try { row = JSON.parse(l); } catch (_e) { continue; }
    if (row.tenant_id === tenantId && typeof row.row_hash === 'string') {
      return row.row_hash;
    }
  }
  return ZERO_HASH;
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
  route = '/v1/chat/completions',
}) {
  ensureFile();
  const ts = new Date().toISOString();
  const prev_hash = findTenantHead(tenant_id);
  const row_hash = sha256Hex(canonicalChainPayload({
    ts, tenant_id, key_id, route, status,
    prompt_tokens, completion_tokens, latency_ms, prev_hash,
  }));
  const line = JSON.stringify({
    ts,
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
    route,
    prev_hash,
    row_hash,
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

// Return chained rows for a single tenant in time order, optionally filtered
// to ts > sinceMs and capped at `limit`. Rows lacking prev_hash/row_hash
// (pre-chain history) are included so the customer sees their full record;
// verifyChain() flags them.
function readByTenant(tenantId, sinceMs = 0, limit = 100) {
  if (!tenantId) return [];
  const all = readAll().filter((r) => r.tenant_id === tenantId);
  const filtered = sinceMs > 0
    ? all.filter((r) => {
        const t = Date.parse(r.ts);
        return Number.isFinite(t) && t > sinceMs;
      })
    : all;
  // ISO-8601 strings sort lexicographically in time order; tie-break is the
  // append order in the file (already chronological).
  filtered.sort((a, b) => (a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : 0));
  return filtered.slice(0, Math.max(0, limit));
}

// Verify a slice of chained rows. Expects rows in time order. Returns
// { ok: true } on a clean chain, or { ok: false, broke_at_index, ... } on
// the first inconsistency.
//
// Failure modes detected:
//   - first row's prev_hash is not the prior tenant head we don't know about,
//     so genesis-row detection is: prev_hash MUST equal ZERO_HASH if this is
//     the first row in the slice AND the caller hasn't supplied a chain head.
//     Otherwise we only check row-to-row continuity.
//   - any row's prev_hash != prior row's row_hash → missing/inserted row
//   - any row's row_hash != recomputed hash of its canonical payload → tamper
//
// `expectedHeadBefore` (optional) lets callers verify a slice that doesn't
// start at genesis (e.g. paginated reads) by passing the row_hash that
// should precede the slice's first row.
function verifyChain(rows, expectedHeadBefore = null) {
  if (!Array.isArray(rows) || rows.length === 0) {
    return { ok: true };
  }
  let priorHash = expectedHeadBefore;
  for (let i = 0; i < rows.length; i += 1) {
    const r = rows[i];
    // A row without row_hash is pre-chain history — surface it as
    // unchained at that index so callers know the chain hasn't started yet.
    if (typeof r.row_hash !== 'string' || typeof r.prev_hash !== 'string') {
      return {
        ok: false,
        broke_at_index: i,
        reason: 'row_missing_chain_fields',
        expected_prev_hash: priorHash,
        found_prev_hash: r.prev_hash || null,
      };
    }
    // Continuity check: prev_hash must equal the previous row's row_hash
    // (or ZERO_HASH if this is the first row of the chain).
    const expected = priorHash !== null ? priorHash : ZERO_HASH;
    if (r.prev_hash !== expected) {
      return {
        ok: false,
        broke_at_index: i,
        reason: 'prev_hash_mismatch',
        expected_prev_hash: expected,
        found_prev_hash: r.prev_hash,
      };
    }
    // Content check: row_hash must match recomputed hash.
    const recomputed = sha256Hex(canonicalChainPayload({
      ts: r.ts,
      tenant_id: r.tenant_id,
      key_id: r.key_id,
      route: r.route,
      status: r.status,
      prompt_tokens: r.prompt_tokens,
      completion_tokens: r.completion_tokens,
      latency_ms: r.latency_ms,
      prev_hash: r.prev_hash,
    }));
    if (recomputed !== r.row_hash) {
      return {
        ok: false,
        broke_at_index: i,
        reason: 'row_hash_mismatch',
        expected_row_hash: recomputed,
        found_row_hash: r.row_hash,
      };
    }
    priorHash = r.row_hash;
  }
  return { ok: true };
}

module.exports = {
  record,
  readAll,
  readByTenant,
  verifyChain,
  ZERO_HASH,
  // exported for tests
  _internal: { canonicalChainPayload, findTenantHead, sha256Hex },
};
