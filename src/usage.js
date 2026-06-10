'use strict';

// Append-only usage log (JSONL). One line per chat completion call.
// Aggregation (daily, by tenant/key, etc.) is a downstream job; this
// file is the immutable substrate.
//
// ---------------------------------------------------------------------------
// Per-(tenant, app) hash chain (Security Hardening Card #3 + multi-app round)
// ---------------------------------------------------------------------------
// Every appended row carries `prev_hash` + `row_hash` so each
// (tenant_id, app_id) slice of the usage log forms an independent
// tamper-evident hash chain. A single tenant running 10 apps therefore
// owns 10 chains — TruthPulse audit can't pollute or be confused with
// 5Central audit, and each app gets a clean genesis.
//
//   prev_hash = the row_hash of the most recent prior row for the SAME
//               (tenant_id, app_id), OR 64 zeros if this is genesis for
//               that pair.
//   row_hash  = sha256-hex( canonical-JSON({
//                 ts, tenant_id, key_id, route, status,
//                 prompt_tokens, completion_tokens, latency_ms,
//                 prev_hash, app_id
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
// CHAIN EPOCH BOUNDARY (multi-app rollout): `app_id` is appended at the
// END of the canonical payload — keeping every field's position stable
// is the contract the comment above promises. Rows persisted under the
// pre-multi-app code do not carry `app_id` and so are NOT hashable under
// the new payload; they're surfaced unchanged at read time but
// verifyChain() flags them as `row_missing_chain_fields` exactly as it
// did for pre-chain rows. From this commit forward every newly-written
// row records `app_id` (defaulting to '_default' when the call site
// hasn't been threaded through) and chains under the new payload.
//
// SCOPING NOTE: a future card will publish a global head-hash (merkle
// aggregation of all (tenant, app) heads) to an Azure Blob public URL
// on an hourly cadence — see SECURITY_HARDENING_PLAN.md card #3. That
// public-checkpoint endpoint is intentionally NOT built in this branch.
//
// MIGRATION NOTE: pre-multi-app rows in an existing usage.jsonl are
// LEFT AS-IS. They lack app_id; at read time they're surfaced under
// app_id='_default' (the default-app interpretation) but their on-disk
// representation is not rewritten. Operators who want a single clean
// chain per tenant can rotate the usage file before deploying this
// version.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const sealedAudit = require('./sealed-audit');

const USAGE_FILE = process.env.USAGE_FILE
  || path.join(__dirname, '..', 'data', 'usage.jsonl');

const ZERO_HASH = '0'.repeat(64);

// Mirror of keys.DEFAULT_APP_ID. Duplicated as a constant rather than
// `require('./keys').DEFAULT_APP_ID` to avoid a circular dependency (keys
// is referenced by auth, auth is referenced upstream from anywhere usage
// is touched). Update in lockstep with src/keys.js.
const DEFAULT_APP_ID = '_default';

// Resolve any caller-supplied app_id to the canonical string used in the
// chain payload. Null/undefined/empty all collapse to DEFAULT_APP_ID;
// any other non-string is coerced to string so a numeric or boolean
// can't accidentally produce a distinct hash bucket. Validation lives
// in src/keys.js — this resolver is intentionally permissive at the
// boundary because /v1/audit reads need to be able to look up rows
// from older data even if the value shape drifted.
function resolveAppId(app_id) {
  if (app_id == null || app_id === '') return DEFAULT_APP_ID;
  return String(app_id);
}

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
//
// LOAD-BEARING ORDER (chain epoch after multi-app rollout):
//   ts, tenant_id, key_id, route, status,
//   prompt_tokens, completion_tokens, latency_ms,
//   prev_hash, app_id
//
// `app_id` is appended at the END per the documented extension contract.
// Two rows with identical content but distinct (tenant, app) now produce
// distinct row_hashes — that's the cryptographic isolation 5CEOs needs to
// run TruthPulse + 5Central + 5Merger on one substrate without cross-app
// chain confusion.
function canonicalChainPayload({
  ts, tenant_id, key_id, route, status,
  prompt_tokens, completion_tokens, latency_ms, prev_hash, app_id,
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
    app_id: resolveAppId(app_id),
  });
}

// Zone C mutation chain row · canonical key order extends the base
// payload with 5 mutation-specific fields APPENDED at the chain epoch
// boundary (charter v0.2 C-14). The order is load-bearing — do NOT
// alphabetize. Pre-Zone-C rows verify against canonicalChainPayload;
// Zone C rows verify against this. Mutation detection on read is via
// the presence of `mutation_type` in the on-disk row.
function canonicalMutationChainPayload({
  ts, tenant_id, key_id, route, status,
  prompt_tokens, completion_tokens, latency_ms, prev_hash, app_id,
  mutation_type, viewport_id, section_id,
  row_version_before, row_version_after,
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
    app_id: resolveAppId(app_id),
    mutation_type: mutation_type || null,
    viewport_id: viewport_id || null,
    section_id: section_id || null,
    row_version_before: row_version_before || null,
    row_version_after: row_version_after || null,
  });
}

// Escalation chain row · CL-NEVER-1 rev 2026-06-06. When the substrate
// auto-escalates to a frontier provider because the sovereign tier
// could not resolve a call, the audit row carries 3 additional fields
// APPENDED at the end of the canonical payload — same extension
// contract as Zone C. Pre-escalation rows verify against
// canonicalChainPayload; escalated rows verify against this.
// Escalation detection on read is via the presence of `was_escalated`
// in the on-disk row.
//
// Field meanings:
//   was_escalated      — boolean. TRUE when the substrate routed this
//                        single call to a frontier provider because the
//                        sovereign tier could not resolve.
//   frontier_provider  — string. The provider that produced the bytes
//                        (gemini · openai · anthropic · openrouter · …).
//                        NULL when was_escalated is FALSE.
//   escalation_reason  — string from the canonical vocabulary:
//                        sovereign_refusal · sovereign_timeout ·
//                        sovereign_error · low_confidence ·
//                        schema_invalid · manual_override.
//                        NULL when was_escalated is FALSE.
function canonicalEscalationChainPayload({
  ts, tenant_id, key_id, route, status,
  prompt_tokens, completion_tokens, latency_ms, prev_hash, app_id,
  was_escalated, frontier_provider, escalation_reason,
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
    app_id: resolveAppId(app_id),
    was_escalated: Boolean(was_escalated),
    frontier_provider: frontier_provider || null,
    escalation_reason: escalation_reason || null,
  });
}

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

// In-memory head cache: Map<"tenantId\0appId", row_hash>. Populated lazily
// from disk on first access, then maintained by append(). Closes the
// O(file-size)-per-append scaling concern when usage.jsonl grows past a
// few MB. Cache rebuilds from disk if cleared (e.g. tests), so it stays
// consistent with the on-disk source of truth.
let _headCache = null;
function _cacheKey(tenantId, appId) {
  return `${tenantId} ${resolveAppId(appId)}`;
}
function _ensureCache() {
  if (_headCache) return _headCache;
  _headCache = new Map();
  ensureFile();
  const raw = fs.readFileSync(USAGE_FILE, 'utf8');
  if (!raw) return _headCache;
  for (const line of raw.split('\n')) {
    if (!line || !line.trim()) continue;
    let row;
    try { row = JSON.parse(line); } catch (_e) { continue; }
    if (typeof row.row_hash !== 'string') continue;
    _headCache.set(_cacheKey(row.tenant_id, row.app_id), row.row_hash);
  }
  return _headCache;
}
function _resetCacheForTest() { _headCache = null; }
function _updateCache(tenantId, appId, rowHash) {
  if (!_headCache) _ensureCache();
  _headCache.set(_cacheKey(tenantId, appId), rowHash);
}

// Look up the most recent row_hash for a (tenant_id, app_id) pair via the
// in-memory cache. O(1) per call. Cache is populated from disk on first
// access. Pre-multi-app rows lack app_id on disk; readers normalize via
// resolveAppId() so the on-disk shape stays untouched.
function findHead(tenantId, appId) {
  const cache = _ensureCache();
  return cache.get(_cacheKey(tenantId, appId)) || ZERO_HASH;
}

// Legacy single-arg head finder, retained because external callers
// (tests or future tooling) may still be on the pre-multi-app shape. New
// code should call findHead(tenantId, appId) directly.
function findTenantHead(tenantId) {
  return findHead(tenantId, DEFAULT_APP_ID);
}

// Append a usage row. Customer-content-sensitive fields (request_id,
// prompt_fingerprint, schema_name) are sealed under the customer's
// X25519 public key when one is supplied via `x25519_pubkey_pem`. When
// no x25519 pubkey is present (bearer-only customers), those fields
// stay in cleartext slots on the row and `sealed: false` is recorded
// so the customer + future auditors know unambiguously whether each
// row was sealed at write-time.
//
// LOAD-BEARING NOTE: the chain hashes the row WITH its sealed fields
// as they appear on disk (encrypted bytes are still bytes). That means
// sealing toggling for the same logical event still produces a
// deterministic row_hash — the only requirement is that the CANONICAL
// chain payload fields (ts, tenant_id, key_id, route, status,
// prompt/completion tokens, latency, prev_hash, app_id) are all
// cleartext, which they are. Sealing does NOT change canonicalChainPayload().
function record({
  key_id,
  tenant_id,
  app_id = null,
  model,
  prompt_tokens = 0,
  completion_tokens = 0,
  latency_ms = 0,
  status = 'success',
  schema_enforced = false,
  request_id,
  prompt_fingerprint = null,
  schema_name = null,
  route = '/v1/chat/completions',
  // X25519 SPKI PEM bound to (tenant_id, app_id) at issuance. When
  // present + valid the content fields ride inside an envelope only
  // the customer can open. Bearer-only customers don't have one and
  // the row stays cleartext (with sealed:false).
  x25519_pubkey_pem = null,
  // Zone C mutation fields (charter v0.2 C-14). When mutation_type is
  // set, the row uses canonicalMutationChainPayload + extended row
  // shape including the 5 appended fields. verifyChain detects on read.
  mutation_type = null,
  viewport_id = null,
  section_id = null,
  row_version_before = null,
  row_version_after = null,
  // Escalation fields (CL-NEVER-1 rev 2026-06-06). When was_escalated
  // is TRUE, the row uses canonicalEscalationChainPayload + persists
  // the 3 extra fields. Escalation is detected on read by presence of
  // was_escalated in the on-disk row.
  was_escalated = false,
  frontier_provider = null,
  escalation_reason = null,
  // Sovereign retry telemetry. Number of attempts against the sovereign
  // upstream BEFORE either success or escalation. Persisted on the row
  // but DELIBERATELY NOT IN THE CANONICAL CHAIN PAYLOAD — adding it
  // would invalidate every existing row_hash on disk. Metadata about
  // HOW the call was served does not affect WHAT was served.
  sovereign_attempts = null,
}) {
  ensureFile();
  const ts = new Date().toISOString();
  // resolveAppId() normalizes null/undefined/empty → '_default'. That's
  // also the on-disk value, so the row carries a concrete app_id even
  // when the call site predates multi-app threading.
  const resolvedAppId = resolveAppId(app_id);
  const prev_hash = findHead(tenant_id, resolvedAppId);
  const isMutation = mutation_type != null;
  const isEscalation = Boolean(was_escalated);
  // Branch precedence: Zone C mutation rows win because they're a
  // distinct surface (Zone C charter v0.2 C-14 substrate). A mutation
  // call cannot escalate to a frontier provider — mutations are
  // platform-substrate writes, not inference. Escalation is only on
  // /v1/chat/completions calls. If both were set we'd want the
  // mutation shape; the chat-api caller never sets both.
  const row_hash = isMutation
    ? sha256Hex(canonicalMutationChainPayload({
        ts, tenant_id, key_id, route, status,
        prompt_tokens, completion_tokens, latency_ms, prev_hash,
        app_id: resolvedAppId,
        mutation_type, viewport_id, section_id,
        row_version_before, row_version_after,
      }))
    : isEscalation
      ? sha256Hex(canonicalEscalationChainPayload({
          ts, tenant_id, key_id, route, status,
          prompt_tokens, completion_tokens, latency_ms, prev_hash,
          app_id: resolvedAppId,
          was_escalated, frontier_provider, escalation_reason,
        }))
      : sha256Hex(canonicalChainPayload({
          ts, tenant_id, key_id, route, status,
          prompt_tokens, completion_tokens, latency_ms, prev_hash,
          app_id: resolvedAppId,
        }));

  // Decide sealing. We require both (a) a valid x25519 pubkey AND (b)
  // at least one content field to actually seal. Sealing an empty
  // payload would still produce a valid envelope but it's pointless
  // ciphertext + ~150B per row; we save the bytes for the bearer-only
  // path which has nothing customer-sensitive to hide anyway.
  const hasContent = (request_id != null && request_id !== '')
    || (prompt_fingerprint != null && prompt_fingerprint !== '')
    || (schema_name != null && schema_name !== '');
  const shouldSeal = hasContent && sealedAudit.isSealablePubkey(x25519_pubkey_pem);

  let sealed = false;
  let sealedContent = undefined;
  let cleartextRequestId = request_id;
  let cleartextPromptFp = prompt_fingerprint;
  let cleartextSchemaName = schema_name;

  if (shouldSeal) {
    const payload = sealedAudit.canonicalContent({
      request_id, prompt_fingerprint, schema_name,
    });
    // AAD binds the envelope to this specific (tenant, app, ts) — a
    // copy-paste of the sealed_content blob onto a different row fails
    // the GCM tag check at unseal time.
    sealedContent = sealedAudit.sealForPubkey(x25519_pubkey_pem, payload, {
      tenant_id, app_id: resolvedAppId, ts,
    });
    sealed = true;
    // Strip cleartext content fields so they don't double-live on disk.
    cleartextRequestId = null;
    cleartextPromptFp = null;
    cleartextSchemaName = null;
  }

  const row = {
    ts,
    key_id,
    tenant_id,
    app_id: resolvedAppId,
    model,
    prompt_tokens,
    completion_tokens,
    total_tokens: prompt_tokens + completion_tokens,
    latency_ms,
    status,
    schema_enforced,
    request_id: cleartextRequestId,
    route,
    prev_hash,
    row_hash,
    sealed,
  };
  // Only attach the content fields when sealing was skipped (preserves
  // the legacy on-disk shape for unsealed rows + avoids redundant null
  // entries on sealed rows).
  if (!sealed) {
    if (prompt_fingerprint != null) row.prompt_fingerprint = cleartextPromptFp;
    if (schema_name != null) row.schema_name = cleartextSchemaName;
  } else {
    row.sealed_content = sealedContent;
  }
  // Zone C mutation fields appended to disk row (charter v0.2 C-14)
  // when this is a mutation chain row. verifyChain detects via
  // mutation_type presence and uses the right canonical payload.
  if (isMutation) {
    row.mutation_type = mutation_type;
    row.viewport_id = viewport_id;
    row.section_id = section_id;
    row.row_version_before = row_version_before;
    row.row_version_after = row_version_after;
  }
  // Escalation fields appended to disk row (CL-NEVER-1 rev 2026-06-06)
  // when this is an escalated chat-completion row. verifyChain detects
  // via was_escalated presence and uses canonicalEscalationChainPayload.
  if (isEscalation) {
    row.was_escalated = true;
    row.frontier_provider = frontier_provider || null;
    row.escalation_reason = escalation_reason || null;
  }
  // Sovereign retry telemetry: attach only when caller passed a value.
  // Existing rows in the wild have no `sovereign_attempts` — that's fine,
  // they map to "unknown" downstream. NOT included in the chain payload.
  if (sovereign_attempts != null) {
    row.sovereign_attempts = sovereign_attempts;
  }
  fs.appendFileSync(USAGE_FILE, JSON.stringify(row) + '\n');
  // Keep the in-memory head cache hot so findHead() stays O(1) for
  // subsequent appends in the same (tenant, app) partition.
  _updateCache(row.tenant_id, row.app_id, row.row_hash);
  // Return the new chain head so callers (admin handlers + future
  // mutation endpoints) can surface chain_head_after in responses
  // without a second findHead() lookup. Existing callers ignore
  // the return value — no breaking change.
  return row.row_hash;
}

function readAll() {
  ensureFile();
  return fs.readFileSync(USAGE_FILE, 'utf8')
    .split('\n')
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l));
}

// Return chained rows for a tenant, optionally narrowed to a single
// app_id, optionally filtered to ts > sinceMs, capped at `limit`. Rows
// lacking prev_hash/row_hash (pre-chain history) or lacking app_id
// (pre-multi-app history) are INCLUDED so the customer sees their full
// record; we surface the missing app_id as DEFAULT_APP_ID at projection
// time so downstream readers + verifyChain() don't have to special-case
// null. The on-disk row is NOT rewritten.
//
// Signature is the option-bag {tenant_id, app_id, since, limit} —
// app_id omitted (or null) means "all apps for this tenant, interleaved
// by ts." This is how /v1/audit serves the customer's full cross-app
// view; the cross-app response then carries chain_ok_by_app so the
// caller can still verify each app's chain independently.
function readSlice({ tenant_id, app_id, since, limit } = {}) {
  if (!tenant_id) return [];
  const sinceMs = Number(since || 0);
  const lim = limit == null ? 100 : Math.max(0, Math.floor(Number(limit) || 0));
  const wantedApp = app_id == null ? null : resolveAppId(app_id);
  const all = readAll().filter((r) => r.tenant_id === tenant_id);
  // Read-time projection:
  //   - app_id absent  → DEFAULT_APP_ID (pre-multi-app history)
  //   - sealed absent  → false (pre-sealed-audit history; cleartext content)
  // Disk shape is NOT rewritten; the projection only smooths the API
  // surface so downstream consumers can rely on these fields being set.
  const projected = all.map((r) => {
    const out = r.app_id == null ? { ...r, app_id: DEFAULT_APP_ID } : r;
    if (out.sealed == null) return { ...out, sealed: false };
    return out;
  });
  const appFiltered = wantedApp == null
    ? projected
    : projected.filter((r) => r.app_id === wantedApp);
  const filtered = sinceMs > 0
    ? appFiltered.filter((r) => {
        const t = Date.parse(r.ts);
        return Number.isFinite(t) && t > sinceMs;
      })
    : appFiltered;
  // ISO-8601 strings sort lexicographically in time order; tie-break is the
  // append order in the file (already chronological).
  filtered.sort((a, b) => (a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : 0));
  return filtered.slice(0, lim);
}

// Legacy single-tenant reader. Equivalent to readSlice with no app_id
// filter — kept for callers that haven't been rewritten yet (tests,
// scripts). New code should call readSlice() directly.
function readByTenant(tenantId, sinceMs = 0, limit = 100) {
  return readSlice({ tenant_id: tenantId, since: sinceMs, limit });
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
//
// MIXED-APP CALLER CONTRACT: chains are per-(tenant, app_id). Passing a
// slice that interleaves rows from multiple apps into this function
// produces undefined behavior — the prev_hash continuity check will
// fire on the first cross-app boundary. The caller is responsible for
// slicing per app (or using verifyByApp() below, which does it for you).
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
    // Content check: row_hash must match recomputed hash. app_id is
    // resolved through resolveAppId() so pre-multi-app rows surfaced
    // under the DEFAULT_APP_ID projection still recompute consistently
    // for new chain epoch verification.
    //
    // Zone C mutation rows (charter v0.2 C-14) carry mutation_type +
    // appended fields. Detect by presence; use the extended canonical.
    // Escalation rows (CL-NEVER-1 rev 2026-06-06) carry was_escalated
    // + frontier_provider + escalation_reason. Mutually exclusive with
    // mutation rows (mutations are platform writes, not inference).
    const isMutation = r.mutation_type != null;
    const isEscalation = r.was_escalated != null;
    const recomputed = isMutation
      ? sha256Hex(canonicalMutationChainPayload({
          ts: r.ts,
          tenant_id: r.tenant_id,
          key_id: r.key_id,
          route: r.route,
          status: r.status,
          prompt_tokens: r.prompt_tokens,
          completion_tokens: r.completion_tokens,
          latency_ms: r.latency_ms,
          prev_hash: r.prev_hash,
          app_id: r.app_id,
          mutation_type: r.mutation_type,
          viewport_id: r.viewport_id,
          section_id: r.section_id,
          row_version_before: r.row_version_before,
          row_version_after: r.row_version_after,
        }))
      : isEscalation
        ? sha256Hex(canonicalEscalationChainPayload({
            ts: r.ts,
            tenant_id: r.tenant_id,
            key_id: r.key_id,
            route: r.route,
            status: r.status,
            prompt_tokens: r.prompt_tokens,
            completion_tokens: r.completion_tokens,
            latency_ms: r.latency_ms,
            prev_hash: r.prev_hash,
            app_id: r.app_id,
            was_escalated: r.was_escalated,
            frontier_provider: r.frontier_provider,
            escalation_reason: r.escalation_reason,
          }))
        : sha256Hex(canonicalChainPayload({
            ts: r.ts,
            tenant_id: r.tenant_id,
            key_id: r.key_id,
            route: r.route,
            status: r.status,
            prompt_tokens: r.prompt_tokens,
            completion_tokens: r.completion_tokens,
            latency_ms: r.latency_ms,
            prev_hash: r.prev_hash,
            app_id: r.app_id,
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

// Verify every distinct app slice inside a mixed-app rows[] array and
// return a per-app verification result: { _default: {ok}, app1: {ok}... }.
// The rows are grouped by app_id (resolved through resolveAppId() so
// pre-multi-app rows fold into _default), each group is sorted by ts,
// and verifyChain is run on each group independently. Used by
// /v1/audit when the caller doesn't pass an app_id filter — every
// app's chain is checked but the response is the interleaved cross-app
// view the customer asked for.
function verifyByApp(rows) {
  const out = {};
  if (!Array.isArray(rows) || rows.length === 0) return out;
  const byApp = new Map();
  for (const r of rows) {
    const app = resolveAppId(r.app_id);
    if (!byApp.has(app)) byApp.set(app, []);
    byApp.get(app).push(r);
  }
  for (const [app, group] of byApp.entries()) {
    group.sort((a, b) => (a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : 0));
    out[app] = verifyChain(group);
  }
  return out;
}

module.exports = {
  record,
  readAll,
  readByTenant,
  readSlice,
  verifyChain,
  verifyByApp,
  ZERO_HASH,
  DEFAULT_APP_ID,
  // exported for tests
  _internal: { canonicalChainPayload, canonicalMutationChainPayload, findTenantHead, findHead, sha256Hex, resolveAppId, _resetCacheForTest },
};
