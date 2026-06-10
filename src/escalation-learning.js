'use strict';

/**
 * Escalation Learning Log · Phase 1 of CL-NEVER-1 learning loop.
 *
 * Append-only JSONL capturing every (prompt → frontier response) pair
 * produced by substrate-automatic escalation. The dataset is the
 * raw material for downstream phases:
 *
 *   Phase 2 — Semantic-similarity cache on prompt fingerprint
 *   Phase 3 — Tier-routing classifier (which prompts genuinely
 *             need 7B / which can stay on 3B)
 *   Phase 4 — Periodic Qwen LoRA fine-tune against this dataset
 *
 * Schema (one JSON object per line):
 *   {
 *     ts,                    // ISO 8601
 *     request_id,            // joins back to the usage chain row
 *     tenant_id,             // partition key
 *     app_id,                // sub-partition (per-app substrate split)
 *     key_id,                // which key issued the call
 *     escalation_reason,     // sovereign_error · sovereign_timeout · manual_override · …
 *     sovereign_model,       // the model that couldn't resolve
 *     frontier_provider,     // gemini · openai · anthropic · …
 *     frontier_model,        // gemini-2.5-flash · …
 *     messages,              // the FULL chat-completions messages array (this
 *                            //   is the load-bearing field for fine-tuning)
 *     response_content,      // the assistant content the frontier returned
 *     prompt_tokens,
 *     completion_tokens,
 *     latency_ms,            // end-to-end (sovereign attempt + frontier call)
 *     frontier_latency_ms,   // just the frontier round-trip
 *   }
 *
 * Privacy model:
 *   - This file contains real customer prompt content. Operator-only.
 *   - Gated by /admin/escalation-learning behind X-Admin-Key.
 *   - Per-customer extraction is a simple grep by tenant_id; safe to
 *     ship a tenant their own subset for fine-tuning their own sovereign.
 *
 * Why JSONL and not the existing usage.jsonl:
 *   - usage.jsonl is the hash-chained substrate-correctness log. Adding
 *     full message bodies bloats it 100×.
 *   - This log is a separate substrate concern: training-data quality,
 *     not chain integrity. Keeping it independent lets one rotate
 *     without disturbing the other.
 *
 * Failure mode:
 *   - Best-effort writes (try/catch around append). A learning-log
 *     failure must NEVER break the escalation success path — the
 *     customer gets their answer either way.
 */

const fs = require('node:fs');
const path = require('node:path');
const logger = require('./logger');

const LOG_FILE = process.env.ESCALATION_LEARNING_FILE
  || path.join(__dirname, '..', 'data', 'escalation-learning.jsonl');

function ensureFile() {
  const dir = path.dirname(LOG_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (!fs.existsSync(LOG_FILE)) fs.writeFileSync(LOG_FILE, '', { mode: 0o600 });
}

/**
 * Append one learning row. Synchronous on purpose — file appends on
 * a local SSD are sub-millisecond and we want the write to either
 * succeed before we return from the request handler or surface a
 * loggable error.
 *
 * Returns true on success, false on any failure (never throws).
 */
function record(row) {
  try {
    ensureFile();
    const entry = {
      ts: row.ts || new Date().toISOString(),
      request_id: row.request_id || null,
      tenant_id: row.tenant_id || null,
      app_id: row.app_id || null,
      key_id: row.key_id || null,
      escalation_reason: row.escalation_reason || null,
      sovereign_model: row.sovereign_model || null,
      // path: 'frontier_llm' (legacy) | 'web_augmented' (new default)
      // | 'verified' (sovereign + post-inference web fact-check).
      // Each tuple shape is captured so future training-data extraction
      // can filter by source quality. Web hits are the most valuable
      // training substrate: (prompt → web sources → sovereign answer)
      // pairs teach sovereign to answer queries it currently has to
      // look up.
      path: row.path || 'frontier_llm',
      // Legacy frontier-LLM fields (still captured when path=frontier_llm)
      frontier_provider: row.frontier_provider || null,
      frontier_model: row.frontier_model || null,
      // Web-augmented fields (captured when path=web_augmented)
      web_provider: row.web_provider || null,
      web_sources: Array.isArray(row.web_sources) ? row.web_sources : null,
      search_latency_ms: Number(row.search_latency_ms || 0),
      // Verifier fields (captured when path=verified)
      verification_summary: row.verification_summary || null,
      claims_checked: Array.isArray(row.claims_checked) ? row.claims_checked : null,
      // Common
      messages: Array.isArray(row.messages) ? row.messages : null,
      response_content: row.response_content || null,
      prompt_tokens: Number(row.prompt_tokens || 0),
      completion_tokens: Number(row.completion_tokens || 0),
      latency_ms: Number(row.latency_ms || 0),
      frontier_latency_ms: Number(row.frontier_latency_ms || 0),
    };
    fs.appendFileSync(LOG_FILE, JSON.stringify(entry) + '\n');
    return true;
  } catch (e) {
    logger.warn('escalation_learning_append_failed', { error: e.message });
    return false;
  }
}

/**
 * Read N most recent rows, optionally filtered by tenant_id / since.
 * Returns an array (newest last per JSONL convention). Used by the
 * /admin/escalation-learning endpoint.
 */
function read({ limit = 100, tenant_id = null, since = null } = {}) {
  try {
    ensureFile();
    const raw = fs.readFileSync(LOG_FILE, 'utf8');
    if (!raw) return [];
    const lines = raw.split('\n').filter((l) => l.trim());
    const out = [];
    for (const line of lines) {
      let row;
      try { row = JSON.parse(line); } catch (_) { continue; }
      if (tenant_id && row.tenant_id !== tenant_id) continue;
      if (since) {
        const ts = new Date(row.ts).getTime();
        if (ts < Number(since)) continue;
      }
      out.push(row);
    }
    // Newest first when returning the limited slice — caller can re-sort.
    out.reverse();
    return out.slice(0, Number(limit) || 100);
  } catch (e) {
    logger.warn('escalation_learning_read_failed', { error: e.message });
    return [];
  }
}

/**
 * Summary stats over the full log — count, by_tenant, by_reason,
 * by_frontier_model, total_tokens. Cheap because the file is small in
 * practice; a heavier substrate can move this to a rollup table later.
 */
function summary() {
  try {
    ensureFile();
    const raw = fs.readFileSync(LOG_FILE, 'utf8');
    if (!raw) {
      return {
        total_rows: 0, by_tenant: {}, by_reason: {}, by_frontier_model: {},
        total_prompt_tokens: 0, total_completion_tokens: 0,
      };
    }
    const lines = raw.split('\n').filter((l) => l.trim());
    const by_tenant = {};
    const by_reason = {};
    const by_frontier_model = {};
    let total_prompt_tokens = 0;
    let total_completion_tokens = 0;
    for (const line of lines) {
      let row;
      try { row = JSON.parse(line); } catch (_) { continue; }
      by_tenant[row.tenant_id || 'unknown']                = (by_tenant[row.tenant_id || 'unknown']                || 0) + 1;
      by_reason[row.escalation_reason || 'unknown']        = (by_reason[row.escalation_reason || 'unknown']        || 0) + 1;
      by_frontier_model[row.frontier_model || 'unknown']   = (by_frontier_model[row.frontier_model || 'unknown']   || 0) + 1;
      total_prompt_tokens     += Number(row.prompt_tokens || 0);
      total_completion_tokens += Number(row.completion_tokens || 0);
    }
    return {
      total_rows: lines.length,
      by_tenant,
      by_reason,
      by_frontier_model,
      total_prompt_tokens,
      total_completion_tokens,
    };
  } catch (e) {
    logger.warn('escalation_learning_summary_failed', { error: e.message });
    return null;
  }
}

module.exports = { record, read, summary, _LOG_FILE: LOG_FILE };
