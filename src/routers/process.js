'use strict';

/**
 * /v1/process/* — CogOS Process Library
 *
 * Path B (operator directive 2026-05-25): deterministic, doctrine-pure
 * processes callable by any sk-cogos-* key, no platform tenant required.
 *
 * v0.1 ships ONE process: iolta-reconcile (vendored from the 5CEOs
 * platform's 5law substrate). See src/processes/iolta-reconciler.js for
 * the vendoring contract.
 *
 * Auth contract: customerAuth + tenantLimiter — identical to /v1/chat/*.
 * Every invocation appends a hash-chained usage row so customers can
 * audit their own spend via /v1/audit.
 *
 * Receipt shape (v0.2): { request_id, ms, deterministic_hash, output_hash }
 * Both hashes are sha256 of the canonicalized payload — deterministic_hash
 * over the request body (proves cogos-api received exactly what was sent),
 * output_hash over the engine response (proves the same input will produce
 * the same output forever, for this engine version). v0.2 closes the
 * output-canonicalization gap by routing every engine response through
 * the shared canonicalize primitive (src/processes/_canonicalize.js)
 * before the hash is computed and before the body ships.
 */

const express = require('express');
const crypto = require('crypto');
const logger = require('../logger');
const usage = require('../usage');
const { canonicalize, canonicalHash } = require('../processes/_canonicalize');
const { REGISTRY, listProcesses, getProcess } = require('../processes/_registry');

// Legacy route-constant exports kept so external callers and tests
// importing PROCESS_ROUTE / CONFLICT_ROUTE still resolve.
const PROCESS_ROUTE = '/v1/process/iolta-reconcile';
const PROCESS_MODEL_ID = 'process:iolta-reconcile-v1';
const CONFLICT_ROUTE = '/v1/process/5law-conflict-check';
const CONFLICT_MODEL_ID = 'process:5law-conflict-check-v1';

// Legacy inline canonicalize · DEPRECATED, kept for the tests that still
// import procRouter._internal.canonicalize. New code in this file uses
// the shared `canonicalize` from _canonicalize.js (imported above).
function legacyCanonicalize(value) {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(legacyCanonicalize);
  const keys = Object.keys(value).sort();
  const out = {};
  for (const k of keys) {
    if (value[k] === undefined) continue;
    out[k] = legacyCanonicalize(value[k]);
  }
  return out;
}

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function newRequestId() {
  // 22-byte random base64url; matches the OpenAI-shaped chatcmpl-* id
  // length the chat handler emits. Differentiated prefix so audit rows
  // can be filtered by route.
  return 'proc_' + crypto.randomBytes(16).toString('base64url');
}

function makeProcessRouter({ customerAuth, tenantLimiter }) {
  const router = express.Router();

  // ─── Shared per-process invocation handler ───────────────────────
  // Both /iolta-reconcile and /5law-conflict-check share the same
  // pipeline: canonicalize → engine call → usage record → response with
  // receipt. Extracted so a third process is one block of config, not
  // 80 lines of copy-paste.
  function invokeProcess({ route, modelId, engine, wrapBody }) {
    return (req, res) => {
      const t0 = Date.now();
      const request_id = newRequestId();
      const rawBody = req.body || {};

      // Input hash · proves cogos-api received exactly what the caller
      // sent (no MITM mutation). Computed on the RAW body BEFORE any
      // wrapBody injection so the hash matches what the customer sent.
      const deterministic_hash = canonicalHash(rawBody);

      // wrapBody · optional per-process pre-engine injection. Lets a
      // process pull tenant-state from the gateway (e.g. 5law-conflict-
      // check using stored firm graph). The wrapped body is what the
      // engine sees and what gets output-hashed.
      const body = typeof wrapBody === 'function' ? wrapBody(req, rawBody) : rawBody;

      let result;
      try {
        result = engine(body);
      } catch (e) {
        const ms = Date.now() - t0;
        const isTypeError = e instanceof TypeError;
        const status = isTypeError ? 400 : 500;
        try {
          usage.record({
            key_id: req.apiKey && req.apiKey.id,
            tenant_id: req.apiKey && req.apiKey.tenant_id,
            app_id: req.apiKey && req.apiKey.app_id,
            model: modelId,
            prompt_tokens: 0,
            completion_tokens: 0,
            latency_ms: ms,
            status: isTypeError ? 'client_error' : 'server_error',
            request_id,
            route,
          });
        } catch (recordErr) {
          logger.warn('[process] usage.record failed', { error: recordErr.message, route });
        }
        return res.status(status).json({
          error: {
            message: e.message,
            type: isTypeError ? 'invalid_request_error' : 'internal_server_error',
            code: isTypeError ? 'invalid_input' : 'engine_failure',
          },
          receipt: { request_id, ms, deterministic_hash },
        });
      }

      const ms = Date.now() - t0;
      try {
        usage.record({
          key_id: req.apiKey && req.apiKey.id,
          tenant_id: req.apiKey && req.apiKey.tenant_id,
          app_id: req.apiKey && req.apiKey.app_id,
          model: modelId,
          prompt_tokens: 0,
          completion_tokens: 0,
          latency_ms: ms,
          status: 'success',
          request_id,
          route,
        });
      } catch (recordErr) {
        logger.warn('[process] usage.record failed', { error: recordErr.message, route });
      }

      // Result shape varies per process; receipt is universal.
      // For non-object results (e.g. arrays from conflict engine), wrap.
      const payload = Array.isArray(result) ? { rows: result } : (result || {});

      // Output hash · proves the engine produced bitwise-stable output
      // for this canonical input. v0.2 substrate engineering: the engines
      // route their output through canonicalize() before return, so the
      // hash here is sha256(canonical engine output) — same input always
      // produces the same output_hash, for this engine version.
      // Spec gap closed by commit 8745d722d on the platform repo.
      const output_hash = canonicalHash(payload);

      return res.status(200).json({
        ...payload,
        receipt: { request_id, ms, deterministic_hash, output_hash },
      });
    };
  }

  // Mount each registered process at its slug. Adding a new process
  // is a one-line drop in src/processes/_registry.js · the route here
  // picks it up via Object.values(REGISTRY).
  for (const p of Object.values(REGISTRY)) {
    const slug = p.id;
    router.post('/' + slug, customerAuth, tenantLimiter, invokeProcess({
      route: '/v1/process/' + slug,
      modelId: p.model_id,
      engine: p.engine,
      wrapBody: p.wrapBody,
    }));
  }

  // GET /v1/process — catalog endpoint so CLI/tooling can discover what's
  // available. Mirrors the Process Library page on the platform, but here
  // it's machine-readable. No auth required for the catalog itself — the
  // INVOCATIONS are auth-gated.
  router.get('/', (req, res) => {
    res.json({ processes: listProcesses() });
  });

  return router;
}

module.exports = {
  makeProcessRouter,
  PROCESS_ROUTE,
  PROCESS_MODEL_ID,
  // exported for tests
  _internal: {
    // Shared canonicalization primitive (used by the handler and the
    // engines via _canonicalize.js). canonicalize() and the tests'
    // sha256Hex shim alias come from the shared module so tests don't
    // diverge from production behavior.
    canonicalize,
    sha256Hex: (s) => require('crypto').createHash('sha256').update(s).digest('hex'),
    canonicalHash,
    // Pre-v0.2 inline canonicalize, kept only for one test that asserts
    // the old behavior. Do not use in new code.
    legacyCanonicalize,
  },
};
