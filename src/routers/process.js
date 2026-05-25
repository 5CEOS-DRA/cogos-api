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
 * Receipt shape: { request_id, ms, deterministic_hash } — the hash is
 * sha256(canonicalized request body) so the customer can re-canonicalize
 * locally and prove the cogos-api received exactly what they sent (no
 * MITM mutation). Output hashing is intentionally NOT promised yet —
 * the engine returns Object.create(null) maps whose key-iteration order
 * is insertion-driven; we'll lock that in v0.2 alongside the doctrine
 * note in the Process Library page.
 */

const express = require('express');
const crypto = require('crypto');
const logger = require('../logger');
const usage = require('../usage');
const reconciler = require('../processes/iolta-reconciler');

const PROCESS_ROUTE = '/v1/process/iolta-reconcile';
const PROCESS_MODEL_ID = 'process:iolta-reconcile-v1';

// Stable canonicalization · sorts keys at every level, drops undefined.
// Matches the doctrinal "same input → same hash" promise on the Process
// Library page. Arrays preserve order (intentional — ledger row order
// is semantically meaningful for downstream audit).
function canonicalize(value) {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(canonicalize);
  const keys = Object.keys(value).sort();
  const out = {};
  for (const k of keys) {
    if (value[k] === undefined) continue;
    out[k] = canonicalize(value[k]);
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

  router.post(
    '/iolta-reconcile',
    customerAuth,
    tenantLimiter,
    (req, res) => {
      const t0 = Date.now();
      const request_id = newRequestId();
      const body = req.body || {};

      // Canonicalize FIRST so the receipt hash is computed off the
      // exact input the engine sees. If validation fails the hash
      // still went on the wire so the customer can prove what they
      // sent.
      const canonicalInput = canonicalize(body);
      const canonicalBytes = JSON.stringify(canonicalInput);
      const deterministic_hash = 'sha256:' + sha256Hex(canonicalBytes);

      let result;
      try {
        result = reconciler.reconcileThreeWay(body);
      } catch (e) {
        const ms = Date.now() - t0;
        const isTypeError = e instanceof TypeError;
        const status = isTypeError ? 400 : 500;
        // Still record the invocation — customer hit the endpoint with
        // their key, that's a billable act even when it fails on input
        // validation. Stripe-side may rebate failed calls later; the
        // audit row is the source of truth.
        try {
          usage.record({
            key_id: req.apiKey && req.apiKey.id,
            tenant_id: req.apiKey && req.apiKey.tenant_id,
            app_id: req.apiKey && req.apiKey.app_id,
            model: PROCESS_MODEL_ID,
            prompt_tokens: 0,
            completion_tokens: 0,
            latency_ms: ms,
            status: isTypeError ? 'client_error' : 'server_error',
            request_id,
            route: PROCESS_ROUTE,
          });
        } catch (recordErr) {
          logger.warn('[process/iolta] usage.record failed', { error: recordErr.message });
        }
        return res.status(status).json({
          error: {
            message: e.message,
            type: isTypeError ? 'invalid_request_error' : 'internal_server_error',
            code: isTypeError ? 'invalid_input' : 'engine_failure',
          },
          receipt: {
            request_id,
            ms,
            deterministic_hash,
          },
        });
      }

      const ms = Date.now() - t0;
      try {
        usage.record({
          key_id: req.apiKey && req.apiKey.id,
          tenant_id: req.apiKey && req.apiKey.tenant_id,
          app_id: req.apiKey && req.apiKey.app_id,
          model: PROCESS_MODEL_ID,
          prompt_tokens: 0,
          completion_tokens: 0,
          latency_ms: ms,
          status: 'success',
          request_id,
          route: PROCESS_ROUTE,
        });
      } catch (recordErr) {
        logger.warn('[process/iolta] usage.record failed', { error: recordErr.message });
      }

      return res.status(200).json({
        ...result,
        receipt: {
          request_id,
          ms,
          deterministic_hash,
          reconciler_version: reconciler.RECONCILER_VERSION,
        },
      });
    },
  );

  // GET /v1/process — catalog endpoint so CLI/tooling can discover what's
  // available. Mirrors the Process Library page on the platform, but here
  // it's machine-readable. No auth required for the catalog itself — the
  // INVOCATIONS are auth-gated.
  router.get('/', (req, res) => {
    res.json({
      processes: [
        {
          id: 'iolta-reconcile',
          version: reconciler.RECONCILER_VERSION,
          status: 'available',
          doctrine: '5law L4 · ABA Rule 1.15',
          endpoint: PROCESS_ROUTE,
          method: 'POST',
          model_id: PROCESS_MODEL_ID,
          description: 'Three-way IOLTA trust account reconciliation. Bank vs trust-ledger vs per-client sub-ledger, with commingling detection. Pure function, no LLM.',
        },
      ],
    });
  });

  return router;
}

module.exports = {
  makeProcessRouter,
  PROCESS_ROUTE,
  PROCESS_MODEL_ID,
  // exported for tests
  _internal: { canonicalize, sha256Hex },
};
