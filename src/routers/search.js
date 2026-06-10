'use strict';

/**
 * /v1/search — receipt-bearing live-web search surface.
 *
 * WHY THIS EXISTS
 * ---------------
 * CogOS keeps the inference LLM small and reaches the open internet on
 * demand for facts the model couldn't have at training time. This router
 * is that reach. Every fetch returns a receipt on the same per-(tenant,
 * app_id) hash chain that records every /v1/chat and /v1/process call,
 * so a customer can replay months later and prove which sources the
 * substrate consulted for an answer.
 *
 * RECEIPT SHAPE (universal across /v1/process and /v1/search)
 *   { request_id, ms, deterministic_hash, output_hash }
 *
 * HONEST RECEIPT SEMANTICS — READ THIS BEFORE EDITING
 * ----------------------------------------------------
 * The receipt shape is the same as /v1/process but ONE FIELD'S SEMANTICS
 * DIFFER and the difference is load-bearing:
 *
 *   deterministic_hash  — sha256 of the canonicalized REQUEST body.
 *                         Proves cogos-api received exactly what the
 *                         caller sent (no MITM mutation). Same meaning
 *                         here as in /v1/process. (R-1)
 *
 *   output_hash         — sha256 of the canonicalized response payload
 *                         (results + provider + query + latency_ms).
 *                         IN /v1/process this proves the engine produces
 *                         bitwise-stable output for this input forever.
 *                         IN /v1/search IT PROVES WHAT WAS RETURNED AT
 *                         THIS MOMENT, NOT WHAT WILL ALWAYS RETURN.
 *                         The web is non-deterministic by nature; an
 *                         identical query tomorrow may return different
 *                         snippets. The hash still has audit value — it
 *                         binds the customer's answer to the exact
 *                         provider response that produced it — but it is
 *                         NOT a determinism guarantee. (R-2)
 *
 * Any future copy on the Front Door page or in marketing MUST preserve
 * this distinction. "Receipt-bearing search" is honest; "deterministic
 * search" is not.
 *
 * USAGE-ROW SHAPE
 * ---------------
 * One row per call, with:
 *   model       = 'search:brave-v1'  (or whatever provider was used)
 *   route       = '/v1/search'
 *   status      = 'success' | 'client_error' | 'server_error'
 *   prompt_tokens = 0  (search doesn't consume tokens)
 *   completion_tokens = 0
 *   latency_ms  = wall clock from t0 to response shipped
 *   request_id  = srch_* base64url, 16 random bytes
 *
 * provider:'none' calls (BRAVE_SEARCH_API_KEY unset) STILL emit a usage
 * row with status='success' and 0 results. The chain records the attempt
 * + the substrate's honest "no provider configured" response. This is
 * the doctrine-clean behavior — silent dropping would let an operator
 * mis-configure search and never see the attempts in /v1/audit.
 *
 * AUTH
 * ----
 * customerAuth + tenantLimiter, identical to /v1/process and /v1/chat.
 * Any valid sk-cogos-* key may call this. The tenantLimiter shares its
 * bucket with the rest of the /v1 surface so a customer can't sneak
 * extra throughput by routing through search.
 */

const express = require('express');
const crypto = require('crypto');
const logger = require('../logger');
const usage = require('../usage');
const { canonicalHash } = require('../processes/_canonicalize');
const searchClient = require('../search-client');

const SEARCH_ROUTE = '/v1/search';
const SEARCH_MODEL_ID_BRAVE = 'search:brave-v1';
const SEARCH_MODEL_ID_NONE  = 'search:none';

function newRequestId() {
  return 'srch_' + crypto.randomBytes(16).toString('base64url');
}

function makeSearchRouter({ customerAuth, tenantLimiter, enforceDailyCap, enforcePackage, _searchClient }) {
  const router = express.Router();
  // Test-injectable client. Production uses the real searchClient
  // imported above; tests pass `_searchClient` with a stub fetch.
  const client = _searchClient || searchClient;
  // Quota gate: search hits the same daily-cap + monthly budget. Optional
  // params let tests build the router without middleware.
  const dailyCap = enforceDailyCap || ((req, _res, next) => next());
  const pkgGate  = enforcePackage  || ((req, _res, next) => next());

  router.post('/', customerAuth, tenantLimiter, dailyCap, pkgGate, async (req, res) => {
    const t0 = Date.now();
    const request_id = newRequestId();
    const rawBody = req.body || {};

    // R-1: deterministic_hash over the raw request body. Same semantics
    // as /v1/process — proves cogos-api saw exactly what the caller
    // sent.
    const deterministic_hash = canonicalHash(rawBody);

    const query = typeof rawBody.query === 'string' ? rawBody.query : '';
    const maxResults = Number.isInteger(rawBody.max_results)
      ? Math.max(1, Math.min(20, rawBody.max_results))
      : 5;

    if (!query.trim()) {
      const ms = Date.now() - t0;
      try {
        usage.record({
          key_id: req.apiKey && req.apiKey.id,
          tenant_id: req.apiKey && req.apiKey.tenant_id,
          app_id: req.apiKey && req.apiKey.app_id,
          model: SEARCH_MODEL_ID_BRAVE,
          prompt_tokens: 0,
          completion_tokens: 0,
          latency_ms: ms,
          status: 'client_error',
          request_id,
          route: SEARCH_ROUTE,
        });
      } catch (recordErr) {
        logger.warn('[search] usage.record failed', { error: recordErr.message });
      }
      return res.status(400).json({
        error: {
          message: 'query is required',
          type: 'invalid_request_error',
          code: 'invalid_input',
        },
        receipt: { request_id, ms, deterministic_hash },
      });
    }

    let result;
    try {
      result = await client.search({ query, maxResults });
    } catch (e) {
      // search() catches its own upstream errors and returns ok:false;
      // we still wrap in case the client itself throws unexpectedly.
      const ms = Date.now() - t0;
      try {
        usage.record({
          key_id: req.apiKey && req.apiKey.id,
          tenant_id: req.apiKey && req.apiKey.tenant_id,
          app_id: req.apiKey && req.apiKey.app_id,
          model: SEARCH_MODEL_ID_BRAVE,
          prompt_tokens: 0,
          completion_tokens: 0,
          latency_ms: ms,
          status: 'server_error',
          request_id,
          route: SEARCH_ROUTE,
        });
      } catch (recordErr) {
        logger.warn('[search] usage.record failed', { error: recordErr.message });
      }
      return res.status(500).json({
        error: {
          message: e.message,
          type: 'internal_server_error',
          code: 'search_client_failure',
        },
        receipt: { request_id, ms, deterministic_hash },
      });
    }

    // Upstream-failure path (ok:false from client). We still record the
    // attempt so /v1/audit shows the customer tried and the substrate
    // hit a wall — silent dropping would mask provider outages.
    if (!result.ok) {
      const ms = Date.now() - t0;
      try {
        usage.record({
          key_id: req.apiKey && req.apiKey.id,
          tenant_id: req.apiKey && req.apiKey.tenant_id,
          app_id: req.apiKey && req.apiKey.app_id,
          model: SEARCH_MODEL_ID_BRAVE,
          prompt_tokens: 0,
          completion_tokens: 0,
          latency_ms: ms,
          status: 'server_error',
          request_id,
          route: SEARCH_ROUTE,
        });
      } catch (recordErr) {
        logger.warn('[search] usage.record failed', { error: recordErr.message });
      }
      return res.status(502).json({
        error: {
          message: result.message || 'search provider failed',
          type: 'bad_gateway',
          code: result.error || 'SEARCH_FAILED',
        },
        receipt: { request_id, ms, deterministic_hash },
      });
    }

    // Success path — including provider:'none' (BRAVE_SEARCH_API_KEY
    // unset). The substrate's honest "no provider configured, 0
    // results" is still a successful receipt-bearing attempt.
    const ms = Date.now() - t0;
    const modelId = result.provider === 'brave'
      ? SEARCH_MODEL_ID_BRAVE
      : SEARCH_MODEL_ID_NONE;

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
        route: SEARCH_ROUTE,
      });
    } catch (recordErr) {
      logger.warn('[search] usage.record failed', { error: recordErr.message });
    }

    // R-2: output_hash over the canonical RESPONSE payload — what was
    // returned at this moment. NOT a determinism guarantee for search
    // (see file-header doctrine block). Computed over results + provider
    // + query + latency_ms; request_id and ms are NOT in the hash so two
    // identical responses produce identical output_hashes.
    const payload = {
      query: result.query,
      provider: result.provider,
      results: result.results,
    };
    const output_hash = canonicalHash(payload);

    return res.status(200).json({
      ...payload,
      receipt: { request_id, ms, deterministic_hash, output_hash },
    });
  });

  return router;
}

module.exports = {
  makeSearchRouter,
  SEARCH_ROUTE,
  SEARCH_MODEL_ID_BRAVE,
  SEARCH_MODEL_ID_NONE,
  _internal: {
    newRequestId,
  },
};
