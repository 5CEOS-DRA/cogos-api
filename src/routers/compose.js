'use strict';

/**
 * /v1/compose · multi-step deterministic workflow surface.
 *
 * v0.1 of process composition (Canon I9 lands when this ships). The
 * caller supplies a steps[] array, each step naming a registered
 * process and its args (optionally referencing prior step output).
 * The substrate runs each step deterministically, links every output
 * into a Merkle-style chain anchored to the workflow definition, and
 * returns a single compose_hash that commits to the entire workflow.
 *
 * Auth: same customerAuth + tenantLimiter pattern as /v1/process/*.
 * Billing: ONE usage row per composition (not per step). The model_id
 * is `process:compose-v1`; the route is `/v1/compose`. Customers pay
 * for the composition; step-level audit lives in the response body's
 * chain[] array (verifiable client-side).
 *
 * Request body shape:
 *   {
 *     steps: [
 *       { name: 'iolta-reconcile', args: { ... } },
 *       { name: '5law-conflict-check',
 *         args: { target_matter: {...}, target_parties: [...] },
 *         refs: { firm_matters: { from_step: 0, path: 'some.path' } }
 *       }
 *     ]
 *   }
 *
 * Response body shape:
 *   {
 *     composition_version: 1,
 *     workflow_hash: 'sha256:...',
 *     results: [step0_result, step1_result, ...],
 *     chain: [
 *       { step, name, output_hash, prev_chain_hash, chain_hash }
 *     ],
 *     compose_hash: 'sha256:...',
 *     receipt: { request_id, ms, deterministic_hash }
 *   }
 *
 * Where:
 *   - workflow_hash is the canonical hash of the steps[] declaration;
 *     mutating any step propagates through the entire chain.
 *   - compose_hash is the final chain_hash; the end-to-end commitment.
 *   - deterministic_hash on the receipt is sha256(canonical input
 *     body), per the universal receipt invariant.
 */

const express = require('express');
const crypto = require('crypto');
const logger = require('../logger');
const usage = require('../usage');
const { canonicalHash } = require('../processes/_canonicalize');
const { compose } = require('../processes/_compose');
const { runStep, REGISTRY } = require('../processes/_registry');

const COMPOSE_ROUTE = '/v1/compose';
const COMPOSE_MODEL_ID = 'process:compose-v1';

function newRequestId() {
  return 'comp_' + crypto.randomBytes(16).toString('base64url');
}

function makeComposeRouter({ customerAuth, tenantLimiter }) {
  const router = express.Router();

  router.post('/', customerAuth, tenantLimiter, async (req, res) => {
    const t0 = Date.now();
    const request_id = newRequestId();
    const body = req.body || {};

    // Input hash · proves cogos-api received exactly what was sent.
    const deterministic_hash = canonicalHash(body);

    if (!body || !Array.isArray(body.steps)) {
      const ms = Date.now() - t0;
      try {
        usage.record({
          key_id: req.apiKey && req.apiKey.id,
          tenant_id: req.apiKey && req.apiKey.tenant_id,
          app_id: req.apiKey && req.apiKey.app_id,
          model: COMPOSE_MODEL_ID,
          prompt_tokens: 0, completion_tokens: 0,
          latency_ms: ms, status: 'client_error',
          request_id, route: COMPOSE_ROUTE,
        });
      } catch (_) {}
      return res.status(400).json({
        error: {
          message: 'request body must include a steps[] array',
          type: 'invalid_request_error',
          code: 'invalid_input',
        },
        receipt: { request_id, ms, deterministic_hash },
      });
    }

    let result;
    try {
      result = await compose(body.steps, runStep);
    } catch (e) {
      const ms = Date.now() - t0;
      const isUserError = e instanceof TypeError || /unknown process|out of range|must be|step \d+/.test(e.message);
      const status = isUserError ? 400 : 500;
      try {
        usage.record({
          key_id: req.apiKey && req.apiKey.id,
          tenant_id: req.apiKey && req.apiKey.tenant_id,
          app_id: req.apiKey && req.apiKey.app_id,
          model: COMPOSE_MODEL_ID,
          prompt_tokens: 0, completion_tokens: 0,
          latency_ms: ms,
          status: isUserError ? 'client_error' : 'server_error',
          request_id, route: COMPOSE_ROUTE,
        });
      } catch (recordErr) {
        logger.warn('[compose] usage.record failed', { error: recordErr.message });
      }
      // Partial chain rides along when compose() failed mid-workflow ·
      // customers can still verify what completed before the failure.
      const payload = {
        error: {
          message: e.message,
          type: isUserError ? 'invalid_request_error' : 'internal_server_error',
          code: isUserError ? 'invalid_input' : 'compose_failure',
          failed_step: e.failed_step,
          failed_step_name: e.failed_step_name,
        },
        partial_chain: e.partial_chain || [],
        partial_results: e.partial_results || [],
        receipt: { request_id, ms, deterministic_hash },
      };
      return res.status(status).json(payload);
    }

    const ms = Date.now() - t0;
    try {
      usage.record({
        key_id: req.apiKey && req.apiKey.id,
        tenant_id: req.apiKey && req.apiKey.tenant_id,
        app_id: req.apiKey && req.apiKey.app_id,
        model: COMPOSE_MODEL_ID,
        prompt_tokens: 0, completion_tokens: 0,
        latency_ms: ms, status: 'success',
        request_id, route: COMPOSE_ROUTE,
      });
    } catch (recordErr) {
      logger.warn('[compose] usage.record failed', { error: recordErr.message });
    }

    return res.status(200).json({
      ...result,
      receipt: { request_id, ms, deterministic_hash },
    });
  });

  // GET /v1/compose — discoverability: name what's composable. The
  // composer is engine-agnostic; what's callable is exactly what the
  // process registry exposes.
  router.get('/', (req, res) => {
    res.json({
      composition_version: 1,
      endpoint: COMPOSE_ROUTE,
      method: 'POST',
      composable_processes: Object.keys(REGISTRY),
      description: 'Linear-sequence composition of registered processes. Each step\'s output can be referenced by later steps via refs: { argKey: { from_step, path } }. Returns a Merkle-style chain anchored to the workflow definition, with a single compose_hash committing to the whole workflow.',
    });
  });

  return router;
}

module.exports = {
  makeComposeRouter,
  COMPOSE_ROUTE,
  COMPOSE_MODEL_ID,
};
