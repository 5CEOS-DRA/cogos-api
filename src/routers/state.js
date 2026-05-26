'use strict';

/**
 * /v1/state · per-key stateful substrate surface.
 *
 * Closes the last of the four years-ahead substrate engineering pieces
 * (Canon I11 lands when this ships). Customers can journal-in their
 * firm graph once, then run every subsequent conflict check against
 * stored state with hash-chained audit-grade integrity.
 *
 * Endpoints (all customerAuth + tenantLimiter gated):
 *   POST /v1/state/matters       · upsert matter (or list of matters)
 *   POST /v1/state/matters/:id/archive · archive matter
 *   POST /v1/state/parties       · upsert parties on a matter
 *   POST /v1/state/parties/remove · remove parties from a matter
 *   GET  /v1/state               · current materialized state
 *   GET  /v1/state/journal       · full hash-chained journal
 *
 * Billing: ONE usage row per mutation (writes are billable). GET is
 * free (catalog-grade discoverability).
 *
 * Receipt: every write returns
 *   {
 *     state_version, state_hash,
 *     row: { ts, mutation, payload, prev_hash, row_hash },
 *     receipt: { request_id, ms, deterministic_hash }
 *   }
 */

const express = require('express');
const crypto = require('crypto');
const logger = require('../logger');
const usage = require('../usage');
const { canonicalHash } = require('../processes/_canonicalize');
const { MUTATION_KIND } = require('../processes/_keyState');
const store = require('../key-state-store');

const STATE_ROUTE_PREFIX = '/v1/state';
const STATE_MODEL_ID = 'process:key-state-v1';

function newRequestId() {
  return 'state_' + crypto.randomBytes(16).toString('base64url');
}

function recordUsage({ req, request_id, route, latency_ms, status }) {
  try {
    usage.record({
      key_id: req.apiKey && req.apiKey.id,
      tenant_id: req.apiKey && req.apiKey.tenant_id,
      app_id: req.apiKey && req.apiKey.app_id,
      model: STATE_MODEL_ID,
      prompt_tokens: 0, completion_tokens: 0,
      latency_ms, status, request_id, route,
    });
  } catch (recordErr) {
    logger.warn('[state] usage.record failed', { error: recordErr.message });
  }
}

function tenantKey(req) {
  return {
    tenant_id: req.apiKey && req.apiKey.tenant_id,
    key_id: req.apiKey && req.apiKey.id,
  };
}

function makeStateRouter({ customerAuth, tenantLimiter }) {
  const router = express.Router();

  // ─── Write: matter.upsert (single or batch) ────────────────────
  router.post('/matters', customerAuth, tenantLimiter, (req, res) => {
    const t0 = Date.now();
    const request_id = newRequestId();
    const route = STATE_ROUTE_PREFIX + '/matters';
    const body = req.body || {};
    const deterministic_hash = canonicalHash(body);

    // Accept either { matter: {...} } or { matters: [...] }.
    const items = Array.isArray(body.matters) ? body.matters
                : body.matter ? [body.matter]
                : null;
    if (!items || items.length === 0) {
      const ms = Date.now() - t0;
      recordUsage({ req, request_id, route, latency_ms: ms, status: 'client_error' });
      return res.status(400).json({
        error: { message: 'body must include matter or matters[]', type: 'invalid_request_error', code: 'invalid_input' },
        receipt: { request_id, ms, deterministic_hash },
      });
    }

    const tk = tenantKey(req);
    const newRows = [];
    let lastState = null;
    try {
      for (const m of items) {
        const r = store.appendMutation({ ...tk, mutation: MUTATION_KIND.MATTER_UPSERT, payload: m });
        newRows.push(r.row);
        lastState = r.state;
      }
    } catch (e) {
      const ms = Date.now() - t0;
      recordUsage({ req, request_id, route, latency_ms: ms, status: 'server_error' });
      const status = e.code === 'JOURNAL_TAMPERED' ? 409 : 500;
      return res.status(status).json({
        error: { message: e.message, type: 'internal_server_error', code: e.code || 'state_failure' },
        receipt: { request_id, ms: Date.now() - t0, deterministic_hash },
      });
    }

    const ms = Date.now() - t0;
    recordUsage({ req, request_id, route, latency_ms: ms, status: 'success' });
    return res.status(200).json({
      state_version: lastState.state_version,
      state_hash:    lastState.state_hash,
      rows:          newRows,
      receipt:       { request_id, ms, deterministic_hash },
    });
  });

  // ─── Write: matter.archive ─────────────────────────────────────
  router.post('/matters/:id/archive', customerAuth, tenantLimiter, (req, res) => {
    const t0 = Date.now();
    const request_id = newRequestId();
    const route = STATE_ROUTE_PREFIX + '/matters/:id/archive';
    const body = { matter_id: req.params.id };
    const deterministic_hash = canonicalHash(body);

    if (!req.params.id) {
      const ms = Date.now() - t0;
      recordUsage({ req, request_id, route, latency_ms: ms, status: 'client_error' });
      return res.status(400).json({
        error: { message: 'matter id is required', type: 'invalid_request_error', code: 'invalid_input' },
        receipt: { request_id, ms, deterministic_hash },
      });
    }

    const tk = tenantKey(req);
    let r;
    try {
      r = store.appendMutation({ ...tk, mutation: MUTATION_KIND.MATTER_ARCHIVE, payload: { id: req.params.id } });
    } catch (e) {
      const ms = Date.now() - t0;
      recordUsage({ req, request_id, route, latency_ms: ms, status: 'server_error' });
      return res.status(e.code === 'JOURNAL_TAMPERED' ? 409 : 500).json({
        error: { message: e.message, type: 'internal_server_error', code: e.code || 'state_failure' },
        receipt: { request_id, ms, deterministic_hash },
      });
    }

    const ms = Date.now() - t0;
    recordUsage({ req, request_id, route, latency_ms: ms, status: 'success' });
    return res.status(200).json({
      state_version: r.state.state_version,
      state_hash:    r.state.state_hash,
      row:           r.row,
      receipt:       { request_id, ms, deterministic_hash },
    });
  });

  // ─── Write: parties.upsert ─────────────────────────────────────
  router.post('/parties', customerAuth, tenantLimiter, (req, res) => {
    const t0 = Date.now();
    const request_id = newRequestId();
    const route = STATE_ROUTE_PREFIX + '/parties';
    const body = req.body || {};
    const deterministic_hash = canonicalHash(body);

    if (!body.matter_id || !Array.isArray(body.parties) || body.parties.length === 0) {
      const ms = Date.now() - t0;
      recordUsage({ req, request_id, route, latency_ms: ms, status: 'client_error' });
      return res.status(400).json({
        error: { message: 'body must include matter_id + parties[]', type: 'invalid_request_error', code: 'invalid_input' },
        receipt: { request_id, ms, deterministic_hash },
      });
    }

    const tk = tenantKey(req);
    let r;
    try {
      r = store.appendMutation({ ...tk, mutation: MUTATION_KIND.PARTIES_UPSERT, payload: { matter_id: body.matter_id, parties: body.parties } });
    } catch (e) {
      const ms = Date.now() - t0;
      recordUsage({ req, request_id, route, latency_ms: ms, status: 'server_error' });
      const status = e.code === 'JOURNAL_TAMPERED' ? 409 : (/required|must/.test(e.message) ? 400 : 500);
      return res.status(status).json({
        error: { message: e.message, type: status === 400 ? 'invalid_request_error' : 'internal_server_error', code: e.code || (status === 400 ? 'invalid_input' : 'state_failure') },
        receipt: { request_id, ms, deterministic_hash },
      });
    }

    const ms = Date.now() - t0;
    recordUsage({ req, request_id, route, latency_ms: ms, status: 'success' });
    return res.status(200).json({
      state_version: r.state.state_version,
      state_hash:    r.state.state_hash,
      row:           r.row,
      receipt:       { request_id, ms, deterministic_hash },
    });
  });

  // ─── Write: parties.remove ─────────────────────────────────────
  router.post('/parties/remove', customerAuth, tenantLimiter, (req, res) => {
    const t0 = Date.now();
    const request_id = newRequestId();
    const route = STATE_ROUTE_PREFIX + '/parties/remove';
    const body = req.body || {};
    const deterministic_hash = canonicalHash(body);

    if (!body.matter_id || !Array.isArray(body.party_ids) || body.party_ids.length === 0) {
      const ms = Date.now() - t0;
      recordUsage({ req, request_id, route, latency_ms: ms, status: 'client_error' });
      return res.status(400).json({
        error: { message: 'body must include matter_id + party_ids[]', type: 'invalid_request_error', code: 'invalid_input' },
        receipt: { request_id, ms, deterministic_hash },
      });
    }

    const tk = tenantKey(req);
    let r;
    try {
      r = store.appendMutation({ ...tk, mutation: MUTATION_KIND.PARTIES_REMOVE, payload: { matter_id: body.matter_id, party_ids: body.party_ids } });
    } catch (e) {
      const ms = Date.now() - t0;
      recordUsage({ req, request_id, route, latency_ms: ms, status: 'server_error' });
      return res.status(e.code === 'JOURNAL_TAMPERED' ? 409 : 500).json({
        error: { message: e.message, type: 'internal_server_error', code: e.code || 'state_failure' },
        receipt: { request_id, ms, deterministic_hash },
      });
    }

    const ms = Date.now() - t0;
    recordUsage({ req, request_id, route, latency_ms: ms, status: 'success' });
    return res.status(200).json({
      state_version: r.state.state_version,
      state_hash:    r.state.state_hash,
      row:           r.row,
      receipt:       { request_id, ms, deterministic_hash },
    });
  });

  // ─── Read: current state (materialized) ─────────────────────────
  router.get('/', customerAuth, tenantLimiter, (req, res) => {
    const t0 = Date.now();
    const request_id = newRequestId();
    const tk = tenantKey(req);
    let snap;
    try {
      snap = store.currentState(tk);
    } catch (e) {
      const ms = Date.now() - t0;
      recordUsage({ req, request_id, route: STATE_ROUTE_PREFIX, latency_ms: ms, status: 'server_error' });
      return res.status(500).json({ error: { message: e.message, type: 'internal_server_error' } });
    }
    const ms = Date.now() - t0;
    // Reads are free · no usage row.
    return res.status(200).json({
      state_version: snap.state.state_version,
      state_hash:    snap.state.state_hash,
      matters:       snap.state.matters,
      parties:       snap.state.parties,
      anchor:        snap.anchor,
      receipt:       { request_id, ms },
    });
  });

  // ─── Read: full journal (hash-chained) ──────────────────────────
  router.get('/journal', customerAuth, tenantLimiter, (req, res) => {
    const t0 = Date.now();
    const request_id = newRequestId();
    const tk = tenantKey(req);
    let j;
    try {
      j = store.currentJournal(tk);
    } catch (e) {
      const ms = Date.now() - t0;
      return res.status(500).json({ error: { message: e.message, type: 'internal_server_error' } });
    }
    const ms = Date.now() - t0;
    return res.status(200).json({
      anchor: j.anchor,
      rows:   j.rows,
      receipt: { request_id, ms },
    });
  });

  return router;
}

module.exports = {
  makeStateRouter,
  STATE_ROUTE_PREFIX,
  STATE_MODEL_ID,
};
