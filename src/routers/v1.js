'use strict';

// /v1/* customer-auth surface — extracted from src/index.js.
//
// customerAuth = ed25519-first, bearer-fallback. Either scheme attaches
// req.apiKey on success; chained handlers read req.apiKey.tenant_id
// without caring which substrate authenticated the request.
//
// tenantLimiter runs AFTER customerAuth so req.apiKey.tenant_id is
// populated. Default 1000 req/min/tenant — generous for real workloads,
// tight enough that a leaked key can't single-handedly fill the
// inference queue. Per-IP limit already absorbed the anonymous-flood
// case upstream in src/index.js.

const express = require('express');
const logger = require('../logger');
const keys = require('../keys');
const usage = require('../usage');

function makeV1Router({
  customerAuth, tenantLimiter,
  handleListModels, handleChatCompletions,
  enforceDailyCap, enforcePackage,
}) {
  const router = express.Router();

  router.get('/models', customerAuth, tenantLimiter, handleListModels);
  router.post(
    '/chat/completions',
    customerAuth, tenantLimiter,
    enforceDailyCap, enforcePackage,
    handleChatCompletions,
  );

  // Customer-facing audit query (Security Hardening Card #3).
  // Returns the requesting tenant's hash-chained usage rows. Strictly
  // tenant-scoped via req.apiKey.tenant_id — customer A can never see
  // customer B's rows. chain_ok is the server-side verifyChain() result
  // on the returned slice; customers re-run verification locally for
  // independent assurance.
  router.get('/audit', customerAuth, tenantLimiter, (req, res) => {
    const sinceMs = Number(req.query.since || 0);
    const limitRaw = Number(req.query.limit || 100);
    if (!Number.isFinite(sinceMs) || sinceMs < 0) {
      return res.status(400).json({
        error: { message: '`since` must be a non-negative unix-ms integer', type: 'invalid_request_error' },
      });
    }
    if (!Number.isFinite(limitRaw) || limitRaw < 0) {
      return res.status(400).json({
        error: { message: '`limit` must be a non-negative integer', type: 'invalid_request_error' },
      });
    }
    const limit = Math.min(1000, Math.max(0, Math.floor(limitRaw)));
    const tenantId = req.apiKey && req.apiKey.tenant_id;
    // app_id query param scopes the slice to a single app's chain. When
    // omitted, response is the interleaved cross-app view for the whole
    // tenant — chain_ok is computed per-app and surfaced as
    // chain_ok_by_app so the caller can verify each app independently.
    // Invalid app_id → 400 (don't 200 with empty rows because that would
    // silently hide a typo).
    const rawAppId = req.query.app_id;
    let scopedAppId = null;
    if (rawAppId != null && rawAppId !== '') {
      try {
        scopedAppId = keys.normalizeAppId(rawAppId);
      } catch (e) {
        return res.status(400).json({
          error: { message: e.message, type: 'invalid_request_error' },
        });
      }
    }

    const rows = usage.readSlice({
      tenant_id: tenantId,
      app_id: scopedAppId,
      since: sinceMs,
      limit,
    });

    // Chain verification:
    //   scoped (single app)  → one chain check on the rows as returned.
    //   cross-app (no scope) → per-app verification. The interleaved
    //                          order is what the customer asked for;
    //                          chain integrity is proved by re-grouping
    //                          per app under the hood.
    // chain_ok is the AND of every app's per-chain result (cross-app)
    // or the single chain's result (scoped) — keeps the legacy boolean
    // useful for "should I trust this slice" wire checks.
    let chainOk;
    let chainBreak = null;
    let chainOkByApp = null;
    if (scopedAppId !== null) {
      const single = usage.verifyChain(rows);
      chainOk = single.ok;
      if (!single.ok) {
        chainBreak = {
          broke_at_index: single.broke_at_index,
          reason: single.reason,
        };
      }
      chainOkByApp = { [scopedAppId]: single.ok };
    } else {
      const perApp = usage.verifyByApp(rows);
      chainOkByApp = {};
      let firstBreak = null;
      for (const [app, result] of Object.entries(perApp)) {
        chainOkByApp[app] = result.ok;
        if (!result.ok && firstBreak === null) {
          firstBreak = {
            app_id: app,
            broke_at_index: result.broke_at_index,
            reason: result.reason,
          };
        }
      }
      chainOk = Object.values(chainOkByApp).every(Boolean);
      if (!chainOk) chainBreak = firstBreak;
    }
    // next_cursor = ts (ms) of the last returned row so the caller can
    // page forward by passing it back as `since`. Null when no rows
    // returned OR slice didn't fill `limit` (no more rows to fetch).
    let nextCursor = null;
    if (rows.length === limit && rows.length > 0) {
      const lastTs = Date.parse(rows[rows.length - 1].ts);
      if (Number.isFinite(lastTs)) nextCursor = lastTs;
    }
    res.json({
      rows,
      next_cursor: nextCursor,
      chain_ok: chainOk,
      chain_break: chainBreak,
      chain_ok_by_app: chainOkByApp,
      app_id: scopedAppId,
      server_time_ms: Date.now(),
    });
  });

  // Customer-driven rotation. Caller MUST succeed authentication with
  // their CURRENT key. We issue a new key of the same scheme inheriting
  // tenant_id / app_id / tier / package_id and CRUCIALLY the parent's
  // expires_at (rotation != renewal). Old record gets a 24h
  // rotation_grace_until stamp; during the grace window both keys
  // authenticate and the old key's responses carry X-Cogos-Key-Deprecated.
  // After grace, verify() auto-revokes the old record on next touch.
  router.post('/keys/rotate', customerAuth, tenantLimiter, (req, res) => {
    try {
      const issued = keys.rotate(req.apiKey);
      const {
        plaintext, hmac_secret, private_pem, pubkey_pem, ed25519_key_id,
        x25519_private_pem, x25519_pubkey_pem, record,
        rotation_grace_until_iso, rotated_from_key_id,
      } = issued;
      logger.info('key_rotated', {
        old_id: rotated_from_key_id,
        new_id: record.id,
        tenant_id: record.tenant_id,
        app_id: record.app_id,
        scheme: record.scheme,
      });
      const response = {
        key_id: record.id,
        tenant_id: record.tenant_id,
        app_id: record.app_id,
        tier: record.tier,
        scheme: record.scheme,
        issued_at: record.issued_at,
        expires_at: record.expires_at,
        rotated_from_key_id,
        rotation_grace_until: rotation_grace_until_iso,
        hmac_secret,
        warning: `Old key remains valid until ${rotation_grace_until_iso}; `
          + 'switch your client to the new key before then. Save the new '
          + 'material now — it will not be shown again.',
      };
      if (record.scheme === 'bearer') {
        response.api_key = plaintext;
      } else {
        response.ed25519_key_id = ed25519_key_id;
        response.private_pem = private_pem;
        response.pubkey_pem = pubkey_pem;
        response.x25519_private_pem = x25519_private_pem;
        response.x25519_pubkey_pem = x25519_pubkey_pem;
      }
      res.status(201).json(response);
    } catch (e) {
      logger.warn('key_rotate_failed', {
        caller_id: req.apiKey && req.apiKey.id,
        error: e.message,
      });
      res.status(400).json({
        error: { message: e.message, type: 'rotation_failed' },
      });
    }
  });

  return router;
}

module.exports = { makeV1Router };
