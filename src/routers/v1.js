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
const { proxyToPlatform } = require('../internal-trust');

function makeV1Router({
  customerAuth, tenantLimiter,
  handleListModels, handleChatCompletions,
  enforceDailyCap, enforcePackage,
}) {
  const router = express.Router();

  router.get('/models', customerAuth, tenantLimiter, handleListModels);

  // GET /v1/me — identity probe.
  //
  // Per Phase 4 acceptance criterion D: returns the caller's identity
  // shape including tenant_type ('subscriber' | 'operator'). Used by
  // CLI startup + `cogos doctor` identity probe so capability matrix
  // populates per role.
  //
  // No state change; no chain row. Cache-Control: no-store because
  // rotation/quarantine state can shift mid-session.
  router.get('/me', customerAuth, tenantLimiter, (req, res) => {
    const k = req.apiKey || {};
    res.set('Cache-Control', 'no-store');
    res.json({
      ok: true,
      tenant_id: k.tenant_id,
      tenant_type: k.tenant_type || 'subscriber',
      key_id: k.id,
      app_id: k.app_id,
      tier: k.tier,
      scheme: k.scheme,
      issued_at: k.issued_at,
      expires_at: k.expires_at,
      active: k.active !== false,
      rotation_grace: k._rotation_grace === true,
    });
  });
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

  // GET /v1/viewports[?app=&status=]
  // GET /v1/viewports/:id
  // GET /v1/viewports/:id/rows
  //
  // Zone B viewport read surface. Each proxies to platform's
  // /api/internal/viewports{,/:id,/:id/rows} with
  // ?tenant=<req.apiKey.tenant_id> injected in the signed canonical
  // path. Tenant tampering breaks the HMAC; platform additionally
  // applies tenant scoping in WHERE clauses + RLS as defense-in-depth.
  //
  // Per Phase 2 acceptance criteria D (commands) + H (cross-tenant 404).
  function proxyViewportRead(internalPath) {
    return async (req, res) => {
      const tenantId = req.apiKey && req.apiKey.tenant_id;
      if (!tenantId) {
        return res.status(401).json({
          ok: false, error: { message: 'tenant context missing', type: 'auth_error' },
        });
      }
      const qsExtra = Object.entries(req.query || {})
        .filter(([k]) => k !== 'tenant')
        .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
        .join('&');
      const path = `/api/internal${internalPath}?tenant=${encodeURIComponent(tenantId)}${qsExtra ? '&' + qsExtra : ''}`;
      try {
        const r = await proxyToPlatform({ method: 'GET', path });
        // Forward Cache-Control header if platform set one
        const cacheControl = r.headers && (r.headers['cache-control'] || r.headers['Cache-Control']);
        if (cacheControl) res.set('Cache-Control', cacheControl);
        res.status(r.status).json(r.body);
      } catch (e) {
        logger.warn('viewport_proxy_failed', { path, error: e.message });
        res.status(503).json({
          ok: false,
          error: { message: 'viewport surface temporarily unavailable', type: 'upstream_unavailable' },
        });
      }
    };
  }

  // POST /v1/apps/build · subscriber app push.
  // GET  /v1/apps/build/:id · build status poll.
  //
  // Push is a state-changing write — chain row appended on success and
  // chain_head_after returned. Status is read-only and doesn't chain.
  //
  // Per Phase 2 acceptance criteria D (commands) + G (receipt arc
  // anchoring on state change).
  function slugifyAppName(name) {
    return String(name || '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '_')
      .replace(/^_|_$/g, '');
  }

  router.post('/apps/build', customerAuth, tenantLimiter, async (req, res) => {
    const tenantId = req.apiKey && req.apiKey.tenant_id;
    if (!tenantId) {
      return res.status(401).json({
        ok: false, error: { message: 'tenant context missing', type: 'auth_error' },
      });
    }

    const blueprint = req.body && req.body.blueprint;
    if (!blueprint || typeof blueprint !== 'object') {
      return res.status(400).json({
        ok: false, error: { message: 'request body must include a `blueprint` object', type: 'invalid_request_error' },
      });
    }

    const appId = slugifyAppName(blueprint.name) || '_default';

    let r;
    try {
      r = await proxyToPlatform({
        method: 'POST',
        path: `/api/internal/apps/build?tenant=${encodeURIComponent(tenantId)}`,
        bodyJson: { blueprint },
      });
    } catch (e) {
      logger.warn('app_push_proxy_failed', { error: e.message });
      return res.status(503).json({
        ok: false, error: { message: 'build service temporarily unavailable', type: 'upstream_unavailable' },
      });
    }

    const isSuccess = r.status >= 200 && r.status < 300;
    if (isSuccess) {
      const chainHead = usage.record({
        key_id: req.apiKey.id,
        tenant_id: tenantId,
        app_id: appId,
        route: 'POST /v1/apps/build',
        status: 'success',
      });
      const body = (r.body && typeof r.body === 'object') ? { ...r.body } : {};
      body.chain_head_after = chainHead;
      return res.status(r.status).set('Cache-Control', 'no-store').json(body);
    }
    // Non-success: forward platform response shape as-is (validation
    // diagnostics, 503 upstream_unavailable, etc.). No chain row —
    // matches the admin.js Phase 1 pattern.
    return res.status(r.status).set('Cache-Control', 'no-store').json(r.body || { ok: false });
  });

  router.get('/apps/build/:id', customerAuth, tenantLimiter, async (req, res) => {
    const tenantId = req.apiKey && req.apiKey.tenant_id;
    if (!tenantId) {
      return res.status(401).json({
        ok: false, error: { message: 'tenant context missing', type: 'auth_error' },
      });
    }
    const path = `/api/internal/apps/build/${encodeURIComponent(req.params.id)}?tenant=${encodeURIComponent(tenantId)}`;
    try {
      const r = await proxyToPlatform({ method: 'GET', path });
      const cacheControl = r.headers && (r.headers['cache-control'] || r.headers['Cache-Control']);
      if (cacheControl) res.set('Cache-Control', cacheControl);
      res.status(r.status).json(r.body);
    } catch (e) {
      logger.warn('app_status_proxy_failed', { error: e.message });
      res.status(503).json({
        ok: false, error: { message: 'build status temporarily unavailable', type: 'upstream_unavailable' },
      });
    }
  });

  router.get('/viewports', customerAuth, tenantLimiter,
    proxyViewportRead('/viewports'));
  router.get('/viewports/:id', customerAuth, tenantLimiter,
    (req, res) => proxyViewportRead(`/viewports/${encodeURIComponent(req.params.id)}`)(req, res));
  router.get('/viewports/:id/rows', customerAuth, tenantLimiter,
    (req, res) => proxyViewportRead(`/viewports/${encodeURIComponent(req.params.id)}/rows`)(req, res));

  // ── Zone C mutation surface (charter v0.2 + Phase 3 criteria F + H) ─
  //
  // POST   /v1/viewports/:vid/sections/:section/rows                  · add
  // PUT    /v1/viewports/:vid/sections/:section/rows/:row_id          · update
  // DELETE /v1/viewports/:vid/sections/:section/rows/:row_id          · delete
  // POST   /v1/viewports/:vid/sections/:section/rows/import           · bulk
  //
  // Each proxies to platform /api/internal/viewports/... with the
  // tenant slug injected. On 2xx success: appends a per-(tenant, app)
  // mutation chain row via usage.record({mutation_type, viewport_id,
  // section_id, row_version_before, row_version_after}) and returns
  // chain_head_after in the response body. Per C-14 + criterion H.
  //
  // No chain row on non-2xx (matches Phase 1 admin + Phase 2 app push
  // patterns — audit chain records successful state changes; failures
  // surface to subscriber via the response and don't pollute the chain).

  function recordZoneCMutation(req, mutationType, body, platformResp) {
    const tenantId = req.apiKey && req.apiKey.tenant_id;
    const appId = (platformResp && platformResp.app_name) || '_default';
    const viewportId = platformResp && platformResp.viewport_id;
    const sectionId = platformResp && platformResp.section_id;
    // For 'add': row_version_before = null (genesis row entry).
    // For 'update': platform doesn't return both versions in body; we
    //               parse from request body's expected_version + response's
    //               new row_version.
    // For 'delete': row_version_after = null.
    // For 'import': single chain row per batch; both versions null —
    //               batch_summary in metadata.
    let rowVersionBefore = null;
    let rowVersionAfter = null;
    if (mutationType === 'add') {
      rowVersionAfter = platformResp && platformResp.row_version;
    } else if (mutationType === 'update') {
      rowVersionBefore = body && body.expected_version;
      rowVersionAfter = platformResp && platformResp.row_version;
    } else if (mutationType === 'delete') {
      // expected_version came in via query; req.query.expected_version
      rowVersionBefore = req.query && req.query.expected_version;
    }
    return usage.record({
      key_id: req.apiKey.id,
      tenant_id: tenantId,
      app_id: appId,
      route: `${req.method} ${req.route?.path || req.path}`,
      status: 'success',
      mutation_type: mutationType,
      viewport_id: viewportId,
      section_id: sectionId,
      row_version_before: rowVersionBefore,
      row_version_after: rowVersionAfter,
    });
  }

  function proxyZoneCWrite({ method, internalPath, mutationType, queryExtra }) {
    return async (req, res) => {
      const tenantId = req.apiKey && req.apiKey.tenant_id;
      if (!tenantId) {
        return res.status(401).json({
          ok: false, error: { message: 'tenant context missing', type: 'auth_error' },
        });
      }
      const params = [`tenant=${encodeURIComponent(tenantId)}`];
      if (queryExtra) params.push(queryExtra);
      // Strip client-supplied ?tenant from query, forward other params
      for (const [k, v] of Object.entries(req.query || {})) {
        if (k === 'tenant') continue;
        params.push(`${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`);
      }
      const path = `/api/internal${internalPath}?${params.join('&')}`;
      try {
        const r = await proxyToPlatform({
          method,
          path,
          bodyJson: req.body,
        });
        const isSuccess = r.status >= 200 && r.status < 300;
        if (isSuccess) {
          const chainHead = recordZoneCMutation(req, mutationType, req.body, r.body || {});
          const body = (r.body && typeof r.body === 'object') ? { ...r.body } : {};
          body.chain_head_after = chainHead;
          return res.status(r.status).set('Cache-Control', 'no-store').json(body);
        }
        return res.status(r.status).set('Cache-Control', 'no-store').json(r.body || { ok: false });
      } catch (e) {
        logger.warn('zone_c_proxy_failed', { path, error: e.message });
        return res.status(503).json({
          ok: false, error: { message: 'row mutation temporarily unavailable', type: 'upstream_unavailable' },
        });
      }
    };
  }

  router.post('/viewports/:vid/sections/:section/rows',
    customerAuth, tenantLimiter,
    (req, res) => proxyZoneCWrite({
      method: 'POST',
      internalPath: `/viewports/${encodeURIComponent(req.params.vid)}/sections/${encodeURIComponent(req.params.section)}/rows`,
      mutationType: 'add',
    })(req, res));

  router.put('/viewports/:vid/sections/:section/rows/:row_id',
    customerAuth, tenantLimiter,
    (req, res) => proxyZoneCWrite({
      method: 'PUT',
      internalPath: `/viewports/${encodeURIComponent(req.params.vid)}/sections/${encodeURIComponent(req.params.section)}/rows/${encodeURIComponent(req.params.row_id)}`,
      mutationType: 'update',
    })(req, res));

  router.delete('/viewports/:vid/sections/:section/rows/:row_id',
    customerAuth, tenantLimiter,
    (req, res) => proxyZoneCWrite({
      method: 'DELETE',
      internalPath: `/viewports/${encodeURIComponent(req.params.vid)}/sections/${encodeURIComponent(req.params.section)}/rows/${encodeURIComponent(req.params.row_id)}`,
      mutationType: 'delete',
    })(req, res));

  router.post('/viewports/:vid/sections/:section/rows/import',
    customerAuth, tenantLimiter,
    (req, res) => proxyZoneCWrite({
      method: 'POST',
      internalPath: `/viewports/${encodeURIComponent(req.params.vid)}/sections/${encodeURIComponent(req.params.section)}/rows/import`,
      mutationType: 'import',
    })(req, res));

  // GET /v1/intents — primitive catalog · Zone B subscriber surface.
  //
  // Validates sk-cogos-* via customerAuth, then proxies to platform
  // /api/internal/intents over the HMAC b-3 trust hop. Forwards the
  // platform's catalog response as-is. Platform sets Cache-Control:
  // max-age=300; we preserve that on the way out.
  //
  // Per project_cli_phase_2_acceptance_criteria_v0_1_2026_05_27 D
  // + project_cli_zone_b_artifact_doctrine_2026_05_27.
  router.get('/intents', customerAuth, tenantLimiter, async (_req, res) => {
    try {
      const r = await proxyToPlatform({
        method: 'GET',
        path: '/api/internal/intents',
      });
      // 503 upstream_unavailable comes from the proxy when the trust hop
      // itself fails (HMAC misconfig / sig invalid) — surface as-is so the
      // CLI can show a clean retry message instead of leaking HMAC details.
      res.status(r.status).set('Cache-Control', 'max-age=300').json(r.body);
    } catch (e) {
      logger.warn('intents_proxy_failed', { error: e.message });
      res.status(503).json({
        ok: false,
        error: { message: 'primitive catalog temporarily unavailable', type: 'upstream_unavailable' },
      });
    }
  });

  return router;
}

module.exports = { makeV1Router };
