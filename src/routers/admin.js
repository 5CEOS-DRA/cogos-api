'use strict';

// /admin/* operator surface — extracted from src/index.js.
//
// All routes are X-Admin-Key gated via adminAuth (passed in by factory).
// Per-IP /admin/* rate limit (30/min, mounted upstream in src/index.js)
// still applies — these endpoints are not bypassable from the wire.
//
// /admin/analytics/* lives in a sibling router (src/routers/admin-
// analytics.js); /admin/health/deep stays here because it cross-reads
// the audit-checkpoint substrate + usage.jsonl tail + rate-limits.jsonl
// + anomalies.jsonl and is closer to the keys/packages/soc2 surface
// in spirit.

const express = require('express');
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');

const logger = require('../logger');
const keys = require('../keys');
const usage = require('../usage');
const packages = require('../packages');
const soc2 = require('../soc2');
const notifySignup = require('../notify-signup');
const auditCheckpoint = require('../audit-checkpoint');

// Repo root for the deep-health endpoint's default JSONL paths.
// __dirname is .../src/routers when this file is required, so the
// data dir is two levels up.
const REPO_ROOT = path.join(__dirname, '..', '..');

function makeAdminRouter({ adminAuth }) {
  const router = express.Router();

  // ---- Notify signups (operator-only list) ----
  router.get('/notify-signups', adminAuth, (_req, res) => {
    res.json({ signups: notifySignup.list() });
  });

  // ---- Keys: issuance + listing ----
  // TODO(week-1-finisher): these routes are slated for removal once
  // the offline admin ceremony lands. See scripts/admin-ceremony/
  // README.md for the migration target.
  //
  // `scheme` selects the customer-auth substrate:
  //   - 'bearer' (default): legacy hash-of-plaintext. We store
  //     sha256(key); customer holds the plaintext (sk-cogos-*).
  //   - 'ed25519':  we generate the keypair, return the private PEM
  //     ONCE, persist only the public PEM + a stable keyId. No
  //     reusable customer auth material at rest on our side.
  router.post('/keys', adminAuth, (req, res) => {
    const {
      tenant_id, app_id, label, tier, scheme, expires_at_iso,
    } = req.body || {};
    if (!tenant_id) {
      return res.status(400).json({ error: { message: 'tenant_id required' } });
    }
    const requestedScheme = scheme || 'bearer';
    if (requestedScheme !== 'bearer' && requestedScheme !== 'ed25519') {
      return res.status(400).json({
        error: { message: `scheme must be 'bearer' or 'ed25519', got '${requestedScheme}'` },
      });
    }
    let issued;
    try {
      issued = keys.issue({
        tenantId: tenant_id,
        app_id,
        label,
        tier,
        scheme: requestedScheme,
        expires_at_iso: expires_at_iso || null,
      });
    } catch (e) {
      return res.status(400).json({ error: { message: e.message } });
    }
    const {
      plaintext, hmac_secret, private_pem, pubkey_pem, ed25519_key_id,
      x25519_private_pem, x25519_pubkey_pem, record,
    } = issued;
    logger.info('key_issued', {
      id: record.id, tenant_id, app_id: record.app_id, tier, scheme: requestedScheme,
    });

    const response = {
      key_id: record.id,
      tenant_id: record.tenant_id,
      app_id: record.app_id,
      tier: record.tier,
      scheme: requestedScheme,
      issued_at: record.issued_at,
      expires_at: record.expires_at,
      hmac_secret,
      warning: 'Save this key + hmac_secret now. They will not be shown again.',
    };
    if (requestedScheme === 'bearer') {
      response.api_key = plaintext;
    } else {
      response.ed25519_key_id = ed25519_key_id;
      response.private_pem = private_pem;
      response.pubkey_pem = pubkey_pem;
      response.x25519_private_pem = x25519_private_pem;
      response.x25519_pubkey_pem = x25519_pubkey_pem;
      response.warning = 'Save api material now. private_pem (auth) '
        + 'and x25519_private_pem (audit decryption) will not be shown '
        + 'again — they are NOT stored server-side.';
    }
    res.status(201).json(response);
  });

  router.get('/keys', adminAuth, (_req, res) => {
    res.json({ keys: keys.list() });
  });

  router.post('/keys/:id/revoke', adminAuth, (req, res) => {
    const ok = keys.revoke(req.params.id);
    if (!ok) return res.status(404).json({ error: { message: 'Key not found' } });
    logger.info('key_revoked', { id: req.params.id });
    res.json({ revoked: true, key_id: req.params.id });
  });

  // ---- Quarantine surfaces ----
  router.get('/keys/quarantined', adminAuth, (_req, res) => {
    res.json({ keys: keys.listQuarantined() });
  });

  router.post('/keys/:id/clear-quarantine', adminAuth, (req, res) => {
    const id = req.params.id;
    const found = keys.findById(id);
    if (!found) return res.status(404).json({ error: { message: 'Key not found' } });
    if (!found.quarantined_at) {
      return res.status(409).json({
        error: { message: 'Key is not currently quarantined' },
      });
    }
    const ok = keys.clearQuarantine(id);
    if (!ok) {
      return res.status(500).json({ error: { message: 'clearQuarantine failed unexpectedly' } });
    }
    logger.info('key_quarantine_cleared', { id });
    res.json({ cleared: true, key_id: id });
  });

  // ---- Usage log (?since=<unix-ms>) ----
  router.get('/usage', adminAuth, (req, res) => {
    const sinceMs = Number(req.query.since || 0);
    const all = usage.readAll();
    const filtered = sinceMs > 0
      ? all.filter((u) => new Date(u.ts).getTime() > sinceMs)
      : all;
    res.json({
      usage: filtered,
      total_count: all.length,
      filtered_count: filtered.length,
      server_time_ms: Date.now(),
    });
  });

  // ---- Packages CRUD ----
  router.get('/packages', adminAuth, (req, res) => {
    const includeInactive = req.query.include_inactive === '1';
    res.json({ packages: packages.list({ includeInactive }) });
  });

  router.post('/packages', adminAuth, async (req, res) => {
    try {
      const pkg = await packages.create(req.body || {});
      res.status(201).json({ package: pkg });
    } catch (e) {
      const status = e.code === 'duplicate_id' ? 409
        : e.code === 'validation_failed' ? 400 : 500;
      logger.warn('admin_packages_create_failed', { error: e.message, status });
      res.status(status).json({
        error: { message: e.message, type: e.code || 'create_failed', errors: e.errors },
      });
    }
  });

  router.put('/packages/:id', adminAuth, async (req, res) => {
    try {
      const pkg = await packages.update(req.params.id, req.body || {});
      res.json({ package: pkg });
    } catch (e) {
      const status = e.code === 'not_found' ? 404
        : e.code === 'validation_failed' ? 400 : 500;
      logger.warn('admin_packages_update_failed', { id: req.params.id, error: e.message, status });
      res.status(status).json({
        error: { message: e.message, type: e.code || 'update_failed', errors: e.errors },
      });
    }
  });

  router.delete('/packages/:id', adminAuth, async (req, res) => {
    try {
      const ok = await packages.softDelete(req.params.id);
      if (!ok) return res.status(404).json({ error: { message: 'Package not found' } });
      res.json({ deactivated: true, id: req.params.id });
    } catch (e) {
      const status = e.code === 'is_default' ? 409 : 500;
      logger.warn('admin_packages_delete_failed', { id: req.params.id, error: e.message });
      res.status(status).json({
        error: { message: e.message, type: e.code || 'delete_failed' },
      });
    }
  });

  // ---- SOC 2 evidence-collection ----
  router.get('/soc2/evidence-bundle', adminAuth, (_req, res) => {
    try {
      const bundle = soc2.buildEvidenceBundle();
      res.json(bundle);
    } catch (e) {
      logger.error('soc2_evidence_bundle_failed', { error: e.message });
      res.status(500).json({ error: { message: e.message, type: 'evidence_bundle_failed' } });
    }
  });

  router.get('/soc2/control-status', adminAuth, (_req, res) => {
    try {
      const status = soc2.readControlMapping();
      res.json(status);
    } catch (e) {
      logger.error('soc2_control_status_failed', { error: e.message });
      res.status(500).json({ error: { message: e.message, type: 'control_status_failed' } });
    }
  });

  // ---- Deep health (Availability Test target) ----
  //
  // Single-shot self-assessed health view. App Insights Availability
  // Tests hit THIS endpoint (instead of public `/`) so up/down reflects
  // what's actually broken inside the gateway. Returned shape is flat
  // + stable so alert rules can match without re-parsing nested
  // structures (see comment block in src/index.js git history for the
  // full field reference; thresholds must stay in sync with
  // scripts/setup-monitoring.sh).
  //
  // PERFORMANCE: invoked frequently. We tail-read usage.jsonl (last
  // ~2MB), full-stream the smaller rate-limits/anomalies JSONLs.
  // Targets <100ms p95 even at a 1GB usage.jsonl.
  router.get('/health/deep', adminAuth, async (_req, res) => {
    const startedAt = Date.now();
    const out = {
      ok: true,
      ts: new Date(startedAt).toISOString(),
      chain_ok: null,
      audit_writes_per_min: 0,
      daily_cap_fires_today: 0,
      anomaly_events_last_hour: 0,
      inference_p99_5min_ms: 0,
      checks_failed: [],
    };

    try {
      const v = auditCheckpoint.verifyChain();
      out.chain_ok = !!(v && v.ok);
      if (!out.chain_ok) {
        out.chain_break = {
          broke_at_index: v && v.broke_at_index,
          reason: v && v.reason,
        };
        out.checks_failed.push('chain_ok');
      }
    } catch (e) {
      out.chain_ok = false;
      out.checks_failed.push('chain_ok');
      logger.warn('deep_health_chain_verify_failed', { error: e.message });
    }

    const fiveMinAgoMs = startedAt - 5 * 60 * 1000;
    const oneHourAgoMs = startedAt - 60 * 60 * 1000;
    const utcDay = new Date(startedAt).toISOString().slice(0, 10);

    const usagePath = process.env.USAGE_FILE
      || path.join(REPO_ROOT, 'data', 'usage.jsonl');
    try {
      if (fs.existsSync(usagePath)) {
        const stat = fs.statSync(usagePath);
        const TAIL_BYTES = 2 * 1024 * 1024;
        const start = Math.max(0, stat.size - TAIL_BYTES);
        const stream = fs.createReadStream(usagePath, { encoding: 'utf8', start });
        const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
        const latencies = [];
        let recentRowCount = 0;
        let skipFirst = start > 0;
        for await (const line of rl) {
          if (skipFirst) { skipFirst = false; continue; }
          if (!line || !line.trim()) continue;
          let row;
          try { row = JSON.parse(line); } catch { continue; }
          if (!row || !row.ts) continue;
          const ms = Date.parse(row.ts);
          if (!Number.isFinite(ms)) continue;
          if (ms < fiveMinAgoMs) continue;
          recentRowCount += 1;
          const lat = Number(row.latency_ms);
          if (Number.isFinite(lat) && lat > 0) latencies.push(lat);
        }
        out.audit_writes_per_min = Math.round((recentRowCount / 5) * 10) / 10;
        if (latencies.length > 0) {
          latencies.sort((a, b) => a - b);
          const rank = Math.ceil(0.99 * latencies.length) - 1;
          out.inference_p99_5min_ms = latencies[
            Math.max(0, Math.min(latencies.length - 1, rank))
          ];
        }
      }
    } catch (e) {
      out.checks_failed.push('inference_p99_5min_ms');
      logger.warn('deep_health_latency_tail_failed', { error: e.message });
    }

    const rateLimitsPath = process.env.RATE_LIMITS_FILE
      || path.join(REPO_ROOT, 'data', 'rate-limits.jsonl');
    try {
      if (fs.existsSync(rateLimitsPath)) {
        const stream = fs.createReadStream(rateLimitsPath, { encoding: 'utf8' });
        const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
        for await (const line of rl) {
          if (!line || !line.trim()) continue;
          let row;
          try { row = JSON.parse(line); } catch { continue; }
          if (!row || !row.ts) continue;
          if (!row.kind) continue;
          if (!String(row.kind).startsWith('daily_quota_')) continue;
          if (String(row.ts).slice(0, 10) !== utcDay) continue;
          out.daily_cap_fires_today += 1;
        }
      }
    } catch (e) {
      out.checks_failed.push('daily_cap_fires_today');
      logger.warn('deep_health_rate_limits_failed', { error: e.message });
    }

    const anomaliesPath = process.env.ANOMALIES_FILE
      || path.join(REPO_ROOT, 'data', 'anomalies.jsonl');
    try {
      if (fs.existsSync(anomaliesPath)) {
        const stream = fs.createReadStream(anomaliesPath, { encoding: 'utf8' });
        const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
        for await (const line of rl) {
          if (!line || !line.trim()) continue;
          let row;
          try { row = JSON.parse(line); } catch { continue; }
          if (!row || !row.ts) continue;
          const ms = Date.parse(row.ts);
          if (!Number.isFinite(ms) || ms < oneHourAgoMs) continue;
          if (row.kind === 'scanner_active' || row.kind === 'auth_brute_force_suspected') {
            out.anomaly_events_last_hour += 1;
          }
        }
      }
    } catch (e) {
      out.checks_failed.push('anomaly_events_last_hour');
      logger.warn('deep_health_anomalies_failed', { error: e.message });
    }

    if (!out.chain_ok) out.ok = false;
    if (out.inference_p99_5min_ms > 15000) out.ok = false;
    if (out.anomaly_events_last_hour > 10) out.ok = false;
    if (out.daily_cap_fires_today > 50) out.ok = false;

    out.duration_ms = Date.now() - startedAt;
    logger.info('deep_health', out);
    res.status(out.ok ? 200 : 503).json(out);
  });

  return router;
}

module.exports = { makeAdminRouter };
