'use strict';

// Public hash-chain checkpoint router — extracted from src/index.js.
//
// Security Hardening Plan card #3 — the global witness for the per-
// (tenant, app_id) audit chains in src/usage.js. A customer or external
// auditor captures /audit/checkpoint/latest at time T1; months later
// they replay the same API to confirm we haven't rewritten any tenant
// row in between. See src/audit-checkpoint.js header for the full
// canonical-input format + verification semantics.
//
// These routes are PUBLIC BY DESIGN. The whole point of a transparency
// primitive is that anyone — customer, regulator, journalist — can pull
// the same data without an account. Per-IP rate limit (mounted upstream
// in src/index.js) still applies; the JSON payloads are tiny (~200B/row)
// so even a sustained scrape is not a real DOS lever.

const express = require('express');
const logger = require('../logger');
const auditCheckpoint = require('../audit-checkpoint');

function makeAuditCheckpointRouter() {
  const router = express.Router();

  router.get('/checkpoint/latest', (_req, res) => {
    try {
      const row = auditCheckpoint.latest();
      if (!row) {
        return res.status(404).json({
          error: {
            type: 'no_checkpoint_yet',
            message: 'no checkpoints recorded yet; will appear after first usage row exists',
          },
        });
      }
      return res.json(row);
    } catch (e) {
      logger.error('audit_checkpoint_latest_failed', { error: e.message });
      return res.status(500).json({ error: { message: e.message, type: 'checkpoint_read_failed' } });
    }
  });

  router.get('/checkpoint', (req, res) => {
    const ts = Number(req.query.ts);
    if (!Number.isFinite(ts) || ts < 0) {
      return res.status(400).json({
        error: {
          type: 'bad_ts',
          message: 'ts query parameter must be a unix-ms number (e.g. ?ts=1715712000000)',
        },
      });
    }
    try {
      const row = auditCheckpoint.at(ts);
      if (!row) {
        return res.status(404).json({
          error: {
            type: 'no_checkpoint_at_or_before',
            message: `no checkpoint recorded at or before ts=${ts}`,
          },
        });
      }
      return res.json(row);
    } catch (e) {
      logger.error('audit_checkpoint_at_failed', { error: e.message });
      return res.status(500).json({ error: { message: e.message, type: 'checkpoint_read_failed' } });
    }
  });

  router.get('/checkpoints', (req, res) => {
    try {
      const limit = req.query.limit == null ? undefined : Number(req.query.limit);
      const sinceMs = req.query.since_ms == null ? undefined : Number(req.query.since_ms);
      const rows = auditCheckpoint.list({ limit, sinceMs });
      res.json({ count: rows.length, checkpoints: rows });
    } catch (e) {
      logger.error('audit_checkpoint_list_failed', { error: e.message });
      res.status(500).json({ error: { message: e.message, type: 'checkpoint_read_failed' } });
    }
  });

  router.get('/checkpoint/verify', (_req, res) => {
    try {
      res.json(auditCheckpoint.verifyChain());
    } catch (e) {
      logger.error('audit_checkpoint_verify_failed', { error: e.message });
      res.status(500).json({ error: { message: e.message, type: 'checkpoint_verify_failed' } });
    }
  });

  return router;
}

module.exports = { makeAuditCheckpointRouter };
