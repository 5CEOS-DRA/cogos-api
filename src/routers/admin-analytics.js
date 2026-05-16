'use strict';

// Operator analytics router — extracted from src/index.js to keep the
// gateway entry point readable. All routes are READ-ONLY admin-gated
// JSON returning the same aggregations the 5CEOs Management Console
// ("CogOS Analytics" tab) consumes.
//
// Per-IP /admin/* rate limit (30/min, mounted at the app level in
// src/index.js) still applies — these endpoints are not bypassable
// from the wire.

const express = require('express');
const logger = require('../logger');
const analytics = require('../analytics');

// since_ms parser — undefined for missing or invalid input so the
// downstream analytics calls fall back to their own default window
// (30d at time of writing). We deliberately don't 400 on garbage so
// a miswired dashboard can still render.
function parseSinceMs(q) {
  if (q == null || q === '') return undefined;
  const n = Number(q);
  if (!Number.isFinite(n) || n < 0) return undefined;
  return Math.floor(n);
}

function makeAdminAnalyticsRouter({ adminAuth }) {
  const router = express.Router();

  router.get('/summary', adminAuth, async (req, res) => {
    try {
      const sinceMs = parseSinceMs(req.query.since_ms);
      const out = await analytics.summary({ sinceMs });
      res.json(out);
    } catch (e) {
      logger.error('analytics_summary_failed', { error: e.message });
      res.status(500).json({ error: { message: e.message, type: 'analytics_failed' } });
    }
  });

  router.get('/signups', adminAuth, async (req, res) => {
    try {
      const sinceMs = parseSinceMs(req.query.since_ms);
      res.json(await analytics.signupsByDay({ sinceMs }));
    } catch (e) {
      logger.error('analytics_signups_failed', { error: e.message });
      res.status(500).json({ error: { message: e.message, type: 'analytics_failed' } });
    }
  });

  router.get('/requests', adminAuth, async (req, res) => {
    try {
      const sinceMs = parseSinceMs(req.query.since_ms);
      const granularity = req.query.granularity === 'day' ? 'day' : 'hour';
      res.json(await analytics.requestsByHour({ sinceMs, granularity }));
    } catch (e) {
      logger.error('analytics_requests_failed', { error: e.message });
      res.status(500).json({ error: { message: e.message, type: 'analytics_failed' } });
    }
  });

  router.get('/anomalies', adminAuth, async (req, res) => {
    try {
      const sinceMs = parseSinceMs(req.query.since_ms);
      res.json(await analytics.anomaliesByKind({ sinceMs }));
    } catch (e) {
      logger.error('analytics_anomalies_failed', { error: e.message });
      res.status(500).json({ error: { message: e.message, type: 'analytics_failed' } });
    }
  });

  router.get('/honeypots', adminAuth, async (req, res) => {
    try {
      const sinceMs = parseSinceMs(req.query.since_ms);
      res.json(await analytics.honeypotsByPath({ sinceMs }));
    } catch (e) {
      logger.error('analytics_honeypots_failed', { error: e.message });
      res.status(500).json({ error: { message: e.message, type: 'analytics_failed' } });
    }
  });

  router.get('/rate-limits', adminAuth, async (req, res) => {
    try {
      const sinceMs = parseSinceMs(req.query.since_ms);
      res.json(await analytics.rateLimitsByDay({ sinceMs }));
    } catch (e) {
      logger.error('analytics_rate_limits_failed', { error: e.message });
      res.status(500).json({ error: { message: e.message, type: 'analytics_failed' } });
    }
  });

  router.get('/tenants', adminAuth, async (req, res) => {
    try {
      const sinceMs = parseSinceMs(req.query.since_ms);
      res.json(await analytics.tenantsActive({ sinceMs }));
    } catch (e) {
      logger.error('analytics_tenants_failed', { error: e.message });
      res.status(500).json({ error: { message: e.message, type: 'analytics_failed' } });
    }
  });

  router.get('/channels', adminAuth, async (req, res) => {
    try {
      const sinceMs = parseSinceMs(req.query.since_ms);
      res.json(await analytics.channelsBySignup({ sinceMs }));
    } catch (e) {
      logger.error('analytics_channels_failed', { error: e.message });
      res.status(500).json({ error: { message: e.message, type: 'analytics_failed' } });
    }
  });

  router.get('/revenue', adminAuth, (_req, res) => {
    try {
      res.json(analytics.revenueSnapshot());
    } catch (e) {
      logger.error('analytics_revenue_failed', { error: e.message });
      res.status(500).json({ error: { message: e.message, type: 'analytics_failed' } });
    }
  });

  return router;
}

module.exports = { makeAdminAnalyticsRouter, parseSinceMs };
