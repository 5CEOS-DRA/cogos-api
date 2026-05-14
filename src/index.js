'use strict';

require('dotenv').config();
const express = require('express');

const logger = require('./logger');
const { bearerAuth, adminAuth } = require('./auth');
const { handleChatCompletions, handleListModels, enforcePackage } = require('./chat-api');
const keys = require('./keys');
const usage = require('./usage');
const stripeMod = require('./stripe');
const packages = require('./packages');
const landing = require('./landing');
const legal = require('./legal');
const whitepaper = require('./whitepaper');
const demo = require('./demo');
const cookbook = require('./cookbook');
const honeypot = require('./honeypot');

// Strict security headers on every response. Strongest possible CSP given
// our architecture: no third-party scripts, no SPA, no marketing tags. The
// only inline script on the customer-facing surface is the "Copy key" button
// on /success — refactored to load from /js/copy.js so script-src can stay
// 'self'-only without 'unsafe-inline'.
//
// CSP grade target: A+ on Mozilla Observatory.
function securityHeaders(_req, res, next) {
  res.setHeader('Content-Security-Policy', [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "form-action 'self' https://checkout.stripe.com",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "connect-src 'self'",
  ].join('; '));
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  next();
}

// Trivial copy-to-clipboard helper. Lives at /js/copy.js so we can keep
// CSP's script-src 'self' without any inline-script exception.
const COPY_JS = `(function(){
  document.querySelectorAll('[data-copy]').forEach(function(btn){
    btn.addEventListener('click', function(){
      var t = btn.getAttribute('data-copy');
      if (navigator.clipboard) navigator.clipboard.writeText(t);
    });
  });
})();`;

function createApp() {
  const app = express();
  app.disable('x-powered-by'); // don't advertise framework/version
  app.use(securityHeaders);

  // Honeypot middleware. Mounted EARLY — after securityHeaders so the
  // CSP/HSTS still apply to fake responses, but before the JSON body
  // parser and before every real route. Intercepts scanner-target
  // paths (/.env, /.git/*, /wp-admin, /api/v0/*, etc) and returns
  // plausible-looking-but-obviously-canary responses. Every hit is
  // logged at WARN level. See src/honeypot.js for the path table.
  app.use(honeypot);

  app.get('/js/copy.js', (_req, res) => {
    res.type('application/javascript').send(COPY_JS);
  });

  // Stripe webhook NEEDS raw body for signature verification. Mount BEFORE
  // express.json() so the body parser doesn't consume the stream first.
  app.post('/stripe/webhook',
    express.raw({ type: 'application/json', limit: '512kb' }),
    async (req, res) => {
      const sig = req.headers['stripe-signature'];
      let event;
      try {
        event = stripeMod.verifyAndParseEvent(req.body, sig);
      } catch (e) {
        logger.warn('stripe_webhook_signature_invalid', { error: e.message });
        return res.status(400).send(`Webhook signature error: ${e.message}`);
      }
      if (stripeMod.isEventProcessed(event.id)) {
        logger.info('stripe_webhook_duplicate', { event_id: event.id, type: event.type });
        return res.json({ received: true, duplicate: true });
      }
      try {
        if (event.type === 'checkout.session.completed') {
          await stripeMod.handleCheckoutCompleted(event);
        } else if (event.type === 'customer.subscription.updated'
                || event.type === 'customer.subscription.deleted') {
          await stripeMod.handleSubscriptionUpdated(event);
        } else {
          logger.info('stripe_webhook_unhandled', { event_id: event.id, type: event.type });
        }
        res.json({ received: true });
      } catch (e) {
        logger.error('stripe_webhook_handler_failed', { event_id: event.id, type: event.type, error: e.message });
        res.status(500).json({ error: e.message });
      }
    });

  // All other endpoints use parsed JSON.
  app.use(express.json({ limit: '512kb' }));
  app.set('trust proxy', 1);

  // ---- Public health (no auth) ----
  // Content-negotiated: browsers get an HTML heartbeat page with a
  // pulsing green check; monitors / curl / supertest get the JSON.
  app.get('/health', (req, res) => {
    const data = {
      status: 'ok',
      service: 'cogos-api',
      version: '0.1.0',
      uptime_s: Math.round(process.uptime()),
      timestamp: new Date().toISOString(),
    };
    // Order matters: res.format() picks the FIRST key whose MIME matches
    // the request's Accept. Browsers send `text/html,...` explicitly so
    // they hit the HTML branch; curl, monitors, and supertest send `*/*`
    // (or omit Accept entirely) and fall through to the JSON branch.
    res.format({
      'application/json': () => res.json(data),
      'text/html': () => res.type('html').send(landing.healthHtml(data)),
      default: () => res.json(data),
    });
  });

  // ---- Public landing + signup + success/cancel ----
  app.get('/', (_req, res) => {
    res.type('html').send(landing.renderLandingHtml(packages.list()));
  });
  app.get('/cancel', (_req, res) => res.type('html').send(landing.CANCEL_HTML));

  // ---- Legal pages (required for Stripe activation, public, no auth) ----
  app.get('/terms', (_req, res) => res.type('html').send(legal.termsHtml()));
  app.get('/privacy', (_req, res) => res.type('html').send(legal.privacyHtml()));
  app.get('/aup', (_req, res) => res.type('html').send(legal.aupHtml()));
  app.get('/whitepaper', (_req, res) => res.type('html').send(whitepaper.whitepaperHtml()));
  app.get('/demo', (_req, res) => res.type('html').send(demo.demoHtml()));
  app.get('/cookbook', (_req, res) => res.type('html').send(cookbook.cookbookHtml()));

  app.post('/signup', async (req, res) => {
    try {
      const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
      const host = req.headers['x-forwarded-host'] || req.headers.host;
      const origin = `${proto}://${host}`;
      const packageId = (req.query && req.query.package)
        || (req.body && req.body.package)
        || null;
      const session = await stripeMod.createCheckoutSession({ origin, packageId });
      logger.info('stripe_checkout_session_created', {
        session_id: session.id, package_id: packageId,
      });
      // Redirect to Stripe-hosted checkout page
      res.redirect(303, session.url);
    } catch (e) {
      logger.error('stripe_checkout_create_failed', { error: e.message });
      res.status(500).send(`Could not start checkout: ${e.message}`);
    }
  });

  app.get('/success', async (req, res) => {
    const sessionId = req.query.session_id;
    if (!sessionId) return res.status(400).send('Missing session_id');
    // Poll for the webhook-issued key for up to ~10s before falling back.
    // Stripe webhooks usually arrive in <2s, but launch-day spikes can push
    // delivery past the redirect — and showing "display window closed" to a
    // customer who JUST paid is the worst possible UX moment in the funnel.
    // Configurable via env so tests can drive the timeout to zero.
    const DEADLINE_MS = parseInt(process.env.SUCCESS_POLL_DEADLINE_MS || '10000', 10);
    const INTERVAL_MS = parseInt(process.env.SUCCESS_POLL_INTERVAL_MS || '400', 10);
    const startedAt = Date.now();
    let issued = stripeMod.getNewlyIssuedKey(sessionId);
    while (!issued && Date.now() - startedAt < DEADLINE_MS) {
      await new Promise((r) => setTimeout(r, INTERVAL_MS));
      issued = stripeMod.getNewlyIssuedKey(sessionId);
    }
    if (!issued) {
      logger.warn('success_key_lookup_timeout', {
        session_id: sessionId, waited_ms: Date.now() - startedAt,
      });
    }
    res.type('html').send(landing.successHtml({
      apiKey: issued ? issued.api_key : null,
      hmacSecret: issued ? issued.hmac_secret : null,
      keyId: issued ? issued.key_id : null,
      expiresAt: issued ? issued.expires_at : null,
      sessionId, // passed through so the Manage-subscription link works
    }));
  });

  // ---- Customer Portal redirect ---------------------------------------------
  // Customer holds their success URL (?session_id=cs_test_...). Hitting
  // /portal with that session_id authenticates them as the customer who
  // bought that subscription, looks up their Stripe customer ID, creates
  // a portal session, and redirects them to Stripe-hosted billing mgmt.
  app.get('/portal', async (req, res) => {
    const sessionId = req.query.session_id;
    if (!sessionId) {
      return res.status(400).type('html').send(
        '<p>Missing session_id. Use the link from your receipt or contact <a href="mailto:support@5ceos.com">support@5ceos.com</a>.</p>',
      );
    }
    const customerId = stripeMod.findStripeCustomerBySession(sessionId);
    if (!customerId) {
      return res.status(404).type('html').send(
        '<p>No subscription found for that session. Contact <a href="mailto:support@5ceos.com">support@5ceos.com</a>.</p>',
      );
    }
    try {
      const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
      const host = req.headers['x-forwarded-host'] || req.headers.host;
      const returnUrl = `${proto}://${host}/`;
      const session = await stripeMod.createCustomerPortalSession({
        customerId,
        returnUrl,
      });
      logger.info('stripe_portal_session_created', {
        customer_id: customerId, session_id: sessionId,
      });
      return res.redirect(303, session.url);
    } catch (e) {
      logger.error('stripe_portal_session_failed', {
        customer_id: customerId, error: e.message,
      });
      return res.status(500).type('html').send(
        `<p>Could not open customer portal: ${e.message}.<br>` +
        `Contact <a href="mailto:support@5ceos.com">support@5ceos.com</a>.</p>`,
      );
    }
  });

  // ---- Public chat-completions surface ----
  app.get('/v1/models', bearerAuth, handleListModels);
  app.post('/v1/chat/completions', bearerAuth, enforcePackage, handleChatCompletions);

  // ---- Customer-facing audit query (Security Hardening Card #3) ----
  // Returns the requesting tenant's hash-chained usage rows. Strictly
  // tenant-scoped via req.apiKey.tenant_id — customer A can never see
  // customer B's rows. `chain_ok` is the server-side verifyChain() result
  // on the returned slice; customers re-run verification locally for
  // independent assurance.
  //
  // PUBLIC-SCOPING NOTE: this endpoint exposes the per-tenant chain only.
  // A future card will publish a GLOBAL head-hash (merkle aggregation of
  // all tenant heads) to a public Azure Blob URL on an hourly cadence,
  // letting any third party verify the entire log hasn't been rewritten.
  // The public `/audit/checkpoint/<ts>` endpoint and Azure Blob
  // integration are intentionally NOT built in this branch — they're
  // a separate card in SECURITY_HARDENING_PLAN.md.
  app.get('/v1/audit', bearerAuth, (req, res) => {
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
    const rows = usage.readByTenant(tenantId, sinceMs, limit);
    const chain = usage.verifyChain(rows);
    // next_cursor = ts (ms) of the last returned row, so the caller can
    // page forward by passing it back as `since`. Null when no rows
    // returned OR the slice didn't fill `limit` (no more rows to fetch).
    let nextCursor = null;
    if (rows.length === limit && rows.length > 0) {
      const lastTs = Date.parse(rows[rows.length - 1].ts);
      if (Number.isFinite(lastTs)) nextCursor = lastTs;
    }
    res.json({
      rows,
      next_cursor: nextCursor,
      chain_ok: chain.ok,
      chain_break: chain.ok ? null : {
        broke_at_index: chain.broke_at_index,
        reason: chain.reason,
      },
      server_time_ms: Date.now(),
    });
  });

  // ---- Admin: key issuance + listing (gated on X-Admin-Key) ----
  // TODO(week-1-finisher): the /admin/* routes below are slated for removal
  // once the offline admin ceremony lands. See scripts/admin-ceremony/README.md
  // for the migration target. They remain LIVE today because tooling depends on
  // them; future card #7-admin-ceremony retires them in favor of signed config
  // diffs that the server verifies on startup.
  app.post('/admin/keys', adminAuth, (req, res) => {
    const { tenant_id, label, tier } = req.body || {};
    if (!tenant_id) {
      return res.status(400).json({ error: { message: 'tenant_id required' } });
    }
    const { plaintext, record } = keys.issue({ tenantId: tenant_id, label, tier });
    logger.info('key_issued', { id: record.id, tenant_id, tier });
    res.status(201).json({
      api_key: plaintext, // shown ONCE; never retrievable again
      key_id: record.id,
      tenant_id: record.tenant_id,
      tier: record.tier,
      issued_at: record.issued_at,
      warning: 'Save this key now. It will not be shown again.',
    });
  });

  app.get('/admin/keys', adminAuth, (_req, res) => {
    res.json({ keys: keys.list() });
  });

  app.post('/admin/keys/:id/revoke', adminAuth, (req, res) => {
    const ok = keys.revoke(req.params.id);
    if (!ok) return res.status(404).json({ error: { message: 'Key not found' } });
    logger.info('key_revoked', { id: req.params.id });
    res.json({ revoked: true, key_id: req.params.id });
  });

  // Usage log — supports `?since=<unix-ms>` for tailing.
  app.get('/admin/usage', adminAuth, (req, res) => {
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

  // ---- Admin: package CRUD (X-Admin-Key, used by Management Console) ----
  // Packages define what each subscription tier gets: monthly USD price,
  // monthly request quota, allowed model tiers. Stripe Products + Prices
  // are kept in sync when STRIPE_SECRET_KEY is configured; otherwise the
  // sync is a no-op (stub mode) so the operator can edit packages before
  // turning on self-serve signup.
  app.get('/admin/packages', adminAuth, (req, res) => {
    const includeInactive = req.query.include_inactive === '1';
    res.json({ packages: packages.list({ includeInactive }) });
  });

  app.post('/admin/packages', adminAuth, async (req, res) => {
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

  app.put('/admin/packages/:id', adminAuth, async (req, res) => {
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

  app.delete('/admin/packages/:id', adminAuth, async (req, res) => {
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

  return app;
}

if (require.main === module) {
  const app = createApp();
  const port = Number(process.env.PORT || 4444);
  app.listen(port, async () => {
    logger.info('cogos_api_listening', { port });
    // Pre-seed the default package so quota enforcement has something to
    // resolve against on a fresh deploy. Idempotent.
    try {
      await packages.seedIfEmpty();
    } catch (e) {
      logger.error('package_seed_failed_on_boot', { error: e.message });
    }
  });
}

module.exports = { createApp };
