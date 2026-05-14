'use strict';

require('dotenv').config();
const express = require('express');

const logger = require('./logger');
const { customerAuth, adminAuth } = require('./auth');
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
const attestation = require('./attestation');
const trust = require('./trust');
const honeypot = require('./honeypot');
const anomaly = require('./anomaly');
const { rateLimitByIp, rateLimitByTenant } = require('./rate-limit');
const soc2 = require('./soc2');

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
  app.set('trust proxy', 1);
  app.use(securityHeaders);

  // Anomaly detector — Security Hardening Card #5.
  //
  // Mounted FIRST in the data path (after securityHeaders, before honeypot)
  // so res.on('finish') is registered on EVERY request — including those
  // that honeypot terminates without calling next(). The observer reads
  // the final response status code, the resolved req.ip (trust proxy is
  // set above), and req.apiKey (when bearerAuth sets it later on
  // /v1/* routes). Default shadow mode; ANOMALY_FAIL_CLOSED=1 enables
  // threshold-tripped bans which the per-IP rate limiter consults below.
  app.use(anomaly);

  // Per-IP rate limit — defense-in-depth against floods on every
  // unauthenticated path (health, /v1/* 401 reject, /admin/* 401 reject,
  // honeypots). Also short-circuits anomaly-banned IPs to 429. Order:
  // anomaly observer first so its res.on('finish') is registered before
  // we possibly short-circuit; honeypot AFTER the limiter so a scanner
  // hammering canary paths still gets throttled (otherwise the honeypot
  // is unlimited and pure CPU burn for us). See pentest F2 (2026-05-14).
  app.use(rateLimitByIp({ label: 'global' }));

  // Honeypot middleware. Mounted EARLY — after securityHeaders + anomaly
  // observer + per-IP limiter so the CSP/HSTS still apply to fake
  // responses, the anomaly detector sees the hit, and floods are
  // throttled — but before the JSON body parser and before every real
  // route. Intercepts scanner-target paths (/.env, /.git/*, /wp-admin,
  // /api/v0/*, etc) and returns plausible-looking-but-obviously-canary
  // responses. Every hit is logged at WARN level. See src/honeypot.js
  // for the path table.
  app.use(honeypot);

  // Stricter per-IP limit on /admin/*. Operator dashboards shouldn't be
  // flooded — 30/min is well above interactive use and well below brute
  // force. Pre-empts the global 100/min by mounting earlier in the path.
  app.use('/admin', rateLimitByIp({ limit: 30, label: 'admin' }));

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

  // All other endpoints use parsed JSON. The `verify` hook stashes the
  // raw bytes onto req.rawBody so the ed25519 middleware can recompute
  // sha256(body) for signature verification. Express 5's json parser
  // otherwise discards the source buffer once it has the parsed object.
  app.use(express.json({
    limit: '512kb',
    verify: (req, _res, buf) => { req.rawBody = buf; },
  }));
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

  // ---- Public: cosign verification pubkey (no auth) ----
  // Customers + auditors fetch this to verify cosigned container images:
  //   cosign verify --key https://cogos.5ceos.com/cosign.pub <image>
  // Source: COSIGN_PUBKEY_PEM env (full PEM string) or COSIGN_PUBKEY_FILE
  // (path to a PEM file readable by the container). Both unset → 404 with
  // a hint so the URL doesn't 500.
  app.get('/cosign.pub', (_req, res) => {
    const pem = process.env.COSIGN_PUBKEY_PEM
      || (process.env.COSIGN_PUBKEY_FILE
          ? (() => { try { return require('node:fs').readFileSync(process.env.COSIGN_PUBKEY_FILE, 'utf8'); } catch { return null; } })()
          : null);
    if (!pem) {
      return res.status(404).type('text/plain').send(
        '# cosign pubkey not yet published\n'
        + '# Set COSIGN_PUBKEY_PEM or COSIGN_PUBKEY_FILE on the deployed container.\n'
      );
    }
    res.type('text/plain').send(pem);
  });

  // ---- Public: per-response attestation pubkey (no auth) ----
  // Companion to /cosign.pub for the new attestation-token primitive.
  // Customers fetch this PEM to verify the X-Cogos-Attestation header on
  // any /v1/* response. The keypair is ephemeral per process — a container
  // restart rotates it. Customers re-fetch on each verification cycle the
  // same way they trust TLS cert rotation. The X-Cogos-Attestation-Kid
  // header echoes the first 16 hex of sha256(pem) so a customer with
  // multiple stale receipts can match each one to its issuing key.
  //
  // Source: in-process Ed25519 keypair generated at first signing call.
  // See src/attestation.js for why we deliberately do NOT load a
  // long-lived signing key here.
  app.get('/attestation.pub', (_req, res) => {
    res.set('X-Cogos-Attestation-Kid', attestation.getAttestationKid());
    res.type('text/plain').send(attestation.getAttestationPubkey());
  });

  // ---- Legal pages (required for Stripe activation, public, no auth) ----
  app.get('/terms', (_req, res) => res.type('html').send(legal.termsHtml()));
  app.get('/privacy', (_req, res) => res.type('html').send(legal.privacyHtml()));
  app.get('/aup', (_req, res) => res.type('html').send(legal.aupHtml()));
  // Enterprise-grade addenda — templates only, counsel review required.
  app.get('/dpa', (_req, res) => res.type('html').send(legal.dpaHtml()));
  app.get('/baa', (_req, res) => res.type('html').send(legal.baaHtml()));
  app.get('/gdpr', (_req, res) => res.type('html').send(legal.gdprArt28Html()));
  app.get('/sub-processors', (_req, res) => res.type('html').send(legal.subProcessorsHtml()));
  app.get('/whitepaper', (_req, res) => res.type('html').send(whitepaper.whitepaperHtml()));
  app.get('/demo', (_req, res) => res.type('html').send(demo.demoHtml()));
  app.get('/cookbook', (_req, res) => res.type('html').send(cookbook.cookbookHtml()));

  // ---- Trust / transparency dashboard (public, no auth) ----
  // Modeled on trust.salesforce.com. Every claim on the page is backed by
  // data this process can prove from env + process state, or mirrored from
  // SECURITY.md §3. We never fabricate uptime, advisories, or pentest data:
  // if the source data isn't present, the page renders an honest placeholder.
  app.get('/trust', (_req, res) => {
    // healthOk reflects whether *this* process can serve traffic — it's true
    // here by definition (we're servicing the request). A future health-aware
    // probe could flip this to 'degraded' on partial-failure signals.
    const state = trust.buildTrustState({ healthOk: true });
    res.type('html').send(trust.trustHtml(state));
  });

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
  // customerAuth = ed25519-first, bearer-fallback. Either scheme attaches
  // req.apiKey on success; the chained handlers read req.apiKey.tenant_id
  // without caring which substrate authenticated the request.
  //
  // rateLimitByTenant runs AFTER customerAuth so req.apiKey.tenant_id is
  // populated. Default is 1000 req/min/tenant — generous for real workloads
  // (16+ rps sustained) and tight enough that a leaked key can't single-
  // handedly fill the inference queue. Per-IP limit already absorbed the
  // anonymous-flood case upstream.
  const tenantLimiter = rateLimitByTenant();
  app.get('/v1/models', customerAuth, tenantLimiter, handleListModels);
  app.post('/v1/chat/completions', customerAuth, tenantLimiter, enforcePackage, handleChatCompletions);

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
  app.get('/v1/audit', customerAuth, tenantLimiter, (req, res) => {
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
    // omitted, the response is the interleaved cross-app view for the
    // whole tenant — chain_ok is computed per-app and surfaced as
    // chain_ok_by_app so the caller can verify each app independently.
    // Validate the query param shape against the same slug rules
    // src/keys.js uses on issue. Invalid app_id → 400 (don't 200 with
    // empty rows because that would silently hide a typo).
    const rawAppId = req.query.app_id;
    let scopedAppId = null; // null = cross-app
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
      app_id: scopedAppId,    // null = cross-app
      since: sinceMs,
      limit,
    });

    // Chain verification semantics:
    //   - scoped (single app)  → one chain check on the rows as returned.
    //   - cross-app (no scope) → per-app verification. The interleaved
    //     row order is what the customer asked for; chain integrity is
    //     proved by re-grouping per app under the hood.
    // chain_ok is the AND of every app's per-chain result (cross-app
    // case) or the single chain's result (scoped case) — keeps the
    // legacy boolean useful for "should I trust this slice" wire checks.
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
      chain_ok: chainOk,
      chain_break: chainBreak,
      chain_ok_by_app: chainOkByApp,
      app_id: scopedAppId, // echoes the scope; null = cross-app response
      server_time_ms: Date.now(),
    });
  });

  // ---- Admin: key issuance + listing (gated on X-Admin-Key) ----
  // TODO(week-1-finisher): the /admin/* routes below are slated for removal
  // once the offline admin ceremony lands. See scripts/admin-ceremony/README.md
  // for the migration target. They remain LIVE today because tooling depends on
  // them; future card #7-admin-ceremony retires them in favor of signed config
  // diffs that the server verifies on startup.
  //
  // `scheme` selects the customer-auth substrate:
  //   - 'bearer' (default): legacy hash-of-plaintext. We store sha256(key),
  //     customer holds the plaintext (sk-cogos-*). One stealable secret per
  //     customer at rest on the customer side.
  //   - 'ed25519':  we generate the keypair, return the private PEM ONCE,
  //     persist only the public PEM + a stable keyId. No reusable customer
  //     auth material at rest on our side. Customer signs every request.
  app.post('/admin/keys', adminAuth, (req, res) => {
    const { tenant_id, app_id, label, tier, scheme } = req.body || {};
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
      // app_id partitions the customer's keyspace + audit chain +
      // anomaly bucket. Null/undefined → keys.issue() defaults to
      // '_default' (validated in src/keys.js — slug shape, max 64).
      // Shape errors surface as 400.
      issued = keys.issue({
        tenantId: tenant_id,
        app_id,
        label,
        tier,
        scheme: requestedScheme,
      });
    } catch (e) {
      return res.status(400).json({ error: { message: e.message } });
    }
    const { plaintext, hmac_secret, private_pem, pubkey_pem, ed25519_key_id, record } = issued;
    logger.info('key_issued', {
      id: record.id, tenant_id, app_id: record.app_id, tier, scheme: requestedScheme,
    });

    // Common response fields; the scheme-specific secrets are added below.
    // hmac_secret is on the common branch because every customer (regardless
    // of bearer vs ed25519 auth) gets HMAC-signed /v1 responses they should
    // be able to verify. Without it on this response, operator-issued keys
    // have no way to verify the X-Cogos-Signature header.
    const response = {
      key_id: record.id,
      tenant_id: record.tenant_id,
      app_id: record.app_id,
      tier: record.tier,
      scheme: requestedScheme,
      issued_at: record.issued_at,
      hmac_secret, // shown ONCE; used to verify X-Cogos-Signature on /v1/*
      warning: 'Save this key + hmac_secret now. They will not be shown again.',
    };
    if (requestedScheme === 'bearer') {
      response.api_key = plaintext; // shown ONCE; never retrievable again
    } else {
      // ed25519: private_pem is the customer's auth material, shown ONCE.
      // pubkey_pem is returned for confirmation; the server retains it.
      // ed25519_key_id goes in the Authorization header `keyId=` field.
      response.ed25519_key_id = ed25519_key_id;
      response.private_pem = private_pem;
      response.pubkey_pem = pubkey_pem;
    }
    res.status(201).json(response);
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

  // ---- SOC 2 evidence-collection endpoints (X-Admin-Key gated) ----
  // The /admin/soc2/* routes are operator-only surfaces an auditor invokes
  // to capture a point-in-time snapshot of the live environment. Both use
  // the existing adminAuth middleware; neither emits env-var VALUES or
  // customer secrets. See src/soc2.js and docs/soc2/README.md §3.
  app.get('/admin/soc2/evidence-bundle', adminAuth, (_req, res) => {
    try {
      const bundle = soc2.buildEvidenceBundle();
      res.json(bundle);
    } catch (e) {
      logger.error('soc2_evidence_bundle_failed', { error: e.message });
      res.status(500).json({ error: { message: e.message, type: 'evidence_bundle_failed' } });
    }
  });

  app.get('/admin/soc2/control-status', adminAuth, (_req, res) => {
    try {
      const status = soc2.readControlMapping();
      res.json(status);
    } catch (e) {
      logger.error('soc2_control_status_failed', { error: e.message });
      res.status(500).json({ error: { message: e.message, type: 'control_status_failed' } });
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
