'use strict';

require('dotenv').config();
const express = require('express');

const logger = require('./logger');
const { customerAuth, adminAuth } = require('./auth');
const { handleChatCompletions, handleListModels, enforcePackage, enforceDailyCap } = require('./chat-api');
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
const notifySignup = require('./notify-signup');
const dashboard = require('./dashboard');
const session = require('./session');
const dailyCap = require('./daily-cap');
const magicLink = require('./magic-link');
const analytics = require('./analytics');

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
  // Form-urlencoded parser for the notify-signup form on the landing page.
  // Cap is tight — only one short email field is expected.
  app.use(express.urlencoded({ extended: false, limit: '4kb' }));
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

  // ---- Customer-facing dashboard (public sign-in surface) ----------------
  // The customer's API key is their password — same login model as Stripe,
  // Vercel, Cloudflare, Fly developer dashboards. Paste the bearer key into
  // the form, the server validates via keys.verify(), and the session
  // cookie carries state for subsequent /dashboard/* requests.
  //
  // Per-IP rate limit already applies (mounted upstream). No CSRF token
  // today — SameSite=Lax + HttpOnly cookie covers most of the state-
  // changing-form surface; a future card can layer per-request tokens.
  //
  // ensureSameTenant() is the cross-tenant defense for handlers that
  // operate on a key by id. The check is done EVERYWHERE that takes a
  // key_id from the URL/body — defense in depth against a future hand-
  // edit that forgets to wire the check on one route.
  function ensureSameTenant(req, record) {
    if (!record) return false;
    return record.tenant_id === req.session.tenant_id;
  }

  // /dashboard — login form (or redirect if already signed in).
  app.get('/dashboard', (req, res) => {
    const cookies = session.parseCookieHeader(req.headers.cookie || '');
    const existing = session.parseSession(cookies[session.COOKIE_NAME]);
    if (existing) {
      // Re-validate against keys store before honoring the redirect.
      const rec = keys.findById(existing.key_id);
      if (rec && rec.active !== false && !rec.quarantined_at) {
        return res.redirect(303, '/dashboard/home');
      }
    }
    const error = typeof req.query.error === 'string' ? req.query.error : null;
    res.type('html').send(dashboard.loginHtml({ error }));
  });

  // /dashboard/login — POST: validate the pasted API key, mint a session.
  app.post('/dashboard/login', (req, res) => {
    const rawKey = req.body && req.body.api_key;
    if (typeof rawKey !== 'string' || !rawKey.trim()) {
      return res.status(400).type('html').send(
        dashboard.loginHtml({ error: 'invalid_api_key' }),
      );
    }
    const record = keys.verify(rawKey.trim());
    if (!record) {
      logger.info('dashboard_login_failed', { reason: 'invalid_or_revoked' });
      return res.status(400).type('html').send(
        dashboard.loginHtml({ error: 'invalid_api_key' }),
      );
    }
    if (record.quarantined_at) {
      logger.warn('dashboard_login_failed', {
        reason: 'quarantined', key_id: record.id,
      });
      return res.status(400).type('html').send(
        dashboard.loginHtml({ error: 'invalid_api_key' }),
      );
    }
    const cookieValue = session.createSession({
      tenant_id: record.tenant_id,
      key_id: record.id,
      app_id: record.app_id || keys.DEFAULT_APP_ID,
    });
    res.setHeader('Set-Cookie', session.createSetCookie(cookieValue));
    logger.info('dashboard_login_ok', {
      tenant_id: record.tenant_id, key_id: record.id,
    });
    return res.redirect(303, '/dashboard/home');
  });

  // /dashboard/logout — POST: clear cookie. No session needed (an already-
  // invalidated cookie should still be able to "log out" cleanly).
  app.post('/dashboard/logout', (_req, res) => {
    res.setHeader('Set-Cookie', session.clearSetCookie());
    return res.redirect(303, '/dashboard');
  });

  // ---- /dashboard/forgot — self-serve magic-link recovery ----------------
  //
  // The substrate can't recover a lost API key (only sha256(plaintext) is
  // stored). Recovery = prove email ownership via a signed magic link,
  // then we rotate to a fresh key under the same tenant. The flow:
  //
  //   1. GET /dashboard/forgot   → form (email field)
  //   2. POST /dashboard/forgot  → look up keys whose label is
  //                                 `free-signup:<email>` OR whose
  //                                 customer_email matches (case-sensitive
  //                                 — same convention as free-tier signup);
  //                                 fire-and-forget SES email if a match
  //                                 exists; ALWAYS return the same "if an
  //                                 account exists, we sent a link" page
  //                                 so the form can't be turned into a
  //                                 customer-enumeration oracle.
  //   3. GET /dashboard/auth?token=<signed_token>
  //                              → verifyToken (kind + sig + ttl + single-
  //                                use nonce); on success rotate the key,
  //                                set the session cookie, stash the new
  //                                material in a short-lived display
  //                                store, 303 to /dashboard/rotate-result.
  //   4. GET /dashboard/rotate-result
  //                              → consume the display cookie, render the
  //                                new key + secret ONCE.
  //
  // NON-ENUMERATION CONTRACT: GET /dashboard/forgot returns 200; POST
  // /dashboard/forgot returns 200 + the SAME HTML body for both known
  // and unknown emails. The SES send happens fire-and-forget on the
  // server side regardless of outcome (skipped silently for unknowns),
  // so the response latency profile is the same — the visible delay is
  // dominated by the synchronous keys.list() scan which runs either way.

  // ---- Display-material store (process-local, single-use, 5-min TTL) ----
  //
  // /dashboard/auth needs to hand the freshly-rotated key material to
  // /dashboard/rotate-result through a 303 redirect. We can't put
  // plaintext in the URL or a long-lived cookie, so we mint a one-time
  // display token, stash {material, exp_ms} in this Map, and set a
  // short-lived HttpOnly cookie carrying the display token. The render
  // route consumes the entry (delete + return) so a refresh shows the
  // "nothing here" state — same show-once semantics as the rotate page.
  // TODO(future): persist this in a shared substrate for multi-replica.
  const DISPLAY_TTL_MS = 5 * 60 * 1000;
  const _displayMaterial = new Map();
  function _stashDisplay(material) {
    const dt = require('crypto').randomBytes(24).toString('base64url');
    _displayMaterial.set(dt, { material, exp_ms: Date.now() + DISPLAY_TTL_MS });
    return dt;
  }
  function _consumeDisplay(dt) {
    if (!dt || typeof dt !== 'string') return null;
    const entry = _displayMaterial.get(dt);
    if (!entry) return null;
    _displayMaterial.delete(dt); // single-use
    if (Date.now() >= entry.exp_ms) return null;
    return entry.material;
  }
  // Garbage-collect expired entries on every stash so a load spike can't
  // pile them up forever. O(n) but n is bounded by recovery-rate × 5min.
  function _gcDisplay() {
    const now = Date.now();
    for (const [k, v] of _displayMaterial.entries()) {
      if (now >= v.exp_ms) _displayMaterial.delete(k);
    }
  }

  // /dashboard/forgot — GET: render the email-entry form.
  app.get('/dashboard/forgot', (_req, res) => {
    res.type('html').send(dashboard.forgotFormHtml({}));
  });

  // /dashboard/forgot — POST: look up keys, fire SES, always show same page.
  app.post('/dashboard/forgot', (req, res) => {
    const rawEmail = (req.body && req.body.email) || '';
    const email = String(rawEmail).trim();
    // Server-side shape check (cheap, no oracle — invalid email also
    // gets the same confirmation page).
    const valid = notifySignup.isValidEmail(email);

    // Find candidate keys. Same case-sensitive match as the free-signup
    // idempotency check in src/index.js POST /signup/free — so the label
    // and customer_email stay one canonical string per identity.
    //
    // MULTI-KEY policy: rotating ONLY the most-recently-issued active key
    // for this email. Rationale: rotating all of them would invalidate
    // working clients the customer hasn't told us about (a customer who
    // still has key #2 but lost key #1 doesn't want #2 nuked when they
    // recover #1's tenant). The recovered key lands the customer in the
    // dashboard signed-in; from there they can revoke any siblings they
    // recognize. If the most-recent-key heuristic misfires (e.g. customer
    // wants to recover a SPECIFIC older identity), they can re-run
    // recovery after revoking — the substrate is convergent. TODO: a
    // future card can render a chooser page when multiple keys match.
    let target = null;
    if (valid) {
      const wantedLabel = `free-signup:${email}`;
      const candidates = keys.list().filter((k) =>
        k.active !== false
        && !k.quarantined_at
        && (k.label === wantedLabel || k.customer_email === email)
      );
      if (candidates.length > 0) {
        // Sort by issued_at DESC, pick first. Falls back to id-stable
        // ordering when issued_at ties (shouldn't happen with UUIDs).
        candidates.sort((a, b) => {
          const ta = Date.parse(a.issued_at || '') || 0;
          const tb = Date.parse(b.issued_at || '') || 0;
          if (tb !== ta) return tb - ta;
          return String(b.id).localeCompare(String(a.id));
        });
        target = candidates[0];
      }
    }

    if (target) {
      // Mint a signed magic-link token for THIS key. baseUrl comes from
      // the request — proto + host, same pattern as /signup uses for the
      // Stripe redirect URL. That keeps the link working in dev (localhost)
      // and prod (cogos.5ceos.com) without an env variable.
      const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
      const host = req.headers['x-forwarded-host'] || req.headers.host;
      const baseUrl = `${proto}://${host}`;
      const { url, exp_ms, nonce } = magicLink.createToken({
        tenant_id: target.tenant_id,
        key_id: target.id,
        email,
        baseUrl,
      });
      logger.info('magic_link_issued', {
        tenant_id: target.tenant_id,
        key_id: target.id,
        nonce, // safe to log — opaque random id, not the token
        exp_ms,
      });

      // Fire-and-forget SES send. We do NOT block the response on the
      // mail delivery (latency would otherwise become an oracle for
      // "email matched a real customer"). The notify-signup helper
      // already encapsulates the SES → Resend → log-only ladder.
      const sendRow = {
        ts: new Date().toISOString(),
        email,
        source: 'magic-link-recovery',
        ip: req.ip || null,
        ua: req.headers['user-agent'] || null,
      };
      // We bend the row shape slightly: forwardEmail builds the subject
      // line from row.email + sends fixed body copy. For recovery we need
      // the URL in the body, so we send a SECOND row to ourselves shaped
      // for the recovery email — operator visibility is the goal here,
      // not customer mail. TODO: a future card adds a dedicated send-as-
      // customer SES path. For v1 the recovery URL is logged AND sent
      // through the operator-notification transport so an operator can
      // forward it manually if SES misfires for a particular customer.
      const recoveryRow = {
        ...sendRow,
        // notify-signup's email template builds: "New signup\n\nemail: ...".
        // We embed the recovery URL in the user-agent slot so it lands
        // in the operator's notification email body unmangled. Hacky but
        // works without forking the transport code — a cleaner template
        // helper is a TODO once we have a second send-case.
        ua: `magic-link recovery URL: ${url} (expires in ${Math.round((exp_ms - Date.now()) / 1000)}s)`,
      };
      notifySignup.forwardEmail(recoveryRow).then((r) => {
        if (r.sent) {
          logger.info('magic_link_email_sent', {
            tenant_id: target.tenant_id,
            transport: r.transport,
            status: r.status,
          });
        } else {
          // Log-only fallback: print the URL so an operator can dig it
          // out of the logs if the customer reports they didn't receive
          // it. Acceptable because the same URL was already issued —
          // logging it doesn't widen the attack surface beyond log
          // access (which gates the secrets file anyway).
          logger.warn('magic_link_email_skipped', {
            tenant_id: target.tenant_id,
            reason: r.reason,
            recovery_url: url,
          });
        }
      }).catch((e) => {
        logger.warn('magic_link_email_error', { error: e.message });
      });
    } else {
      // No match. We deliberately do NOT log the email at INFO — log
      // forensics shouldn't grow a list of "addresses someone probed."
      logger.info('magic_link_request_no_match', { ip: req.ip || null });
    }

    // SAME response either way — this is the non-enumeration contract.
    // 200 + identical body shape regardless of match outcome.
    res.type('html').send(dashboard.forgotConfirmHtml({ email }));
  });

  // /dashboard/auth — GET: verify magic-link token, rotate key, set
  // session cookie, stash material, 303 to /dashboard/rotate-result.
  app.get('/dashboard/auth', (req, res) => {
    const token = typeof req.query.token === 'string' ? req.query.token : '';
    const parsed = magicLink.verifyToken(token);
    if (!parsed) {
      // Single 400-with-error page for every failure mode (bad sig,
      // expired, replayed, garbage). The form-error UX is the same
      // closed-map pattern as the dashboard login page — no reflected
      // echo of the token value into the page.
      logger.info('magic_link_verify_failed', { ip: req.ip || null });
      return res.status(400).type('html').send(
        dashboard.forgotFormHtml({
          error: 'That recovery link is invalid, expired, or already used. '
            + 'Request a fresh one below.',
        }),
      );
    }

    // Re-validate the target key is still rotatable. The token might
    // have been minted minutes ago and the key could have been revoked
    // since then (e.g. operator triage). Refuse cleanly if so.
    const target = keys.findById(parsed.key_id);
    if (!target || target.active === false || target.quarantined_at
        || target.tenant_id !== parsed.tenant_id) {
      logger.warn('magic_link_target_unrotatable', {
        tenant_id: parsed.tenant_id, key_id: parsed.key_id,
      });
      return res.status(400).type('html').send(
        dashboard.forgotFormHtml({
          error: 'The key on that recovery link is no longer active. '
            + 'Sign in with a different key if you have one, or contact support.',
        }),
      );
    }

    // Rotate. Same pattern as the dashboard /dashboard/keys/rotate
    // handler — the old key keeps its 24h grace, the new key is the
    // customer's going forward. We pass the FULL record (rotate()
    // requires the caller record with id; findById returns it without
    // key_hash which is fine — rotate() looks the record up by id
    // internally before reading any sensitive field).
    let issued;
    try {
      issued = keys.rotate(target);
    } catch (e) {
      logger.error('magic_link_rotate_failed', {
        tenant_id: parsed.tenant_id, key_id: parsed.key_id, error: e.message,
      });
      return res.status(500).type('html').send(
        dashboard.forgotFormHtml({
          error: 'Could not mint a fresh key for your tenant. Try again or '
            + 'contact support@5ceos.com.',
        }),
      );
    }

    // Audit-log marker: an operator scanning /v1/audit (or the dashboard
    // audit table) should see a clear "tenant X recovered via magic
    // link at ts Y" row. We append a 0-token row to the new key's
    // (tenant, app) chain so the marker is INSIDE the same hash chain
    // the customer reads — tamper-evident.
    try {
      usage.record({
        tenant_id: issued.record.tenant_id,
        key_id: issued.record.id,
        app_id: issued.record.app_id || keys.DEFAULT_APP_ID,
        route: '/dashboard/auth',
        status: 'magic_link_recovery',
        prompt_tokens: 0,
        completion_tokens: 0,
        latency_ms: 0,
      });
    } catch (e) {
      // Don't fail recovery on an audit-log glitch. The rotation is
      // already on disk in keys.json.
      logger.warn('magic_link_audit_record_failed', { error: e.message });
    }

    // Mint a session cookie bound to the NEW key. The customer is now
    // signed in — clicking through to /dashboard/home from the result
    // page just works.
    const cookieValue = session.createSession({
      tenant_id: issued.record.tenant_id,
      key_id: issued.record.id,
      app_id: issued.record.app_id || keys.DEFAULT_APP_ID,
    });

    // Stash the show-once material in the in-memory display store +
    // mint a short-lived cookie carrying the lookup key. Two Set-Cookie
    // headers — the session cookie + the one-time display cookie.
    _gcDisplay();
    const displayToken = _stashDisplay({
      new_api_key: issued.plaintext,
      new_hmac_secret: issued.hmac_secret,
      ed25519_key_id: issued.ed25519_key_id,
      private_pem: issued.private_pem,
      pubkey_pem: issued.pubkey_pem,
      x25519_private_pem: issued.x25519_private_pem,
      x25519_pubkey_pem: issued.x25519_pubkey_pem,
      expires_at: issued.record.expires_at,
      grace_until: issued.rotation_grace_until_iso,
      scheme: issued.record.scheme,
    });
    const displayCookie = `cogos_recovery_display=${displayToken}; `
      + `HttpOnly; Secure; SameSite=Strict; Path=/dashboard; `
      + `Max-Age=${Math.floor(DISPLAY_TTL_MS / 1000)}`;
    res.setHeader('Set-Cookie', [
      session.createSetCookie(cookieValue),
      displayCookie,
    ]);

    logger.info('magic_link_recovery_ok', {
      tenant_id: issued.record.tenant_id,
      old_key_id: parsed.key_id,
      new_key_id: issued.record.id,
    });

    return res.redirect(303, '/dashboard/rotate-result');
  });

  // /dashboard/rotate-result — render the show-once new-key page. Reads
  // the one-time display cookie, looks up the material in-memory, clears
  // both the cookie and the store entry, renders the page. If the
  // display token is missing/consumed/expired we render a friendly
  // "nothing to show" page rather than an error — the customer might
  // have refreshed after closing the tab.
  app.get('/dashboard/rotate-result', (req, res) => {
    const cookies = session.parseCookieHeader(req.headers.cookie || '');
    const displayToken = cookies['cogos_recovery_display'];
    const material = _consumeDisplay(displayToken);

    // Clear the display cookie regardless of lookup outcome.
    res.setHeader('Set-Cookie',
      `cogos_recovery_display=; HttpOnly; Secure; SameSite=Strict; `
      + `Path=/dashboard; Max-Age=0`,
    );

    if (!material) {
      return res.type('html').send(dashboard.forgotFormHtml({
        error: 'Nothing to display here — the recovery material has already '
          + 'been shown once or the 5-minute window expired. If you saved '
          + 'the new key, you can sign in normally. Otherwise, run recovery '
          + 'again from this same email address.',
      }));
    }
    return res.type('html').send(dashboard.recoveryResultHtml(material));
  });

  // /dashboard/home — the actual dashboard surface. Session-gated.
  app.get('/dashboard/home', session.customerSessionAuth, (req, res) => {
    const tenantId = req.session.tenant_id;
    const myKeyId = req.session.key_id;

    // CROSS-TENANT DEFENSE: keys.list() returns every key in the
    // store. We FILTER HERE to req.session.tenant_id — that line is
    // load-bearing for tenant isolation on the dashboard.
    const tenantKeys = keys.list().filter((k) => k.tenant_id === tenantId);

    // Daily-cap counter for the current key's (tenant, app) bucket.
    // getCounter is a read-only snapshot that doesn't keep buckets alive.
    const myApp = (req.sessionRecord && req.sessionRecord.app_id) || keys.DEFAULT_APP_ID;
    const dailyCounter = dailyCap.getCounter(tenantId, myApp);

    // Monthly quota — look up the key's package to surface the
    // headline number. Best-effort: a key without package_id (legacy)
    // gets the default package; if package resolution fails entirely
    // we surface null (the UI renders ∞).
    let monthlyQuota = null;
    try {
      const pkg = packages.resolveForKey
        ? packages.resolveForKey(req.sessionRecord)
        : null;
      if (pkg && typeof pkg.monthly_request_quota === 'number') {
        monthlyQuota = pkg.monthly_request_quota;
      }
    } catch (_e) { /* no-op — surface as null */ }

    // Audit slice — last 20 rows for this tenant, cross-app. We pass
    // tenant_id ONLY, no app_id, so the customer sees all their apps'
    // chains interleaved. chain_ok_by_app comes from verifyByApp so
    // each app's chain is independently checked.
    const auditRows = usage.readSlice({
      tenant_id: tenantId, limit: 20,
    });
    const chainOkByApp = (usage.verifyByApp ? usage.verifyByApp(auditRows) : {});
    const chainBoolByApp = {};
    for (const [app, result] of Object.entries(chainOkByApp)) {
      chainBoolByApp[app] = result && result.ok === true;
    }

    res.type('html').send(dashboard.homeHtml({
      tenant_id: tenantId,
      key_id: myKeyId,
      app_id: myApp,
      key_prefix: (req.sessionRecord && req.sessionRecord.key_prefix) || null,
      scheme: (req.sessionRecord && req.sessionRecord.scheme) || 'bearer',
      expires_at: (req.sessionRecord && req.sessionRecord.expires_at) || null,
      daily_counter: dailyCounter,
      monthly_used: null,        // future card: month-to-date counter
      monthly_quota: monthlyQuota,
      keys: tenantKeys,
      audit_rows: auditRows,
      chain_ok_by_app: chainBoolByApp,
    }));
  });

  // /dashboard/keys/:id/revoke — POST: revoke a key after verifying it
  // belongs to the session's tenant. Self-revoke is rejected with the
  // self_revoke error code (defense in depth — the UI hides the button
  // on the current row, but a forged form post would otherwise reach
  // here).
  app.post('/dashboard/keys/:id/revoke', session.customerSessionAuth, (req, res) => {
    const target = keys.findById(req.params.id);
    if (!target) {
      return res.redirect(303, '/dashboard/home');
    }
    if (!ensureSameTenant(req, target)) {
      logger.warn('dashboard_cross_tenant_revoke_blocked', {
        attacker_tenant: req.session.tenant_id,
        target_tenant: target.tenant_id,
        target_key_id: target.id,
      });
      return res.status(403).type('html').send(
        dashboard.loginHtml({ error: 'cross_tenant' }),
      );
    }
    if (target.id === req.session.key_id) {
      // Self-revoke would log the customer out and break the rotation
      // safety story (rotate IS the correct way to retire the current
      // key). UI hides the button; this is the server-side reflection.
      return res.redirect(303, '/dashboard/home?error=self_revoke');
    }
    const ok = keys.revoke(target.id);
    if (!ok) {
      return res.redirect(303, '/dashboard/home?error=revoke_failed');
    }
    logger.info('dashboard_key_revoked', {
      tenant_id: req.session.tenant_id,
      revoker_key_id: req.session.key_id,
      revoked_key_id: target.id,
    });
    res.redirect(303, '/dashboard/home');
  });

  // /dashboard/keys/rotate — POST: rotate the session's own key. The
  // new material is rendered ONCE; the customer's session cookie is
  // NOT swapped (the old key stays valid through the 24h grace window,
  // and the cookie is bound to the old key_id — that's fine because
  // customerSessionAuth re-validates against the keys store which
  // still finds the old record as active).
  app.post('/dashboard/keys/rotate', session.customerSessionAuth, (req, res) => {
    try {
      const issued = keys.rotate(req.sessionRecord);
      const {
        plaintext, hmac_secret, private_pem, pubkey_pem, ed25519_key_id,
        x25519_private_pem, x25519_pubkey_pem, record,
        rotation_grace_until_iso,
      } = issued;
      logger.info('dashboard_key_rotated', {
        tenant_id: req.session.tenant_id,
        old_key_id: req.session.key_id,
        new_key_id: record.id,
      });
      res.type('html').send(dashboard.rotateResultHtml({
        new_api_key: plaintext,
        new_hmac_secret: hmac_secret,
        ed25519_key_id,
        private_pem,
        pubkey_pem,
        x25519_private_pem,
        x25519_pubkey_pem,
        expires_at: record.expires_at,
        grace_until: rotation_grace_until_iso,
        scheme: record.scheme,
      }));
    } catch (e) {
      logger.warn('dashboard_key_rotate_failed', {
        tenant_id: req.session.tenant_id,
        key_id: req.session.key_id,
        error: e.message,
      });
      res.redirect(303, '/dashboard/home?error=rotate_failed');
    }
  });

  // Public "notify-me-when-X-ships" capture. Per-IP rate-limit middleware
  // already applies (mounted earlier in the chain). Persists every
  // submission; forwards to NOTIFY_EMAIL via Resend if RESEND_API_KEY is set.
  app.post('/notify-signup', notifySignup.handleSignup);

  // Operator-only list of captured signups.
  app.get('/admin/notify-signups', adminAuth, (_req, res) => {
    res.json({ signups: notifySignup.list() });
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

  // ---- Free-tier signup (no Stripe) ----
  // Public, no auth. Per-IP rate limit already applies (mounted upstream).
  // Path-based routing — explicitly NOT /signup?tier=free. A query-string
  // overload of the Stripe-bound /signup would force packageId-parsing
  // logic to fork in two places.
  //
  // Gating: the "free" package must exist in the registry AND have
  // public_signup === true. Either condition false → 503. Operator can
  // disable free-tier signup at runtime by flipping public_signup via
  // PUT /admin/packages/free without touching code.
  //
  // Idempotency by email: prevents the route from becoming an oracle
  // for "is this email already a customer" (label match returns the
  // already-exists page either way) AND prevents printing N keys for
  // the same email. Anonymous (no-email) signups are NOT deduped —
  // each anonymous POST issues a fresh key. Anonymous abuse mitigation
  // is the per-IP rate limit, not idempotency.
  //
  // Email is opaque: NOT validated, NOT lowercased server-side beyond
  // what the label substring match needs. Treated as a free-text tag.
  // Future card: CAPTCHA, email-confirmation, customer self-service
  // recovery via Resend.
  app.post('/signup/free', async (req, res) => {
    try {
      const all = packages.list();
      const freePkg = all.find((p) => p.id === 'free');
      if (!freePkg || freePkg.public_signup !== true) {
        logger.warn('signup_free_not_enabled', {
          present: !!freePkg,
          public_signup: freePkg ? freePkg.public_signup : null,
        });
        return res.status(503).json({ error: 'Free tier not enabled' });
      }

      // Email is opaque. Accept anything (or nothing). We DO trim the
      // surrounding whitespace so a copy-paste with a trailing newline
      // doesn't create a separate identity. We do NOT lowercase: case-
      // preservation lets two operators inspect labels and tell the
      // submission apart from a duplicate-with-different-case (a manual
      // recovery signal). The exact-string match below is therefore
      // case-sensitive — documented in the report.
      const rawEmail = req.body && req.body.email;
      const email = (typeof rawEmail === 'string' && rawEmail.trim())
        ? rawEmail.trim()
        : '';

      // Idempotency: only when an email was provided. Anonymous signups
      // are not deduplicated — every anonymous POST mints a fresh key.
      if (email) {
        const wantedLabel = `free-signup:${email}`;
        const existing = keys.list().find((k) =>
          k.label === wantedLabel && k.active !== false
        );
        if (existing) {
          logger.info('signup_free_already_exists', { tenant_id: existing.tenant_id });
          return res.type('html').send(landing.freeSignupHtml({
            apiKey: null,
            hmacSecret: null,
            expiresAt: null,
            alreadyExists: true,
            email,
          }));
        }
      }

      // Mint a fresh free-tier key. tenant_id is `free-<random>` so each
      // visitor gets an isolated tenant (no shared-quota collision). The
      // bearer scheme keeps the issued-on-form-submit UX simple — no
      // PEM key material to display.
      const tenantId = `free-${require('crypto').randomBytes(8).toString('hex')}`;
      const issued = keys.issue({
        tenantId,
        scheme: 'bearer',
        tier: 'free',
        package_id: 'free',
        label: email ? `free-signup:${email}` : 'free-signup',
      });

      logger.info('signup_free_issued', {
        tenant_id: tenantId,
        has_email: !!email,
      });

      res.type('html').send(landing.freeSignupHtml({
        apiKey: issued.plaintext,
        hmacSecret: issued.hmac_secret,
        expiresAt: issued.record.expires_at,
        alreadyExists: false,
        email,
      }));
    } catch (e) {
      logger.error('signup_free_failed', { error: e.message });
      res.status(500).type('html').send(
        `<p>Could not issue free-tier key: ${e.message}. ` +
        `Contact <a href="mailto:support@5ceos.com">support@5ceos.com</a>.</p>`
      );
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
  app.post('/v1/chat/completions', customerAuth, tenantLimiter, enforceDailyCap, enforcePackage, handleChatCompletions);

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

  // ---- Customer-driven rotation (Security Hardening Card: key lifecycle) ----
  //
  // POST /v1/keys/rotate — customerAuth-gated (works with both bearer +
  // ed25519). The caller MUST succeed authentication with their CURRENT
  // key. We issue a new key of the same scheme (bearer → bearer
  // plaintext; ed25519 → fresh ed25519 + x25519 keypair) inheriting
  // tenant_id / app_id / tier / package_id and CRUCIALLY the parent's
  // expires_at (rotation != renewal). The old record gets a 24h
  // rotation_grace_until stamp; during the grace window both keys
  // authenticate and the old key's responses carry X-Cogos-Key-Deprecated.
  // After grace, verify() auto-revokes the old record on next touch.
  //
  // KNOWN GAP (TODO future card): an attacker who already has the old
  // key can rotate it themselves — this protects against future leaks
  // but not the leak that's already happened. A human-in-the-loop
  // confirmation flow (email-the-original-customer-before-rotating)
  // closes that hole and is a separate card.
  //
  // Response shape mirrors POST /admin/keys so customer SDKs / the
  // cookbook recipe can share display logic.
  app.post('/v1/keys/rotate', customerAuth, tenantLimiter, (req, res) => {
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
      // app_id partitions the customer's keyspace + audit chain +
      // anomaly bucket. Null/undefined → keys.issue() defaults to
      // '_default' (validated in src/keys.js — slug shape, max 64).
      // Shape errors surface as 400.
      //
      // expires_at_iso (optional, lifecycle card): caller can override
      // the default 1-year expiration window. Past timestamps allowed
      // for operator testing — the auth path treats them as expired.
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

    // Common response fields; the scheme-specific secrets are added below.
    // hmac_secret is on the common branch because every customer (regardless
    // of bearer vs ed25519 auth) gets HMAC-signed /v1 responses they should
    // be able to verify. Without it on this response, operator-issued keys
    // have no way to verify the X-Cogos-Signature header.
    //
    // expires_at is surfaced so the customer + their SDK know when to
    // rotate. The default is 1 year from now; operator can override via
    // expires_at_iso on the request.
    const response = {
      key_id: record.id,
      tenant_id: record.tenant_id,
      app_id: record.app_id,
      tier: record.tier,
      scheme: requestedScheme,
      issued_at: record.issued_at,
      expires_at: record.expires_at,
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
      // x25519 sealing keypair: customer holds the private PEM and
      // uses it to decrypt sealed_content envelopes on /v1/audit rows.
      // The pubkey is also returned for the customer to verify the
      // value the server retained matches what they hold.
      response.x25519_private_pem = x25519_private_pem;
      response.x25519_pubkey_pem = x25519_pubkey_pem;
      response.warning = 'Save api material now. private_pem (auth) '
        + 'and x25519_private_pem (audit decryption) will not be shown '
        + 'again — they are NOT stored server-side.';
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

  // ---- Admin: quarantine surfaces (lifecycle card commit 3/3) ----
  //
  // List every key currently held in quarantine. Returned shape mirrors
  // /admin/keys listing so the operator dashboard can reuse the same
  // table component. Includes quarantine_reason for triage.
  app.get('/admin/keys/quarantined', adminAuth, (_req, res) => {
    res.json({ keys: keys.listQuarantined() });
  });

  // Clear quarantine. The operator decides the key is safe to return to
  // production. clearQuarantine() appends to quarantine_history so the
  // audit trail survives. 404 if no matching key; 409 if not currently
  // quarantined (caller would otherwise believe they cleared something
  // they didn't).
  app.post('/admin/keys/:id/clear-quarantine', adminAuth, (req, res) => {
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

  // ---- Operator analytics endpoints (X-Admin-Key gated) ----
  //
  // Aggregated, time-series-shaped JSON the 5CEOs Management Console
  // ("CogOS Analytics" tab) fetches to chart substrate activity. All
  // endpoints are READ-ONLY — none of them write state, mint keys,
  // call Stripe, or talk to anything off-host. Source data is the
  // same JSONL/JSON the gateway already writes (usage.jsonl,
  // anomalies.jsonl, notify-signups.jsonl, keys.json, packages.json).
  //
  // `since_ms` query parameter (optional): a unix-ms cutoff. Rows
  // older than this are excluded. Defaults to "now − 30 days." Must
  // be a non-negative integer; anything else falls back to the
  // 30-day default (we deliberately don't 400 on garbage so a
  // miswired dashboard can still render).
  //
  // Per-IP /admin/* rate limit (30/min, mounted upstream) still
  // applies — these endpoints are not bypassable from the wire.
  function parseSinceMs(q) {
    if (q == null || q === '') return undefined;
    const n = Number(q);
    if (!Number.isFinite(n) || n < 0) return undefined;
    return Math.floor(n);
  }

  app.get('/admin/analytics/summary', adminAuth, async (req, res) => {
    try {
      const sinceMs = parseSinceMs(req.query.since_ms);
      const out = await analytics.summary({ sinceMs });
      res.json(out);
    } catch (e) {
      logger.error('analytics_summary_failed', { error: e.message });
      res.status(500).json({ error: { message: e.message, type: 'analytics_failed' } });
    }
  });

  app.get('/admin/analytics/signups', adminAuth, async (req, res) => {
    try {
      const sinceMs = parseSinceMs(req.query.since_ms);
      res.json(await analytics.signupsByDay({ sinceMs }));
    } catch (e) {
      logger.error('analytics_signups_failed', { error: e.message });
      res.status(500).json({ error: { message: e.message, type: 'analytics_failed' } });
    }
  });

  app.get('/admin/analytics/requests', adminAuth, async (req, res) => {
    try {
      const sinceMs = parseSinceMs(req.query.since_ms);
      const granularity = req.query.granularity === 'day' ? 'day' : 'hour';
      res.json(await analytics.requestsByHour({ sinceMs, granularity }));
    } catch (e) {
      logger.error('analytics_requests_failed', { error: e.message });
      res.status(500).json({ error: { message: e.message, type: 'analytics_failed' } });
    }
  });

  app.get('/admin/analytics/anomalies', adminAuth, async (req, res) => {
    try {
      const sinceMs = parseSinceMs(req.query.since_ms);
      res.json(await analytics.anomaliesByKind({ sinceMs }));
    } catch (e) {
      logger.error('analytics_anomalies_failed', { error: e.message });
      res.status(500).json({ error: { message: e.message, type: 'analytics_failed' } });
    }
  });

  app.get('/admin/analytics/honeypots', adminAuth, async (req, res) => {
    try {
      const sinceMs = parseSinceMs(req.query.since_ms);
      res.json(await analytics.honeypotsByPath({ sinceMs }));
    } catch (e) {
      logger.error('analytics_honeypots_failed', { error: e.message });
      res.status(500).json({ error: { message: e.message, type: 'analytics_failed' } });
    }
  });

  app.get('/admin/analytics/rate-limits', adminAuth, async (req, res) => {
    try {
      const sinceMs = parseSinceMs(req.query.since_ms);
      res.json(await analytics.rateLimitsByDay({ sinceMs }));
    } catch (e) {
      logger.error('analytics_rate_limits_failed', { error: e.message });
      res.status(500).json({ error: { message: e.message, type: 'analytics_failed' } });
    }
  });

  app.get('/admin/analytics/tenants', adminAuth, async (req, res) => {
    try {
      const sinceMs = parseSinceMs(req.query.since_ms);
      res.json(await analytics.tenantsActive({ sinceMs }));
    } catch (e) {
      logger.error('analytics_tenants_failed', { error: e.message });
      res.status(500).json({ error: { message: e.message, type: 'analytics_failed' } });
    }
  });

  app.get('/admin/analytics/revenue', adminAuth, (_req, res) => {
    try {
      res.json(analytics.revenueSnapshot());
    } catch (e) {
      logger.error('analytics_revenue_failed', { error: e.message });
      res.status(500).json({ error: { message: e.message, type: 'analytics_failed' } });
    }
  });

  return app;
}

if (require.main === module) {
  const app = createApp();
  const port = Number(process.env.PORT || 4444);
  app.listen(port, async () => {
    logger.info('cogos_api_listening', { port });
    // Resolve the Data Encryption Key once at startup so the source is
    // visible in logs (env / file / generated). The DEK is the wrapping
    // key for HMAC secrets + the attestation signing PEM — both encrypted
    // at rest under AES-256-GCM. See src/dek.js + STATE.md.
    // We deliberately do NOT log the key path or the key itself.
    try {
      const dek = require('./dek');
      dek.getDek();
      logger.info('dek_resolved', { source: dek.getSource() });
    } catch (e) {
      logger.error('dek_resolution_failed', { error: e.message });
    }
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
