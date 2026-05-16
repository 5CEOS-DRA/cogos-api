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
const honeypot = require('./honeypot');
const anomaly = require('./anomaly');
const { rateLimitByIp, rateLimitByTenant } = require('./rate-limit');
const notifySignup = require('./notify-signup');
const dashboard = require('./dashboard');
const session = require('./session');
const dailyCap = require('./daily-cap');
const magicLink = require('./magic-link');
const auditCheckpoint = require('./audit-checkpoint');
const usageRollup = require('./usage-rollup');
const { makeAdminAnalyticsRouter } = require('./routers/admin-analytics');
const { makeAuditCheckpointRouter } = require('./routers/audit-checkpoint');
const { makePublicContentRouter } = require('./routers/public-content');
const { makeV1Router } = require('./routers/v1');
const { makeAdminRouter } = require('./routers/admin');

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

  // ---- Public read-only surface (no auth) ----
  // /health, /, /cancel, /cosign.pub, /attestation.pub, /terms, /privacy,
  // /aup, /dpa, /baa, /gdpr, /sub-processors, /whitepaper, /demo,
  // /cookbook, /trust. Implementation in src/routers/public-content.js.
  app.use(makePublicContentRouter());

  // ---- Public hash-chain checkpoint endpoints (no auth) ----
  // Security Hardening Plan card #3 — global witness for per-(tenant,
  // app_id) audit chains. Public by design. Implementation lives in
  // src/routers/audit-checkpoint.js.
  app.use('/audit', makeAuditCheckpointRouter());

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

      // Channel attribution. Captures referer + UTM params + user-agent
      // so the operator can answer "which distribution channel brings
      // devs". Truthful: a curl-direct signup has no referer and the
      // signup_source object documents that absence rather than faking
      // a source. Length-capped to avoid pathological inputs growing
      // keys.json. UTM params come from query string OR body (some
      // analytics tools post them as form fields). All fields optional.
      const trunc = (v, n) => (typeof v === 'string' ? v.slice(0, n) : null);
      const q = req.query || {};
      const b = req.body || {};
      const signupSource = {
        referer: trunc(req.headers['referer'] || req.headers['referrer'], 512),
        ua: trunc(req.headers['user-agent'], 256),
        ip: req.ip || null,
        utm_source:   trunc(q.utm_source   || b.utm_source,   128),
        utm_medium:   trunc(q.utm_medium   || b.utm_medium,   128),
        utm_campaign: trunc(q.utm_campaign || b.utm_campaign, 128),
        utm_content:  trunc(q.utm_content  || b.utm_content,  128),
        utm_term:     trunc(q.utm_term     || b.utm_term,     128),
        ts: new Date().toISOString(),
      };

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
        signup_source: signupSource,
      });

      logger.info('signup_free_issued', {
        tenant_id: tenantId,
        has_email: !!email,
        utm_source: signupSource.utm_source,
        utm_medium: signupSource.utm_medium,
        utm_campaign: signupSource.utm_campaign,
        referer_present: !!signupSource.referer,
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

  // ---- /v1/* customer-auth surface ----
  // /v1/models, /v1/chat/completions, /v1/audit, /v1/keys/rotate.
  // Implementation in src/routers/v1.js. tenantLimiter is constructed
  // here (not inside the router) so a single instance is shared across
  // every /v1/* route — its rate-limit buckets must not be duplicated.
  const tenantLimiter = rateLimitByTenant();
  app.use('/v1', makeV1Router({
    customerAuth, tenantLimiter,
    handleListModels, handleChatCompletions,
    enforceDailyCap, enforcePackage,
  }));

  // ---- /admin/* operator surface (X-Admin-Key gated) ----
  // Keys CRUD + quarantine, packages CRUD, usage log, SOC 2 evidence,
  // and the App-Insights-targeted /admin/health/deep endpoint.
  // Implementation in src/routers/admin.js.
  app.use("/admin", makeAdminRouter({ adminAuth }));

  // ---- Operator analytics endpoints (X-Admin-Key gated) ----
  // Aggregated, time-series-shaped JSON the 5CEOs Management Console
  // ("CogOS Analytics" tab) fetches. READ-ONLY; per-IP /admin/* rate
  // limit (30/min, mounted upstream) still applies. Implementation
  // lives in src/routers/admin-analytics.js.
  app.use('/admin/analytics', makeAdminAnalyticsRouter({ adminAuth }));

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
    // Start the public hash-chain checkpoint scheduler. Idempotent on
    // restart — if the last on-disk checkpoint is fresh, the next run
    // is delayed until CHECKPOINT_INTERVAL_MS has actually elapsed. See
    // src/audit-checkpoint.js for the genesis policy.
    try {
      auditCheckpoint.startScheduler();
      logger.info('audit_checkpoint_scheduler_started', {
        interval_ms: auditCheckpoint.CHECKPOINT_INTERVAL_MS,
      });
    } catch (e) {
      logger.error('audit_checkpoint_scheduler_failed', { error: e.message });
    }
    // Daily usage rollup — pre-aggregates yesterday's chunk of
    // usage.jsonl into data/usage-rollup-YYYY-MM-DD.json so analytics
    // streaming reads stay fast as usage.jsonl grows past ~10M rows.
    // Idempotent on restart — files already on disk are not recomputed.
    try {
      usageRollup.startScheduler();
      logger.info('usage_rollup_scheduler_started', {});
    } catch (e) {
      logger.error('usage_rollup_scheduler_failed', { error: e.message });
    }
  });
}

module.exports = { createApp };
