'use strict';

// Public "tell me when there's news" signup capture.
// Persists every submission to data/notify-signups.jsonl so nothing is
// lost. If RESEND_API_KEY (or any future relay) is configured, sends a
// real-time forward to NOTIFY_EMAIL. Without a relay configured, the
// data is still captured and queryable via the admin endpoint.

const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const logger = require('./logger');

const SIGNUPS_FILE = process.env.NOTIFY_SIGNUPS_FILE
  || path.join(process.cwd(), 'data', 'notify-signups.jsonl');
const NOTIFY_TO = process.env.NOTIFY_EMAIL || 'adams.denny@gmail.com';

// Basic RFC-compatible-enough email check. Not 100% complete (no IDN /
// punycode) — good enough to keep obvious garbage out without rejecting
// legit addresses. Stricter validation should happen at the relay layer.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function isValidEmail(s) {
  if (typeof s !== 'string') return false;
  if (s.length < 3 || s.length > 254) return false;
  return EMAIL_RE.test(s);
}

function ensureStore() {
  const dir = path.dirname(SIGNUPS_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (!fs.existsSync(SIGNUPS_FILE)) {
    fs.writeFileSync(SIGNUPS_FILE, '', { mode: 0o600 });
  }
}

function record({ email, source, ip, ua }) {
  ensureStore();
  const row = {
    ts: new Date().toISOString(),
    email: String(email).toLowerCase().trim(),
    source: source || 'landing',
    ip: ip || null,
    ua: ua || null,
  };
  fs.appendFileSync(SIGNUPS_FILE, JSON.stringify(row) + '\n');
  return row;
}

function list() {
  ensureStore();
  return fs.readFileSync(SIGNUPS_FILE, 'utf8')
    .split('\n')
    .filter((l) => l.trim())
    .map((l) => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);
}

// Forward via Resend if RESEND_API_KEY is configured. Best-effort:
// failures are logged but do NOT fail the signup flow — the row is
// already persisted. Pick Resend for v1 because it's a single HTTPS
// POST with no SDK, no SES setup, no SMTP outbound dance.
async function forwardViaResend(row) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) return { sent: false, reason: 'RESEND_API_KEY not configured' };
  const fromAddress = process.env.RESEND_FROM || 'notify@cogos.5ceos.com';
  const body = JSON.stringify({
    from: fromAddress,
    to: [NOTIFY_TO],
    subject: `[cogos-signup] ${row.email}`,
    text: `New signup\n\nemail: ${row.email}\nsource: ${row.source}\nip: ${row.ip}\nua: ${row.ua}\nts: ${row.ts}\n`,
  });
  return new Promise((resolve) => {
    const req = https.request({
      method: 'POST',
      hostname: 'api.resend.com',
      path: '/emails',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
      timeout: 5000,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ sent: true, status: res.statusCode });
        } else {
          resolve({ sent: false, reason: `resend ${res.statusCode}: ${text.slice(0, 120)}` });
        }
      });
    });
    req.on('error', (e) => resolve({ sent: false, reason: `resend error: ${e.message}` }));
    req.on('timeout', () => { req.destroy(); resolve({ sent: false, reason: 'resend timeout' }); });
    req.write(body);
    req.end();
  });
}

// Express handler. Public, no auth (rate-limit middleware in index.js
// caps the per-IP rate so this can't be turned into a spam relay).
async function handleSignup(req, res) {
  // Trim before validating so the rich-textbox auto-trailing-space pattern
  // doesn't bounce legitimate signups.
  const rawEmail = (req.body && req.body.email) || '';
  const email = String(rawEmail).trim();
  if (!isValidEmail(email)) {
    return res.status(400).type('html').send(thankPage({
      ok: false,
      message: 'That email did not look right. Go back and try again.',
    }));
  }
  let row;
  try {
    row = record({
      email,
      source: (req.body && req.body.source) || 'landing',
      ip: req.ip || null,
      ua: req.headers['user-agent'] || null,
    });
  } catch (e) {
    logger.error('notify_signup_record_failed', { error: e.message });
    return res.status(500).type('html').send(thankPage({
      ok: false,
      message: 'Couldn\'t save your email. Try again in a minute.',
    }));
  }
  logger.info('notify_signup_received', { email: row.email, source: row.source, ip: row.ip });
  // Fire-and-forget forwarding; don't block the response on it.
  forwardViaResend(row).then((r) => {
    if (r.sent) logger.info('notify_signup_forwarded', { email: row.email, status: r.status });
    else logger.warn('notify_signup_forward_skipped', { email: row.email, reason: r.reason });
  }).catch((e) => logger.warn('notify_signup_forward_error', { error: e.message }));

  res.type('html').send(thankPage({ ok: true, email: row.email }));
}

function thankPage({ ok, email, message }) {
  const titleText = ok ? 'You&apos;re on the list' : 'Something went wrong';
  const bodyText = ok
    ? `Thanks &mdash; we&apos;ll email <code>${escapeHtml(email)}</code> when there&apos;s news. No spam, no upsells, no third-party trackers.`
    : escapeHtml(message || 'Please go back and try again.');
  return `<!DOCTYPE html>
<html>
<head>
  <title>${titleText} &mdash; CogOS</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    body{font-family:ui-monospace,SF Mono,Menlo,monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:48px 20px;line-height:1.65}
    main{max-width:560px;margin:0 auto;text-align:center}
    h1{color:${ok ? '#3fb950' : '#f85149'};font-size:22px;margin:0 0 14px}
    p{color:#c9d1d9;font-size:14px;margin:0 0 18px}
    code{background:#161b22;padding:2px 6px;border-radius:3px;color:#79c0ff;font-size:13px}
    a{display:inline-block;margin-top:18px;background:#238636;color:#fff;padding:10px 22px;border-radius:6px;text-decoration:none;font-size:13px}
    a:hover{background:#2ea043}
  </style>
</head>
<body>
<main>
  <h1>${titleText}.</h1>
  <p>${bodyText}</p>
  <a href="/">&larr; back to CogOS</a>
</main>
</body>
</html>`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

module.exports = {
  handleSignup,
  list,
  isValidEmail,
  _internal: { record, thankPage },
};
