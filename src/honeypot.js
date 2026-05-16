'use strict';

// Honeypot middleware.
//
// Sits early in the stack (after securityHeaders, before the JSON body
// parser, before every real route) and intercepts well-known scanner
// targets — leaked .env paths, .git/, .aws/, WordPress + phpMyAdmin
// login surfaces, fake API versions, fake admin panels, fake SQL dumps.
//
// For each path we return a plausible-looking response so the scanner
// thinks it found something, BUT every secret-shaped value embedded in
// the response is an obvious canary token:
//
//   - AWS keys use the AWS-published example key (AKIAIOSFODNN7EXAMPLE)
//     which is universally recognized as fake / triggers GuardDuty.
//   - Passwords, DB connection strings, and API keys all carry
//     HONEYPOT / REPORT_TO_SECURITY_AT_5CEOS_COM markers in their value.
//
// An attacker who scrapes credentials from /.env here and tries to use
// them either (a) hits a canary alert or (b) finds the credentials
// don't work and the format is obviously bogus on inspection. They
// must NEVER look real enough to pass a sanity check — that would
// undermine the whole purpose.
//
// We log every hit at WARN level. The middleware is terminal for the
// matched paths — it returns the response and never calls next().
//
// Hits are ALSO persisted to data/honeypots.jsonl via appendHit() so
// the operator analytics endpoint (/admin/analytics/honeypots) can
// surface real time-series numbers — see src/analytics.js. The append
// is fail-safe via src/event-log.js: a disk error logs at WARN and
// returns; the canary response still ships.

const path = require('path');
const logger = require('./logger');
const eventLog = require('./event-log');

// File-path resolver. Honors HONEYPOTS_FILE for test/operator overrides
// (tests point this at a tmpdir so the repo data/ folder stays clean);
// defaults to data/honeypots.jsonl under process.cwd() to match the
// convention used by src/notify-signup.js (SIGNUPS_FILE).
function honeypotsFile() {
  return process.env.HONEYPOTS_FILE
    || path.join(process.cwd(), 'data', 'honeypots.jsonl');
}

// Append one honeypot-hit row. Schema is fixed:
//
//   { ts, path, normalized_path, method, ip, ua, country }
//
// `country` is null in v1 — a future card can enrich via GeoIP at the
// edge or operator-side lookup. `normalized_path` is the lowercased +
// trailing-slash-stripped form the lookup actually used (so scanner
// variants `/.ENV` and `/.env/` both map to `/.env` for aggregation).
function appendHit(row) {
  return eventLog.appendEvent(honeypotsFile(), row);
}

// ---------------------------------------------------------------------------
// Canary tokens. These appear verbatim inside the response bodies. They are
// the single point of truth — change them in one place and every honeypot
// updates.
// ---------------------------------------------------------------------------
const TOKEN = 'HONEYPOT_TOKEN_REPORT_TO_SECURITY_AT_5CEOS_COM';
// AWS-published example access key — universally fake; GuardDuty knows it.
const FAKE_AWS_AK = 'AKIAIOSFODNN7EXAMPLE';
const FAKE_AWS_SK = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
const FAKE_PG_URL = 'postgresql://honeypot:HONEYPOT@db.fake.invalid:5432/honeypot';
const FAKE_STRIPE = 'sk_test_HONEYPOT_NOT_A_REAL_KEY_REPORT_TO_5CEOS';

// ---------------------------------------------------------------------------
// Fake response bodies.
// ---------------------------------------------------------------------------
const FAKE_ENV = [
  '# cogos-api .env',
  'NODE_ENV=production',
  'DATABASE_URL=' + FAKE_PG_URL,
  'STRIPE_SECRET_KEY=' + FAKE_STRIPE,
  'AWS_ACCESS_KEY_ID=' + FAKE_AWS_AK,
  'AWS_SECRET_ACCESS_KEY=' + FAKE_AWS_SK,
  'ADMIN_KEY=' + TOKEN,
  'JWT_SECRET=' + TOKEN,
  'password=' + TOKEN,
  '',
].join('\n');

const FAKE_GIT_CONFIG = [
  '[core]',
  '\trepositoryformatversion = 0',
  '\tfilemode = true',
  '\tbare = false',
  '\tlogallrefupdates = true',
  '[remote "origin"]',
  '\turl = https://github.com/honeypot/' + TOKEN + '.git',
  '\tfetch = +refs/heads/*:refs/remotes/origin/*',
  '[branch "main"]',
  '\tremote = origin',
  '\tmerge = refs/heads/main',
  '',
].join('\n');

const FAKE_GIT_HEAD = 'ref: refs/heads/main\n';

const FAKE_AWS_CREDENTIALS = [
  '[default]',
  'aws_access_key_id = ' + FAKE_AWS_AK,
  'aws_secret_access_key = ' + FAKE_AWS_SK,
  '',
  '[' + TOKEN + ']',
  'aws_access_key_id = ' + FAKE_AWS_AK,
  'aws_secret_access_key = ' + FAKE_AWS_SK,
  '',
].join('\n');

const FAKE_AWS_CONFIG = [
  '[default]',
  'region = us-east-1',
  'output = json',
  '',
  '# ' + TOKEN,
  '',
].join('\n');

const FAKE_WP_LOGIN = [
  '<!DOCTYPE html>',
  '<html><head><title>Log In &lsaquo; WordPress</title>',
  '<meta name="generator" content="WordPress 6.4.1">',
  '</head><body class="login wp-core-ui">',
  '<div id="login">',
  '<h1><a href="https://wordpress.org/">WordPress</a></h1>',
  '<form name="loginform" id="loginform" action="wp-login.php" method="post">',
  '<p><label>Username<input type="text" name="log" id="user_login"></label></p>',
  '<p><label>Password<input type="password" name="pwd" id="user_pass"></label></p>',
  '<p class="submit"><input type="submit" name="wp-submit" value="Log In"></p>',
  '</form>',
  '<!-- ' + TOKEN + ' -->',
  '</div></body></html>',
].join('\n');

const FAKE_XMLRPC = [
  '<?xml version="1.0"?>',
  '<methodResponse><params><param><value><string>XML-RPC server accepts POST requests only.</string></value></param></params></methodResponse>',
  '<!-- ' + TOKEN + ' -->',
].join('\n');

const FAKE_PHPMYADMIN = [
  '<!DOCTYPE html>',
  '<html><head><title>phpMyAdmin</title>',
  '<meta name="generator" content="phpMyAdmin 5.2.1">',
  '</head><body>',
  '<div id="page_content"><form method="post" action="index.php">',
  '<label>Username<input type="text" name="pma_username"></label>',
  '<label>Password<input type="password" name="pma_password"></label>',
  '<input type="submit" value="Go">',
  '</form></div>',
  '<!-- phpmyadmin honeypot — ' + TOKEN + ' -->',
  '</body></html>',
].join('\n');

const FAKE_SERVER_STATUS = [
  '<!DOCTYPE html><html><head><title>Apache Status</title></head><body>',
  '<h1>Apache Server Status for localhost (via 127.0.0.1)</h1>',
  '<dl>',
  '<dt>Server Version: Apache/2.4.57 (Unix)</dt>',
  '<dt>Server Built: ' + TOKEN + '</dt>',
  '<dt>Current Time: ' + new Date().toUTCString() + '</dt>',
  '<dt>Total accesses: 0 - Total Traffic: 0 kB</dt>',
  '</dl>',
  '</body></html>',
].join('\n');

const FAKE_ADMIN_LOGIN = [
  '<!DOCTYPE html>',
  '<html><head><title>Admin Login</title></head><body>',
  '<h1>Administrator Login</h1>',
  '<form method="post" action="">',
  '<label>Username<input type="text" name="username"></label>',
  '<label>Password<input type="password" name="password" placeholder="' + TOKEN + '"></label>',
  '<input type="submit" value="Login">',
  '</form>',
  '<!-- ' + TOKEN + ' -->',
  '</body></html>',
].join('\n');

// .DS_Store — return non-printing bytes that look like a real one would
// from the outside (it really is a binary plist-ish blob). We embed the
// canary token inside the byte buffer so a hex-dump still reveals it.
const FAKE_DS_STORE = Buffer.concat([
  Buffer.from([0x00, 0x00, 0x00, 0x01, 0x42, 0x75, 0x64, 0x31, 0x00, 0x00, 0x10, 0x00]),
  Buffer.from(TOKEN, 'utf8'),
  Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
]);

const FAKE_SQL_DUMP = [
  '-- MySQL dump 10.13 ' + TOKEN,
  '-- Host: db.fake.invalid    Database: honeypot',
  '-- ------------------------------------------------------',
  '-- Server version    8.0.35',
  '',
  'CREATE TABLE `users` (',
  '  `id` int NOT NULL AUTO_INCREMENT,',
  '  `email` varchar(255) NOT NULL,',
  '  `password_hash` varchar(255) NOT NULL,',
  '  PRIMARY KEY (`id`)',
  ') ENGINE=InnoDB;',
  '',
  "INSERT INTO `users` VALUES (1,'admin@honeypot.invalid','" + TOKEN + "');",
  '',
  '-- Dump completed',
  '',
].join('\n');

// ---------------------------------------------------------------------------
// Route table. Order matters only for the regex catch-all at the end.
// ---------------------------------------------------------------------------
function sendText(res, status, body) {
  res.status(status).type('text/plain; charset=utf-8').send(body);
}
function sendHtml(res, status, body) {
  res.status(status).type('text/html; charset=utf-8').send(body);
}
function sendJson(res, status, body) {
  res.status(status).type('application/json; charset=utf-8').send(JSON.stringify(body));
}
function sendBytes(res, status, buf, mime) {
  res.status(status).type(mime || 'application/octet-stream').send(buf);
}

const EXACT = {
  '/.env':            (_req, res) => sendText(res, 200, FAKE_ENV),
  '/.env.local':      (_req, res) => sendText(res, 200, FAKE_ENV),
  '/.env.production': (_req, res) => sendText(res, 200, FAKE_ENV),
  '/.git/config':     (_req, res) => sendText(res, 200, FAKE_GIT_CONFIG),
  '/.git/HEAD':       (_req, res) => sendText(res, 200, FAKE_GIT_HEAD),
  '/.aws/credentials': (_req, res) => sendText(res, 200, FAKE_AWS_CREDENTIALS),
  '/.aws/config':     (_req, res) => sendText(res, 200, FAKE_AWS_CONFIG),
  '/wp-admin':        (_req, res) => sendHtml(res, 200, FAKE_WP_LOGIN),
  '/wp-admin/':       (_req, res) => sendHtml(res, 200, FAKE_WP_LOGIN),
  '/wp-login.php':    (_req, res) => sendHtml(res, 200, FAKE_WP_LOGIN),
  '/xmlrpc.php':      (_req, res) => sendText(res, 200, FAKE_XMLRPC),
  '/phpmyadmin/':     (_req, res) => sendHtml(res, 200, FAKE_PHPMYADMIN),
  '/phpmyadmin/index.php': (_req, res) => sendHtml(res, 200, FAKE_PHPMYADMIN),
  '/server-status':   (_req, res) => sendHtml(res, 200, FAKE_SERVER_STATUS),
  '/server-info':     (_req, res) => sendHtml(res, 200, FAKE_SERVER_STATUS),
  '/admin.php':       (_req, res) => sendHtml(res, 200, FAKE_ADMIN_LOGIN),
  '/administrator/':  (_req, res) => sendHtml(res, 200, FAKE_ADMIN_LOGIN),
  '/login.php':       (_req, res) => sendHtml(res, 200, FAKE_ADMIN_LOGIN),
  '/.DS_Store':       (_req, res) => sendBytes(res, 200, FAKE_DS_STORE, 'application/octet-stream'),
  '/sitemap.xml.gz':  (_req, res) => sendText(res, 200, FAKE_SQL_DUMP),
  '/backup.sql':      (_req, res) => sendText(res, 200, FAKE_SQL_DUMP),
  '/database.sql':    (_req, res) => sendText(res, 200, FAKE_SQL_DUMP),
  '/dump.sql':        (_req, res) => sendText(res, 200, FAKE_SQL_DUMP),
};

// /api/v0/*, /api/v2/*, /api/v3/* — API versions we don't ship. Return
// what a real OpenAI-style stack would emit for a bad token: 401 JSON.
// This keeps scanners from inferring "this is a honeypot" by looking at
// the error shape — it matches the live /v1/* error shape closely
// enough to be ambiguous without burning the canary.
const FAKE_API_VERSIONS = /^\/api\/v(0|2|3)(\/|$)/;

// Normalize path before honeypot lookup so trivial scanner variations
// (mixed-case, trailing slash) all trip the trap. Pentest finding
// 2026-05-14: `/.ENV`, `/Wp-Admin`, `/.env/` previously bypassed the
// honeypot and got a real 404, leaking signal to systematic scanners.
function normalizePath(p) {
  let n = String(p || '/');
  if (n.length > 1 && n.endsWith('/')) n = n.slice(0, -1);
  return n.toLowerCase();
}

function isHoneypotPath(p) {
  const n = normalizePath(p);
  if (Object.prototype.hasOwnProperty.call(EXACT, n)) return true;
  if (FAKE_API_VERSIONS.test(n)) return true;
  return false;
}

function honeypot(req, res, next) {
  const p = req.path;
  if (!isHoneypotPath(p)) return next();

  const n = normalizePath(p);
  const ip = req.ip || (req.socket && req.socket.remoteAddress) || null;
  const ua = (req.headers && req.headers['user-agent']) || null;

  logger.warn('honeypot_hit', {
    path: p,
    ip,
    ua,
    method: req.method,
  });

  // Persist the hit for analytics. appendHit is fail-safe — a disk
  // error logs at WARN and returns; the canary response still ships.
  appendHit({
    ts: new Date().toISOString(),
    path: p,
    normalized_path: n,
    method: req.method,
    ip,
    ua,
    country: null,
  });

  if (FAKE_API_VERSIONS.test(n)) {
    return sendJson(res, 401, { error: 'invalid token' });
  }
  const handler = EXACT[n];
  return handler(req, res);
}

module.exports = honeypot;
module.exports.isHoneypotPath = isHoneypotPath;
module.exports.appendHit = appendHit;
module.exports.honeypotsFile = honeypotsFile;
module.exports._TOKEN = TOKEN; // exported for test introspection only
