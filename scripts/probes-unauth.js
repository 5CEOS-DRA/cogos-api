#!/usr/bin/env node
// Node port of scripts/probes-unauth.sh — runs the same continuous probes
// from inside the distroless cogos-api image, which has no bash.
// Same env-var contract: HOST overrides the target, PROBE_HISTORY_FILE
// receives a JSONL append on completion.

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');

const HOST = process.env.HOST || 'https://cogos.5ceos.com';
const HISTORY = process.env.PROBE_HISTORY_FILE || '';

let pass = 0;
let fail = 0;
const fails = [];

function ok(msg) { console.log(`  [PASS] ${msg}`); pass++; }
function bad(msg) { console.log(`  [FAIL] ${msg}`); fail++; fails.push(msg); }

function fetch(urlStr, opts = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlStr);
    const req = https.request({
      method: opts.method || 'GET',
      hostname: url.hostname,
      port: url.port || 443,
      path: url.pathname + url.search,
      headers: opts.headers || {},
      timeout: 15000,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(new Error('timeout')); });
    req.end();
  });
}

async function probe(name, fn) {
  try { await fn(); }
  catch (e) { bad(`${name}: ${e.message}`); }
}

async function main() {
  console.log(`[probes-unauth] target=${HOST}`);

  // Honeypot canary content
  for (const p of ['/.env', '/.aws/credentials', '/.git/config', '/wp-admin', '/backup.sql']) {
    await probe(`honeypot ${p}`, async () => {
      const r = await fetch(HOST + p);
      if (/HONEYPOT|EXAMPLE|fake/i.test(r.body)) ok(`honeypot ${p} returns canary content`);
      else bad(`honeypot ${p} missing canary markers`);
    });
  }
  // Case + slash variants (the 2026-05-14 finding must stay closed)
  for (const p of ['/.ENV', '/Wp-Admin', '/Backup.SQL', '/.env/']) {
    await probe(`variant ${p}`, async () => {
      const r = await fetch(HOST + p);
      if (r.status === 200) ok(`honeypot variant ${p} trips trap (200)`);
      else bad(`honeypot variant ${p} bypasses trap (${r.status})`);
    });
  }

  // /admin/* and /v1/* reject without auth
  for (const p of ['/admin/keys', '/admin/usage', '/admin/packages', '/v1/models', '/v1/audit']) {
    await probe(`auth-required ${p}`, async () => {
      const r = await fetch(HOST + p);
      if (r.status === 401) ok(`${p} → 401 without auth`);
      else bad(`${p} → ${r.status} (expected 401)`);
    });
  }

  // /admin/live must stay 404
  await probe('/admin/live removed', async () => {
    const r = await fetch(HOST + '/admin/live');
    if (r.status === 404) ok('/admin/live → 404 (removed in v15)');
    else bad(`/admin/live → ${r.status} (route resurrection?)`);
  });

  // No source / config file leakage
  for (const p of ['/SECURITY.md', '/STATE.md', '/package.json', '/Dockerfile', '/src/index.js', '/tests/api.test.js', '/.gitignore']) {
    await probe(`no leak ${p}`, async () => {
      const r = await fetch(HOST + p);
      if (r.status === 404) ok(`${p} → 404`);
      else bad(`${p} → ${r.status} (file leak?)`);
    });
  }

  // Security headers
  for (const p of ['/', '/health', '/cosign.pub', '/attestation.pub', '/.env']) {
    await probe(`headers ${p}`, async () => {
      const r = await fetch(HOST + p);
      const h = r.headers;
      const has = (k) => k in h;
      if (has('content-security-policy') && has('strict-transport-security') && has('x-frame-options') && has('x-content-type-options')) {
        ok(`${p} carries CSP + HSTS + X-Frame + X-Content-Type`);
      } else {
        bad(`${p} missing one or more required security headers`);
      }
    });
  }

  // Public pubkey endpoints
  for (const [p, label] of [['/cosign.pub', 'cosign'], ['/attestation.pub', 'attestation']]) {
    await probe(label, async () => {
      const r = await fetch(HOST + p);
      if (/-----BEGIN [A-Z ]*PUBLIC KEY-----/.test(r.body)) ok(`${p} serves a PEM`);
      else bad(`${p} not a PEM (status=${r.status})`);
    });
  }

  // Policy + trust pages reachable
  for (const p of ['/terms', '/privacy', '/aup', '/dpa', '/baa', '/gdpr', '/sub-processors', '/trust', '/cookbook', '/whitepaper', '/demo']) {
    await probe(`reachable ${p}`, async () => {
      const r = await fetch(HOST + p);
      if (r.status === 200) ok(`${p} → 200`);
      else bad(`${p} → ${r.status}`);
    });
  }

  console.log('');
  console.log('============================================================');
  console.log(`[probes-unauth] ${pass} pass, ${fail} fail`);
  if (fail > 0) fails.forEach((f) => console.log(`  - ${f}`));
  else console.log('[probes-unauth] all unauth probes clean.');
  console.log('============================================================');

  if (HISTORY) {
    try {
      fs.mkdirSync(path.dirname(HISTORY), { recursive: true });
      const entry = {
        ts: new Date().toISOString(),
        kind: 'probes-unauth',
        status: fail === 0 ? 'pass' : 'fail',
        pass, fail,
        failures: fails,
        host: HOST,
      };
      fs.appendFileSync(HISTORY, JSON.stringify(entry) + '\n');
    } catch (e) {
      console.error(`[probes-unauth] could not write PROBE_HISTORY_FILE=${HISTORY}: ${e.message}`);
    }
  }

  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(`[probes-unauth] runner failed: ${e.message}`);
  process.exit(2);
});
