'use strict';

/**
 * internal-trust — HMAC signer for cogos-api → 5ceos-platform b-3 proxy.
 *
 * Mirrors backend/middleware/internalTrustAuth.js on the platform side.
 * SAME canonical message construction; if these drift, signatures will
 * mismatch and the platform returns 401. Treat the two files as a
 * locked pair — any change here MUST land in lockstep on the platform.
 *
 * Per project_cli_phase_2_acceptance_criteria_v0_1_2026_05_27 criterion A
 * + project_cli_server_side_gap_consolidation_pending_2026_05_27 Decision 1.
 *
 * Architecture:
 *   subscriber CLI → cogos-api /v1/* (sk-cogos-* auth)
 *                  ↓ this module signs + forwards
 *                  → platform /internal/* (HMAC auth via internalTrustAuth)
 *
 * Outbound error mapping (so we don't leak internal failure to subscriber):
 *   - Platform 401 internal_auth_* → cogos-api surfaces 503 upstream_unavailable
 *   - Platform 500 internal_*     → cogos-api surfaces 503 upstream_unavailable
 *   - Platform 2xx                → forward body as-is
 *   - Platform 4xx (not auth)     → forward (subscriber-facing validation errors)
 *
 * Env vars:
 *   COGOS_INTERNAL_HMAC_SECRET  — shared with platform; deploy-time set
 *   PLATFORM_INTERNAL_BASE      — e.g. "https://5ceos.com" (no trailing slash)
 */

const crypto = require('node:crypto');
const https = require('node:https');
const http = require('node:http');
const { URL } = require('node:url');

const HMAC_ALGORITHM = 'sha256';
const HEADER_AUTH = 'X-Cogos-Internal-Auth';
const HEADER_TS = 'X-Cogos-Internal-Ts';

function canonicalMessage(ts, method, path, body) {
  return `${ts}\n${method}\n${path}\n${body}`;
}

function signCanonical(secret, ts, method, path, body) {
  const msg = canonicalMessage(ts, method, path, body);
  return crypto.createHmac(HMAC_ALGORITHM, secret).update(msg, 'utf8').digest('hex');
}

// signRequest builds the canonical signature + headers for an outbound
// platform call. Returns { headers, ts, sig }; caller composes with
// existing fetch/https options. Path MUST include any query string.
function signRequest({ secret, method, path, body }) {
  if (!secret) throw new Error('signRequest: secret required');
  if (!method) throw new Error('signRequest: method required');
  if (!path) throw new Error('signRequest: path required');
  const bodyStr = typeof body === 'string' ? body : '';
  const ts = Date.now();
  const sig = signCanonical(secret, ts, method, path, bodyStr);
  return {
    ts,
    sig,
    headers: {
      [HEADER_AUTH]: sig,
      [HEADER_TS]: String(ts),
    },
  };
}

// proxyToPlatform — high-level helper: sign + dispatch + map auth errors
// to 503 so subscriber doesn't see internal HMAC details.
//
// Returns: { status, body (parsed JSON or raw string), headers }
// Auth/misconfig failures from platform (401 internal_auth_*, 500
// internal_*, 500 raw_body_*) are remapped to status=503 with
// { ok: false, error: 'upstream_unavailable' } body.
async function proxyToPlatform({ method, path, bodyJson, baseUrl, secret }) {
  const base = baseUrl || process.env.PLATFORM_INTERNAL_BASE;
  const sec = secret || process.env.COGOS_INTERNAL_HMAC_SECRET;
  if (!base) throw new Error('proxyToPlatform: PLATFORM_INTERNAL_BASE not set');
  if (!sec) throw new Error('proxyToPlatform: COGOS_INTERNAL_HMAC_SECRET not set');

  const bodyStr = bodyJson === undefined ? '' : JSON.stringify(bodyJson);
  const { headers } = signRequest({ secret: sec, method, path, body: bodyStr });

  const url = new URL(path, base);
  const lib = url.protocol === 'https:' ? https : http;

  return new Promise((resolve, reject) => {
    const req = lib.request(
      {
        method,
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname + (url.search || ''),
        headers: {
          ...headers,
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(bodyStr),
        },
      },
      (res) => {
        let chunks = '';
        res.on('data', (c) => { chunks += c.toString('utf8'); });
        res.on('end', () => {
          let parsed = chunks;
          try { parsed = JSON.parse(chunks); } catch (_e) { /* keep raw */ }
          const isInternalAuthFailure =
            (res.statusCode === 401 && parsed && typeof parsed === 'object' &&
              String(parsed.error || '').startsWith('internal_auth_')) ||
            (res.statusCode === 500 && parsed && typeof parsed === 'object' &&
              (parsed.error === 'internal_hmac_secret_missing' ||
                parsed.error === 'raw_body_not_captured'));
          if (isInternalAuthFailure) {
            resolve({
              status: 503,
              body: { ok: false, error: 'upstream_unavailable' },
              headers: {},
            });
            return;
          }
          resolve({ status: res.statusCode, body: parsed, headers: res.headers });
        });
      },
    );
    req.on('error', reject);
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

module.exports = {
  signRequest,
  signCanonical,
  canonicalMessage,
  proxyToPlatform,
  HEADER_AUTH,
  HEADER_TS,
};
