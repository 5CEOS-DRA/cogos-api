'use strict';

// Public-content router — extracted from src/index.js.
//
// Holds every customer-visible read-only page that doesn't require
// auth: landing, /health, legal pages, whitepaper, demo, cookbook,
// /trust transparency dashboard, /cosign.pub + /attestation.pub key
// material. All pure delegates to existing render helpers; no local
// state, no closures.
//
// Per-IP rate limit (mounted upstream in src/index.js) still applies.

const express = require('express');
const fs = require('node:fs');
const landing = require('../landing');
const legal = require('../legal');
const whitepaper = require('../whitepaper');
const demo = require('../demo');
const cookbook = require('../cookbook');
const trust = require('../trust');
const attestation = require('../attestation');
const packages = require('../packages');

function makePublicContentRouter() {
  const router = express.Router();

  // Content-negotiated health: HTML for browsers, JSON for monitors/curl/supertest.
  router.get('/health', (req, res) => {
    const data = {
      status: 'ok',
      service: 'cogos-api',
      version: '0.1.0',
      uptime_s: Math.round(process.uptime()),
      timestamp: new Date().toISOString(),
    };
    res.format({
      'application/json': () => res.json(data),
      'text/html': () => res.type('html').send(landing.healthHtml(data)),
      default: () => res.json(data),
    });
  });

  router.get('/', (_req, res) => {
    res.type('html').send(landing.renderLandingHtml(packages.list()));
  });
  router.get('/cancel', (_req, res) => res.type('html').send(landing.CANCEL_HTML));

  // Cosign verification pubkey (customers + auditors fetch this to verify
  // cosigned container images). Source: COSIGN_PUBKEY_PEM env (full PEM)
  // or COSIGN_PUBKEY_FILE (path to a PEM file). Both unset → 404 with a
  // hint so the URL doesn't 500.
  router.get('/cosign.pub', (_req, res) => {
    const pem = process.env.COSIGN_PUBKEY_PEM
      || (process.env.COSIGN_PUBKEY_FILE
          ? (() => { try { return fs.readFileSync(process.env.COSIGN_PUBKEY_FILE, 'utf8'); } catch { return null; } })()
          : null);
    if (!pem) {
      return res.status(404).type('text/plain').send(
        '# cosign pubkey not yet published\n'
        + '# Set COSIGN_PUBKEY_PEM or COSIGN_PUBKEY_FILE on the deployed container.\n'
      );
    }
    res.type('text/plain').send(pem);
  });

  // Per-response attestation pubkey. Companion to /cosign.pub for the
  // X-Cogos-Attestation header on /v1/* responses. Ephemeral per process —
  // container restart rotates it. See src/attestation.js.
  router.get('/attestation.pub', (_req, res) => {
    res.set('X-Cogos-Attestation-Kid', attestation.getAttestationKid());
    res.type('text/plain').send(attestation.getAttestationPubkey());
  });

  // Legal pages — required for Stripe activation, all public, no auth.
  router.get('/terms', (_req, res) => res.type('html').send(legal.termsHtml()));
  router.get('/privacy', (_req, res) => res.type('html').send(legal.privacyHtml()));
  router.get('/aup', (_req, res) => res.type('html').send(legal.aupHtml()));
  router.get('/dpa', (_req, res) => res.type('html').send(legal.dpaHtml()));
  router.get('/baa', (_req, res) => res.type('html').send(legal.baaHtml()));
  router.get('/gdpr', (_req, res) => res.type('html').send(legal.gdprArt28Html()));
  router.get('/sub-processors', (_req, res) => res.type('html').send(legal.subProcessorsHtml()));
  router.get('/whitepaper', (_req, res) => res.type('html').send(whitepaper.whitepaperHtml()));
  router.get('/demo', (_req, res) => res.type('html').send(demo.demoHtml()));
  router.get('/cookbook', (_req, res) => res.type('html').send(cookbook.cookbookHtml()));

  // Trust / transparency dashboard. Modeled on trust.salesforce.com.
  // healthOk=true here by definition (we're servicing the request).
  router.get('/trust', (_req, res) => {
    const state = trust.buildTrustState({ healthOk: true });
    res.type('html').send(trust.trustHtml(state));
  });

  return router;
}

module.exports = { makePublicContentRouter };
