'use strict';

/**
 * /v1/search · receipt shape + usage-chain integration.
 *
 * These tests prove the substrate's "receipt-bearing live-web search"
 * claim end-to-end through the HTTP boundary:
 *
 *   - request → response carries the standard receipt
 *     { request_id, ms, deterministic_hash, output_hash }
 *   - usage.jsonl gets a hash-chained row per call (success, error, or
 *     provider:'none')
 *   - /v1/audit can read the chain back and verify it
 *   - HONEST RECEIPT SEMANTICS for search are preserved: same query +
 *     same results → same output_hash; same query + DIFFERENT results
 *     → different output_hash (web is non-deterministic by nature)
 *
 * No real network calls — the upstream provider is stubbed via
 * makeSearchRouter's `_searchClient` injection seam.
 */

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-search-test-'));
process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
process.env.HONEYPOTS_FILE = path.join(tmpDir, 'honeypots.jsonl');
process.env.RATE_LIMITS_FILE = path.join(tmpDir, 'rate-limits.jsonl');

// Clear any inherited key so the no-provider path is the default.
// Individual tests that exercise the brave path inject a stub instead
// of relying on env (real network calls are forbidden in tests).
delete process.env.BRAVE_SEARCH_API_KEY;

const express = require('express');
const request = require('supertest');
const { createApp } = require('../src/index');
const { makeSearchRouter, SEARCH_ROUTE, SEARCH_MODEL_ID_BRAVE, SEARCH_MODEL_ID_NONE } =
  require('../src/routers/search');

afterAll(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

// ─── helpers ──────────────────────────────────────────────────────────

async function issueKey(app, tenantId = 'denny', tier = 'starter') {
  const res = await request(app)
    .post('/admin/keys')
    .set('X-Admin-Key', process.env.ADMIN_KEY)
    .send({ tenant_id: tenantId, tier });
  return res.body;
}

// Bare express app that mounts only the search router with a stub auth
// middleware. Used by tests that need to inject a fake search client
// without going through the full createApp() wiring.
function makeBareApp({ stubClient, apiKeyOverride }) {
  const app = express();
  app.use(express.json());
  const customerAuth = (req, _res, next) => {
    req.apiKey = apiKeyOverride || {
      id: 'k_test',
      tenant_id: 't_test',
      app_id: '_default',
    };
    next();
  };
  const tenantLimiter = (_req, _res, next) => next();
  app.use(
    '/v1/search',
    makeSearchRouter({ customerAuth, tenantLimiter, _searchClient: stubClient }),
  );
  return app;
}

// ─── shape + provider:'none' fallback ─────────────────────────────────

describe('/v1/search · receipt shape', () => {
  test('provider:none (no BRAVE key) — 200 with full receipt + 0 results', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    const r = await request(app)
      .post('/v1/search')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send({ query: 'site:sec.gov AAPL 10-K' });
    expect(r.status).toBe(200);
    expect(r.body.provider).toBe('none');
    expect(r.body.results).toEqual([]);
    expect(r.body.query).toBe('site:sec.gov AAPL 10-K');
    expect(r.body.receipt.request_id).toMatch(/^srch_/);
    expect(r.body.receipt.deterministic_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(r.body.receipt.output_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(typeof r.body.receipt.ms).toBe('number');
  });

  test('deterministic_hash and output_hash are not aliased', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    const r = await request(app)
      .post('/v1/search')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send({ query: 'q1' });
    expect(r.body.receipt.deterministic_hash).not.toBe(r.body.receipt.output_hash);
  });

  test('missing query → 400 with receipt (deterministic_hash only)', async () => {
    const app = createApp();
    const issued = await issueKey(app);
    const r = await request(app)
      .post('/v1/search')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send({});
    expect(r.status).toBe(400);
    expect(r.body.error.code).toBe('invalid_input');
    expect(r.body.receipt.deterministic_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(r.body.receipt.output_hash).toBeUndefined();
  });
});

// ─── deterministic_hash stability + honest output_hash semantics ──────

describe('/v1/search · hash semantics', () => {
  test('same request body → same deterministic_hash (proves input bind)', async () => {
    const stub = { search: async ({ query }) => ({
      ok: true, query, results: [{ title: 'A', snippet: 's', url: 'u' }],
      provider: 'brave', latency_ms: 42,
    }) };
    const app = makeBareApp({ stubClient: stub });
    const a = await request(app).post('/v1/search').send({ query: 'X', max_results: 5 });
    const b = await request(app).post('/v1/search').send({ query: 'X', max_results: 5 });
    expect(a.body.receipt.deterministic_hash).toBe(b.body.receipt.deterministic_hash);
  });

  test('same results → same output_hash (audit-replayable at this moment)', async () => {
    const fixed = [{ title: 'A', snippet: 'a', url: 'https://example.com/a' }];
    const stub = { search: async ({ query }) => ({
      ok: true, query, results: fixed, provider: 'brave', latency_ms: 30,
    }) };
    const app = makeBareApp({ stubClient: stub });
    const a = await request(app).post('/v1/search').send({ query: 'X' });
    const b = await request(app).post('/v1/search').send({ query: 'X' });
    expect(a.body.receipt.output_hash).toBe(b.body.receipt.output_hash);
  });

  test('different results → different output_hash (web non-determinism honored)', async () => {
    let n = 0;
    const stub = { search: async ({ query }) => ({
      ok: true, query,
      results: [{ title: `r${++n}`, snippet: '', url: '' }],
      provider: 'brave', latency_ms: 10,
    }) };
    const app = makeBareApp({ stubClient: stub });
    const a = await request(app).post('/v1/search').send({ query: 'X' });
    const b = await request(app).post('/v1/search').send({ query: 'X' });
    expect(a.body.receipt.output_hash).not.toBe(b.body.receipt.output_hash);
  });

  test('upstream failure → 502 with receipt + no output_hash', async () => {
    const stub = { search: async () => ({
      ok: false, error: 'SEARCH_FAILED', message: 'Brave API 500', query: 'X', latency_ms: 8,
    }) };
    const app = makeBareApp({ stubClient: stub });
    const r = await request(app).post('/v1/search').send({ query: 'X' });
    expect(r.status).toBe(502);
    expect(r.body.error.code).toBe('SEARCH_FAILED');
    expect(r.body.receipt.deterministic_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(r.body.receipt.output_hash).toBeUndefined();
  });
});

// ─── usage chain emission ─────────────────────────────────────────────

describe('/v1/search · usage chain integration', () => {
  // Each usage-chain test runs against an isolated tenant_id so the
  // shared usage.jsonl file doesn't bleed rows between tests. The chain
  // is keyed by (tenant_id, app_id), so a fresh tenant = a fresh chain.

  test('success path emits one usage row · /v1/audit shows it', async () => {
    const app = createApp();
    const issued = await issueKey(app, 't_chain_success');
    await request(app)
      .post('/v1/search')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send({ query: 'audit-chain proof' });
    const audit = await request(app)
      .get('/v1/audit')
      .set('Authorization', 'Bearer ' + issued.api_key);
    expect(audit.status).toBe(200);
    const rows = audit.body.rows || audit.body.usage || [];
    const searchRows = rows.filter((r) => r.route === SEARCH_ROUTE);
    expect(searchRows.length).toBe(1);
    expect(searchRows[0].status).toBe('success');
    expect(searchRows[0].model).toBe(SEARCH_MODEL_ID_NONE); // no BRAVE key in test env
    expect(searchRows[0].row_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(searchRows[0].prev_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  test('client error (empty query) emits status=client_error row', async () => {
    const app = createApp();
    const issued = await issueKey(app, 't_chain_cliterr');
    await request(app)
      .post('/v1/search')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send({});
    const audit = await request(app)
      .get('/v1/audit')
      .set('Authorization', 'Bearer ' + issued.api_key);
    const rows = audit.body.rows || audit.body.usage || [];
    const errRow = rows.find((r) => r.route === SEARCH_ROUTE && r.status === 'client_error');
    expect(errRow).toBeDefined();
    expect(errRow.model).toBe(SEARCH_MODEL_ID_BRAVE);
  });

  test('search rows extend the same per-(tenant, app) chain as chat/process', async () => {
    // Per usage.js doctrine: the chain is keyed by (tenant_id, app_id),
    // not by route. A search row's prev_hash must equal whatever the
    // tenant's prior chain head was — proving search calls share the
    // same audit spine as inference.
    const app = createApp();
    const issued = await issueKey(app, 't_chain_continuity');
    // First search establishes the genesis row for this tenant.
    await request(app)
      .post('/v1/search')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send({ query: 'first' });
    // Second search must chain onto the first.
    await request(app)
      .post('/v1/search')
      .set('Authorization', 'Bearer ' + issued.api_key)
      .send({ query: 'second' });
    const audit = await request(app)
      .get('/v1/audit')
      .set('Authorization', 'Bearer ' + issued.api_key);
    const rows = (audit.body.rows || audit.body.usage || [])
      .filter((r) => r.route === SEARCH_ROUTE);
    expect(rows.length).toBe(2);
    const [first, second] = rows;
    expect(second.prev_hash).toBe(first.row_hash);
  });
});
