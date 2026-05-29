'use strict';

/**
 * search-client — neutral live-web search provider for cogos-api.
 *
 * WHY THIS EXISTS
 * ---------------
 * CogOS's positioning rests on a small sovereign LLM fleet that reaches
 * the open internet on demand instead of pretending to "know" the world
 * out of frozen training weights. The /v1/search router is the substrate
 * surface that backs that claim — every fetch returns a receipt on the
 * same hash-chained usage spine that records every /v1/chat and
 * /v1/process call. This file is the thin neutral provider client the
 * router calls.
 *
 * DOCTRINE BINDINGS
 * -----------------
 * - **Search is not inference.** This is a query-out / snippets-in
 *   primitive. It does not run a model, does not see the customer's
 *   prompt, does not receive private substrate state. The sovereign-
 *   inference doctrine (no third-party hosted LLM) is unaffected — the
 *   ban is on inference, not on fact retrieval.
 * - **Fail-soft on missing key.** When BRAVE_SEARCH_API_KEY is not
 *   configured the client returns a structured `provider: 'none'`
 *   envelope so the calling router can record a clean receipt and the
 *   downstream caller can interpret "no fresh research available" rather
 *   than fabricate results. This is the same contract the
 *   5ceos-platform-internal sibling has shipped against since 2026-05-25
 *   (backend/services/search/braveSearchClient.cjs).
 * - **No caching at this layer.** The client is a thin wrapper. Any
 *   caching (TTL, dedup, prefetch) belongs to the calling router or
 *   above — caching here would couple the substrate to a policy the
 *   operator should be able to change without touching the network code.
 *
 * ENV CONTRACT
 *   BRAVE_SEARCH_API_KEY  — required for live results. When absent the
 *                           client returns provider:'none' (see above).
 *
 * OUTPUT SHAPE
 *   {
 *     ok:         true,
 *     query:      string,
 *     results:    [{ title, snippet, url }],
 *     provider:   'brave' | 'none',
 *     latency_ms: number,
 *   }
 * OR (on bad request):
 *   { ok: false, error: 'BAD_REQUEST', message, query }
 * OR (on upstream failure):
 *   { ok: false, error: 'SEARCH_FAILED', message, query, latency_ms }
 */

const logger = require('./logger');

const BRAVE_ENDPOINT = 'https://api.search.brave.com/res/v1/web/search';

async function search({ query, maxResults = 5 } = {}) {
  const startedAt = Date.now();

  if (!query || typeof query !== 'string' || !query.trim()) {
    return { ok: false, error: 'BAD_REQUEST', message: 'query is required', query };
  }
  const cleanQuery = query.trim();

  const apiKey = process.env.BRAVE_SEARCH_API_KEY;
  if (!apiKey) {
    return {
      ok: true,
      query: cleanQuery,
      results: [],
      provider: 'none',
      latency_ms: 0,
    };
  }

  try {
    const url = `${BRAVE_ENDPOINT}?q=${encodeURIComponent(cleanQuery)}&count=${Math.min(maxResults, 20)}`;
    const resp = await fetch(url, {
      headers: {
        'Accept': 'application/json',
        'Accept-Encoding': 'gzip',
        'X-Subscription-Token': apiKey,
      },
    });

    if (!resp.ok) {
      throw new Error(`Brave API ${resp.status} ${resp.statusText}`);
    }

    const data = await resp.json();
    const results = (data.web?.results || []).slice(0, maxResults).map((r) => ({
      title:   String(r.title || ''),
      snippet: String(r.description || ''),
      url:     String(r.url || ''),
    }));

    return {
      ok: true,
      query: cleanQuery,
      results,
      provider: 'brave',
      latency_ms: Date.now() - startedAt,
    };
  } catch (err) {
    logger.warn('[search-client] Brave API failed', { error: err.message, query: cleanQuery });
    return {
      ok: false,
      error: 'SEARCH_FAILED',
      message: err.message,
      query: cleanQuery,
      latency_ms: Date.now() - startedAt,
    };
  }
}

function isConfigured() {
  return !!process.env.BRAVE_SEARCH_API_KEY;
}

module.exports = {
  search,
  isConfigured,
  // exported for tests so they can swap a fake fetch without
  // mocking the global. Production calls go through search() above.
  _internal: {
    BRAVE_ENDPOINT,
  },
};
