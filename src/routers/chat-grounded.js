'use strict';

/**
 * /v1/chat-grounded — search-augmented LLM endpoint with unified receipt.
 *
 * WHY THIS EXISTS
 * ---------------
 * The substrate exposes /v1/chat (sovereign LLM) and /v1/search (Brave
 * neutral provider) as two separate calls. /v1/chat-grounded composes
 * them on the substrate side so the customer makes ONE call and the
 * receipt binds the answer to its cited sources end-to-end. The earlier
 * #/cogos/hosting page positioning ("when the model needs facts it
 * could not have at training time, the substrate fetches live results")
 * is what this endpoint mechanizes.
 *
 * REQUEST SHAPE
 *   POST /v1/chat-grounded
 *   {
 *     query:        string,         // required — the user's question
 *     mode?:        'auto' | 'always-search' | 'never-search',  // default 'auto'
 *     model?:       string,         // default cogos-tier-b
 *     temperature?: number,         // default 0
 *     max_tokens?:  number,         // default 500
 *     max_results?: number,         // search max_results, default 5
 *   }
 *
 * RESPONSE SHAPE
 *   {
 *     answer:       string,
 *     citations:    [{ title, url, snippet }],
 *     search_used:  boolean,
 *     search_skip_reason?: string,
 *     model:        string,
 *     usage:        { prompt_tokens, completion_tokens },
 *     receipt: {
 *       request_id, ms, deterministic_hash, output_hash,
 *       evidence_chain: {
 *         search_request_id?:        string,
 *         search_provider?:          string,
 *         search_output_hash?:       string,
 *         search_ms?:                number,
 *         chat_ms:                   number,
 *       }
 *     }
 *   }
 *
 * RECEIPT SEMANTICS
 *   deterministic_hash → sha256(canonical request body). Proves cogos-api
 *                        received the exact query the caller sent.
 *   output_hash        → sha256(canonical { answer, citations, search_used }).
 *                        Binds the customer-visible answer to its citations
 *                        as one indivisible artifact. NOT a determinism
 *                        guarantee — search is non-deterministic by nature
 *                        and the LLM has its own per-run variance. The hash
 *                        proves *what was returned at this moment*.
 *   evidence_chain     → trace identifiers for the internal sub-operations
 *                        (search call + chat call). Operators can re-derive
 *                        the search output from search_output_hash to verify
 *                        the LLM was grounded on the documented evidence.
 *
 * SEARCH TRIGGER HEURISTIC (mode: 'auto')
 *   Search fires when the query contains any of:
 *     today, current, latest, recent, this week, this month, this year,
 *     now, news, price of, who won, what happened, since 20XX
 *   The keyword list is deliberately small and inspectable. mode='always-search'
 *   or mode='never-search' bypass the heuristic.
 *
 * HONESTY RULES
 *   - mode='never-search' or no triggers in 'auto' → search_used:false,
 *     citations:[]; the answer is from the bare LLM only.
 *   - search returns provider:'none' (no API key configured) → search_used:true
 *     but citations:[]; the LLM is told there's no fresh research available
 *     so it composes from training knowledge with honesty about the gap.
 *   - search returns 0 brave hits → same as provider:'none' for the LLM
 *     prompt purposes; citations:[].
 *
 * USAGE ROW
 *   ONE row per /v1/chat-grounded call, model='grounded:<tier>:v1',
 *   route='/v1/chat-grounded'. The internal search + chat sub-operations
 *   are NOT recorded as separate rows — the customer made one call, the
 *   substrate did the work, the receipt's evidence_chain field carries
 *   sub-operation traceability without inflating the per-tenant chain.
 */

const express = require('express');
const crypto = require('crypto');
const logger = require('../logger');
const usage = require('../usage');
const { canonicalHash } = require('../processes/_canonicalize');
const searchClient = require('../search-client');
const chatApi = require('../chat-api');

const ROUTE = '/v1/chat-grounded';

function newRequestId() {
  return 'grnd_' + crypto.randomBytes(16).toString('base64url');
}

// Inspectable heuristic. Add a keyword here = wider search trigger.
const SEARCH_TRIGGERS = [
  /\btoday\b/i, /\bcurrent\b/i, /\blatest\b/i, /\brecent\b/i,
  /\bthis week\b/i, /\bthis month\b/i, /\bthis year\b/i,
  /\bnow\b/i, /\bnews\b/i,
  /\bprice of\b/i, /\bwho won\b/i, /\bwhat happened\b/i,
  /\bsince 20\d\d\b/i, /\bafter 20\d\d\b/i,
  /\b(latest|recent|current)\s+(filing|form|10[-\s]?[KQ]|annual report)\b/i,
];

function shouldSearch(query, mode) {
  if (mode === 'always-search') return { yes: true,  reason: 'mode=always-search' };
  if (mode === 'never-search')  return { yes: false, reason: 'mode=never-search' };
  // mode === 'auto' (default)
  for (const re of SEARCH_TRIGGERS) {
    if (re.test(query)) return { yes: true, reason: `keyword: ${re.source}` };
  }
  return { yes: false, reason: 'no_trigger_match' };
}

function buildAugmentedMessages(query, searchResult) {
  // No search results — be explicit so the LLM doesn't pretend.
  if (!searchResult || !searchResult.results || searchResult.results.length === 0) {
    return [
      {
        role: 'system',
        content: 'You are a helpful assistant grounded in the CircaOS substrate. For this query, NO fresh search results are available. Answer from your training knowledge and explicitly note any cutoff limitations. Do not fabricate current data.',
      },
      { role: 'user', content: query },
    ];
  }
  const snippetBlock = searchResult.results.slice(0, 5).map((r, i) => {
    const snip = String(r.snippet || '').replace(/<[^>]+>/g, '').slice(0, 320);
    return `[${i + 1}] ${r.title}\n    URL: ${r.url}\n    ${snip}`;
  }).join('\n\n');
  return [
    {
      role: 'system',
      content:
        'You are a helpful assistant grounded in the CircaOS substrate. Use ONLY the sources below to answer. ' +
        'Cite the source number in square brackets next to each claim, e.g. "Microsoft FY25 revenue was $X [1]". ' +
        'If the sources do not contain the answer, say so explicitly — do not fabricate.\n\n' +
        'SOURCES:\n' + snippetBlock,
    },
    { role: 'user', content: query },
  ];
}

function makeChatGroundedRouter({ customerAuth, tenantLimiter, enforceDailyCap, enforcePackage }) {
  const router = express.Router();

  // Quota gate: grounded calls hit the same daily-cap + monthly-package
  // budget as /v1/chat/completions. Without these middlewares a free-tier
  // key that exhausted its /v1/chat allowance could route around it here.
  // Optional-param pattern keeps tests that build a router without
  // middleware (pure-shape unit tests) working — they just skip the gate.
  const dailyCap = enforceDailyCap || ((req, _res, next) => next());
  const pkgGate  = enforcePackage  || ((req, _res, next) => next());

  router.post('/', customerAuth, tenantLimiter, dailyCap, pkgGate, async (req, res) => {
    const t0 = Date.now();
    const request_id = newRequestId();
    const rawBody = req.body || {};

    // R-1: deterministic_hash over the raw request body.
    const deterministic_hash = canonicalHash(rawBody);

    const query = typeof rawBody.query === 'string' ? rawBody.query.trim() : '';
    if (!query) {
      return res.status(400).json({
        error: { message: 'query is required', type: 'invalid_request_error', code: 'invalid_input' },
        receipt: { request_id, ms: Date.now() - t0, deterministic_hash },
      });
    }
    const mode = ['auto', 'always-search', 'never-search'].includes(rawBody.mode) ? rawBody.mode : 'auto';
    const model = typeof rawBody.model === 'string' && rawBody.model ? rawBody.model : 'cogos-tier-b';
    const temperature = typeof rawBody.temperature === 'number' ? rawBody.temperature : 0;
    const max_tokens = Number.isInteger(rawBody.max_tokens) ? rawBody.max_tokens : 500;
    const max_results = Number.isInteger(rawBody.max_results) ? Math.max(1, Math.min(10, rawBody.max_results)) : 5;

    // ── 1. Decide on search ──
    const decision = shouldSearch(query, mode);
    let searchResult = null;
    let evidence = {};
    if (decision.yes) {
      const sT0 = Date.now();
      try {
        searchResult = await searchClient.search({ query, maxResults: max_results });
      } catch (e) {
        logger.warn('[chat-grounded] search threw', { error: e.message });
        searchResult = { ok: false, results: [], provider: 'error', error: e.message };
      }
      const sMs = Date.now() - sT0;
      const searchPayload = {
        query: searchResult.query || query,
        provider: searchResult.provider || 'unknown',
        results: searchResult.results || [],
      };
      evidence.search_request_id  = 'srch_inline_' + crypto.randomBytes(8).toString('base64url');
      evidence.search_provider    = searchPayload.provider;
      evidence.search_output_hash = canonicalHash(searchPayload);
      evidence.search_ms          = sMs;
    }

    // ── 2. Compose LLM prompt + call upstream ──
    const messages = buildAugmentedMessages(query, searchResult);
    const cT0 = Date.now();
    let upstreamResult;
    let escalationReason = null;
    try {
      const upstreamUrl = process.env.UPSTREAM_URL || process.env.OLLAMA_URL || 'http://localhost:11434';
      // Resolve the customer-tier model id to the actual upstream model.
      const resolvedModel = chatApi.resolveModel(model);
      upstreamResult = await chatApi._internal.callOllama({
        url: upstreamUrl,
        model: resolvedModel,
        messages,
        temperature,
        max_tokens,
      });
      if (!upstreamResult.parsed) escalationReason = 'sovereign_error';
    } catch (e) {
      // Sovereign threw — eligible for frontier escalation. Don't bail
      // yet; B4 wires the same fallback pattern /v1/chat/completions uses.
      escalationReason = 'sovereign_error';
      upstreamResult = null;
    }
    const cMs = Date.now() - cT0;
    evidence.chat_ms = cMs;

    // ── 2b. B4 · Frontier escalation when sovereign failed ──
    // Same policy as chat-api.js: if escalation is configured + enabled +
    // budget allows, retry on the frontier (Gemini by default). On success
    // surface the frontier answer with was_escalated in evidence_chain.
    if (escalationReason && chatApi._frontier && chatApi._frontier.escalationAllowed(escalationReason)) {
      const budget = chatApi._frontier.checkFrontierBudget();
      if (budget.allowed) {
        const fT0 = Date.now();
        const frontier = await chatApi._frontier.callFrontier({
          messages,
          temperature,
          max_tokens,
        });
        if (frontier.ok) {
          // Replace upstreamResult with the frontier shape so the rest of
          // the handler treats it as a normal success.
          upstreamResult = { parsed: frontier.parsed };
          evidence.was_escalated     = true;
          evidence.frontier_provider = chatApi._frontier.FRONTIER_PROVIDER_NAME();
          evidence.frontier_model    = chatApi._frontier.FRONTIER_MODEL_NAME();
          evidence.escalation_reason = escalationReason;
          evidence.frontier_ms       = Date.now() - fT0;
          logger.info('[chat-grounded] frontier escalation success', {
            request_id, reason: escalationReason, frontier_ms: evidence.frontier_ms,
          });
        } else {
          logger.warn('[chat-grounded] frontier escalation failed', {
            request_id, reason: escalationReason, frontier_reason: frontier.reason,
          });
          evidence.was_escalated     = true;
          evidence.escalation_reason = escalationReason;
          evidence.frontier_reason   = frontier.reason;
        }
      } else {
        logger.warn('[chat-grounded] frontier budget cap reached, skipping escalation', {
          request_id, spent_today_usd: budget.spentToday, cap_usd: budget.capUsd,
        });
        evidence.escalation_reason   = escalationReason;
        evidence.frontier_reason     = 'budget_cap_reached';
      }
    }

    // ── 2c. Sovereign failed AND escalation didn't recover → 502 ──
    if (!upstreamResult || !upstreamResult.parsed) {
      const ms = Date.now() - t0;
      try {
        usage.record({
          key_id: req.apiKey && req.apiKey.id,
          tenant_id: req.apiKey && req.apiKey.tenant_id,
          app_id: req.apiKey && req.apiKey.app_id,
          model: `grounded:${model}:v1`,
          prompt_tokens: 0, completion_tokens: 0,
          latency_ms: ms, status: 'server_error',
          request_id, route: ROUTE,
        });
      } catch (_e) { /* swallow */ }
      return res.status(502).json({
        error: { message: 'upstream LLM call failed and frontier escalation did not recover', type: 'bad_gateway', code: 'upstream_failure' },
        receipt: { request_id, ms, deterministic_hash, evidence_chain: evidence },
      });
    }

    const answer = upstreamResult.parsed.content || '';
    const citations = (searchResult && searchResult.results)
      ? searchResult.results.slice(0, 5).map((r) => ({
          title:   String(r.title || ''),
          url:     String(r.url || ''),
          snippet: String(r.snippet || '').replace(/<[^>]+>/g, '').slice(0, 320),
        }))
      : [];
    const search_used = !!decision.yes;

    const ms = Date.now() - t0;
    try {
      // B4: when the answer came from the frontier, flag was_escalated +
      // attribute the provider so the daily-budget tracker (which reads
      // these fields off the usage log) accounts for the spend.
      const usageRow = {
        key_id: req.apiKey && req.apiKey.id,
        tenant_id: req.apiKey && req.apiKey.tenant_id,
        app_id: req.apiKey && req.apiKey.app_id,
        model: evidence.was_escalated
          ? `grounded:${model}:v1+frontier`
          : `grounded:${model}:v1`,
        prompt_tokens: upstreamResult.parsed.prompt_tokens || 0,
        completion_tokens: upstreamResult.parsed.completion_tokens || 0,
        latency_ms: ms, status: 'success',
        request_id, route: ROUTE,
      };
      if (evidence.was_escalated) {
        usageRow.was_escalated     = true;
        usageRow.frontier_provider = evidence.frontier_provider;
        usageRow.escalation_reason = evidence.escalation_reason;
      }
      usage.record(usageRow);
    } catch (recordErr) {
      logger.warn('[chat-grounded] usage.record failed', { error: recordErr.message });
    }

    // R-2: output_hash binds the customer-visible answer + citations together.
    // search_used is hashed so a "no-search" answer cannot be replayed as a
    // "grounded" answer with the same hash.
    const outputPayload = { answer, citations, search_used };
    const output_hash = canonicalHash(outputPayload);

    return res.status(200).json({
      answer,
      citations,
      search_used,
      search_skip_reason: search_used ? undefined : decision.reason,
      model,
      usage: {
        prompt_tokens: upstreamResult.parsed.prompt_tokens || 0,
        completion_tokens: upstreamResult.parsed.completion_tokens || 0,
      },
      receipt: { request_id, ms, deterministic_hash, output_hash, evidence_chain: evidence },
    });
  });

  return router;
}

module.exports = {
  makeChatGroundedRouter,
  ROUTE,
  _internal: { shouldSearch, buildAugmentedMessages, SEARCH_TRIGGERS },
};
