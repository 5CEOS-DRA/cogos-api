#!/usr/bin/env node
'use strict';

/**
 * llm-search-bench.js — throw a varied prompt list at /v1/chat and
 * /v1/search, measure latency, report side-by-side.
 *
 * Demonstrates the substrate's two answer paths in isolation. A future
 * v0.2 wedge will integrate them (model auto-invokes search mid-
 * completion); today they're two separate calls.
 *
 * Usage:  COGOS_API_KEY=sk-cogos-... node scripts/llm-search-bench.js
 */

const BASE = process.env.COGOS_BASE || 'http://localhost:4444';
const KEY  = process.env.COGOS_API_KEY;

if (!KEY) {
  console.error('Set COGOS_API_KEY=sk-cogos-...');
  process.exit(2);
}

const PROMPTS = [
  { kind: 'training-knowledge',  text: 'In one sentence, what is the capital of France?' },
  { kind: 'training-knowledge',  text: 'Explain the difference between TCP and UDP in one sentence.' },
  { kind: 'reasoning',           text: 'If a train leaves Chicago at 60mph and another at 45mph heading toward each other 200 miles apart, when do they meet? Answer in one sentence.' },
  { kind: 'training-knowledge',  text: 'List three properties of a hash chain in one sentence.' },
  { kind: 'post-cutoff',         text: 'What is the current price of Bitcoin in US dollars?' },
  { kind: 'post-cutoff',         text: 'Who won the most recent NBA championship?' },
  { kind: 'post-cutoff',         text: 'What was a major AI news story this week?' },
];

const MODEL = process.env.COGOS_MODEL || 'cogos-tier-b'; // starter-tier default

function fmtMs(ms) { return ms.toFixed(0).padStart(5, ' ') + 'ms'; }
function trim(s, n = 90) { s = String(s || '').replace(/\s+/g, ' ').trim(); return s.length > n ? s.slice(0, n - 1) + '…' : s; }

async function callChat(prompt) {
  const t0 = Date.now();
  try {
    const res = await fetch(`${BASE}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + KEY },
      body: JSON.stringify({
        model: MODEL,
        messages: [{ role: 'user', content: prompt }],
        temperature: 0,
        max_tokens: 120,
      }),
    });
    const dt = Date.now() - t0;
    const body = await res.json();
    if (!res.ok) return { ok: false, ms: dt, err: body.error?.message || `HTTP ${res.status}` };
    const text = body.choices?.[0]?.message?.content || '';
    return {
      ok: true,
      ms: dt,
      text,
      tokens: (body.usage?.prompt_tokens || 0) + (body.usage?.completion_tokens || 0),
    };
  } catch (e) {
    return { ok: false, ms: Date.now() - t0, err: e.message };
  }
}

async function callSearch(query) {
  const t0 = Date.now();
  try {
    const res = await fetch(`${BASE}/v1/search`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + KEY },
      body: JSON.stringify({ query, max_results: 5 }),
    });
    const dt = Date.now() - t0;
    const body = await res.json();
    if (!res.ok) return { ok: false, ms: dt, err: body.error?.message || `HTTP ${res.status}` };
    return {
      ok: true,
      ms: dt,
      provider: body.provider,
      results: body.results || [],
      receipt: body.receipt,
    };
  } catch (e) {
    return { ok: false, ms: Date.now() - t0, err: e.message };
  }
}

(async () => {
  console.log(`\nCogOS LLM + Search bench  ·  base=${BASE}  ·  model=${MODEL}\n`);
  console.log('─'.repeat(118));
  console.log('KIND'.padEnd(20) + 'PROMPT'.padEnd(50) + 'LLM'.padEnd(10) + 'SEARCH'.padEnd(10) + 'PROVIDER'.padEnd(10) + 'RESULTS');
  console.log('─'.repeat(118));

  const chatTimes = [];
  const searchTimes = [];
  const details = [];

  for (const p of PROMPTS) {
    const [c, s] = await Promise.all([callChat(p.text), callSearch(p.text)]);

    if (c.ok)  chatTimes.push(c.ms);
    if (s.ok)  searchTimes.push(s.ms);

    const llmCell    = c.ok ? fmtMs(c.ms) : ('ERR '.padStart(8));
    const searchCell = s.ok ? fmtMs(s.ms) : ('ERR '.padStart(8));
    const providerCell = (s.provider || (s.ok ? '?' : '-')).padEnd(10);
    const resultsCell = s.ok ? (`${s.results.length} hit${s.results.length === 1 ? '' : 's'}`) : (s.err || '');

    console.log(
      p.kind.padEnd(20) +
      trim(p.text, 48).padEnd(50) +
      llmCell.padEnd(10) +
      searchCell.padEnd(10) +
      providerCell +
      resultsCell,
    );
    details.push({ p, c, s });
  }

  console.log('─'.repeat(118));

  // Aggregates
  const avg = (arr) => arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : 0;
  const min = (arr) => arr.length ? Math.min(...arr) : 0;
  const max = (arr) => arr.length ? Math.max(...arr) : 0;
  console.log('\nAGGREGATES');
  console.log(`  LLM (/v1/chat)    n=${chatTimes.length}  min=${fmtMs(min(chatTimes))}  avg=${fmtMs(avg(chatTimes))}  max=${fmtMs(max(chatTimes))}`);
  console.log(`  Search (/v1/search) n=${searchTimes.length}  min=${fmtMs(min(searchTimes))}  avg=${fmtMs(avg(searchTimes))}  max=${fmtMs(max(searchTimes))}`);

  console.log('\nLLM ANSWER PREVIEWS');
  details.forEach(({ p, c }, i) => {
    if (c.ok) console.log(`  ${(i + 1).toString().padStart(2)}. [${fmtMs(c.ms)}] ${trim(c.text, 110)}`);
    else      console.log(`  ${(i + 1).toString().padStart(2)}. [ERR ] ${c.err}`);
  });

  // Show any real search results when Brave is configured
  const haveBrave = details.some(({ s }) => s.ok && s.provider === 'brave' && s.results.length);
  if (haveBrave) {
    console.log('\nSEARCH FIRST-HIT PREVIEWS');
    details.forEach(({ p, s }, i) => {
      if (s.ok && s.results.length) {
        const top = s.results[0];
        console.log(`  ${(i + 1).toString().padStart(2)}. [${fmtMs(s.ms)}] ${trim(top.title, 80)}  ::  ${trim(top.url, 60)}`);
      }
    });
  } else {
    console.log('\nNOTE  ·  BRAVE_SEARCH_API_KEY is not set on the local cogos-api');
    console.log('       · /v1/search returns provider:none with 0 results (fail-soft path)');
    console.log('       · LLM latency numbers above are real; search latency is the substrate round-trip only');
    console.log('       · Set BRAVE_SEARCH_API_KEY in cogos-api/.env and restart to get live web results');
  }

  console.log('');
})();
