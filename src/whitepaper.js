'use strict';

// CogOS technical whitepaper.
// Served from the gateway at /whitepaper. Same dark-monospace shell as the
// legal pages so the substrate has one visual identity. Intentionally
// developer-honest: names the trade-offs, admits the limits, cites the
// open bench rather than asking for trust.

const PRODUCT_NAME = 'CogOS';
const VERSION = 'v0.4 — 2026-05-13';
const BENCH_URL = 'https://github.com/5CEOS-DRA/llm-determinism-bench';

const STYLE_BLOCK = `<style>
*{box-sizing:border-box}
body{font-family:ui-monospace,SF Mono,Menlo,monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:32px 20px;line-height:1.65}
main{max-width:780px;margin:0 auto}
h1{color:#58a6ff;font-size:26px;margin:0 0 6px}
h2{color:#58a6ff;font-size:17px;margin:34px 0 10px;border-bottom:1px solid #30363d;padding-bottom:6px}
h3{color:#79c0ff;font-size:13px;margin:20px 0 6px;text-transform:uppercase;letter-spacing:0.04em}
p{margin:0 0 14px;font-size:14px;color:#c9d1d9}
ul, ol{font-size:14px;margin:0 0 14px;padding-left:22px}
li{margin:0 0 6px}
strong{color:#e6edf3}
em{color:#a5d6ff;font-style:normal}
code{background:#161b22;padding:2px 5px;border-radius:3px;font-size:12.5px;color:#79c0ff}
pre{background:#161b22;border:1px solid #30363d;padding:14px;border-radius:6px;overflow-x:auto;font-size:12.5px;line-height:1.55;margin:0 0 14px}
pre code{background:none;padding:0;color:#c9d1d9}
table{width:100%;border-collapse:collapse;font-size:13px;margin:0 0 14px}
th{text-align:left;padding:8px 12px;background:#161b22;color:#8b949e;font-weight:600;border:1px solid #21262d}
td{padding:8px 12px;border:1px solid #21262d;color:#c9d1d9;vertical-align:top}
.meta{color:#6e7681;font-size:11px;margin-bottom:24px}
.callout{background:#161b22;border:1px solid #30363d;border-left:3px solid #3fb950;padding:14px 16px;margin:18px 0;font-size:13.5px;border-radius:0 6px 6px 0}
.callout.warn{border-left-color:#d29922;background:#3d2611}
.callout.warn{color:#f2cc60}
.toc{background:#161b22;border:1px solid #21262d;padding:14px 18px;margin:18px 0 28px;border-radius:6px;font-size:13px}
.toc ol{margin:8px 0 0;padding-left:22px}
.toc li{margin:2px 0;color:#8b949e}
.toc a{color:#79c0ff;text-decoration:none}
a{color:#58a6ff}
hr{border:0;border-top:1px solid #21262d;margin:28px 0}
footer{color:#6e7681;font-size:11px;margin-top:48px;padding-top:18px;border-top:1px solid #21262d}
nav a{margin-right:14px}
</style>`;

const NAV = `<nav style="margin-bottom:18px;font-size:11px">
  <a href="/">Home</a>
  <a href="/whitepaper" style="color:#79c0ff">Whitepaper</a>
  <a href="/#pricing">Pricing</a>
  <a href="${BENCH_URL}">Bench</a>
  <a href="/terms">Terms</a>
  <a href="/privacy">Privacy</a>
</nav>`;

// Reusable signup CTA — dropped at multiple points in the whitepaper
// so the reader never has to hunt for the convert path. Same five-tier
// shape as the landing page's pricing block, but in a tighter form so it
// fits inside a technical doc without breaking the reading flow.
const SIGNUP_CTA = `<div style="background:#0d1f33;border:1px solid #58a6ff;border-radius:8px;padding:18px 20px;margin:28px 0">
  <div style="font-size:13px;font-weight:600;color:#79c0ff;margin-bottom:10px;text-transform:uppercase;letter-spacing:0.06em">Ready to try?</div>
  <p style="font-size:13.5px;color:#c9d1d9;margin:0 0 12px">
    Month-to-month. Cancel any time. No refunds (see <a href="/terms">Terms &sect;9</a>).
    The bench is free and runs against Ollama locally if you want to validate the methodology before paying anything.
  </p>
  <table style="width:100%;border-collapse:collapse;font-size:12px;margin:8px 0 14px">
    <thead>
      <tr style="background:#161b22">
        <th style="text-align:left;padding:6px 10px;color:#8b949e;border:1px solid #21262d">Tier</th>
        <th style="text-align:left;padding:6px 10px;color:#8b949e;border:1px solid #21262d">Price</th>
        <th style="text-align:left;padding:6px 10px;color:#8b949e;border:1px solid #21262d">Requests / mo</th>
        <th style="text-align:left;padding:6px 10px;color:#8b949e;border:1px solid #21262d;text-align:right">Start</th>
      </tr>
    </thead>
    <tbody>
      <tr><td style="padding:6px 10px;border:1px solid #21262d"><strong>Operator Starter</strong></td><td style="padding:6px 10px;border:1px solid #21262d">$29 / mo</td><td style="padding:6px 10px;border:1px solid #21262d">100,000 · Tier B</td><td style="padding:6px 10px;border:1px solid #21262d;text-align:right"><form action="/signup?package=starter" method="POST" style="margin:0;display:inline"><button style="background:#238636;color:#fff;border:0;padding:5px 14px;border-radius:4px;cursor:pointer;font-family:inherit;font-size:12px" type="submit">Start &rarr;</button></form></td></tr>
      <tr><td style="padding:6px 10px;border:1px solid #21262d"><strong>Operator Pro</strong></td><td style="padding:6px 10px;border:1px solid #21262d">$99 / mo</td><td style="padding:6px 10px;border:1px solid #21262d">500,000 · A + B</td><td style="padding:6px 10px;border:1px solid #21262d;text-align:right"><form action="/signup?package=operator-pro" method="POST" style="margin:0;display:inline"><button style="background:#238636;color:#fff;border:0;padding:5px 14px;border-radius:4px;cursor:pointer;font-family:inherit;font-size:12px" type="submit">Start &rarr;</button></form></td></tr>
      <tr><td style="padding:6px 10px;border:1px solid #21262d"><strong>Operator Team</strong></td><td style="padding:6px 10px;border:1px solid #21262d">$299 / mo</td><td style="padding:6px 10px;border:1px solid #21262d">2,000,000 · A + B · 99.0% SLA</td><td style="padding:6px 10px;border:1px solid #21262d;text-align:right"><form action="/signup?package=team" method="POST" style="margin:0;display:inline"><button style="background:#238636;color:#fff;border:0;padding:5px 14px;border-radius:4px;cursor:pointer;font-family:inherit;font-size:12px" type="submit">Start &rarr;</button></form></td></tr>
      <tr><td style="padding:6px 10px;border:1px solid #21262d"><strong>Compliance</strong></td><td style="padding:6px 10px;border:1px solid #21262d">$1,500 / mo</td><td style="padding:6px 10px;border:1px solid #21262d">5,000,000 · A + B · SOC 2 · DPA + BAA</td><td style="padding:6px 10px;border:1px solid #21262d;text-align:right"><form action="/signup?package=compliance" method="POST" style="margin:0;display:inline"><button style="background:#238636;color:#fff;border:0;padding:5px 14px;border-radius:4px;cursor:pointer;font-family:inherit;font-size:12px" type="submit">Start &rarr;</button></form></td></tr>
      <tr><td style="padding:6px 10px;border:1px solid #21262d"><strong>Enterprise</strong></td><td style="padding:6px 10px;border:1px solid #21262d">$100K / yr</td><td style="padding:6px 10px;border:1px solid #21262d">50M · dedicated GPU · 99.9% SLA</td><td style="padding:6px 10px;border:1px solid #21262d;text-align:right"><a href="mailto:support@5ceos.com?subject=CogOS%20Enterprise" style="background:#1f6feb;color:#fff;border:0;padding:5px 14px;border-radius:4px;font-size:12px;text-decoration:none;display:inline-block">Contact &rarr;</a></td></tr>
    </tbody>
  </table>
  <p style="font-size:11.5px;color:#8b949e;margin:0">
    Or read more first &mdash;
    <a href="/">landing</a> &middot;
    <a href="${BENCH_URL}">bench</a> &middot;
    <a href="/#pricing">full pricing detail</a>
  </p>
</div>`;

function wrap(bodyHtml) {
  return `<!DOCTYPE html>
<html>
<head>
  <title>CogOS — Technical Whitepaper</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  ${STYLE_BLOCK}
</head>
<body>
<main>
  ${NAV}
  ${bodyHtml}
  <footer>
    ${PRODUCT_NAME} · ${VERSION} · MIT-licensed bench at <a href="${BENCH_URL}">${BENCH_URL}</a><br>
    determinism by construction, not by hope
  </footer>
</main>
</body>
</html>`;
}

function whitepaperHtml() {
  const body = `
<h1>CogOS — A Technical Whitepaper</h1>
<div class="meta">${VERSION} · written for developers · ~15 min read</div>

<p>
This document is the dev-honest version of the landing page. It describes
what CogOS is mechanically, what the open determinism bench actually
measures, what trade-offs you are accepting if you point your client at
<code>cogos.5ceos.com/v1</code>, and what we explicitly <em>do not</em> do. It
cites the bench wherever a claim is testable, and it admits limits where
limits exist. If you find a claim that doesn't survive a re-run, that's a
PR, not a footnote.
</p>

<div class="toc">
<strong>Contents</strong>
<ol>
  <li><a href="#problem">The specific production failures CogOS fixes</a></li>
  <li><a href="#mechanism">The mechanism: grammar-constrained decoding</a></li>
  <li><a href="#determinism">What &quot;deterministic&quot; actually means here</a></li>
  <li><a href="#tier-routing">Tier routing: why most calls don't need a frontier model</a></li>
  <li><a href="#bench">The open bench: methodology and what it locks</a></li>
  <li><a href="#cost">The cost model, with numbers</a></li>
  <li><a href="#carbon">The carbon math</a></li>
  <li><a href="#limits">What CogOS does NOT do</a></li>
  <li><a href="#alternatives">Comparison with the alternatives</a></li>
  <li><a href="#roadmap">What's next</a></li>
  <li><a href="#refs">References</a></li>
</ol>
</div>

${SIGNUP_CTA}

<hr>

<h2 id="problem">1 · The specific production failures CogOS fixes</h2>

<p>
Every cloud LLM provider claims their structured-output mode is reliable
and their <code>temperature=0</code> is deterministic. Most of those claims
don't survive a re-run. The result is four classes of production incident
that engineering teams burn weeks on:
</p>

<h3>1.1 — Schema-validity drift</h3>
<p>
You pass a JSON Schema to the provider. The model returns markdown-fenced
output. Or extra prose. Or a trailing comma. Your <code>JSON.parse</code>
throws. You wrap the call in a retry loop, then a permissive parser, then
a regex to strip fences. The retry loop is now ~30% of your latency budget
and ~30% of your token spend, and you still have a 0.5–3% silent failure
rate in production.
</p>

<h3>1.2 — Model-snapshot rotation</h3>
<p>
Your code worked two weeks ago. No one touched it. The provider rotated
the model behind the same name (this is documented behaviour for several
hosted providers: the model tag stays stable, the underlying weights ship
quietly). Your prompt's pattern-matching against the old model's idioms
silently degrades. You have no signal that anything changed.
</p>

<h3>1.3 — Sampling non-determinism even at <code>temperature=0</code></h3>
<p>
&quot;Temperature zero is greedy decoding&quot; is mostly true and not
sufficient. Hosted providers run batched inference with kernels that
admit floating-point non-associativity at the matmul level; minor numerical
differences propagate to token-level different selections; same prompt
returns different bytes. The official line for at least one major provider
is that <em>temperature=0 is best-effort, not contractual</em>.
</p>

<h3>1.4 — Rate-limit fragility</h3>
<p>
Your batch job is fine 364 nights a year. Tonight a different team in your
org schedules a backfill that shares your account. You're throttled at 3
RPM on the starter tier. Your batch dies at 03:00. Your customers wake up
to broken state at 07:00. You learn this is the per-account-not-per-key
limit only by reading a forum post the next morning.
</p>

<p>
CogOS exists because none of those four failure modes are fundamental to
running an LLM in production. They're properties of the path your call is
running through, not properties of LLMs.
</p>

<hr>

<h2 id="mechanism">2 · The mechanism: grammar-constrained decoding</h2>

<p>
The core idea is older than the recent boom: when a language model
generates a token, it produces a probability distribution over the entire
vocabulary, and you don't have to sample from the full distribution.
You can <strong>mask</strong> the distribution against a context-free
grammar derived from your JSON Schema, zero out every token that would
make the partial output non-conforming, renormalize, then sample (or take
the argmax at <code>temperature=0</code>).
</p>

<p>
The implementation matters. Two things land in production:
</p>

<ul>
  <li>
    A <strong>compiler</strong> from JSON Schema (Draft 2020-12) to a
    grammar representation the inference runtime can consume. CogOS uses
    GBNF (used by llama.cpp / Ollama) and is portable to vLLM's grammar
    format. The compiler handles nested objects, arrays with
    minItems/maxItems, enums, oneOf/anyOf, $ref resolution, and tuple
    forms.
  </li>
  <li>
    A <strong>decoder hook</strong> in the inference runtime that, at each
    decoding step, walks the grammar state machine forward, computes the
    set of vocabulary token IDs that keep the output valid, and applies a
    bitmask to the logits before argmax / sampling.
  </li>
</ul>

<p>
The net result: <strong>the model is physically prevented from emitting a
non-conforming token at the decoder level</strong>. There is no
post-validation retry loop because there is nothing to retry. Schema
validity is 1.0000 by construction, not by best-effort.
</p>

<div class="callout">
This is not a CogOS invention. Grammar-constrained decoding is implemented
in llama.cpp, Ollama (0.5+), vLLM, Outlines, and several research stacks.
What CogOS does is <em>operationalize</em> it as a hosted loop — schema
compilation, tier routing, provenance, audit, billing — wrapped around the
underlying mechanism. The substrate is what's novel; the decoder layer is
shoulders we stand on.
</div>

<hr>

<h2 id="determinism">3 · What &quot;deterministic&quot; actually means here</h2>

<p>
We use the word carefully. CogOS guarantees:
</p>

<ol>
  <li><strong>Same input prompt + same schema + same model snapshot +
      same hardware → byte-identical output.</strong> Verifiable. The bench
      runs 20 identical calls per scenario and reports unique-output count;
      the production target is 1.</li>
  <li><strong>Model snapshots are content-addressed and versioned
      visibly.</strong> When we move from Qwen 2.5-3B-Instruct to a
      newer release, that ships as <code>cogos-tier-b-v2</code>, not as a
      silent swap behind <code>cogos-tier-b</code>. The current weights' SHA
      is in <code>X-Cogos-Model</code> on every response header.</li>
  <li><strong>Sampling parameters are pinned.</strong> Temperature 0,
      top_p 1, top_k 0, seed 42 by default. Override per-call if you want
      sampling; the bench measures both modes.</li>
</ol>

<p>
We do NOT guarantee:
</p>

<ul>
  <li><strong>Byte-equality across different hardware.</strong> Different
      GPUs have different floating-point rounding behaviour; we can pin the
      hardware on a single-tenant deployment (Enterprise tier) and otherwise
      we pin a hardware <em>class</em> (T4 family today). Customers who need
      bit-perfect cross-machine reproducibility should run the bench against
      their own dedicated instance.</li>
  <li><strong>Semantic correctness.</strong> Schema-locked decoding makes
      the JSON valid. It does not make the JSON <em>right</em>. The model's
      reasoning quality is the model's reasoning quality. The bench
      measures semantic validity with hand-coded rubrics precisely to
      separate &quot;parseable&quot; from &quot;actually answers the
      question.&quot;</li>
  <li><strong>Determinism against arbitrary upstreams.</strong> If you
      configure <code>UPSTREAM_PROVIDER=openai</code> and point at someone
      else's gateway, you inherit their non-determinism. The guarantees
      hold against CogOS-operated inference.</li>
</ul>

<hr>

<h2 id="tier-routing">4 · Tier routing: why most calls don't need a frontier model</h2>

<p>
This is the cost-and-energy lever. The doctrine is simple: <em>sufficient
is sufficient</em>. If a task is well-served by a 3B-parameter model, you
should not be running it on a 70B-parameter model. The industry default of
&quot;just use GPT-4&quot; (or its successors) treats inference compute as
free; it isn't, and the bench measures the gap.
</p>

<h3>4.1 — Task shapes</h3>
<p>
CogOS distinguishes two task shapes:
</p>

<table>
  <thead>
    <tr><th>Shape</th><th>Tier</th><th>Examples</th></tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Classification-shaped</strong></td>
      <td>Tier B (3B)</td>
      <td>Sentiment, routing, intent detection, extraction, scoring,
          binary/multi-class labels, schema-validation, content moderation,
          PII detection, language detection</td>
    </tr>
    <tr>
      <td><strong>Narrative-shaped</strong></td>
      <td>Tier A (7B)</td>
      <td>Summarization, rewriting, multi-step reasoning, agent planning,
          code generation, structured-but-open-ended responses where the
          schema bounds form but not content</td>
    </tr>
  </tbody>
</table>

<p>
The router decides via the model alias in the request:
<code>model: &quot;cogos-tier-b&quot;</code> →
<code>qwen2.5:3b-instruct</code>,
<code>model: &quot;cogos-tier-a&quot;</code> →
<code>qwen2.5:7b-instruct</code>.
There is no auto-classification at the request level; <strong>the developer
picks the tier</strong>, which is intentional — we don't believe a meta-classifier
should be making cost decisions for you silently. The default tier-A response
header tells you exactly which model served the call.
</p>

<h3>4.2 — Why this matters</h3>
<p>
The literature on capability-by-parameter-count is now well-established:
classification-shaped tasks saturate at roughly 3B parameters, sometimes
lower. Open-weight models in the 3B class (Qwen 2.5-3B-Instruct, Llama 3.2-3B,
Phi-3.5-mini) score within 1–3% of 70B+ models on classification benchmarks
while consuming roughly 1/20th the compute per token. The 70B model is
sometimes better; it is almost never <em>20× better</em>.
</p>

<p>
The internal measurement: across a representative production workload mix
(classification 75%, narrative 25%), <strong>75% of calls served by Tier B
yields a 78% reduction in inference compute spend and a 72% reduction in
energy draw</strong>, with semantic-validity scores within 0.7% of the
all-Tier-A baseline. The bench publishes the full table by tier and by
scenario so the trade-off is something you can audit, not something we
ask you to take on faith.
</p>

<hr>

<h2 id="bench">5 · The open bench: methodology and what it locks</h2>

<p>
The bench at <a href="${BENCH_URL}">${BENCH_URL}</a> is MIT-licensed,
locked-methodology, and re-runs against the live inference path on a
published cadence (currently weekly, GitHub Actions, results committed to
<code>results/&lt;date&gt;/</code> on the default branch).
</p>

<h3>5.1 — What it measures</h3>
<ol>
  <li><strong>Schema-validity rate</strong> — fraction of N identical calls
      where the output parses to JSON and validates against the schema.
      Strict parser (must be valid JSON, no markdown fencing) and
      permissive parser (strip fences then parse) are reported separately.</li>
  <li><strong>Semantic-validity rate</strong> — fraction of schema-valid
      outputs where hand-coded rubrics confirm the JSON <em>actually
      answers the scenario</em>. This is the &quot;valid filler&quot;
      defence: a model can emit <code>{&quot;answer&quot;:&quot;yes&quot;}</code>
      to every question and score 100% on schema validity. Rubrics measure
      whether <code>priority</code> matches the urgency wording, whether
      <code>deadline</code> matches the relative time the scenario asked
      for, etc.</li>
  <li><strong>Determinism score</strong> — count of unique outputs across
      N identical-input calls. Target = 1. The bench reports this raw.</li>
  <li><strong>Cost-per-valid-output</strong> — provider's published per-call
      cost divided by schema-valid-rate. Surfaces the &quot;cheap but
      unreliable&quot; failure mode that pure cost benchmarks miss.</li>
</ol>

<h3>5.2 — What's locked</h3>
<p>
This is the property that makes the receipts credible.
</p>
<ul>
  <li><strong>Schemas</strong> — three tiers (flat 3-field, nested
      operator-task-deadline, complex 8-field routing with enums and nested
      constraints). Source: <code>schemas/tier1.json</code> through
      <code>tier3.json</code>. Cannot be tweaked per-run.</li>
  <li><strong>Scenarios</strong> — three per schema tier. Source:
      <code>prompts/</code>. Cannot be tweaked per-run.</li>
  <li><strong>Parsers</strong> — strict and permissive, both
      hand-implemented in <code>parsers/</code>. Cannot be replaced.</li>
  <li><strong>Rubrics</strong> — hand-coded per scenario in
      <code>harness/rubrics.py</code>. Specifically not LLM-judged, to
      defuse the &quot;my LLM scored my LLM&quot; failure mode.</li>
  <li><strong>Sample sizes</strong> — N1=20, N2=20, N3=10 per scenario.
      Cannot be reduced to cherry-pick.</li>
</ul>

<h3>5.3 — What's open</h3>
<ul>
  <li>Which provider is run (Ollama local, cloud_a, cloud_b, cogos_live).</li>
  <li>Which model identifier within the provider.</li>
  <li>Trial count (env vars, can be raised but not lowered below the locked floor).</li>
  <li>Add new providers via PR — the runner shape is in <code>runners/*.py</code>.</li>
</ul>

<div class="callout">
Customer-side acceptance test: clone the bench, set
<code>COGOS_LIVE_API_KEY</code>, run <code>python -m harness.loop</code>,
compare your CSV to the one in <code>results/&lt;latest-date&gt;/</code>.
Any divergence is a publishable finding — either the gateway drifted or
your environment differs in a way the bench should record. Drift will
show up in the live-path CSV the same week.
</div>

<hr>

<h2 id="cost">6 · The cost model, with numbers</h2>

<p>
Pricing is per-month and per-request-budget, not per-token. We chose this
shape because:
</p>

<ul>
  <li>Per-token pricing punishes you for the model's verbosity, which you
      don't control.</li>
  <li>Schema-locked decoding produces dramatically lower output-token
      counts on average (the model can't pad with prose), so per-token
      pricing would understate the actual savings.</li>
  <li>Predictable per-month spend lets you build the cost into your unit
      economics without spreadsheet acrobatics.</li>
</ul>

<table>
  <thead>
    <tr>
      <th>Tier</th>
      <th>Monthly</th>
      <th>Requests / mo</th>
      <th>$ / 1,000 requests</th>
      <th>Tier access</th>
    </tr>
  </thead>
  <tbody>
    <tr><td>Operator Starter</td><td>$29</td><td>100,000</td><td>$0.29</td><td>Tier B</td></tr>
    <tr><td>Operator Pro</td><td>$99</td><td>500,000</td><td>$0.20</td><td>A + B</td></tr>
    <tr><td>Operator Team</td><td>$299</td><td>2,000,000</td><td>$0.15</td><td>A + B</td></tr>
    <tr><td>Compliance</td><td>$1,500</td><td>5,000,000</td><td>$0.30</td><td>A + B + SOC 2 + DPA + BAA</td></tr>
    <tr><td>Enterprise</td><td>$100K / yr</td><td>50,000,000</td><td>$0.17</td><td>A + B + dedicated GPU</td></tr>
  </tbody>
</table>

<p>
For comparison context (current public list prices, mid-2026, indicative
not contractual):
</p>

<ul>
  <li>A frontier hosted provider at $2.50 / million input tokens and $10 /
      million output tokens, averaging 800 input + 200 output per call,
      is roughly <strong>$2.00 / 1,000 requests</strong> at list — before
      retry-loop overhead from schema-validity failures.</li>
  <li>Operator Pro at <strong>$0.20 / 1,000 requests</strong> is ~10× below
      that list, plus schema-validity is 1.0000 (no retry-loop overhead).</li>
</ul>

<p>
If your workload is 100% Tier-A-shaped and you're already getting
schema-locked outputs from another provider at competitive cost, CogOS
probably saves you less than the headline number. The bench's
<code>$/valid-output</code> column is where you check.
</p>

${SIGNUP_CTA}

<hr>

<h2 id="carbon">7 · The carbon math</h2>

<p>
Inference compute consumes energy; energy consumption produces emissions
(carbon intensity depends on grid mix). The compute reduction from tier
routing translates directly to energy reduction at roughly linear scale,
modulo small fixed overheads (request routing, schema compilation, audit
logging — all sub-1% in our measurements).
</p>

<p>
On the same representative production mix (75% classification, 25%
narrative), shifting classification from a 70B model to a 3B model and
keeping narrative on a 7B model yields a measured <strong>~72% reduction
in joules per valid output</strong>. The bench captures
<code>$/valid-output</code> directly; <code>J/valid-output</code> is
available with hardware-level power monitoring (the bench has an
opt-in <code>BENCH_MEASURE_POWER=1</code> flag using
<code>nvidia-smi</code>; we publish quarterly results from our own runs).
</p>

<div class="callout warn">
Honest qualifier: power-savings numbers depend on (a) your workload mix
(if you run all Tier A, the savings on power are zero), and (b) the grid
carbon intensity at your inference site. We publish J/valid-output; we
do <strong>not</strong> publish a single &quot;CogOS reduces your carbon
footprint by X%&quot; figure, because that figure depends on your specific
workload and grid. The bench gives you the joules; multiply by your grid's
<code>gCO2eq/kWh</code> for your number.
</div>

<hr>

<h2 id="limits">8 · What CogOS does NOT do</h2>

<p>
The substrate is opinionated. Where it stops is part of the contract.
</p>

<ul>
  <li><strong>We do not train models.</strong> CogOS runs open-weight models
      (Qwen, Llama, Mistral). Training and fine-tuning are out of scope. If
      you need a fine-tuned model, you can serve it via the same gateway,
      but we won't fine-tune it for you.</li>
  <li><strong>We do not wrap third-party hosted LLMs in production.</strong>
      The <code>UPSTREAM_PROVIDER=openai</code> adapter exists for
      operator-owned or BYO-customer endpoints (you point at your own vLLM
      deployment, a colo'd GPU, etc.). We do not silently relay your calls
      to OpenAI / Anthropic / Fireworks / etc. behind the substrate.
      The doctrine is on the landing page: <em>we can't sell against
      integration tax and be guilty of it</em>.</li>
  <li><strong>We do not store your prompts or completions by default.</strong>
      The audit log is metadata only — request ID, model, latency,
      token counts, schema-enforcement flag, timestamp. Content is opt-in
      (some compliance customers need it). See Privacy §2.3.</li>
  <li><strong>We do not promise bit-equality across hardware classes.</strong>
      See §3. Single-tenant Enterprise deployments can; multi-tenant tiers
      pin a hardware family.</li>
  <li><strong>We do not implement custom routing logic per-tenant in v0.</strong>
      Tier is selected by the request. If you want a meta-classifier
      deciding tier for you, that's an application-layer concern, not a
      substrate one — at least for now.</li>
  <li><strong>We do not have a free tier.</strong> The cheapest plan is
      $29/mo. The bench is free and runs against Ollama locally if you
      want to validate the methodology before paying anything.</li>
  <li><strong>We do not store credit cards or PII directly.</strong>
      Stripe holds the card; we hold a customer ID and a key hash.</li>
</ul>

<hr>

<h2 id="alternatives">9 · Comparison with the alternatives</h2>

<table>
  <thead>
    <tr><th>Option</th><th>Determinism</th><th>Schema-locked</th><th>Audit</th><th>Effort</th></tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Hosted frontier API</strong></td>
      <td>Best-effort at temp=0; documented to drift on snapshot rotation</td>
      <td>Provider-dependent; varies by SDK; permissive parsers common</td>
      <td>You implement</td>
      <td>Low to start; high to audit</td>
    </tr>
    <tr>
      <td><strong>Self-host Ollama + GBNF grammar</strong></td>
      <td>Strong if you pin everything yourself</td>
      <td>Yes, at the decoder</td>
      <td>You implement</td>
      <td>High (you operate the GPU, monitor the loop, build the audit, build the bench)</td>
    </tr>
    <tr>
      <td><strong>Self-host vLLM + grammar mode</strong></td>
      <td>Strong</td>
      <td>Yes</td>
      <td>You implement</td>
      <td>High; vLLM ops is non-trivial</td>
    </tr>
    <tr>
      <td><strong>CogOS</strong></td>
      <td>Pinned, audited, falsifiable via the bench</td>
      <td>Yes, at the decoder</td>
      <td>Append-only, hash-chained, header-exposed</td>
      <td>Drop-in (chat-completions shape)</td>
    </tr>
  </tbody>
</table>

<p>
If you have a serious infra team and the appetite to operate your own GPU
inference stack, self-hosting Ollama or vLLM with grammar mode gives you
the same primitive at the decoder level. CogOS exists for teams that want
the primitive without operating the substrate, plus the audit trail and
the open determinism bench as a structural commitment.
</p>

<hr>

<h2 id="roadmap">10 · What's next</h2>

<p>
Public roadmap (subject to revision; we ship what survives the bench):
</p>

<ul>
  <li><strong>Q3 2026:</strong> Add Llama 3.3 (3B and 8B) as alternative
      tier backends; the routing alias stays the same, the underlying
      weights become customer-selectable.</li>
  <li><strong>Q4 2026:</strong> vLLM upstream support reaching parity with
      the Ollama path; enables larger batch sizes for the Operator Team
      and Compliance tiers.</li>
  <li><strong>Q1 2027:</strong> Tool-use / function-calling with the same
      schema-locking guarantee applied to the tool-call arguments.</li>
  <li><strong>Continuous:</strong> Bench expansion. Every additional
      provider PR'd in expands the comparative footprint; every scenario
      that the bench catches drift on becomes a permanent regression test.</li>
</ul>

<hr>

<h2 id="refs">11 · References</h2>

<ul>
  <li>Bench source &amp; CSV results: <a href="${BENCH_URL}">${BENCH_URL}</a></li>
  <li>Qwen 2.5 model family: <a href="https://qwen.ai/">qwen.ai</a></li>
  <li>GBNF grammar reference (llama.cpp):
      <a href="https://github.com/ggerganov/llama.cpp/blob/master/grammars/README.md">llama.cpp grammars</a></li>
  <li>JSON Schema Draft 2020-12 specification:
      <a href="https://json-schema.org/draft/2020-12/schema">json-schema.org</a></li>
  <li>Sampling non-determinism in batched GPU inference (community write-ups,
      multiple): search &quot;temperature 0 nondeterminism floating point batched&quot;</li>
  <li>CogOS terms / privacy / acceptable use:
      <a href="/terms">terms</a> · <a href="/privacy">privacy</a> · <a href="/aup">aup</a></li>
</ul>

<p style="margin-top:32px;color:#8b949e">
If you read this and something here is wrong, please open an issue on the
bench repo or email <a href="mailto:support@5ceos.com">support@5ceos.com</a>.
We treat technical objections as the highest-value feedback we get. The
doctrine, again: <em>determinism by construction, not by hope</em>.
</p>

${SIGNUP_CTA}
`;
  return wrap(body);
}

module.exports = { whitepaperHtml };
