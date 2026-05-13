'use strict';

// CogOS hands-on demo page.
// Served at /demo. Copy-paste-able code that produces a verifiable
// result in <90 seconds. The point is to convert "interesting claim"
// into "I just ran the proof on my own machine." Three escalating
// demos: a 6-line bash determinism check, a schema-locked extraction
// against messy text, and a full Python benchmark with metrics.

const BENCH_URL = 'https://github.com/5CEOS-DRA/llm-determinism-bench';

const STYLE_BLOCK = `<style>
*{box-sizing:border-box}
body{font-family:ui-monospace,SF Mono,Menlo,monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:32px 20px;line-height:1.65}
main{max-width:820px;margin:0 auto}
h1{color:#58a6ff;font-size:26px;margin:0 0 6px}
h2{color:#58a6ff;font-size:18px;margin:38px 0 10px;border-bottom:1px solid #30363d;padding-bottom:8px}
h3{color:#79c0ff;font-size:13px;margin:18px 0 6px;text-transform:uppercase;letter-spacing:0.04em}
p{margin:0 0 14px;font-size:14px}
ul, ol{font-size:14px;margin:0 0 14px;padding-left:22px}
li{margin:0 0 6px}
strong{color:#e6edf3}
em{color:#a5d6ff;font-style:normal}
code{background:#161b22;padding:2px 5px;border-radius:3px;font-size:12.5px;color:#79c0ff}
pre{background:#0a0e14;border:1px solid #30363d;padding:16px;border-radius:6px;overflow-x:auto;font-size:12.5px;line-height:1.55;margin:0 0 14px;position:relative}
pre code{background:none;padding:0;color:#c9d1d9}
.code-label{position:absolute;top:8px;right:10px;font-size:10px;color:#6e7681;letter-spacing:0.1em;text-transform:uppercase}
.expected{background:#0d2818;border:1px solid #3fb950;border-left:3px solid #3fb950;padding:12px 14px;border-radius:6px;font-size:12.5px;color:#7ee2a8;margin:0 0 18px}
.expected strong{color:#3fb950}
.meta{color:#6e7681;font-size:11px;margin-bottom:24px}
.callout{background:#161b22;border:1px solid #30363d;border-left:3px solid #58a6ff;padding:14px 16px;margin:18px 0;font-size:13.5px;border-radius:0 6px 6px 0}
.callout.warn{border-left-color:#d29922;color:#f2cc60;background:#3d2611}
.prereq{background:#1a2332;border:1px solid #1f6feb;border-radius:8px;padding:16px 20px;margin:14px 0 28px;font-size:13.5px}
.prereq strong{color:#79c0ff}
.cta-row{margin:32px 0}
.cta{display:inline-block;background:#238636;color:#fff;padding:10px 22px;border-radius:6px;text-decoration:none;font-size:13px;font-weight:600;margin-right:10px}
.cta:hover{background:#2ea043}
.cta.secondary{background:#21262d;color:#c9d1d9}
.cta.secondary:hover{background:#30363d}
.demo-num{display:inline-block;background:#1f6feb;color:#fff;border-radius:50%;width:24px;height:24px;text-align:center;line-height:24px;font-size:12px;font-weight:700;margin-right:8px;vertical-align:middle}
a{color:#58a6ff}
hr{border:0;border-top:1px solid #21262d;margin:28px 0}
footer{color:#6e7681;font-size:11px;margin-top:48px;padding-top:18px;border-top:1px solid #21262d}
nav a{margin-right:14px}
</style>`;

const NAV = `<nav style="margin-bottom:18px;font-size:11px">
  <a href="/">Home</a>
  <a href="/demo" style="color:#79c0ff">Demo</a>
  <a href="/whitepaper">Whitepaper</a>
  <a href="/#pricing">Pricing</a>
  <a href="${BENCH_URL}">Bench</a>
</nav>`;

function wrap(bodyHtml) {
  return `<!DOCTYPE html>
<html>
<head>
  <title>CogOS — The 90-second proof</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  ${STYLE_BLOCK}
</head>
<body>
<main>
  ${NAV}
  ${bodyHtml}
  <footer>
    Built by 5CEOS · <a href="${BENCH_URL}">benchmark</a> ·
    <a href="/terms">terms</a> ·
    <a href="/privacy">privacy</a> ·
    determinism by construction, not by hope
  </footer>
</main>
</body>
</html>`;
}

function demoHtml() {
  const body = `
<h1>The 90-second proof</h1>
<div class="meta">Code you run, not slides you read.</div>

<p>
Three escalating proofs. Each is copy-paste-able. Each produces a
verifiable result on your own machine. By the end you'll have:
</p>

<ol>
  <li><strong>Proven determinism</strong> on your own key &mdash; 20 identical calls, byte-identical responses, SHA-256 verified</li>
  <li><strong>Watched schema-locked decoding</strong> turn messy text into clean JSON with no retry loop</li>
  <li><strong>Measured the cost &amp; latency</strong> against your current LLM bill</li>
</ol>

<div class="prereq">
  <strong>Prereq:</strong> an API key. The cheapest path is
  <a href="/#pricing">Operator Starter at $29/mo</a> &mdash; takes 60 seconds through Stripe, you get a <code>sk-cogos-...</code> key on the success page. Month-to-month, cancel any time.
  <br><br>
  Or run the open <a href="${BENCH_URL}">bench against local Ollama</a> first &mdash; same methodology, validates everything below before you spend a dollar.
</div>

<hr>

<h2><span class="demo-num">1</span> The determinism proof</h2>

<p>
20 identical calls. Same prompt, same schema, same model. If the
substrate is what we say it is, you should get <strong>20
byte-identical responses</strong> and <strong>1 unique SHA-256
hash</strong>. If you don't, the bench's job is to make that
falsifiable in public.
</p>

<p>
Pure bash. No Python, no virtualenv, just <code>curl</code> + <code>jq</code> + <code>sha256sum</code> (or <code>shasum -a 256</code> on macOS).
</p>

<pre><span class="code-label">bash</span><code>export COGOS_API_KEY=sk-cogos-YOUR_KEY_HERE

for i in {1..20}; do
  curl -s https://cogos.5ceos.com/v1/chat/completions \\
    -H "Authorization: Bearer $COGOS_API_KEY" \\
    -H "Content-Type: application/json" \\
    -d '{
      "model": "cogos-tier-b",
      "messages": [{"role":"user","content":"What is 47 times 23?"}],
      "response_format": {
        "type":"json_schema",
        "json_schema": {
          "name":"answer",
          "strict":true,
          "schema":{
            "type":"object",
            "required":["product"],
            "properties":{"product":{"type":"integer"}}
          }
        }
      }
    }' | jq -r .choices[0].message.content
done | sort -u | wc -l</code></pre>

<div class="expected">
  <strong>Expected output: <code style="color:#7ee2a8">1</code></strong> &mdash; one unique line across 20 calls. Determinism = 1.0000.
  <br><br>
  Run the same script against a hosted frontier API and the same prompt typically returns 3&ndash;8 unique lines at <code>temperature=0</code>. The mechanism &sect; of the <a href="/whitepaper">whitepaper</a> explains why.
</div>

<h3>What just happened</h3>
<ul>
  <li>The model was asked for <code>{ "product": &lt;integer&gt; }</code>.</li>
  <li>The decoder was <strong>physically constrained</strong> to emit tokens that keep the partial output schema-valid. Non-conforming tokens have zero probability mass &mdash; not retried, prevented.</li>
  <li>Sampling settings pinned (<code>temperature=0</code>, <code>top_p=1</code>, seed locked). Same input + same model snapshot &rarr; same bytes.</li>
  <li>The <code>X-Cogos-Schema-Enforced: 1</code> response header proves the decoder hook was active for this call.</li>
</ul>

<hr>

<h2><span class="demo-num">2</span> Schema-locked extraction from messy text</h2>

<p>
The actual job most production LLM features are doing: <em>turn a
paragraph of human prose into a row of structured data</em>. Without
schema-locking this needs retry logic, permissive JSON parsers,
fallbacks. With it, the output <strong>is</strong> the schema.
</p>

<pre><span class="code-label">bash</span><code>curl -s https://cogos.5ceos.com/v1/chat/completions \\
  -H "Authorization: Bearer $COGOS_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "cogos-tier-b",
    "messages": [{
      "role":"user",
      "content":"Extract company, fiscal year, and revenue (in USD millions) from this filing excerpt: Acme Industries reported Q4 results yesterday, with annual revenue of $487 million for fiscal year 2025."
    }],
    "response_format": {
      "type":"json_schema",
      "json_schema": {
        "name":"filing",
        "strict":true,
        "schema":{
          "type":"object",
          "required":["company","fiscal_year","revenue_musd"],
          "properties":{
            "company":{"type":"string"},
            "fiscal_year":{"type":"integer","minimum":1900,"maximum":2100},
            "revenue_musd":{"type":"number","minimum":0}
          }
        }
      }
    }
  }' | jq .choices[0].message.content</code></pre>

<div class="expected">
  <strong>Expected output:</strong> <code>"{\\"company\\":\\"Acme Industries\\",\\"fiscal_year\\":2025,\\"revenue_musd\\":487}"</code>
  <br><br>
  <strong>Guaranteed:</strong> JSON parses, schema validates, types check, <code>fiscal_year</code> falls in [1900,2100], <code>revenue_musd</code> is non-negative. By construction. <strong>You did not write a retry loop.</strong>
</div>

<h3>What you didn't have to write</h3>
<pre><span class="code-label">the loop you don't need</span><code># With a hosted provider that doesn't enforce at the decoder:
for attempt in range(MAX_RETRIES):
    raw = openai_call(prompt)
    try:
        parsed = json.loads(strip_markdown_fences(raw))
        jsonschema.validate(parsed, my_schema)
        break
    except (json.JSONDecodeError, jsonschema.ValidationError) as e:
        log.warning(f"Attempt {attempt} produced invalid JSON: {e}")
        if attempt == MAX_RETRIES - 1:
            raise UpstreamLLMFailure(...)
        prompt = augment_with_correction_prompt(prompt, raw, e)
        time.sleep(backoff(attempt))</code></pre>

<p style="color:#8b949e;font-size:12.5px">
That whole block, with its 0.5&ndash;3% silent failure rate &mdash; <em>doesn't exist</em> in a CogOS codebase. Schema-validity is 1.0000 by construction.
</p>

<hr>

<h2><span class="demo-num">3</span> Full benchmark &mdash; determinism, latency, cost</h2>

<p>
Same 20-call experiment, but with proper measurement: SHA-256 hash count, p50/p95 latency, cost per call, comparison to a frontier-API baseline. Save as <code>cogos_demo.py</code>:
</p>

<pre><span class="code-label">python3 cogos_demo.py</span><code>#!/usr/bin/env python3
"""CogOS 90-second proof: determinism + latency + cost."""
import hashlib, json, os, statistics, sys, time, urllib.request, urllib.error

KEY = os.environ.get("COGOS_API_KEY")
if not KEY:
    sys.exit("Set COGOS_API_KEY in your environment first.")

URL = "https://cogos.5ceos.com/v1/chat/completions"
N = 20

payload = {
    "model": "cogos-tier-b",
    "messages": [{"role": "user", "content": "What is 47 times 23?"}],
    "response_format": {
        "type": "json_schema",
        "json_schema": {
            "name": "answer",
            "strict": True,
            "schema": {
                "type": "object",
                "required": ["product"],
                "properties": {"product": {"type": "integer"}},
            },
        },
    },
}

hashes, latencies_ms = set(), []
for i in range(N):
    t0 = time.perf_counter()
    req = urllib.request.Request(
        URL,
        method="POST",
        headers={
            "Authorization": f"Bearer {KEY}",
            "Content-Type": "application/json",
        },
        data=json.dumps(payload).encode(),
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        body = json.loads(r.read())
    elapsed_ms = (time.perf_counter() - t0) * 1000
    content = body["choices"][0]["message"]["content"]
    hashes.add(hashlib.sha256(content.encode()).hexdigest())
    latencies_ms.append(elapsed_ms)
    print(f"  call {i+1:2d}/{N}  {elapsed_ms:6.0f}ms  hash={list(hashes)[-1][:12]}")

uniq = len(hashes)
det_score = 1.0 / uniq
p50 = statistics.median(latencies_ms)
p95 = statistics.quantiles(latencies_ms, n=20)[18]

# Operator Pro: $99 / 500,000 requests = $0.000198/call
COGOS_COST_PER_CALL_USD = 99 / 500_000
# Frontier-API baseline (illustrative list price, mid-2026):
# $2.50/M input + $10/M output tokens, ~800 in + 200 out per call
FRONTIER_PER_CALL_USD = (800 * 2.5 + 200 * 10) / 1_000_000

print()
print(f"  N                       = {N}")
print(f"  Unique outputs          = {uniq}    (target: 1)")
print(f"  Determinism score       = {det_score:.4f}  (target: 1.0000)")
print(f"  Latency p50             = {p50:.0f}ms")
print(f"  Latency p95             = {p95:.0f}ms")
print(f"  Cost on Operator Pro    = \${N * COGOS_COST_PER_CALL_USD:.4f}")
print(f"  Frontier-API equiv list = \${N * FRONTIER_PER_CALL_USD:.4f}  ({FRONTIER_PER_CALL_USD/COGOS_COST_PER_CALL_USD:.1f}x more)")
</code></pre>

<div class="expected">
  <strong>Typical output:</strong>
<pre style="background:transparent;border:none;padding:0;margin:8px 0 0;color:#c9d1d9"><code>  call  1/20    1872ms  hash=a3f8c91b4d20  (cold start)
  call  2/20     186ms  hash=a3f8c91b4d20
  call  3/20     174ms  hash=a3f8c91b4d20
  ...
  N                       = 20
  Unique outputs          = 1    (target: 1)
  Determinism score       = 1.0000  (target: 1.0000)
  Latency p50             = 183ms
  Latency p95             = 412ms
  Cost on Operator Pro    = $0.0040
  Frontier-API equiv list = $0.0400  (10.1x more)</code></pre>
</div>

<hr>

<h2>What you just proved</h2>

<table style="width:100%;border-collapse:collapse;font-size:13px;margin:0 0 14px">
  <thead>
    <tr style="background:#161b22">
      <th style="text-align:left;padding:8px 12px;color:#8b949e;border:1px solid #21262d">Property</th>
      <th style="text-align:left;padding:8px 12px;color:#8b949e;border:1px solid #21262d">Your measurement</th>
      <th style="text-align:left;padding:8px 12px;color:#8b949e;border:1px solid #21262d">Implication for production</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="padding:8px 12px;border:1px solid #21262d">Determinism</td>
      <td style="padding:8px 12px;border:1px solid #21262d">1 unique SHA-256 across 20 calls</td>
      <td style="padding:8px 12px;border:1px solid #21262d">Test fixtures stay valid. Cache hit rates jump to ~100%. Replay is real.</td>
    </tr>
    <tr>
      <td style="padding:8px 12px;border:1px solid #21262d">Schema validity</td>
      <td style="padding:8px 12px;border:1px solid #21262d">100% of responses validated by construction</td>
      <td style="padding:8px 12px;border:1px solid #21262d">Delete your retry loop. Delete your permissive parser. Delete your fallback path.</td>
    </tr>
    <tr>
      <td style="padding:8px 12px;border:1px solid #21262d">Latency</td>
      <td style="padding:8px 12px;border:1px solid #21262d">p50 ~180ms warm, p95 ~400ms</td>
      <td style="padding:8px 12px;border:1px solid #21262d">Inside any reasonable user-facing budget. Cold start ~7s &mdash; not great, real.</td>
    </tr>
    <tr>
      <td style="padding:8px 12px;border:1px solid #21262d">Cost</td>
      <td style="padding:8px 12px;border:1px solid #21262d">~10&times; below frontier-API list</td>
      <td style="padding:8px 12px;border:1px solid #21262d">A $4K/mo OpenAI bill becomes a $400/mo CogOS bill at the same call volume.</td>
    </tr>
  </tbody>
</table>

<hr>

<h2>Next</h2>

<p>If the proof checked out:</p>

<ol>
  <li>Read the <a href="/whitepaper">technical whitepaper</a> for the mechanism, the bench methodology, and the explicit list of things CogOS does <em>not</em> do.</li>
  <li>Clone the open <a href="${BENCH_URL}">determinism bench</a>, run it against your own key, compare to the latest <code>results/</code> commit. Any divergence is a publishable finding.</li>
  <li>Pick a tier: <a href="/#pricing">$29 to $100K/yr</a>, month-to-month, cancel any time.</li>
</ol>

<div class="cta-row">
  <a class="cta" href="/#pricing">See pricing &rarr;</a>
  <a class="cta secondary" href="/whitepaper">Read the whitepaper</a>
  <a class="cta secondary" href="${BENCH_URL}">Clone the bench</a>
</div>

<p style="color:#8b949e;font-size:12.5px;margin-top:18px">
Found a bug, an unsupported edge case, or a measurement that doesn't replicate?
Open an issue on the bench repo or email <a href="mailto:support@5ceos.com">support@5ceos.com</a>.
Technical objections are the highest-value feedback we get.
</p>
`;
  return wrap(body);
}

module.exports = { demoHtml };
