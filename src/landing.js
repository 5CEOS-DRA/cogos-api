'use strict';

// Public landing + success + cancel pages. Pure HTML, served from the
// gateway itself (no separate static host needed for v1).

const LANDING_HTML = `<!DOCTYPE html>
<html>
<head>
  <title>CogOS — deterministic LLM API</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    *{box-sizing:border-box}
    body{font-family:ui-monospace,SF Mono,Menlo,monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:32px 20px}
    main{max-width:760px;margin:0 auto}
    h1{color:#58a6ff;font-size:28px;margin:0 0 6px}
    .tag{color:#8b949e;font-size:13px;margin-bottom:32px}
    h2{color:#58a6ff;font-size:18px;margin:28px 0 10px;border-bottom:1px solid #30363d;padding-bottom:6px}
    pre{background:#161b22;border:1px solid #30363d;padding:14px;border-radius:6px;overflow-x:auto;font-size:12px;line-height:1.5}
    code{background:#161b22;padding:2px 5px;border-radius:3px;font-size:12px}
    .pill{background:#161b22;border:1px solid #30363d;padding:14px 18px;margin:12px 0;border-radius:6px}
    .pill .head{color:#58a6ff;font-weight:600;margin-bottom:4px}
    .price{font-size:42px;color:#3fb950;font-weight:600;margin:18px 0 4px}
    .price-sub{color:#8b949e;font-size:12px;margin-bottom:16px}
    .cta{display:inline-block;background:#238636;color:#fff;padding:11px 28px;border-radius:6px;font-size:14px;font-weight:600;border:0;cursor:pointer;font-family:inherit;text-decoration:none}
    .cta:hover{background:#2ea043}
    .cta:disabled{background:#444;cursor:not-allowed}
    .compare{width:100%;border-collapse:collapse;font-size:12px;margin:14px 0}
    .compare th,.compare td{padding:8px 10px;border-bottom:1px solid #21262d;text-align:left}
    .compare th{color:#8b949e;font-weight:600;background:#161b22}
    .yes{color:#3fb950}.no{color:#f85149}
    a{color:#58a6ff}
    footer{color:#6e7681;font-size:11px;margin-top:48px;padding-top:18px;border-top:1px solid #21262d}
    .live-note{background:#1a3a5c;border:1px solid #1f6feb;color:#79c0ff;padding:10px 14px;border-radius:6px;font-size:12px;margin-bottom:24px}
  </style>
</head>
<body>
<main>
  <h1>CogOS</h1>
  <div class="tag">An OpenAI-compatible LLM API with the guarantees you actually need in production.</div>

  <div class="live-note">
    🟢 Live preview: this gateway is operational right now. Visit
    <code><a href="/health">/health</a></code> to see it respond. The bench data backing every
    claim on this page is at
    <a href="https://github.com/5CEOS-DRA/llm-determinism-bench">github.com/5CEOS-DRA/llm-determinism-bench</a> —
    run it against any provider; we'll wait.
  </div>

  <h2>What you get</h2>

  <div class="pill">
    <div class="head">Deterministic outputs at temperature=0</div>
    Same input → same bytes out, run after run. Provable. OpenAI and Anthropic
    won't promise this even with <code>seed</code>; CogOS does, because the
    model digest is pinned and the decoder is local.
  </div>

  <div class="pill">
    <div class="head">Schema-locked structured output</div>
    Pass <code>response_format: { type: "json_schema", json_schema: {...} }</code>
    and the decoder is grammar-constrained at the token level. Not "try and retry."
    The model <em>physically can't</em> emit non-conforming JSON.
  </div>

  <div class="pill">
    <div class="head">Drop-in OpenAI compatibility</div>
    Already using <code>openai</code> or <code>@anthropic/sdk</code>? Change one
    env var: <code>OPENAI_BASE_URL=https://cogos.5ceos.com/v1</code>. Done.
    If you don't like it, change it back in 10 seconds.
  </div>

  <div class="pill">
    <div class="head">No rate limits within your plan</div>
    OpenAI's $5/mo Tier-1 starts at 3 RPM. Anthropic's free tier caps you faster.
    CogOS Operator Starter: <strong>100k requests/month, no per-minute throttle</strong>.
  </div>

  <h2>How it compares</h2>

  <table class="compare">
    <tr><th>Promise</th><th>OpenAI gpt-4o</th><th>Anthropic Claude</th><th>CogOS</th></tr>
    <tr><td>Deterministic at temperature=0</td><td class="no">best-effort</td><td class="no">best-effort</td><td class="yes">guaranteed</td></tr>
    <tr><td>JSON schema enforced at decode</td><td class="yes">strict mode</td><td class="no">tool-use only</td><td class="yes">always available</td></tr>
    <tr><td>Model snapshot pinned across upgrades</td><td class="no">no</td><td class="no">no</td><td class="yes">yes</td></tr>
    <tr><td>Rate limit on $25 plan</td><td>n/a</td><td>n/a</td><td class="yes">none within 100k req/mo</td></tr>
    <tr><td>Inference is local (no data egress)</td><td class="no">no</td><td class="no">no</td><td class="yes">yes</td></tr>
  </table>

  <h2>Pricing</h2>

  <div class="pill">
    <div class="head">Operator Starter</div>
    <div class="price">$25/mo</div>
    <div class="price-sub">100,000 requests · OpenAI-compatible · schema-locked decoding · no rate limit</div>
    <form action="/signup" method="POST" style="margin:0">
      <button class="cta" type="submit">Start with Stripe →</button>
    </form>
  </div>

  <h2>Try it in 30 seconds (after signup)</h2>

  <pre><code>curl https://cogos.5ceos.com/v1/chat/completions \\
  -H "Authorization: Bearer sk-cogos-..." \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "cogos-tier-b",
    "messages": [{"role":"user","content":"Capital of France?"}]
  }'</code></pre>

  <h2>FAQ</h2>

  <div class="pill">
    <div class="head">What model is "cogos-tier-b"?</div>
    Qwen 2.5 3B-instruct. Tier-routed by task shape per the GreenOps doctrine:
    classification → Tier B (3B), narrative → Tier A (7B). Pinned by content
    digest; we don't silently upgrade.
  </div>

  <div class="pill">
    <div class="head">What happens at the 100k limit?</div>
    You get a clean 429 with <code>X-Cogos-Rate-Limit-Reset</code>. Upgrade to
    Operator Pro ($99/mo, 1M requests + Tier-A access) or wait for the next
    billing cycle.
  </div>

  <div class="pill">
    <div class="head">Why should I trust you on determinism?</div>
    Don't. Run our bench against us:
    <a href="https://github.com/5CEOS-DRA/llm-determinism-bench">github.com/5CEOS-DRA/llm-determinism-bench</a>.
    Open source, MIT, you re-run with your own credentials.
  </div>

  <footer>
    Built by 5CEOS · <a href="https://5ceos-dra.github.io">blog</a> ·
    <a href="https://github.com/5CEOS-DRA/cogos-api">source visibility on request</a>
  </footer>
</main>
</body>
</html>`;

function successHtml({ apiKey, keyId, expiresAt }) {
  // apiKey may be null if the customer revisited /success past the 10-min window.
  const keyBlock = apiKey
    ? `<pre id="apikey"><code>${apiKey}</code></pre>
       <button onclick="navigator.clipboard.writeText('${apiKey}')" class="cta">Copy key</button>
       <div class="warn">⚠ This is the only time we'll show this key. Save it now.
       (Expires for /success display at ${expiresAt}; it remains valid as an API key.)</div>`
    : `<div class="warn">This success page expired (10-min window).
       Your key was issued — check your Stripe receipt email for confirmation.
       To rotate or recover, contact support.</div>`;

  return `<!DOCTYPE html>
<html><head>
<title>CogOS — welcome</title>
<style>
*{box-sizing:border-box}
body{font-family:ui-monospace,SF Mono,Menlo,monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:32px 20px}
main{max-width:680px;margin:0 auto}
h1{color:#3fb950;font-size:24px;margin:0 0 24px}
pre{background:#161b22;border:1px solid #30363d;padding:14px;border-radius:6px;overflow-x:auto;font-size:13px}
code{font-family:inherit}
.cta{background:#238636;color:#fff;border:0;padding:9px 22px;border-radius:6px;cursor:pointer;font-family:inherit;font-size:13px;margin:8px 0}
.warn{background:#3d2611;border:1px solid #9e6a03;color:#d29922;padding:12px 14px;border-radius:6px;margin:14px 0;font-size:12px}
a{color:#58a6ff}
</style></head><body><main>
<h1>✓ Welcome to CogOS</h1>
<p>Your subscription is active and your API key is ready below.</p>
${keyBlock}
<h2 style="color:#58a6ff;font-size:16px;margin-top:28px">Try your first call</h2>
<pre><code>curl https://cogos.5ceos.com/v1/chat/completions \\
  -H "Authorization: Bearer ${apiKey || 'sk-cogos-XXXXXXX'}" \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "cogos-tier-b",
    "messages": [{"role":"user","content":"Hello"}]
  }'</code></pre>
<p style="color:#6e7681;font-size:11px;margin-top:24px">
Receipts at your billing email. Cancel anytime via Stripe customer portal.
</p>
</main></body></html>`;
}

const CANCEL_HTML = `<!DOCTYPE html>
<html><head><title>CogOS — checkout cancelled</title>
<style>body{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:32px 20px;text-align:center}
main{max-width:480px;margin:0 auto}h1{color:#f85149}a{color:#58a6ff}
.cta{display:inline-block;background:#238636;color:#fff;padding:10px 22px;border-radius:6px;text-decoration:none;margin-top:16px}</style></head>
<body><main>
<h1>Checkout cancelled</h1>
<p>No payment was taken. You can try again whenever.</p>
<a class="cta" href="/">← Back to home</a>
</main></body></html>`;

module.exports = { LANDING_HTML, successHtml, CANCEL_HTML };
