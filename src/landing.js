'use strict';

// Public landing + success + cancel pages. Pure HTML, served from the
// gateway itself (no separate static host needed for v1).

const LANDING_HTML = `<!DOCTYPE html>
<html>
<head>
  <title>CogOS — the cognition substrate for production AI</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    *{box-sizing:border-box}
    body{font-family:ui-monospace,SF Mono,Menlo,monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:32px 20px}
    main{max-width:760px;margin:0 auto}
    h1{color:#58a6ff;font-size:28px;margin:0 0 6px}
    .tag{color:#8b949e;font-size:13px;margin-bottom:32px;line-height:1.5}
    h2{color:#58a6ff;font-size:18px;margin:28px 0 10px;border-bottom:1px solid #30363d;padding-bottom:6px}
    pre{background:#161b22;border:1px solid #30363d;padding:14px;border-radius:6px;overflow-x:auto;font-size:12px;line-height:1.5}
    code{background:#161b22;padding:2px 5px;border-radius:3px;font-size:12px}
    .pill{background:#161b22;border:1px solid #30363d;padding:14px 18px;margin:12px 0;border-radius:6px}
    .pill .head{color:#58a6ff;font-weight:600;margin-bottom:4px}
    .price{font-size:42px;color:#3fb950;font-weight:600;margin:18px 0 4px}
    .price-sub{color:#8b949e;font-size:12px;margin-bottom:16px}
    .cta{display:inline-block;background:#238636;color:#fff;padding:11px 28px;border-radius:6px;font-size:14px;font-weight:600;border:0;cursor:pointer;font-family:inherit;text-decoration:none}
    .cta:hover{background:#2ea043}
    .pain-fix{width:100%;border-collapse:collapse;font-size:12px;margin:14px 0}
    .pain-fix th,.pain-fix td{padding:10px 12px;border-bottom:1px solid #21262d;text-align:left;vertical-align:top}
    .pain-fix th{color:#8b949e;font-weight:600;background:#161b22}
    .pain-fix .pain{color:#f85149;width:50%}
    .pain-fix .fix{color:#3fb950;width:50%}
    a{color:#58a6ff}
    footer{color:#6e7681;font-size:11px;margin-top:48px;padding-top:18px;border-top:1px solid #21262d}
    .live-note{background:#1a3a5c;border:1px solid #1f6feb;color:#79c0ff;padding:10px 14px;border-radius:6px;font-size:12px;margin-bottom:24px}
  </style>
</head>
<body>
<main>
  <h1>CogOS</h1>
  <div class="tag">A <strong>deterministic uptime loop</strong> for production AI. Same call → same bytes out. Same call next month → same bytes out. Same call under load → no rate limit, no throttle, no provider drift. The mechanism that makes AI-backed features safe to ship.</div>

  <div class="live-note">
    🟢 Live now: this gateway is serving real traffic. Hit
    <code><a href="/health">/health</a></code> for the heartbeat.
    Every claim below is verifiable in
    <a href="https://github.com/5CEOS-DRA/llm-determinism-bench">the public bench</a> —
    open-source, MIT, run it yourself with any provider's credentials.
  </div>

  <h2>The mechanism</h2>

  <div class="pill">
    <div class="head">Deterministic</div>
    Every call is a closed function: input → bytes out. Schema-locked at the decoder level (the model physically can't emit non-conforming JSON). Model digest pinned, sampling settings pinned, temperature 0 by default. Run the same prompt 20 times, get 20 identical responses. Verifiable via the public bench.
  </div>

  <div class="pill">
    <div class="head">Uptime</div>
    Local inference, no third-party rate limit, no provider snapshot rotation, no ToS surface that can change under you. Your plan's request budget is yours — burst as hard as you need within it. The loop stays up because there's no remote dependency to fail.
  </div>

  <div class="pill">
    <div class="head">Loop</div>
    Request → constrained decode → schema-validated response → provenance event → metered usage. Every step deterministic, every step observable, every step replayable from the hash-chained event log. The substrate isn't an LLM endpoint; it's a loop you can build production code on.
  </div>

  <h2>What breaks without it</h2>

  <table class="pain-fix">
    <tr><th>What breaks in production today</th><th>What CogOS guarantees</th></tr>
    <tr>
      <td class="pain"><strong>The model returned malformed JSON in prod.</strong> Worked fine in dev. You're debugging the LLM, not your code.</td>
      <td class="fix"><strong>Schema-locked decoding at the token level.</strong> Pass a JSON Schema, the decoder is physically constrained. Non-conforming output is impossible — not retried, prevented.</td>
    </tr>
    <tr>
      <td class="pain"><strong>Your code stopped working two weeks ago.</strong> No one touched it. The provider rotated the model behind the same name.</td>
      <td class="fix"><strong>Model digest is pinned.</strong> Same content hash every call. Upgrades are explicit operator actions, not silent vendor pushes.</td>
    </tr>
    <tr>
      <td class="pain"><strong>3 requests per minute on the starter tier.</strong> Your batch job runs at 3am. You wake to angry customers at 7.</td>
      <td class="fix"><strong>100,000 requests/month, no per-minute throttle.</strong> Burst as hard as your business needs. No tier ladder to climb before you can scale.</td>
    </tr>
    <tr>
      <td class="pain"><strong>"Temperature zero" is best-effort.</strong> Same input, different bytes, no reproducible test runs.</td>
      <td class="fix"><strong>Byte-identical outputs at temperature 0.</strong> Verifiable — 20 identical calls return 1 unique output. Determinism = 1.0000. Provable.</td>
    </tr>
    <tr>
      <td class="pain"><strong>Compliance asks where the inference happens.</strong> You don't know exactly. Their counsel doesn't sign off.</td>
      <td class="fix"><strong>Local inference, no data egress to third-party clouds.</strong> Your provenance log is hash-chained, queryable, auditable.</td>
    </tr>
  </table>

  <h2>How the loop is built</h2>

  <div class="pill">
    <div class="head">A runtime, not a model</div>
    Open-weight models (Qwen, Llama, Mistral) are commodities. CogOS is the runtime layer above them — grammar-constrained decoders, pinned digests, tier routing per task shape, provenance events on every call. The model is the CPU. CogOS is the OS that makes it operable. The loop is what you ship against.
  </div>

  <div class="pill">
    <div class="head">Drop-in for your existing chat-completions client</div>
    The API speaks the same <code>POST /v1/chat/completions</code> shape your current SDK already sends. Point your client at <code>https://cogos.5ceos.com/v1</code> and try it. If you don't like it, change it back in ten seconds.
  </div>

  <div class="pill">
    <div class="head">Tier-routed by task, not by guess</div>
    Use <code>model: "cogos-tier-b"</code> for classification-shaped work, <code>"cogos-tier-a"</code> for narrative. The router picks the right size of open-weight model per shape — sufficient is sufficient, the GreenOps doctrine.
  </div>

  <h2>Pricing</h2>

  <div class="pill">
    <div class="head">Operator Starter</div>
    <div class="price">$25/mo</div>
    <div class="price-sub">100,000 requests · schema-locked decoding · deterministic at temp=0 · no per-minute rate limit</div>
    <form action="/signup" method="POST" style="margin:0">
      <button class="cta" type="submit">Start →</button>
    </form>
  </div>

  <h2>Try it in 30 seconds (after signup)</h2>

  <pre><code>curl https://cogos.5ceos.com/v1/chat/completions \\
  -H "Authorization: Bearer sk-cogos-..." \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "cogos-tier-b",
    "messages": [{"role":"user","content":"Capital of France?"}],
    "response_format": {
      "type": "json_schema",
      "json_schema": {
        "name": "answer",
        "strict": true,
        "schema": {
          "type": "object",
          "required": ["country","capital"],
          "properties": {
            "country": {"type":"string"},
            "capital": {"type":"string"}
          }
        }
      }
    }
  }'</code></pre>

  <h2>FAQ</h2>

  <div class="pill">
    <div class="head">Why should I trust you on determinism?</div>
    Don't. Clone <a href="https://github.com/5CEOS-DRA/llm-determinism-bench">the bench</a> and run it. MIT-licensed, open methodology, hand-coded rubrics — every claim on this page becomes a CSV you can publish or attack.
  </div>

  <div class="pill">
    <div class="head">What models?</div>
    Qwen 2.5 (3B and 7B) today. Open-weight, content-addressed. New tiers (Llama 3.3, Mistral) land as discrete versioned upgrades — no silent swaps.
  </div>

  <div class="pill">
    <div class="head">What happens at the 100k limit?</div>
    A clean <code>429</code> with <code>X-Cogos-Rate-Limit-Reset</code>. Upgrade to <em>Operator Pro</em> ($99/mo, 1M req + Tier-A) or wait for next cycle. Plans aren't lottery tickets — you know what you're getting.
  </div>

  <footer>
    Built by 5CEOS · <a href="https://5ceos-dra.github.io">blog</a> ·
    <a href="https://github.com/5CEOS-DRA/llm-determinism-bench">benchmark</a> ·
    determinism by construction, not by hope
  </footer>
</main>
</body>
</html>`;

function successHtml({ apiKey, keyId, expiresAt }) {
  const keyBlock = apiKey
    ? `<pre id="apikey"><code>${apiKey}</code></pre>
       <button onclick="navigator.clipboard.writeText('${apiKey}')" class="cta">Copy key</button>
       <div class="warn">⚠ This is the only time we'll show this key. Save it now.
       (Display window expires at ${expiresAt}; the key itself remains valid.)</div>`
    : `<div class="warn">This success page expired (10-min window).
       Your key was issued — check your billing receipt email for confirmation.
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
Receipts at your billing email. Cancel anytime via customer portal.
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
<p>No payment was taken. Come back whenever.</p>
<a class="cta" href="/">← Back to home</a>
</main></body></html>`;

module.exports = { LANDING_HTML, successHtml, CANCEL_HTML };
