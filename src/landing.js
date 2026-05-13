'use strict';

// Public landing + success + cancel pages. Pure HTML, served from the
// gateway itself (no separate static host needed for v1).
//
// Pricing pills + the at-the-limit FAQ are rendered from the live
// packages.json registry — change a package in the Management Console
// and the landing page reflects it on next request, no HTML edit.

function tierLabel(tierId) {
  // 'cogos-tier-a' → 'Tier A', etc.
  const m = /^cogos-tier-([a-z])$/.exec(tierId);
  return m ? `Tier ${m[1].toUpperCase()}` : tierId;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function renderPricingPill(pkg) {
  const tiers = (pkg.allowed_model_tiers || []).map(tierLabel).join(' + ');
  const quota = (pkg.monthly_request_quota || 0).toLocaleString('en-US');
  const desc = pkg.description ? escapeHtml(pkg.description) : '';
  const priceLabel = pkg.monthly_usd === 0
    ? 'Free'
    : `$${Number(pkg.monthly_usd).toLocaleString('en-US')}/mo`;
  return `
  <div class="pill">
    <div class="head">${escapeHtml(pkg.display_name)}</div>
    <div class="price">${priceLabel}</div>
    <div class="price-sub">${quota.toLowerCase() === '0' ? 'unmetered' : quota + ' requests/mo'} · ${escapeHtml(tiers || '—')} · schema-locked decoding · deterministic at temp=0</div>
    ${desc ? `<div class="price-sub" style="margin-bottom:14px">${desc}</div>` : ''}
    <form action="/signup?package=${encodeURIComponent(pkg.id)}" method="POST" style="margin:0">
      <button class="cta" type="submit">Start →</button>
    </form>
  </div>`;
}

// The Enterprise pill is a static, sales-led offering — it is NOT a Stripe
// package because Enterprise contracts are negotiated (region pinning,
// dedicated GPU, MSA, SLA add-ons). The number is published on the page
// for honesty per Denny's directive ("show the enterprise prices and not
// hide it like the others"). No CTA — the price + description signal
// the tier exists; interested parties contact enterprise@5ceos.com via
// the footer or directly.
const ENTERPRISE_PILL_HTML = `
  <div class="pill" style="border-color:#58a6ff;background:#0d1f33">
    <div class="head">Enterprise</div>
    <div class="price">$100,000/yr</div>
    <div class="price-sub">50M requests/mo · dedicated GPU container · single-tenant · 99.9% SLA · SOC 2 Type II · MSA + DPA + BAA · quarterly business review · 12-month minimum</div>
    <div class="price-sub">Real deals close at $100K–$250K depending on add-ons (extra GPUs, 99.95% SLA, on-prem deployment, dedicated CSM).</div>
  </div>`;

function renderPricingSection(packages) {
  let pillsHtml;
  if (!packages || packages.length === 0) {
    pillsHtml = `
  <div class="pill">
    <div class="head">Self-serve tiers — setup pending</div>
    <div class="price-sub">No self-serve packages configured yet. The operator will set these from the Management Console. Enterprise is always available below.</div>
  </div>`;
  } else {
    pillsHtml = packages
      .sort((a, b) => (a.monthly_usd || 0) - (b.monthly_usd || 0))
      .map(renderPricingPill)
      .join('\n');
  }
  return pillsHtml + ENTERPRISE_PILL_HTML;
}

function renderAtLimitFaq(packages) {
  const list = (packages || []).filter((p) => p.active !== false);
  if (list.length <= 1) {
    return `
  <div class="pill">
    <div class="head">What happens at your monthly quota?</div>
    A clean <code>429</code> with <code>X-Cogos-Quota-Reset</code> pointing at the start of the next billing cycle. Plans aren't lottery tickets — you know what you're getting.
  </div>`;
  }
  return `
  <div class="pill">
    <div class="head">What happens at your monthly quota?</div>
    A clean <code>429</code> with <code>X-Cogos-Quota-Reset</code> pointing at the start of the next billing cycle. Upgrade to a higher-quota package or wait for next cycle. Plans aren't lottery tickets — you know what you're getting.
  </div>`;
}

function renderLandingHtml(packages = []) {
  const PRICING_HTML = renderPricingSection(packages);
  const AT_LIMIT_FAQ_HTML = renderAtLimitFaq(packages);
  return `<!DOCTYPE html>
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
  <div class="tag"><strong>Reproducible LLM calls. No retry loops. No model drift.</strong> Schema-locked decoding means the model physically can't emit malformed JSON. Same call → same bytes out. Same call next month → same bytes out. Same call under load → no rate limit, no throttle. <strong style="color:#3fb950">78% less inference spend, 72% less carbon</strong> on a typical production mix — because most of your calls don't need a frontier model. Stop debugging the LLM. Ship the feature.</div>

  <div class="live-note">
    🟢 Live now: this gateway is serving real traffic. Hit
    <code><a href="/health">/health</a></code> for the heartbeat.
    Every claim below is verifiable in
    <a href="https://github.com/5CEOS-DRA/llm-determinism-bench">the public bench</a> —
    open-source, MIT, run it yourself with any provider's credentials.
  </div>

  <div style="background:#0d1f33;border:1px solid #58a6ff;border-left:3px solid #58a6ff;color:#c9d1d9;padding:14px 18px;border-radius:6px;font-size:13px;margin-bottom:14px">
    <strong style="color:#79c0ff">&rarr; Run the 90-second proof.</strong>
    Copy-paste code that proves determinism, schema-locking, and cost on your own machine.
    <a href="/demo" style="color:#3fb950;font-weight:600">Open the demo &rarr;</a>
  </div>

  <div style="background:#0d2818;border:1px solid #3fb950;border-left:3px solid #3fb950;color:#7ee2a8;padding:10px 14px;border-radius:6px;font-size:12.5px;margin-bottom:24px">
    <strong style="color:#3fb950">Or read the dev-honest version.</strong>
    The <a href="/whitepaper" style="color:#79c0ff">technical whitepaper</a> &mdash; mechanism, bench methodology, cost math, and the explicit list of things CogOS does <em>not</em> do. ~15 min read.
  </div>

  <div style="background:linear-gradient(180deg,#0d1f33 0%,#0d1117 100%);border:1px solid #30363d;border-left:3px solid #58a6ff;padding:24px 26px;border-radius:8px;margin:32px 0 40px;font-size:15px;line-height:1.75;color:#c9d1d9">
    <div style="font-size:11px;font-weight:700;letter-spacing:0.18em;text-transform:uppercase;color:#79c0ff;margin-bottom:14px">Why this matters</div>
    <p style="margin:0 0 14px;font-size:15px;line-height:1.75">
      Most AI failures don&apos;t come from your code &mdash; they come from <strong style="color:#e6edf3">drift, retries, malformed JSON, and silent provider changes</strong> that break features without warning. But the deeper cost is bigger than debugging. When a company can&apos;t get a <em style="color:#a5d6ff">truthful, stable view of its own operations</em>, everyone pays for it: higher prices, slower products, wasted compute, wasted labor, and decisions made on bad data.
    </p>
    <p style="margin:0 0 14px;font-size:15px;line-height:1.75">
      This loop removes that waste. <strong style="color:#e6edf3">Reproducible LLM calls</strong> with no drift, no retry storms, and no malformed output because schema-locked decoding makes invalid JSON <em style="color:#a5d6ff">physically impossible</em>. Same call &rarr; same bytes out. Same call next month &rarr; same bytes out. Same call under load &rarr; no throttles, no surprises.
    </p>
    <p style="margin:0 0 18px;font-size:15px;line-height:1.75">
      The result is <strong style="color:#3fb950">78% less inference spend</strong>, <strong style="color:#3fb950">72% less carbon</strong>, and a business that finally sees what&apos;s actually happening instead of guessing.
    </p>
    <div style="border-top:1px solid #30363d;padding-top:16px;font-size:14.5px;line-height:1.9">
      <div style="color:#e6edf3"><strong>Developers stop debugging.</strong></div>
      <div style="color:#e6edf3"><strong>Employers stop burning money.</strong></div>
      <div style="color:#e6edf3"><strong>Customers stop paying for the company&apos;s confusion.</strong></div>
    </div>
  </div>

  <h2>The mechanism</h2>

  <div class="pill">
    <div class="head">Deterministic</div>
    Every call is a closed function: input → bytes out. Schema-locked at the decoder level (the model physically can't emit non-conforming JSON). Sampling settings pinned, temperature 0 by default. Run the same prompt 20 times, get 20 identical responses. Verifiable via the public bench — we re-run it against our live inference path on a published cadence so determinism is something you can audit, not something we ask you to take on faith.
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
      <td class="fix"><strong>The public bench runs against our live path on a published cadence.</strong> Drift shows up in the CSV the same day. Customers see the same audit we see. No "trust us" — the receipts are open.</td>
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
    Open-weight models (Qwen, Llama, Mistral) are commodities. CogOS is the runtime layer above them — grammar-constrained decoders, tier routing per task shape, provenance events on every call, and an open determinism bench that audits the inference path on a published cadence. The model is the CPU. CogOS is the OS that makes it operable. The loop is what you ship against.
  </div>

  <div class="pill">
    <div class="head">Drop-in for your existing chat-completions client</div>
    The API speaks the same <code>POST /v1/chat/completions</code> shape your current SDK already sends. Point your client at <code>https://cogos.5ceos.com/v1</code> and try it. If you don't like it, change it back in ten seconds.
  </div>

  <div class="pill">
    <div class="head">Tier-routed by task, not by guess</div>
    Use <code>model: "cogos-tier-b"</code> for classification-shaped work, <code>"cogos-tier-a"</code> for narrative. The router picks the right size of open-weight model per shape — sufficient is sufficient, the GreenOps doctrine.
  </div>

  <div class="pill">
    <div class="head">Power savings, by construction</div>
    Most production LLM workloads are classification-shaped — sentiment, routing, extraction, scoring — and burning frontier-model wattage on them is just lighting money on fire. The router runs that traffic on Tier B (3B params) and reserves Tier A (7B) for narrative. Internal measurements on a representative production mix: <strong>78% reduction in inference spend</strong>, <strong>72% reduction in energy draw</strong>, and <strong>~75% of all calls served by Tiny/Mid tiers</strong> — while 100% of outputs remain schema-locked and auditable. The bench publishes <code>$/valid-output</code> by tier so the savings are something you can audit, not something we ask you to take on faith.
  </div>

  <h2>About us</h2>

  <div class="pill" style="border-color:#3fb950;background:#0d2818">
    <div class="head" style="color:#3fb950">We're privately backed. Not VC-funded.</div>
    Which means we get to <strong>hold pricing</strong>, refuse the <strong>growth-at-all-costs playbook</strong>, and keep the substrate <strong>determinism-first</strong> — instead of optimizing for the next funding round. Your tier won't get re-priced under you, the audit trail won't become a paid add-on, the bench stays open, and the substrate stays the substrate. We get to dream and build instead of pitch and exit.
  </div>

  <h2>Pricing</h2>
${PRICING_HTML}

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
    Qwen 2.5 (3B and 7B) today. Open-weight, content-addressed. New tiers (Llama 3.3, Mistral) land as discrete versioned upgrades — no silent swaps. The bench is re-run against the live inference path so any drift is published, not hidden.
  </div>

${AT_LIMIT_FAQ_HTML}

  <footer>
    Built by 5CEOS · <a href="https://5ceos-dra.github.io">blog</a> ·
    <a href="https://github.com/5CEOS-DRA/llm-determinism-bench">benchmark</a> ·
    <a href="/terms">terms</a> ·
    <a href="/privacy">privacy</a> ·
    <a href="/aup">acceptable use</a> ·
    determinism by construction, not by hope
  </footer>
</main>
</body>
</html>`;
}

function successHtml({ apiKey, keyId, expiresAt, sessionId }) {
  const portalHref = sessionId ? `/portal?session_id=${encodeURIComponent(sessionId)}` : null;
  const keyBlock = apiKey
    ? `<pre id="apikey"><code>${apiKey}</code></pre>
       <button onclick="navigator.clipboard.writeText('${apiKey}')" class="cta">Copy key</button>
       <div class="warn">⚠ This key is displayed for 24 hours after issuance. Save it now — after the window closes, the key remains valid but cannot be re-displayed.
       (Display window expires at ${expiresAt}.)</div>`
    : `<div class="warn">The 24-hour display window for this key has closed.
       Your key was issued and is still valid — bookmark this page next time to keep access for the full window.
       To rotate or recover, contact <a href="mailto:support@5ceos.com">support@5ceos.com</a>.</div>`;

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
<p style="color:#8b949e;font-size:12px;margin:0 0 8px">
First call may take 5&ndash;8s on cold start. Subsequent calls run in &lt;2s.
</p>
<pre><code>curl https://cogos.5ceos.com/v1/chat/completions \\
  -H "Authorization: Bearer ${apiKey || 'sk-cogos-XXXXXXX'}" \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "cogos-tier-b",
    "messages": [{"role":"user","content":"Hello"}]
  }'</code></pre>

<h2 style="color:#58a6ff;font-size:16px;margin-top:32px">What next</h2>
<p style="color:#8b949e;font-size:12px;margin:0 0 12px">
Three 30-second next steps to feel out what the substrate actually does:
</p>

<h3 style="color:#c9d1d9;font-size:13px;margin:18px 0 6px">1 &middot; List available models</h3>
<pre><code>curl https://cogos.5ceos.com/v1/models \\
  -H "Authorization: Bearer ${apiKey || 'sk-cogos-XXXXXXX'}"</code></pre>

<h3 style="color:#c9d1d9;font-size:13px;margin:18px 0 6px">2 &middot; Structured output (schema-locked at decode)</h3>
<p style="color:#8b949e;font-size:12px;margin:0 0 6px">
Pass a JSON Schema in <code>response_format</code> &mdash; the decoder is physically constrained to emit conforming JSON. Non-conforming output is impossible, not retried.
</p>
<pre><code>curl https://cogos.5ceos.com/v1/chat/completions \\
  -H "Authorization: Bearer ${apiKey || 'sk-cogos-XXXXXXX'}" \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "cogos-tier-b",
    "messages": [{"role":"user","content":"capital of France?"}],
    "response_format": {
      "type": "json_schema",
      "json_schema": {
        "name": "answer",
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

<h3 style="color:#c9d1d9;font-size:13px;margin:18px 0 6px">3 &middot; Verify determinism yourself</h3>
<p style="color:#8b949e;font-size:12px;margin:0 0 6px">
Clone the open bench &mdash; MIT-licensed, hand-coded rubrics, locked schemas + scenarios. Run it against your own key and publish or attack the CSV. The same bench is auto-re-run against the live gateway on a published cadence &mdash; drift shows up the same day.
</p>
<pre><code>git clone https://github.com/5CEOS-DRA/llm-determinism-bench
cd llm-determinism-bench
/usr/bin/python3 -m venv .venv &amp;&amp; source .venv/bin/activate
pip install -r requirements.txt
COGOS_LIVE_API_KEY=${apiKey || 'sk-cogos-XXXXXXX'} python -m harness.loop
python -m harness.summarize</code></pre>

<p style="color:#8b949e;font-size:12px;margin:24px 0 0">
Tier shapes: <code>cogos-tier-b</code> (Qwen 2.5 3B, classification-shaped work) &middot; <code>cogos-tier-a</code> (Qwen 2.5 7B, narrative) &mdash; the router picks the right size of open-weight model per shape. Sufficient is sufficient.
</p>

${portalHref ? `<p style="margin-top:24px"><a class="cta" style="text-decoration:none;display:inline-block" href="${portalHref}">Manage subscription &rarr;</a></p>` : ''}
<p style="color:#6e7681;font-size:11px;margin-top:24px">
Receipts at your billing email.${portalHref ? ` Cancel, change payment method, or download invoices from the link above.` : ` To manage your subscription, contact <a href="mailto:support@5ceos.com">support@5ceos.com</a>.`}
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

function healthHtml(data) {
  return `<!DOCTYPE html>
<html><head>
<title>CogOS — health</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{box-sizing:border-box}
body{font-family:ui-monospace,SF Mono,Menlo,monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:48px 20px;line-height:1.6}
main{max-width:560px;margin:0 auto;text-align:center}
.pulse{width:88px;height:88px;border-radius:50%;background:#0d2818;border:3px solid #3fb950;margin:0 auto 24px;display:flex;align-items:center;justify-content:center;font-size:42px;color:#3fb950;animation:pulse 1.6s ease-in-out infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(63,185,80,0.4)}50%{box-shadow:0 0 0 18px rgba(63,185,80,0)}}
h1{color:#3fb950;font-size:24px;margin:0 0 8px}
.sub{color:#8b949e;font-size:13px;margin-bottom:32px}
table{margin:0 auto 24px;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:8px 14px;color:#8b949e;border-bottom:1px solid #21262d;font-weight:600}
td{text-align:left;padding:8px 14px;color:#c9d1d9;border-bottom:1px solid #21262d}
.json{background:#161b22;border:1px solid #30363d;padding:12px 14px;border-radius:6px;text-align:left;overflow-x:auto;font-size:11.5px;color:#8b949e;margin-top:18px}
a{color:#58a6ff;text-decoration:none}
a:hover{text-decoration:underline}
.nav{margin-top:32px;font-size:12px}
.nav a{margin:0 12px}
</style></head><body><main>
  <div class="pulse">&check;</div>
  <h1>Gateway is up</h1>
  <div class="sub">The cogos-api gateway is serving traffic. Same call, same bytes &mdash; live.</div>
  <table>
    <tr><th>Service</th><td>${data.service}</td></tr>
    <tr><th>Status</th><td style="color:#3fb950">${data.status}</td></tr>
    <tr><th>Version</th><td>${data.version}</td></tr>
    <tr><th>Uptime</th><td>${data.uptime_s} seconds</td></tr>
    <tr><th>Checked at</th><td>${data.timestamp}</td></tr>
  </table>
  <details>
    <summary style="cursor:pointer;color:#79c0ff;font-size:12px;margin-top:18px">Raw JSON (for monitors)</summary>
    <pre class="json">${JSON.stringify(data, null, 2)}</pre>
  </details>
  <div class="nav">
    <a href="/">&larr; Home</a>
    <a href="/whitepaper">Whitepaper</a>
    <a href="https://github.com/5CEOS-DRA/llm-determinism-bench">Bench</a>
  </div>
</main></body></html>`;
}

module.exports = { renderLandingHtml, successHtml, CANCEL_HTML, healthHtml };
