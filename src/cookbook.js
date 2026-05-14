'use strict';

// CogOS substrate cookbook.
// Served at /cookbook. Six archetypal patterns every dev recognizes —
// extraction, classification, routing, scoring, agent step, multi-extract.
// Each pattern shows the JSON Schema + the curl + 2 lines on why this
// pattern is bulletproof on schema-locked decoding instead of best-effort.
//
// Deliberately substrate-shaped, NOT business-logic-shaped. No TruthPulse,
// Cross-Exam, M&A, or other 5CEOs operator IP. These are the same shapes
// Anthropic / OpenAI / Outlines / Instructor docs cover — what's different
// is that on CogOS each one is verified-by-construction, not retried.

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
pre{background:#0a0e14;border:1px solid #30363d;padding:16px;border-radius:6px;overflow-x:auto;font-size:12px;line-height:1.55;margin:0 0 14px;position:relative}
pre code{background:none;padding:0;color:#c9d1d9}
.code-label{position:absolute;top:8px;right:10px;font-size:10px;color:#6e7681;letter-spacing:0.1em;text-transform:uppercase}
.meta{color:#6e7681;font-size:11px;margin-bottom:24px}
.callout{background:#161b22;border:1px solid #30363d;border-left:3px solid #d29922;padding:14px 16px;margin:18px 0;font-size:13px;border-radius:0 6px 6px 0;color:#f2cc60}
.recipe{background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:24px 26px;margin:0 0 24px}
.recipe h3{margin-top:0}
.lesson{font-size:13px;color:#8b949e;font-style:italic;margin:14px 0 0;padding:10px 14px;background:#161b22;border-radius:6px;border-left:2px solid #58a6ff}
.recipe-num{display:inline-block;background:#d29922;color:#0d1117;border-radius:50%;width:24px;height:24px;text-align:center;line-height:24px;font-size:12px;font-weight:700;margin-right:8px;vertical-align:middle}
.cta-row{margin:32px 0}
.cta{display:inline-block;background:#238636;color:#fff;padding:10px 22px;border-radius:6px;text-decoration:none;font-size:13px;font-weight:600;margin-right:10px}
.cta:hover{background:#2ea043}
.cta.secondary{background:#21262d;color:#c9d1d9}
.cta.secondary:hover{background:#30363d}
a{color:#58a6ff}
hr{border:0;border-top:1px solid #21262d;margin:28px 0}
footer{color:#6e7681;font-size:11px;margin-top:48px;padding-top:18px;border-top:1px solid #21262d}
nav a{margin-right:14px}
</style>`;

const NAV = `<nav style="margin-bottom:18px;font-size:11px">
  <a href="/">Home</a>
  <a href="/cookbook" style="color:#79c0ff">Cookbook</a>
  <a href="/demo">Demo</a>
  <a href="/whitepaper">Whitepaper</a>
  <a href="/trust">Trust</a>
  <a href="/#pricing">Pricing</a>
  <a href="${BENCH_URL}">Bench</a>
</nav>`;

function wrap(bodyHtml) {
  return `<!DOCTYPE html>
<html>
<head>
  <title>CogOS — Cookbook</title>
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

function cookbookHtml() {
  const body = `
<h1>The CogOS cookbook</h1>
<div class="meta">Six archetypal patterns. Copy, paste, ship.</div>

<p>
Every production LLM feature ends up being one of about six shapes:
extracting structured data, classifying with reasons, routing to a
handler, scoring on a calibrated scale, taking a bounded agent step,
or doing all of the above in bulk. This page shows each shape as a
copy-paste recipe on the CogOS substrate.
</p>

<div class="callout">
What&apos;s different here vs. the same recipes against a hosted frontier API: every output below is <strong>schema-valid by construction</strong>. No retry loops, no permissive parsers, no fallback paths. The decoder is physically constrained to emit conforming tokens. <a href="/whitepaper#mechanism" style="color:#79c0ff">Why</a>.
</div>

<p style="font-size:12.5px;color:#8b949e">
All recipes assume <code>COGOS_API_KEY</code> is set in your env. If you don&apos;t have one yet, <a href="/#pricing">grab a $29/mo Operator Starter key</a> &mdash; one curl, one minute.
</p>

<hr>

<h2><span class="recipe-num">1</span> Extract structured data from messy text</h2>

<div class="recipe">
<p>The most common pattern. Take human prose, return a row of structured data ready to insert into a database. Min/max constraints catch most of the edge cases that would otherwise surface as bad data downstream.</p>

<pre><span class="code-label">curl</span><code>curl -s https://cogos.5ceos.com/v1/chat/completions \\
  -H "Authorization: Bearer $COGOS_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "cogos-tier-b",
    "messages": [{"role":"user","content":"Acme Industries reported Q4 results yesterday, with annual revenue of $487 million for fiscal year 2025."}],
    "response_format": {
      "type":"json_schema",
      "json_schema": {
        "name":"filing",
        "strict":true,
        "schema":{
          "type":"object",
          "required":["company","fiscal_year","revenue_musd"],
          "properties":{
            "company":{"type":"string","minLength":1},
            "fiscal_year":{"type":"integer","minimum":1900,"maximum":2100},
            "revenue_musd":{"type":"number","minimum":0}
          }
        }
      }
    }
  }'</code></pre>

<div class="lesson">Lesson: schema constraints (<code>minimum</code>, <code>maximum</code>, <code>minLength</code>) are enforced by the decoder. The model can&apos;t emit <code>fiscal_year: 0</code> or <code>revenue_musd: -1</code> &mdash; non-conforming integers have zero probability mass.</div>
</div>

<h2><span class="recipe-num">2</span> Classify with confidence + reason</h2>

<div class="recipe">
<p>Enum schema for the label, plus an optional <code>reasoning</code> field for the model&apos;s justification. Pattern for content moderation, intent detection, sentiment with rationale.</p>

<pre><span class="code-label">curl</span><code>curl -s https://cogos.5ceos.com/v1/chat/completions \\
  -H "Authorization: Bearer $COGOS_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "cogos-tier-b",
    "messages": [{"role":"user","content":"Classify the urgency: \\"My demo is in 30 minutes and the build is broken.\\""}],
    "response_format": {
      "type":"json_schema",
      "json_schema": {
        "name":"classification",
        "strict":true,
        "schema":{
          "type":"object",
          "required":["label","reasoning"],
          "properties":{
            "label":{"type":"string","enum":["low","medium","high","critical"]},
            "reasoning":{"type":"string","maxLength":280}
          }
        }
      }
    }
  }'</code></pre>

<div class="lesson">Lesson: <code>enum</code> on the label means the model literally cannot return any string outside your allowed set. No "high-ish" or "very-high" or random new categories appearing in your data three months in.</div>
</div>

<h2><span class="recipe-num">3</span> Triage / route to a handler</h2>

<div class="recipe">
<p>Discriminated-union schema. The <code>type</code> field tells your code which handler to dispatch to; the per-type fields are bound to that branch. Replaces giant if/else routing trees with a single deterministic LLM call.</p>

<pre><span class="code-label">curl</span><code>curl -s https://cogos.5ceos.com/v1/chat/completions \\
  -H "Authorization: Bearer $COGOS_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "cogos-tier-b",
    "messages": [{"role":"user","content":"Customer email: \\"My charge for $99 last week was supposed to be $29. Please refund the difference.\\""}],
    "response_format": {
      "type":"json_schema",
      "json_schema": {
        "name":"route",
        "strict":true,
        "schema":{
          "type":"object",
          "required":["handler","priority"],
          "properties":{
            "handler":{"type":"string","enum":["billing","support","sales","legal","spam"]},
            "priority":{"type":"string","enum":["p0","p1","p2","p3"]},
            "summary":{"type":"string","maxLength":120}
          }
        }
      }
    }
  }'</code></pre>

<div class="lesson">Lesson: the dispatch happens on the LLM&apos;s side, but the contract is yours. Your code switches on <code>handler</code> with a guarantee the value is one of your five enum entries &mdash; no defensive default branch needed.</div>
</div>

<h2><span class="recipe-num">4</span> Score on a calibrated scale</h2>

<div class="recipe">
<p>Integer schema with bounded range. Pattern for quality scoring, rubric grading, confidence thresholds. Pair with <code>reasoning</code> to make the score auditable.</p>

<pre><span class="code-label">curl</span><code>curl -s https://cogos.5ceos.com/v1/chat/completions \\
  -H "Authorization: Bearer $COGOS_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "cogos-tier-b",
    "messages": [{"role":"user","content":"Score this PR description for clarity (0-10): \\"fix bug\\""}],
    "response_format": {
      "type":"json_schema",
      "json_schema": {
        "name":"score",
        "strict":true,
        "schema":{
          "type":"object",
          "required":["score","reasoning"],
          "properties":{
            "score":{"type":"integer","minimum":0,"maximum":10},
            "reasoning":{"type":"string","maxLength":200}
          }
        }
      }
    }
  }'</code></pre>

<div class="lesson">Lesson: the <code>minimum</code>/<code>maximum</code> integer constraint means downstream code can <code>assert 0 &lt;= score &lt;= 10</code> without ever firing. The decoder enforces it at the token level, before the bytes reach you.</div>
</div>

<h2><span class="recipe-num">5</span> Bounded agent step (tool-use shape)</h2>

<div class="recipe">
<p>Allowed actions as an enum, action arguments in a sibling object. The agent decides <em>which</em> action; you decide <em>which actions are even possible</em>. Maps cleanly onto OpenAI / Anthropic tool-use loops.</p>

<pre><span class="code-label">curl</span><code>curl -s https://cogos.5ceos.com/v1/chat/completions \\
  -H "Authorization: Bearer $COGOS_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "cogos-tier-a",
    "messages": [{"role":"user","content":"User said: \\"What is 47 times 23?\\". Pick the right tool."}],
    "response_format": {
      "type":"json_schema",
      "json_schema": {
        "name":"agent_step",
        "strict":true,
        "schema":{
          "type":"object",
          "required":["action","args"],
          "properties":{
            "action":{"type":"string","enum":["calculator","web_search","read_file","reply_directly"]},
            "args":{"type":"object","additionalProperties":true},
            "rationale":{"type":"string","maxLength":160}
          }
        }
      }
    }
  }'</code></pre>

<div class="lesson">Lesson: the agent <em>cannot</em> invent a new tool name. If it suggests <code>"action":"shell_exec"</code> and that&apos;s not in your enum, the decoder won&apos;t emit it. Bounded action surface = bounded blast radius.</div>
</div>

<h2><span class="recipe-num">6</span> Multi-extraction (array of structured items)</h2>

<div class="recipe">
<p>Array schema with <code>maxItems</code> and per-item required fields. Pattern for pulling multiple entities, line items, or events out of a single document in one call.</p>

<pre><span class="code-label">curl</span><code>curl -s https://cogos.5ceos.com/v1/chat/completions \\
  -H "Authorization: Bearer $COGOS_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "cogos-tier-b",
    "messages": [{"role":"user","content":"Extract up to 3 line items from: \\"Office supplies: 5 reams paper @ $4.50, 2 boxes pens @ $12, and 1 stapler @ $18.\\""}],
    "response_format": {
      "type":"json_schema",
      "json_schema": {
        "name":"line_items",
        "strict":true,
        "schema":{
          "type":"object",
          "required":["items"],
          "properties":{
            "items":{
              "type":"array",
              "minItems":0,
              "maxItems":10,
              "items":{
                "type":"object",
                "required":["description","quantity","unit_price"],
                "properties":{
                  "description":{"type":"string","minLength":1},
                  "quantity":{"type":"integer","minimum":1},
                  "unit_price":{"type":"number","minimum":0}
                }
              }
            }
          }
        }
      }
    }
  }'</code></pre>

<div class="lesson">Lesson: <code>maxItems</code> bounds the worst-case payload size. Per-item <code>required</code> fields mean every element in the array is shaped the same way &mdash; no missing fields on item #3 because the model "forgot."</div>
</div>

<hr>

<h2 id="verify-signature">Verify a response signature</h2>

<div class="recipe">
<p>Every <code>/v1/*</code> response carries an <code>X-Cogos-Signature</code> header: <code>HMAC-SHA256(hmac_secret, raw_response_body)</code> in lowercase hex. Re-compute it on your side and compare with constant-time equality. If it doesn&apos;t match, the body was tampered with in transit &mdash; reject the response.</p>

<p>Your HMAC secret is displayed once, alongside your API key, on the post-checkout success page. Store it the same way you store the API key.</p>

<pre><span class="code-label">python</span><code>import hmac, hashlib, requests

API_KEY = os.environ["COGOS_API_KEY"]
HMAC_SECRET = os.environ["COGOS_HMAC_SECRET"]

r = requests.post(
  "https://cogos.5ceos.com/v1/chat/completions",
  headers={"Authorization": f"Bearer {API_KEY}"},
  json={"model":"cogos-tier-b","messages":[{"role":"user","content":"hi"}]},
)

raw = r.content  # bytes, NOT r.text — must be the exact bytes the server signed
expected = hmac.new(HMAC_SECRET.encode(), raw, hashlib.sha256).hexdigest()
got = r.headers["X-Cogos-Signature"]

if not hmac.compare_digest(expected, got):
    raise RuntimeError("response signature mismatch — reject")

data = r.json()</code></pre>

<pre><span class="code-label">node</span><code>import crypto from "node:crypto";

const r = await fetch("https://cogos.5ceos.com/v1/chat/completions", {
  method: "POST",
  headers: {
    "Authorization": \`Bearer \${process.env.COGOS_API_KEY}\`,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({ model: "cogos-tier-b", messages: [{ role: "user", content: "hi" }] }),
});

const raw = Buffer.from(await r.arrayBuffer());
const expected = crypto.createHmac("sha256", process.env.COGOS_HMAC_SECRET).update(raw).digest("hex");
const got = r.headers.get("x-cogos-signature");

const ok = expected.length === got.length &&
  crypto.timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(got, "hex"));
if (!ok) throw new Error("response signature mismatch — reject");

const data = JSON.parse(raw.toString("utf8"));</code></pre>

<div class="lesson">Lesson: sign the <em>bytes</em>, not the parsed JSON. Re-serializing changes whitespace and key order, and the HMAC won&apos;t match. Always compare with <code>hmac.compare_digest</code> / <code>crypto.timingSafeEqual</code>; <code>==</code> leaks length-prefix information through timing.</div>
</div>

<hr>

<h2 id="verify-attestation">Verify a per-response attestation token</h2>

<div class="recipe">
<p>Every <code>/v1/*</code> response also carries an <code>X-Cogos-Attestation</code> header containing a small Ed25519-signed token. Where <code>X-Cogos-Signature</code> proves "this body wasn&apos;t tampered with in transit," the attestation token proves something much stronger: <strong>this exact response was emitted by a specific build of CogOS, against a specific request, at a specific position in the audit chain.</strong></p>

<p>The token binds five things cryptographically:</p>
<ul>
  <li><code>req_hash</code> &mdash; <code>sha256(METHOD || "\n" || path || "\n" || ts || "\n" || sha256(body))</code> of your request</li>
  <li><code>resp_hash</code> &mdash; <code>sha256</code> of the raw response body bytes you received</li>
  <li><code>rev</code> &mdash; the cogos-api source revision SHA the response came from</li>
  <li><code>chain_head</code> &mdash; the <code>row_hash</code> of the audit row appended for this request</li>
  <li><code>ts</code> &mdash; server-side issuance timestamp</li>
</ul>

<p>Signed with an Ed25519 key bound to the running process. Fetch the public PEM from <code>/attestation.pub</code> to verify. The wire format is <code>&lt;payload_b64url&gt;.&lt;signature_b64url&gt;</code> &mdash; JWT-style separator, no JWT header (algorithm is pinned to Ed25519 by spec, no negotiation = no alg-confusion attack surface).</p>

<div class="callout">
This is what no other AI vendor emits. Frontier APIs sign only at the TLS layer &mdash; you can&apos;t prove later, to a regulator, that a specific response actually came from a specific build of their substrate, at a specific position in their audit chain. With CogOS attestation, you keep the token alongside the response and you hold the receipt forever. If we ever rewrote our audit log after the fact, no path through the rewritten log would reproduce a <code>chain_head</code> you already wrote down.
</div>

<pre><span class="code-label">python</span><code>import base64, hashlib, json, os
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
import requests

API_KEY = os.environ["COGOS_API_KEY"]
BASE = "https://cogos.5ceos.com"

# 1. Make a request — capture body bytes, headers, token.
body = json.dumps({
  "model": "cogos-tier-b",
  "messages": [{"role":"user","content":"hi"}],
})
r = requests.post(
  f"{BASE}/v1/chat/completions",
  headers={"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"},
  data=body,
)
raw_resp = r.content                                   # exact bytes the server signed
token = r.headers["X-Cogos-Attestation"]

# 2. Decode payload + signature.
def b64url_decode(s: str) -> bytes:
  return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

payload_b64, sig_b64 = token.split(".")
payload_json = b64url_decode(payload_b64)
sig = b64url_decode(sig_b64)
payload = json.loads(payload_json)

# 3. Verify the signature against the live pubkey.
pub_pem = requests.get(f"{BASE}/attestation.pub").content
pub_key = load_pem_public_key(pub_pem)
try:
  pub_key.verify(sig, payload_json)                    # raises on bad signature
except InvalidSignature:
  raise RuntimeError("attestation signature invalid — reject")

# 4. Verify the bindings.
body_hash = hashlib.sha256(body.encode()).hexdigest()
canonical = f"POST\\n/v1/chat/completions\\n{payload['ts']}\\n{body_hash}"
expected_req_hash = hashlib.sha256(canonical.encode()).hexdigest()
assert payload["req_hash"] == expected_req_hash, "request bind broken"

expected_resp_hash = hashlib.sha256(raw_resp).hexdigest()
assert payload["resp_hash"] == expected_resp_hash, "response bind broken — body tampered"

# 5. (Optional) record payload['chain_head'] + payload['rev'] alongside
# the response. Later you can cross-check chain_head against your own
# /v1/audit history; the rev field tells you exactly which CogOS build
# emitted this response.
print(f"verified: rev={payload['rev']} chain_head={payload['chain_head'][:16]}...")</code></pre>

<pre><span class="code-label">node</span><code>import crypto from "node:crypto";

const BASE = "https://cogos.5ceos.com";
const API_KEY = process.env.COGOS_API_KEY;

// 1. Make a request — capture exact bytes, headers, token.
const body = JSON.stringify({
  model: "cogos-tier-b",
  messages: [{ role: "user", content: "hi" }],
});
const r = await fetch(\`\${BASE}/v1/chat/completions\`, {
  method: "POST",
  headers: { "Authorization": \`Bearer \${API_KEY}\`, "Content-Type": "application/json" },
  body,
});
const rawResp = Buffer.from(await r.arrayBuffer());
const token = r.headers.get("x-cogos-attestation");

// 2. Decode payload + signature (base64url, no padding).
const b64urlDecode = (s) => {
  const pad = s.length % 4 === 0 ? 0 : 4 - (s.length % 4);
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad), "base64");
};
const [payloadB64, sigB64] = token.split(".");
const payloadJson = b64urlDecode(payloadB64);
const sig = b64urlDecode(sigB64);
const payload = JSON.parse(payloadJson.toString("utf8"));

// 3. Verify the signature against the live pubkey.
const pubPem = await (await fetch(\`\${BASE}/attestation.pub\`)).text();
const pubKey = crypto.createPublicKey(pubPem);
const ok = crypto.verify(null, payloadJson, pubKey, sig);
if (!ok) throw new Error("attestation signature invalid — reject");

// 4. Verify the bindings.
const bodyHash = crypto.createHash("sha256").update(body).digest("hex");
const canonical = \`POST\\n/v1/chat/completions\\n\${payload.ts}\\n\${bodyHash}\`;
const expectedReqHash = crypto.createHash("sha256").update(canonical).digest("hex");
if (payload.req_hash !== expectedReqHash) throw new Error("request bind broken");

const expectedRespHash = crypto.createHash("sha256").update(rawResp).digest("hex");
if (payload.resp_hash !== expectedRespHash) throw new Error("response bind broken — body tampered");

console.log(\`verified: rev=\${payload.rev} chain_head=\${payload.chain_head.slice(0, 16)}...\`);</code></pre>

<div class="lesson">Lesson: the signature is over the <em>token payload</em>, not over the response body. A MITM that rewrites the body but keeps the original token will leave the token signature-valid &mdash; but <code>resp_hash</code> inside the token will no longer match <code>sha256(body)</code> you received. That hash mismatch is the detection mechanism. Always verify BOTH the Ed25519 signature AND the resp_hash bind.</div>

<div class="lesson">Operational note: each container restart rotates the keypair. The fetch of <code>/attestation.pub</code> is therefore live, not cached &mdash; same operational shape as TLS cert rotation. Tokens you stored from a previous deploy can no longer be verified against the current pubkey; for long-lived court-defensible receipts, capture the pubkey alongside the token at issuance time.</div>
</div>

<hr>

<h2>Patterns we deliberately don&apos;t show</h2>

<p>
The viewports on <a href="https://5ceos.com">5ceos.com</a> &mdash; TruthPulse, Cross-Exam, M&amp;A Truth Report, Enron evidence corpus &mdash; are 5CEOs products built on this substrate. They&apos;re not copy-paste recipes; they&apos;re years of domain work in contradiction detection, commitment-drift tracking, and forensic evidence reconstruction. We sell those as products to enterprise customers.
</p>

<p>
What you get on cogos.5ceos.com is the <strong>substrate</strong> &mdash; the same primitive those products are built on. Combine the six recipes above and you have the building blocks for almost any production LLM feature you&apos;d ship next week.
</p>

<hr>

<h2>Next</h2>

<ul>
  <li>Run the <a href="/demo">90-second proof</a> to verify everything above on your own machine.</li>
  <li>Read the <a href="/whitepaper">technical whitepaper</a> for the mechanism, bench methodology, and explicit limits.</li>
  <li>Clone the open <a href="${BENCH_URL}">determinism bench</a> to verify the substrate keeps its promises over time.</li>
  <li>Pick a tier: <a href="/#pricing">$29/mo &rarr; $100K/yr</a>, month-to-month, cancel any time.</li>
</ul>

<div class="cta-row">
  <a class="cta" href="/#pricing">See pricing &rarr;</a>
  <a class="cta secondary" href="/demo">Run the demo</a>
  <a class="cta secondary" href="/whitepaper">Read the whitepaper</a>
</div>

<p style="color:#8b949e;font-size:12.5px;margin-top:18px">
A pattern missing? Open an issue on the <a href="${BENCH_URL}">bench repo</a> or email <a href="mailto:support@5ceos.com">support@5ceos.com</a>. The cookbook grows with what devs ask for.
</p>
`;
  return wrap(body);
}

module.exports = { cookbookHtml };
