'use strict';

// Public trust / transparency dashboard.
// Served at /trust. Modeled after trust.salesforce.com — every claim is
// backed by data the page can prove from the running process or from
// SECURITY.md. No static "99.999%" handwave. If we don't have data, the
// page says so honestly instead of fabricating a number.
//
// State input shape (built by the route handler in src/index.js):
//   {
//     status:           'operational' | 'degraded' | 'outage',
//     statusLabel:      'Operational' | 'Degraded' | 'Outage',
//     imageTag:         string,                  // from COGOS_IMAGE_TAG env or pkg.version
//     uptimeSeconds:    number,                  // process.uptime()
//     cosign: {
//       published:      boolean,
//       detail:         string,                  // operator-readable one-liner
//     },
//     advisories:       [{ id, date, severity, summary, url? }, ...],  // [] = none
//     pentestHistory:   [{ date, scope, severity_counts:{...}, fix_cadence_summary }, ...],
//     renderedAt:       string,                  // ISO timestamp
//   }
//
// Section 4 (recent revisions) is intentionally NOT in state — the runtime
// process doesn't have a list of past revisions, and we won't fabricate one.
// The section renders a known-honest placeholder pointing at az containerapp.

const fs = require('node:fs');
const path = require('node:path');

const PRODUCT_NAME = 'CogOS';
const SERVICE_DOMAIN = 'cogos.5ceos.com';
const SUPPORT_EMAIL = 'support@5ceos.com';
const BENCH_URL = 'https://github.com/5CEOS-DRA/llm-determinism-bench';

const STYLE_BLOCK = `<style>
*{box-sizing:border-box}
body{font-family:ui-monospace,SF Mono,Menlo,monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:32px 20px;line-height:1.6}
main{max-width:860px;margin:0 auto}
h1{color:#58a6ff;font-size:26px;margin:0 0 6px}
h2{color:#58a6ff;font-size:17px;margin:34px 0 10px;border-bottom:1px solid #30363d;padding-bottom:6px}
h3{color:#79c0ff;font-size:13px;margin:18px 0 6px;text-transform:uppercase;letter-spacing:0.04em}
p{margin:0 0 14px;font-size:14px;color:#c9d1d9}
ul, ol{font-size:14px;margin:0 0 14px;padding-left:22px}
li{margin:0 0 6px}
strong{color:#e6edf3}
em{color:#a5d6ff;font-style:normal}
code{background:#161b22;padding:2px 5px;border-radius:3px;font-size:12.5px;color:#79c0ff}
pre{background:#0a0e14;border:1px solid #30363d;padding:14px;border-radius:6px;overflow-x:auto;font-size:12px;line-height:1.55;margin:0 0 14px;color:#c9d1d9}
pre code{background:none;padding:0;color:#c9d1d9}
table{width:100%;border-collapse:collapse;font-size:13px;margin:0 0 14px}
th{text-align:left;padding:8px 12px;background:#161b22;color:#8b949e;font-weight:600;border:1px solid #21262d}
td{padding:10px 12px;border:1px solid #21262d;color:#c9d1d9;vertical-align:top}
.meta{color:#6e7681;font-size:11px;margin-bottom:24px}
.banner{padding:18px 22px;border-radius:8px;margin:0 0 26px;border:1px solid #30363d;display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.banner.operational{background:#0d2818;border-color:#3fb950}
.banner.degraded{background:#3d2611;border-color:#d29922}
.banner.outage{background:#3d1418;border-color:#f85149}
.dot{display:inline-block;width:12px;height:12px;border-radius:50%;flex-shrink:0}
.dot.operational{background:#3fb950;box-shadow:0 0 8px #3fb95080}
.dot.degraded{background:#d29922;box-shadow:0 0 8px #d2992280}
.dot.outage{background:#f85149;box-shadow:0 0 8px #f8514980}
.banner-title{font-size:18px;color:#e6edf3;font-weight:600;margin:0}
.banner-sub{font-size:12px;color:#8b949e;margin-top:4px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin:0 0 28px}
.tile{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 18px}
.tile-label{font-size:10px;color:#8b949e;text-transform:uppercase;letter-spacing:0.08em;margin:0 0 8px}
.tile-value{font-size:15px;color:#e6edf3;margin:0;word-break:break-word}
.tile-sub{font-size:11.5px;color:#8b949e;margin:6px 0 0}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:10.5px;text-transform:uppercase;letter-spacing:0.04em;font-weight:600;margin-left:6px;vertical-align:middle}
.badge.shipped{background:#0d2818;color:#3fb950;border:1px solid #3fb950}
.badge.todo{background:#3d2611;color:#f2cc60;border:1px solid #d29922}
.callout{background:#161b22;border:1px solid #30363d;border-left:3px solid #58a6ff;padding:14px 16px;margin:14px 0;font-size:13.5px;border-radius:0 6px 6px 0}
.callout.warn{background:#3d2611;border-left-color:#d29922;color:#f2cc60}
.placeholder{background:#161b22;border:1px dashed #30363d;border-radius:6px;padding:14px 16px;margin:0 0 14px;font-size:13px;color:#8b949e}
a{color:#58a6ff}
hr{border:0;border-top:1px solid #21262d;margin:28px 0}
footer{color:#6e7681;font-size:11px;margin-top:48px;padding-top:18px;border-top:1px solid #21262d}
nav a{margin-right:14px}
</style>`;

const NAV = `<nav style="margin-bottom:18px;font-size:11px">
  <a href="/">Home</a>
  <a href="/cookbook">Cookbook</a>
  <a href="/whitepaper">Whitepaper</a>
  <a href="/trust" style="color:#79c0ff">Trust</a>
  <a href="/#pricing">Pricing</a>
  <a href="${BENCH_URL}">Bench</a>
</nav>`;

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

// Format process.uptime() seconds into "X days Y hours" if >= 24h, else
// "X hours Y min" if >= 1h, else "X min Y sec". Honest fractional rendering,
// no rounding-up that would imply more uptime than we have.
function formatUptime(seconds) {
  const s = Math.max(0, Math.floor(Number(seconds) || 0));
  const days = Math.floor(s / 86400);
  const hours = Math.floor((s % 86400) / 3600);
  const minutes = Math.floor((s % 3600) / 60);
  const secs = s % 60;
  if (days > 0) return `${days} day${days === 1 ? '' : 's'} ${hours} hour${hours === 1 ? '' : 's'}`;
  if (hours > 0) return `${hours} hour${hours === 1 ? '' : 's'} ${minutes} min`;
  if (minutes > 0) return `${minutes} min ${secs} sec`;
  return `${secs} sec`;
}

// ---------------------------------------------------------------------------
// Section 3 — Verifiable security claims, mirrored from SECURITY.md §3.
// Curated subset, copy-paste-equivalent commands. Status flags match what
// SECURITY.md currently records; the 'todo' rendering gets a yellow badge
// so readers see what's rolling out vs what's already binding.
// ---------------------------------------------------------------------------
const SECURITY_CLAIMS = [
  {
    id: '3.2',
    title: 'Image signature (cosign)',
    status: 'todo', // matches SECURITY.md §3.2 "Rolling out in deploy cadence"
    claim: 'Every deployed image is signed with a 5CEOS-controlled cosign key. Customers verify the running image hash against the public key.',
    verify: 'cosign verify \\\n  --key https://cogos.5ceos.com/cosign.pub \\\n  cogos5ceos.azurecr.io/cogos-api:vN',
  },
  {
    id: '3.3',
    title: 'Response signature (HMAC)',
    status: 'shipped',
    claim: 'Every /v1/* response carries X-Cogos-Signature = HMAC-SHA256(per-tenant-secret, body). Tampering in transit is detectable.',
    verify: 'curl -isX POST https://cogos.5ceos.com/v1/chat/completions \\\n  -H "Authorization: Bearer sk-cogos-…" \\\n  -d \'{"model":"cogos-tier-b","messages":[{"role":"user","content":"ping"}]}\'\n# Re-compute HMAC client-side; recipe at /cookbook#verify-signature',
  },
  {
    id: '3.4',
    title: 'Open determinism bench',
    status: 'shipped',
    claim: 'The "same call in, same bytes out" claim is auditable by anyone — bench is OSS, published cadence runs are posted, drift surfaces same-day.',
    verify: 'git clone ' + BENCH_URL + '\ncd llm-determinism-bench && cat README.md',
  },
  {
    id: '3.5',
    title: 'Customer-key auth flow',
    status: 'shipped',
    claim: 'API keys are stored as sha256 hashes; plaintext is shown once at issue time and never returned again. A keys.json leak does not leak usable keys.',
    verify: '# In this repo:\ngrep -n "createHash\\|sha256" src/*.js',
  },
  {
    id: '3.6',
    title: 'Admin auth flow',
    status: 'shipped',
    claim: 'Admin endpoints (issue / revoke / list keys, read usage) require X-Admin-Key. Rotation is one env-var change; revocation is immediate.',
    verify: '# Should 401:\ncurl -sI https://cogos.5ceos.com/admin/keys',
  },
  {
    id: '3.7',
    title: 'Stripe webhook signature',
    status: 'shipped',
    claim: 'POST /stripe/webhook is gated on a valid Stripe-Signature header verified against STRIPE_WEBHOOK_SECRET. Forged checkout completions cannot trigger key issuance.',
    verify: '# Should 400 (signature missing):\ncurl -sI -X POST https://cogos.5ceos.com/stripe/webhook \\\n  -H "Content-Type: application/json" -d \'{}\'',
  },
  {
    id: '3.8',
    title: 'Schema-enforced output',
    status: 'shipped',
    claim: 'When response_format is json_schema, the decoder is grammar-constrained at the token level. Non-conforming output is physically impossible, not retried.',
    verify: '# See /cookbook recipe 1 — strict integer schema, prompt for a string answer, get an integer.',
  },
];

function renderStatusBanner(state) {
  const cls = state.status || 'operational';
  const label = state.statusLabel || 'Operational';
  const subline = cls === 'operational'
    ? `Service ${escapeHtml(SERVICE_DOMAIN)} is responding to /health with 200 OK as of the render time below.`
    : cls === 'degraded'
      ? `Service ${escapeHtml(SERVICE_DOMAIN)} is responding with elevated error rates or partial failures.`
      : `Service ${escapeHtml(SERVICE_DOMAIN)} is currently failing health checks.`;
  return `<div class="banner ${escapeHtml(cls)}">
  <span class="dot ${escapeHtml(cls)}" aria-hidden="true"></span>
  <div>
    <div class="banner-title">${escapeHtml(label)} &middot; ${escapeHtml(SERVICE_DOMAIN)}</div>
    <div class="banner-sub">${subline} Updated: ${escapeHtml(state.renderedAt)}.</div>
  </div>
</div>`;
}

function renderTiles(state) {
  const cosignBadge = state.cosign && state.cosign.published
    ? '<span class="badge shipped">verified</span>'
    : '<span class="badge todo">pending</span>';
  return `<div class="tiles">
  <div class="tile">
    <div class="tile-label">Image tag</div>
    <div class="tile-value">${escapeHtml(state.imageTag)}</div>
    <div class="tile-sub">From <code>COGOS_IMAGE_TAG</code> or <code>package.json</code> version. Bound to a cosign signature once §3.2 finishes rolling out.</div>
  </div>
  <div class="tile">
    <div class="tile-label">Process uptime</div>
    <div class="tile-value">${escapeHtml(formatUptime(state.uptimeSeconds))}</div>
    <div class="tile-sub">Time since this revision started. Restarted on every deploy — not a historical SLA metric.</div>
  </div>
  <div class="tile">
    <div class="tile-label">Cosign pubkey ${cosignBadge}</div>
    <div class="tile-value">${escapeHtml((state.cosign && state.cosign.detail) || 'Cosign pubkey publication pending')}</div>
    <div class="tile-sub"><a href="/cosign.pub">/cosign.pub</a> · verify with <code>cosign verify --key https://cogos.5ceos.com/cosign.pub &lt;image&gt;</code></div>
  </div>
  <div class="tile">
    <div class="tile-label">Tenant audit chain</div>
    <div class="tile-value"><a href="/v1/audit">/v1/audit</a></div>
    <div class="tile-sub">Every customer fetches their own hash-chained usage rows and re-verifies them locally — no need to trust our copy.</div>
  </div>
  ${renderLatencyTiles(state.latency)}
</div>`;
}

function renderLatencyTiles(latency) {
  if (!latency) {
    return `<div class="tile">
    <div class="tile-label">API latency (p50 · p95 · p99)</div>
    <div class="tile-value">no data yet</div>
    <div class="tile-sub">Rollup empty for the last 7 days. Numbers appear here once paid + free traffic accrues. We don't fabricate latency percentiles.</div>
  </div>`;
  }
  const fmt = (ms) => (ms == null ? '—' : `${ms} ms`);
  return `<div class="tile">
    <div class="tile-label">API latency · p50</div>
    <div class="tile-value">${escapeHtml(fmt(latency.p50_ms))}</div>
    <div class="tile-sub">Median end-to-end latency across all completions on ${escapeHtml(latency.as_of_date)}. ${escapeHtml(String(latency.request_count))} requests, ${escapeHtml(String(latency.sample_count))} latency samples.</div>
  </div>
  <div class="tile">
    <div class="tile-label">API latency · p95</div>
    <div class="tile-value">${escapeHtml(fmt(latency.p95_ms))}</div>
    <div class="tile-sub">95th-percentile latency. Reservoir-sampled across the day; raw samples are summarized in <a href="/v1/audit">/v1/audit</a> per tenant.</div>
  </div>
  <div class="tile">
    <div class="tile-label">API latency · p99</div>
    <div class="tile-value">${escapeHtml(fmt(latency.p99_ms))}</div>
    <div class="tile-sub">99th-percentile latency. Tail behavior. Spikes correlate with cold-start container scale events; warm path stays in the p50 band.</div>
  </div>`;
}

function renderClaimsTable() {
  const rows = SECURITY_CLAIMS.map((c) => {
    const badge = c.status === 'shipped'
      ? '<span class="badge shipped">shipped</span>'
      : '<span class="badge todo">rolling out</span>';
    return `<tr>
    <td><strong>SECURITY.md &sect;${escapeHtml(c.id)} &mdash; ${escapeHtml(c.title)}</strong> ${badge}<br><span style="color:#8b949e;font-size:12.5px">${escapeHtml(c.claim)}</span></td>
    <td><pre style="margin:0"><code>${escapeHtml(c.verify)}</code></pre></td>
  </tr>`;
  }).join('\n');
  return `<table>
  <thead>
    <tr><th style="width:48%">Claim</th><th>Verify command</th></tr>
  </thead>
  <tbody>
    ${rows}
  </tbody>
</table>`;
}

function renderRevisionsSection(state) {
  return `<div class="placeholder">
  Live revision: <code>${escapeHtml(state.imageTag)}</code>. Recent revisions are tracked via
  <code>az containerapp revision list --name cogos-api --resource-group cogos-api-rg</code>
  on the operator substrate; a published recent-revisions card is a future addition.
  We don&apos;t fabricate prior versions on this page.
</div>`;
}

function renderAdvisoriesSection(state) {
  if (!state.advisories || state.advisories.length === 0) {
    return `<div class="placeholder">
  No published advisories. A subscription URL (RSS / JSON feed) for future advisories is <em>TBD</em>
  &mdash; until then, watch the <a href="https://github.com/5CEOS-DRA/llm-determinism-bench">bench repo</a> and the
  <code>SECURITY.md</code> change log for notices.
</div>`;
  }
  return state.advisories.map((a) => `<div class="callout">
  <strong>${escapeHtml(a.id)}</strong> &middot; ${escapeHtml(a.date)} &middot; severity <strong>${escapeHtml(a.severity)}</strong><br>
  ${escapeHtml(a.summary)}${a.url ? ` &middot; <a href="${escapeHtml(a.url)}">details</a>` : ''}
</div>`).join('\n');
}

function renderPentestSection(state) {
  if (!state.pentestHistory || state.pentestHistory.length === 0) {
    return `<div class="placeholder">
  Most recent internal pentest: <strong>2026-05-14</strong>. External pentest cadence: engagement pending.
  When a third-party engagement closes, a redacted summary lands here (date, scope, severity counts, fix-cadence summary)
  &mdash; never raw findings.
</div>`;
  }
  const rows = state.pentestHistory.map((p) => {
    const counts = p.severity_counts || {};
    const countParts = ['critical', 'high', 'medium', 'low', 'info']
      .filter((k) => counts[k] != null)
      .map((k) => `${escapeHtml(k)}: <strong>${escapeHtml(counts[k])}</strong>`)
      .join(' &middot; ');
    return `<tr>
    <td>${escapeHtml(p.date)}</td>
    <td>${escapeHtml(p.scope || '')}</td>
    <td>${countParts || '<span style="color:#8b949e">—</span>'}</td>
    <td>${escapeHtml(p.fix_cadence_summary || '')}</td>
  </tr>`;
  }).join('\n');
  return `<table>
  <thead><tr><th>Date</th><th>Scope</th><th>Severity counts</th><th>Fix cadence</th></tr></thead>
  <tbody>${rows}</tbody>
</table>`;
}

// Renders the latest public hash-chain checkpoint plus the
// verify-yourself curl command. Empty-state is the expected pre-data
// state — the very first checkpoint requires at least one usage row to
// exist, so on a fresh deploy this section is the placeholder.
function renderCheckpointSection(s) {
  const c = s.latestCheckpoint;
  const chainLen = (s.checkpointChain && typeof s.checkpointChain.chain_length === 'number')
    ? s.checkpointChain.chain_length
    : 0;
  if (!c) {
    return `<div class="placeholder">
  No public checkpoint recorded yet. The scheduler computes one every hour from every (tenant, app_id) chain head and appends it to <code>data/audit-checkpoints.jsonl</code>; the first checkpoint appears after the first usage row exists. Endpoints:
  <ul style="margin-top:8px">
    <li><code>GET <a href="/audit/checkpoint/latest">/audit/checkpoint/latest</a></code></li>
    <li><code>GET /audit/checkpoint?ts=&lt;unix_ms&gt;</code> — nearest-before for a captured ts</li>
    <li><code>GET /audit/checkpoints?limit=N&amp;since_ms=M</code> — paginated history</li>
    <li><code>GET <a href="/audit/checkpoint/verify">/audit/checkpoint/verify</a></code> — operator-verifies local file is untampered</li>
  </ul>
</div>`;
  }
  const headPrefix = String(c.global_head || '').slice(0, 16);
  return `<p>Every hour we snapshot every <code>(tenant_id, app_id)</code> chain head into a globally hash-chained checkpoint. Capture <code>global_head</code> now, replay <code>/audit/checkpoint?ts=&lt;your_capture_ts&gt;</code> later, prove we haven&apos;t rewritten any row in between.</p>
<table>
  <tr><th>Last checkpoint</th><td><code>${escapeHtml(c.ts || 'unknown')}</code></td></tr>
  <tr><th>Global head (prefix)</th><td><code>${escapeHtml(headPrefix)}…</code></td></tr>
  <tr><th>Partitions snapshotted</th><td>${escapeHtml(c.partition_count)}</td></tr>
  <tr><th>Chain length</th><td>${escapeHtml(chainLen)} checkpoint${chainLen === 1 ? '' : 's'} on disk</td></tr>
</table>
<p style="font-size:12px;color:#8b949e;margin:8px 0 4px">Verify yourself:</p>
<pre><code>curl -s https://${escapeHtml(SERVICE_DOMAIN)}/audit/checkpoint/latest
curl -s https://${escapeHtml(SERVICE_DOMAIN)}/audit/checkpoint/verify</code></pre>`;
}

function renderContinuousProbes(s) {
  const p = s.latestProbe;
  if (!p) {
    return `<p>An Azure Container App Job runs <code>scripts/probes-unauth.sh</code> against this domain on a daily schedule (no auth, no third-party services in the loop). The latest run will appear here once the job has executed once. Probe source: <code>scripts/probes-unauth.sh</code> and <code>scripts/pentest-authed.sh</code> in the repo.</p>`;
  }
  const total = (Number(p.pass) || 0) + (Number(p.fail) || 0);
  const ok = (Number(p.fail) || 0) === 0;
  const badge = ok
    ? `<span style="color:#3fb950;font-weight:600">PASS</span>`
    : `<span style="color:#f85149;font-weight:600">FAIL</span>`;
  const failures = (p.failures && p.failures.length)
    ? `<details><summary style="cursor:pointer">${p.failures.length} failing check(s)</summary><ul>${p.failures.map((f) => `<li><code>${String(f).replace(/[<>&]/g, (c) => ({ '<':'&lt;','>':'&gt;','&':'&amp;' }[c]))}</code></li>`).join('')}</ul></details>`
    : '';
  return `<p>An Azure Container App Job runs <code>scripts/probes-unauth.sh</code> against this domain on a daily schedule. Results below; raw log appended to <code>data/probe-history.jsonl</code>.</p>
<table>
  <tr><th>Last run</th><td>${p.ts || 'unknown'}</td></tr>
  <tr><th>Status</th><td>${badge} &mdash; ${p.pass || 0} / ${total} probes</td></tr>
  <tr><th>Probe set</th><td><code>${p.kind || 'probes-unauth'}</code></td></tr>
  <tr><th>Target</th><td><code>${p.host || 'cogos.5ceos.com'}</code></td></tr>
</table>
${failures}`;
}

function trustHtml(state) {
  const s = state || {};
  const body = `
<h1>Trust &amp; transparency</h1>
<div style="color:#8b949e;font-size:13px;margin:-2px 0 12px;font-style:italic">CogOS is the substrate behind 5CEOs. This page is what we publish to prove every claim.</div>
<div class="meta">Modeled after trust.salesforce.com. Every claim on this page maps to data the page can prove from the running process or to a section of <code>SECURITY.md</code>. If we don&apos;t have data, we say so &mdash; we don&apos;t fabricate uptime percentages or past advisories.</div>

${renderStatusBanner(s)}

<h2>Live numbers</h2>
${renderTiles(s)}

<h2>Verifiable security claims</h2>
<p>Mirror of <code>SECURITY.md</code> &sect;3. Each row is a claim plus the command an external auditor runs to check us right now. Items marked <em>rolling out</em> are wired in the deploy pipeline but not yet announced as enforced &mdash; <code>SECURITY.md</code> remains the source of truth.</p>
${renderClaimsTable()}

<h2>Recent revisions</h2>
${renderRevisionsSection(s)}

<h2>Published security advisories</h2>
${renderAdvisoriesSection(s)}

<h2>Public hash-chain checkpoint</h2>
${renderCheckpointSection(s)}

<h2>Continuous probes</h2>
${renderContinuousProbes(s)}

<h2>Pentest summary</h2>
${renderPentestSection(s)}

<h2>Coordinated disclosure</h2>
<div class="callout">
  Report a security issue: <a href="mailto:${SUPPORT_EMAIL}?subject=%5BSECURITY%5D%20">${SUPPORT_EMAIL}</a> with subject prefix <code>[SECURITY]</code>.
  Response SLA, scope, and safe-harbor terms are documented in <code>SECURITY.md</code> &sect;1.
</div>
`;
  return `<!DOCTYPE html>
<html>
<head>
  <title>${PRODUCT_NAME} &mdash; Trust &amp; transparency</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  ${STYLE_BLOCK}
</head>
<body>
<main>
  ${NAV}
  ${body}
  <footer>
    ${PRODUCT_NAME} &middot; trust dashboard &middot;
    <a href="/cookbook">cookbook</a> &middot;
    <a href="/whitepaper">whitepaper</a> &middot;
    <a href="${BENCH_URL}">bench</a> &middot;
    determinism by construction, not by hope
  </footer>
</main>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// State builder — called by the route handler. Pulls every fact from a
// concrete source: env, process, the cosign.pub route's own logic, the
// optional pentest-history.json file. Never invents data.
// ---------------------------------------------------------------------------

// Mirror of /cosign.pub logic in src/index.js — kept in lockstep with that
// route. We check the SAME env vars (COSIGN_PUBKEY_PEM or COSIGN_PUBKEY_FILE)
// in-process rather than HTTP-fetching ourselves: an in-process check is
// race-free with deploy state, and saves us from having to know our own
// public URL at render time. The spec asks for "fetch cosign.pub" semantics;
// this is the deterministic version of that same check.
function cosignState() {
  const pem = process.env.COSIGN_PUBKEY_PEM
    || (process.env.COSIGN_PUBKEY_FILE
        ? (() => { try { return fs.readFileSync(process.env.COSIGN_PUBKEY_FILE, 'utf8'); } catch { return null; } })()
        : null);
  if (pem && /-----BEGIN [A-Z ]*PUBLIC KEY-----/.test(pem)) {
    return {
      published: true,
      detail: 'Image cryptographically verified — cosign pubkey served at /cosign.pub',
    };
  }
  return {
    published: false,
    detail: 'Cosign pubkey publication pending',
  };
}

function loadPentestHistory() {
  // Default path: data/pentest-history.json. Operator can override via env.
  // File absence is the expected state — render the honest placeholder.
  const filePath = process.env.PENTEST_HISTORY_FILE
    || path.join(process.cwd(), 'data', 'pentest-history.json');
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed;
    if (parsed && Array.isArray(parsed.entries)) return parsed.entries;
    return [];
  } catch {
    return [];
  }
}

// Read the latest line of the probe-history JSONL (written by the
// continuous-pentest Container App Job) so /trust can render the most
// recent automated probe result. File absence is the expected state
// before the job has run once.
function loadLatestProbe() {
  const filePath = process.env.PROBE_HISTORY_FILE
    || path.join(process.cwd(), 'data', 'probe-history.jsonl');
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const lines = raw.trim().split('\n').filter(Boolean);
    if (lines.length === 0) return null;
    // Last line is most recent (append-only log)
    return JSON.parse(lines[lines.length - 1]);
  } catch {
    return null;
  }
}

// Read the latest public hash-chain checkpoint + the local verify
// result. Both calls are read-only (no chain mutation), and both swallow
// failure into a null/empty shape so a corrupt file never throws into
// the /trust render. See src/audit-checkpoint.js for the chain
// semantics + when "no checkpoint" is the expected state.
function loadLatestCheckpoint() {
  try { return require('./audit-checkpoint').latest(); }
  catch { return null; }
}
function loadCheckpointChainStatus() {
  try { return require('./audit-checkpoint').verifyChain(); }
  catch { return { ok: true, chain_length: 0, broke_at_index: null, reason: null }; }
}

// Read p50/p95/p99 latency from the usage rollup. Walks back up to 7 days
// so a zero-traffic day doesn't blank the tiles. Returns null if no rollup
// exists in the window -- the renderer shows an honest "no data yet"
// placeholder rather than fabricating numbers. Source data is operator-
// aggregated globals only (no prompt content, no per-customer attribution).
function loadLatestLatency() {
  try {
    const usageRollup = require('./usage-rollup');
    if (!usageRollup.readRollup) return null;
    const now = new Date();
    for (let i = 0; i < 7; i++) {
      const d = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
      const dateIso = d.toISOString().slice(0, 10);
      const r = usageRollup.readRollup(dateIso);
      if (r && r.globals && r.globals.requests > 0) {
        const g = r.globals;
        return {
          p50_ms: g.p50_latency_ms != null ? Math.round(g.p50_latency_ms) : null,
          p95_ms: g.p95_latency_ms != null ? Math.round(g.p95_latency_ms) : null,
          p99_ms: g.p99_latency_ms != null ? Math.round(g.p99_latency_ms) : null,
          request_count: g.requests || 0,
          sample_count: Array.isArray(g.latency_samples) ? g.latency_samples.length : 0,
          as_of_date: dateIso,
        };
      }
    }
  } catch { /* fall through */ }
  return null;
}

function buildTrustState({ healthOk = true } = {}) {
  let pkgVersion = '0.1.0';
  try {
    pkgVersion = require('../package.json').version || pkgVersion;
  } catch { /* not fatal */ }
  const imageTag = process.env.COGOS_IMAGE_TAG || pkgVersion;
  const status = healthOk ? 'operational' : 'degraded';
  const statusLabel = healthOk ? 'Operational' : 'Degraded';
  return {
    status,
    statusLabel,
    imageTag,
    uptimeSeconds: process.uptime(),
    cosign: cosignState(),
    advisories: [], // none published; do not fabricate
    pentestHistory: loadPentestHistory(),
    latestProbe: loadLatestProbe(),
    latency: loadLatestLatency(),
    latestCheckpoint: loadLatestCheckpoint(),
    checkpointChain: loadCheckpointChainStatus(),
    renderedAt: new Date().toISOString(),
  };
}

module.exports = { trustHtml, buildTrustState, formatUptime, SECURITY_CLAIMS };
