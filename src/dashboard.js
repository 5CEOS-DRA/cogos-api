'use strict';

// Customer-facing dashboard HTML.
//
// SURFACE
// -----------------------------------------------------------------------------
// /dashboard            → login form (paste your API key)
// /dashboard/login      → POST: validates key, sets session cookie
// /dashboard/home       → session-gated: tenant overview, keys, audit
// /dashboard/keys/:id/revoke   → POST: revoke a key (same-tenant only)
// /dashboard/keys/rotate       → POST: rotate the session's own key
// /dashboard/forgot     → public stub for key recovery (future card)
// /dashboard/logout     → POST: clears the cookie
//
// AUTH MODEL: same as Stripe / Vercel / Cloudflare developer dashboards.
// The customer's API key IS the password. Paste it in, the server
// verifies via keys.verify(), and an HttpOnly session cookie carries
// state for subsequent requests. There is NO separate username/password
// today; magic-link "I lost my key" recovery is a separate future card
// (linked from /dashboard/forgot).
//
// STYLE: monospace dark theme, identical to src/landing.js +
// src/cookbook.js. The NAV element exposes the dashboard alongside the
// other public surfaces.

const BENCH_URL = 'https://github.com/5CEOS-DRA/llm-determinism-bench';

function escapeHtml(s) {
  if (s == null) return '';
  return String(s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

// Shared NAV — mirrors the landing-page + cookbook nav with /dashboard
// promoted as the current page when rendered from a dashboard surface.
function navHtml({ current = '/dashboard' } = {}) {
  function mark(href, label) {
    const style = href === current ? ' style="color:#79c0ff"' : '';
    return `<a href="${href}"${style}>${label}</a>`;
  }
  return `<nav style="margin-bottom:18px;font-size:11px">
  ${mark('/', 'Home')}
  ${mark('/cookbook', 'Cookbook')}
  ${mark('/demo', 'Demo')}
  ${mark('/whitepaper', 'Whitepaper')}
  ${mark('/trust', 'Trust')}
  ${mark('/dashboard', 'Dashboard')}
  <a href="${BENCH_URL}">Bench</a>
</nav>`;
}

// Shared style block — matches src/landing.js + src/cookbook.js
// monospace dark theme so the dashboard doesn't feel like a different
// product.
const STYLE_BLOCK = `<style>
*{box-sizing:border-box}
body{font-family:ui-monospace,SF Mono,Menlo,monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:32px 20px;line-height:1.55}
main{max-width:880px;margin:0 auto}
h1{color:#58a6ff;font-size:26px;margin:0 0 4px}
h2{color:#58a6ff;font-size:18px;margin:32px 0 10px;border-bottom:1px solid #30363d;padding-bottom:6px}
h3{color:#79c0ff;font-size:13px;margin:18px 0 6px;text-transform:uppercase;letter-spacing:0.04em}
p{margin:0 0 14px;font-size:14px}
small{color:#6e7681;font-size:11px}
code{background:#161b22;padding:2px 5px;border-radius:3px;font-size:12.5px;color:#79c0ff}
pre{background:#0a0e14;border:1px solid #30363d;padding:14px;border-radius:6px;overflow-x:auto;font-size:12px;line-height:1.5;margin:0 0 14px}
pre code{background:none;padding:0;color:#c9d1d9}
.tile{background:#161b22;border:1px solid #30363d;padding:16px 18px;margin:14px 0;border-radius:6px}
.tile .head{color:#58a6ff;font-weight:600;margin-bottom:6px;font-size:13px;text-transform:uppercase;letter-spacing:0.04em}
.metric{font-size:28px;color:#3fb950;font-weight:600;margin:6px 0 2px}
.metric-sub{color:#8b949e;font-size:12px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
table{width:100%;border-collapse:collapse;font-size:12px;margin:0 0 14px}
th{text-align:left;padding:8px 10px;color:#8b949e;font-weight:600;background:#161b22;border-bottom:1px solid #30363d;text-transform:uppercase;letter-spacing:0.04em;font-size:11px}
td{padding:8px 10px;border-bottom:1px solid #21262d;color:#c9d1d9;vertical-align:top}
tr.current{background:#0d2818}
tr.current td{color:#7ee2a8}
.badge{display:inline-block;padding:1px 7px;border-radius:10px;font-size:10px;font-weight:600;background:#21262d;color:#c9d1d9;letter-spacing:0.04em}
.badge.active{background:#0d2818;color:#3fb950;border:1px solid #2ea04340}
.badge.revoked{background:#3d1212;color:#f85149;border:1px solid #f8514940}
.badge.bearer{background:#0d1f33;color:#79c0ff}
.badge.ed25519{background:#1a1633;color:#c8b3ff}
.btn{display:inline-block;background:#21262d;color:#c9d1d9;border:1px solid #30363d;padding:5px 12px;border-radius:4px;cursor:pointer;font-family:inherit;font-size:11px;text-decoration:none}
.btn:hover{background:#30363d}
.btn-danger{background:#3d1212;color:#f85149;border-color:#f8514940}
.btn-danger:hover{background:#5c1b1b}
.btn-primary{background:#238636;color:#fff;border-color:#238636}
.btn-primary:hover{background:#2ea043}
.btn:disabled{opacity:0.4;cursor:not-allowed}
form.inline{display:inline;margin:0;padding:0}
.warn{background:#3d2611;border:1px solid #9e6a03;color:#d29922;padding:12px 14px;border-radius:6px;margin:14px 0;font-size:12px}
.info{background:#0d1f33;border:1px solid #1f6feb;color:#79c0ff;padding:12px 14px;border-radius:6px;margin:14px 0;font-size:12px}
.error{background:#3d1212;border:1px solid #f85149;color:#f85149;padding:12px 14px;border-radius:6px;margin:14px 0;font-size:13px}
input[type=password],input[type=text]{width:100%;background:#0a0e14;color:#c9d1d9;border:1px solid #30363d;padding:10px 14px;border-radius:4px;font-family:inherit;font-size:13px}
input:focus{outline:none;border-color:#58a6ff}
a{color:#58a6ff;text-decoration:none}
a:hover{text-decoration:underline}
footer{color:#6e7681;font-size:11px;margin-top:48px;padding-top:18px;border-top:1px solid #21262d}
.subheader{color:#8b949e;font-size:13px;margin:0 0 24px}
.kbd{display:inline-block;background:#161b22;border:1px solid #30363d;padding:1px 6px;border-radius:3px;font-size:11px;color:#79c0ff}
.muted{color:#6e7681}
.right{text-align:right}
.spread{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}
</style>`;

function wrap({ title, bodyHtml, current = '/dashboard' }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${escapeHtml(title)}</title>
${STYLE_BLOCK}
</head>
<body><main>
${navHtml({ current })}
${bodyHtml}
<footer>
  CogOS dashboard &middot; <a href="/trust">trust</a> &middot;
  <a href="/cookbook">cookbook</a> &middot;
  <a href="mailto:support@5ceos.com">support@5ceos.com</a>
</footer>
</main></body></html>`;
}

// -----------------------------------------------------------------------------
// /dashboard — login form
// -----------------------------------------------------------------------------

// Friendly mapping for the ?error= query param. We never echo the raw
// query value back into the page (no reflected XSS, no oracle for "is
// this error code real"); the map is closed.
const ERROR_MESSAGES = {
  invalid_api_key: 'That API key was not recognized. Check for stray whitespace, '
    + 'confirm it starts with sk-cogos-, or paste a fresh one.',
  login_required: 'Your dashboard session expired or was invalidated. '
    + 'Paste your API key to continue.',
  rotate_failed: 'Key rotation failed. Try again, or contact support@5ceos.com.',
  revoke_failed: 'Could not revoke that key. It may have been removed already.',
  cross_tenant: 'That key does not belong to your tenant.',
  self_revoke: 'You cannot revoke the key you are currently signed in with. '
    + 'Rotate it instead, or sign in with a different key first.',
};

function loginHtml({ error } = {}) {
  const errMsg = (error && ERROR_MESSAGES[error]) ? ERROR_MESSAGES[error] : null;
  const errorBlock = errMsg
    ? `<div class="error">${escapeHtml(errMsg)}</div>`
    : '';
  const body = `
  <h1>Dashboard sign-in</h1>
  <div class="subheader">Paste your API key. The key itself is your password &mdash; same model as Stripe, Vercel, Cloudflare, Fly. We never see it in the URL or your browser history.</div>
  ${errorBlock}
  <form action="/dashboard/login" method="POST" autocomplete="off">
    <label for="api_key" style="display:block;font-size:12px;color:#8b949e;margin-bottom:6px">Your API key</label>
    <input type="password" name="api_key" id="api_key" placeholder="sk-cogos-..." autocomplete="off" autofocus required>
    <div style="margin-top:14px">
      <button class="btn btn-primary" type="submit">Sign in</button>
      <a class="btn" href="/dashboard/forgot" style="margin-left:8px">Forgot key?</a>
    </div>
  </form>
  <div class="info" style="margin-top:28px">
    <strong>Bearer keys only.</strong> The dashboard sign-in path validates plaintext bearer keys against the server&apos;s stored hash. Ed25519-scheme keys hold no replayable plaintext &mdash; they sign each request and don&apos;t fit a paste-and-go form. Operator-scope ed25519 customers should manage via <code>POST /v1/keys/rotate</code> directly. A future card can layer an attest-once challenge to bring ed25519 customers into the dashboard.
  </div>
  <div class="warn">
    <strong>Lost or rotated all your keys?</strong> Use <a href="/dashboard/forgot">key recovery</a> &mdash; enter the email you signed up or subscribed with and we&apos;ll send a single-use link to mint a fresh key under the same tenant.
  </div>
`;
  return wrap({ title: 'CogOS — dashboard sign-in', bodyHtml: body });
}

// -----------------------------------------------------------------------------
// /dashboard/home — logged-in surface
// -----------------------------------------------------------------------------

function formatTs(ts) {
  if (!ts) return '—';
  // ISO-8601 strings render fine as-is, but trim the milliseconds to
  // keep the table narrow.
  const s = String(ts);
  return s.replace(/\.\d+Z$/, 'Z');
}

function renderUsageTile(state) {
  const dailyReq = (state.daily_counter && state.daily_counter.requests) || 0;
  const dailyTok = (state.daily_counter && state.daily_counter.fallback_tokens) || 0;
  const monthlyUsed = state.monthly_used == null ? '—' : state.monthly_used.toLocaleString('en-US');
  const monthlyQuota = state.monthly_quota == null ? '∞' : state.monthly_quota.toLocaleString('en-US');
  return `
  <div class="grid">
    <div class="tile">
      <div class="head">Today</div>
      <div class="metric">${dailyReq.toLocaleString('en-US')}</div>
      <div class="metric-sub">requests today (UTC)</div>
    </div>
    <div class="tile">
      <div class="head">Fallback tokens today</div>
      <div class="metric">${dailyTok.toLocaleString('en-US')}</div>
      <div class="metric-sub">cumulative this UTC day</div>
    </div>
    <div class="tile">
      <div class="head">This billing cycle</div>
      <div class="metric">${monthlyUsed}</div>
      <div class="metric-sub">of ${monthlyQuota} quota</div>
    </div>
  </div>`;
}

function renderKeysTable(state) {
  const myKeyId = state.key_id;
  const rows = (state.keys || []).map((k) => {
    const isMe = k.id === myKeyId;
    const schemeBadge = k.scheme === 'ed25519'
      ? '<span class="badge ed25519">ed25519</span>'
      : '<span class="badge bearer">bearer</span>';
    const activeBadge = k.active === false
      ? '<span class="badge revoked">revoked</span>'
      : '<span class="badge active">active</span>';
    const shortId = String(k.id || '').slice(0, 8);
    const label = k.label ? escapeHtml(k.label) : '<span class="muted">—</span>';
    // Action column:
    //   - Current session's key: rotate button only. Revoke is hidden
    //     entirely (UX choice: HIDDEN — telling the user "you can't
    //     revoke this" is noise; rotate is the right action). Server
    //     also 400s on self-revoke as a defense-in-depth measure.
    //   - Other active key: revoke button.
    //   - Already-revoked key: no actions.
    let actions = '';
    if (isMe) {
      actions = `<form class="inline" action="/dashboard/keys/rotate" method="POST" onsubmit="return confirm('Rotate this key? The new material is shown ONCE and the old key stays valid for 24h grace.');">
        <button class="btn btn-primary" type="submit">Rotate</button>
      </form>`;
    } else if (k.active !== false) {
      actions = `<form class="inline" action="/dashboard/keys/${encodeURIComponent(k.id)}/revoke" method="POST" onsubmit="return confirm('Revoke this key? Any client using it will start getting 401s immediately.');">
        <button class="btn btn-danger" type="submit">Revoke</button>
      </form>`;
    } else {
      actions = '<span class="muted">—</span>';
    }
    return `<tr class="${isMe ? 'current' : ''}">
      <td><code>${escapeHtml(shortId)}</code>${isMe ? ' <small class="muted">(this session)</small>' : ''}</td>
      <td>${label}</td>
      <td>${escapeHtml(k.app_id || '_default')}</td>
      <td>${schemeBadge}</td>
      <td><small>${formatTs(k.issued_at)}</small></td>
      <td><small>${formatTs(k.last_used_at)}</small></td>
      <td>${activeBadge}</td>
      <td class="right">${actions}</td>
    </tr>`;
  }).join('\n');
  return `
  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>Label</th>
        <th>App</th>
        <th>Scheme</th>
        <th>Issued</th>
        <th>Last used</th>
        <th>Status</th>
        <th class="right">Actions</th>
      </tr>
    </thead>
    <tbody>${rows || '<tr><td colspan="8" class="muted">No keys for this tenant.</td></tr>'}</tbody>
  </table>`;
}

function renderAuditTable(state) {
  const rows = (state.audit_rows || []).map((r) => {
    const okFor = state.chain_ok_by_app && r.app_id
      ? state.chain_ok_by_app[r.app_id]
      : null;
    const chainBadge = okFor === true
      ? '<span class="badge active">ok</span>'
      : okFor === false
        ? '<span class="badge revoked">broken</span>'
        : '<span class="muted">—</span>';
    const status = r.status == null ? '—' : String(r.status);
    const statusColor = r.status >= 400 ? '#f85149' : '#3fb950';
    return `<tr>
      <td><small>${formatTs(r.ts)}</small></td>
      <td>${escapeHtml(r.app_id || '_default')}</td>
      <td><small>${escapeHtml(r.route || '—')}</small></td>
      <td style="color:${statusColor}">${status}</td>
      <td class="right"><small>${r.prompt_tokens == null ? '—' : r.prompt_tokens}</small></td>
      <td class="right"><small>${r.completion_tokens == null ? '—' : r.completion_tokens}</small></td>
      <td class="right"><small>${r.latency_ms == null ? '—' : r.latency_ms} ms</small></td>
      <td>${chainBadge}</td>
    </tr>`;
  }).join('\n');
  return `
  <table>
    <thead>
      <tr>
        <th>Time</th>
        <th>App</th>
        <th>Route</th>
        <th>Status</th>
        <th class="right">Prompt</th>
        <th class="right">Completion</th>
        <th class="right">Latency</th>
        <th>Chain</th>
      </tr>
    </thead>
    <tbody>${rows || '<tr><td colspan="8" class="muted">No audit rows yet. Make a call to <code>/v1/chat/completions</code> to populate.</td></tr>'}</tbody>
  </table>`;
}

function homeHtml(state) {
  const keyPrefix = state.key_prefix
    ? `${escapeHtml(state.key_prefix.slice(0, 12))}&hellip;`
    : '<span class="muted">—</span>';
  const expiresAt = state.expires_at
    ? `<small class="muted">expires ${escapeHtml(formatTs(state.expires_at))}</small>`
    : '';
  const body = `
  <div class="spread">
    <div>
      <h1>${escapeHtml(state.tenant_id)}</h1>
      <div class="subheader">
        Signed in with <code>${keyPrefix}</code> (app <code>${escapeHtml(state.app_id || '_default')}</code> / scheme <span class="badge ${state.scheme || 'bearer'}">${escapeHtml(state.scheme || 'bearer')}</span>) ${expiresAt}
      </div>
    </div>
    <form class="inline" action="/dashboard/logout" method="POST">
      <button class="btn" type="submit">Sign out</button>
    </form>
  </div>

  <h2>Usage</h2>
  ${renderUsageTile(state)}

  <h2>Keys</h2>
  <p class="muted">Every key issued for tenant <code>${escapeHtml(state.tenant_id)}</code>. The row you&apos;re signed in with cannot be revoked from this surface &mdash; rotate it instead and revoke the previous key after switching your client.</p>
  ${renderKeysTable(state)}

  <h2>Audit</h2>
  <p class="muted">Last 20 calls on your tenant. Each app maintains its own hash-chained audit log; the <span class="badge active">ok</span> badge means the server-side <code>verifyChain()</code> returned clean for that app. The full chain is available at <a href="/v1/audit"><code>/v1/audit</code></a> &mdash; you can re-run verification client-side. <a href="/cookbook#verify-signature">How to verify &rarr;</a></p>
  ${renderAuditTable(state)}

  <div class="warn" style="margin-top:32px">
    <strong>Lost a key?</strong> If you still have ANY valid key, sign in with it and rotate via the keys table. If you&apos;ve lost every key, <a href="/dashboard/forgot">key recovery</a> sends a single-use link to the email on file.
  </div>
`;
  return wrap({
    title: `CogOS — dashboard · ${state.tenant_id}`,
    bodyHtml: body,
    current: '/dashboard',
  });
}

// -----------------------------------------------------------------------------
// /dashboard/forgot — magic-link "I lost my API key" recovery flow
// -----------------------------------------------------------------------------
//
// The substrate cannot recover a lost API key (only sha256(plaintext) is
// stored). "Recovery" therefore means: prove you own the email associated
// with a key → we mint a fresh key for the same tenant → the old key
// enters its standard 24h grace window. The flow has THREE surfaces:
//
//   1. forgotFormHtml({error})    — the email-entry form at GET /dashboard/forgot
//   2. forgotConfirmHtml({email}) — the "if-an-account-exists-we-sent-a-link"
//                                    page returned on POST /dashboard/forgot.
//                                    INTENTIONALLY VAGUE — the same page is
//                                    returned whether the email matched a real
//                                    customer or not, so a poking attacker
//                                    can't enumerate customers via this form.
//   3. recoveryResultHtml({...})  — the show-once new-key display at
//                                    /dashboard/rotate-result (mirrors
//                                    rotateResultHtml's shape).

function forgotFormHtml({ error } = {}) {
  const errorBlock = error
    ? `<div class="error">${escapeHtml(String(error))}</div>`
    : '';
  const body = `
  <h1>Key recovery</h1>
  <div class="subheader">Lost every API key for your tenant? Enter the email on file and we&apos;ll send a single-use link to mint a fresh key. The old key keeps working for 24h after recovery so any client you forgot about doesn&apos;t 401 mid-call.</div>
  ${errorBlock}
  <form action="/dashboard/forgot" method="POST" autocomplete="off">
    <label for="email" style="display:block;font-size:12px;color:#8b949e;margin-bottom:6px">Your billing or signup email</label>
    <input type="email" name="email" id="email" placeholder="you@example.com" autocomplete="email" autofocus required>
    <div style="margin-top:14px">
      <button class="btn btn-primary" type="submit">Send recovery link</button>
      <a class="btn" href="/dashboard" style="margin-left:8px">&larr; back to sign-in</a>
    </div>
  </form>
  <div class="info" style="margin-top:28px">
    <strong>How this works.</strong> The link is good for 15 minutes and can only be used once. Clicking it issues a new API key under your existing tenant; we never see or transmit the old plaintext (we never had it). Your audit chain, billing identity, and app namespaces all carry forward unchanged.
  </div>
  <div class="warn">
    <strong>Doesn&apos;t work?</strong> If you signed up anonymously (no email at signup) or the email on your Stripe receipt has changed, email <a href="mailto:support@5ceos.com?subject=%5BSECURITY%5D%20Key%20recovery">support@5ceos.com</a> with the subject prefix <code>[SECURITY]</code> &mdash; an operator can run a manual identity check.
  </div>
`;
  return wrap({ title: 'CogOS — key recovery', bodyHtml: body, current: '/dashboard' });
}

// The "if-an-account-exists" confirmation page. Intentionally vague:
// the same page is returned for both real customers and unknown emails
// so the form can't be turned into an enumeration oracle. The echoed
// email is HTML-escaped — we render exactly what the user typed.
function forgotConfirmHtml({ email } = {}) {
  const safeEmail = escapeHtml(String(email || '').slice(0, 254));
  const body = `
  <h1>Check your inbox</h1>
  <div class="subheader">If an account exists for <code>${safeEmail}</code>, we&apos;ve sent a single-use recovery link.</div>
  <div class="info">
    <strong>Next steps.</strong>
    <ul style="margin-top:8px">
      <li>Open the email and click the link within <strong>15 minutes</strong>. The link mints a fresh API key under your existing tenant and signs you into the dashboard.</li>
      <li>If you don&apos;t see it, check spam &mdash; we send from <code>notify@5ceos.com</code> via AWS SES. Then double-check the spelling of the address you submitted.</li>
      <li>If the email genuinely never arrives, or you signed up without an email, contact <a href="mailto:support@5ceos.com?subject=%5BSECURITY%5D%20Key%20recovery">support@5ceos.com</a> with the subject prefix <code>[SECURITY]</code> for a manual identity check.</li>
    </ul>
  </div>
  <div class="warn" style="margin-top:18px">
    <strong>Privacy note.</strong> We deliberately do not confirm whether <code>${safeEmail}</code> is a real customer &mdash; that would let anyone enumerate our customer list by trying addresses. You see the same page either way.
  </div>
  <p style="margin-top:24px"><a class="btn" href="/dashboard">&larr; Back to sign-in</a></p>
`;
  return wrap({ title: 'CogOS — recovery link sent', bodyHtml: body, current: '/dashboard' });
}

// Show-once display of the newly-issued key + secret after a successful
// magic-link recovery. Mirrors rotateResultHtml's shape — the only
// material difference is the copy reflects "you recovered" rather than
// "you rotated voluntarily."
function recoveryResultHtml({
  new_api_key, new_hmac_secret, expires_at, grace_until,
  ed25519_key_id, private_pem, pubkey_pem,
  x25519_private_pem, x25519_pubkey_pem, scheme,
}) {
  const safeKey = escapeHtml(new_api_key || '');
  const safeHmac = escapeHtml(new_hmac_secret || '');
  const safeEd = escapeHtml(ed25519_key_id || '');
  const safePriv = escapeHtml(private_pem || '');
  const safePub = escapeHtml(pubkey_pem || '');
  const safeX25Priv = escapeHtml(x25519_private_pem || '');
  const safeX25Pub = escapeHtml(x25519_pubkey_pem || '');

  const bearerBlock = (scheme === 'bearer' && safeKey) ? `
  <h2>Your new API key</h2>
  <pre><code>${safeKey}</code></pre>
  <h2>Your new HMAC secret</h2>
  <p>Use this to verify the <code>X-Cogos-Signature</code> header on every <code>/v1/*</code> response. <a href="/cookbook#verify-signature">How to verify &rarr;</a></p>
  <pre><code>${safeHmac}</code></pre>
  ` : '';

  const ed25519Block = (scheme === 'ed25519' && safeEd) ? `
  <h2>Your new ed25519 keypair</h2>
  <p><code>keyId</code>: <code>${safeEd}</code></p>
  <h3>Private key (PEM) &mdash; auth signing</h3>
  <pre><code>${safePriv}</code></pre>
  <h3>Public key (PEM)</h3>
  <pre><code>${safePub}</code></pre>
  <h3>X25519 sealing keypair</h3>
  <p>Used to decrypt sealed audit rows. Hold the private PEM client-side. The server retains only the public.</p>
  <pre><code>${safeX25Priv}</code></pre>
  <pre><code>${safeX25Pub}</code></pre>
  <h2>HMAC secret (response signing)</h2>
  <pre><code>${safeHmac}</code></pre>
  ` : '';

  const body = `
  <h1>&check; Recovery complete</h1>
  <div class="subheader">A new API key has been minted under your existing tenant. Your audit chain, billing identity, and app namespaces all carry forward unchanged.</div>

  <div class="warn">
    <strong>Save this material NOW.</strong> The new key + secret are displayed exactly once. Navigating away loses them. We store only the sealed envelope server-side. If you lose this material too, run recovery again from this same email address.
    ${expires_at ? `<br><br><small>New key expires at <code>${escapeHtml(expires_at)}</code>.</small>` : ''}
    ${grace_until ? `<br><small>Old key grace window ends at <code>${escapeHtml(grace_until)}</code> &mdash; any client still using the lost key will continue working until then. After that the old key auto-revokes on its next touch.</small>` : ''}
  </div>

  ${bearerBlock}
  ${ed25519Block}

  <h2>What next</h2>
  <ol>
    <li>Update any client you still have access to with the new key.</li>
    <li>The lost key is in its standard 24h grace window. After that it auto-revokes &mdash; no further action required.</li>
    <li>If you want to cut the grace short (e.g. you suspect the lost key was stolen, not just misplaced), sign in here and revoke it from the keys table immediately.</li>
  </ol>

  <p style="margin-top:24px">
    <a class="btn btn-primary" href="/dashboard/home">&rarr; Go to dashboard</a>
  </p>
`;
  return wrap({ title: 'CogOS — recovery complete', bodyHtml: body, current: '/dashboard' });
}

// -----------------------------------------------------------------------------
// /dashboard/keys/rotate — show-once display of the newly-rotated key
// -----------------------------------------------------------------------------

// Mirrors landing.successHtml's "save now or lose it" UX. The new key
// material is rendered into the page exactly once; navigating away
// loses it. The customer is signed-in via the OLD key's session
// cookie — we keep that session live during the 24h grace window so
// they can copy the new material in the same browser tab.
function rotateResultHtml({
  new_api_key, new_hmac_secret, ed25519_key_id, private_pem, x25519_private_pem,
  pubkey_pem, x25519_pubkey_pem,
  expires_at, grace_until, scheme,
}) {
  const safeKey = escapeHtml(new_api_key || '');
  const safeHmac = escapeHtml(new_hmac_secret || '');
  const safeEd = escapeHtml(ed25519_key_id || '');
  const safePriv = escapeHtml(private_pem || '');
  const safePub = escapeHtml(pubkey_pem || '');
  const safeX25Priv = escapeHtml(x25519_private_pem || '');
  const safeX25Pub = escapeHtml(x25519_pubkey_pem || '');

  const bearerBlock = (scheme === 'bearer' && safeKey) ? `
  <h2>Your new API key</h2>
  <pre><code>${safeKey}</code></pre>
  <h2>Your new HMAC secret</h2>
  <p>Use this to verify the <code>X-Cogos-Signature</code> header on every <code>/v1/*</code> response. <a href="/cookbook#verify-signature">How to verify &rarr;</a></p>
  <pre><code>${safeHmac}</code></pre>
  ` : '';

  const ed25519Block = (scheme === 'ed25519' && safeEd) ? `
  <h2>Your new ed25519 keypair</h2>
  <p><code>keyId</code>: <code>${safeEd}</code></p>
  <h3>Private key (PEM) &mdash; auth signing</h3>
  <pre><code>${safePriv}</code></pre>
  <h3>Public key (PEM)</h3>
  <pre><code>${safePub}</code></pre>
  <h3>X25519 sealing keypair</h3>
  <p>Used to decrypt sealed audit rows. Hold the private PEM client-side. The server retains only the public.</p>
  <pre><code>${safeX25Priv}</code></pre>
  <pre><code>${safeX25Pub}</code></pre>
  <h2>HMAC secret (response signing)</h2>
  <pre><code>${safeHmac}</code></pre>
  ` : '';

  const body = `
  <h1>&check; Key rotated</h1>
  <div class="subheader">A new key has been minted under your tenant. The OLD key stays valid for 24h grace so you can roll your client at your own cadence.</div>

  <div class="warn">
    <strong>Save this material NOW.</strong> The new key + secret are displayed exactly once. Navigating away loses them. We store only the sealed envelope server-side. If you lose it, rotate again with a still-valid key, or contact <a href="mailto:support@5ceos.com?subject=%5BSECURITY%5D%20Key%20recovery">support@5ceos.com</a>.
    ${expires_at ? `<br><br><small>New key expires at <code>${escapeHtml(expires_at)}</code>.</small>` : ''}
    ${grace_until ? `<br><small>Old key grace window ends at <code>${escapeHtml(grace_until)}</code> &mdash; rotate your client before then.</small>` : ''}
  </div>

  ${bearerBlock}
  ${ed25519Block}

  <h2>What next</h2>
  <ol>
    <li>Update your client(s) to use the new key.</li>
    <li>After your last service has cut over, return to the dashboard and revoke the old key from the keys table.</li>
    <li>Or just let the 24h grace window expire &mdash; the old key auto-revokes on its next touch past the deadline.</li>
  </ol>

  <p style="margin-top:24px">
    <a class="btn btn-primary" href="/dashboard/home">&larr; Back to dashboard</a>
  </p>
`;
  return wrap({ title: 'CogOS — key rotated', bodyHtml: body, current: '/dashboard' });
}

module.exports = {
  loginHtml,
  homeHtml,
  forgotFormHtml,
  forgotConfirmHtml,
  recoveryResultHtml,
  rotateResultHtml,
  // Exposed for the route handler to translate query-string errors
  // through the same closed map (no reflected echo).
  ERROR_MESSAGES,
  // Exposed for tests.
  _internal: { escapeHtml, navHtml, wrap },
};
