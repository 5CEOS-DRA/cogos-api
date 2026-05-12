'use strict';

require('dotenv').config();
const express = require('express');

const logger = require('./logger');
const { bearerAuth, adminAuth } = require('./auth');
const { handleChatCompletions, handleListModels, enforcePackage } = require('./chat-api');
const keys = require('./keys');
const usage = require('./usage');
const stripeMod = require('./stripe');
const packages = require('./packages');
const landing = require('./landing');

function createApp() {
  const app = express();

  // Stripe webhook NEEDS raw body for signature verification. Mount BEFORE
  // express.json() so the body parser doesn't consume the stream first.
  app.post('/stripe/webhook',
    express.raw({ type: 'application/json', limit: '512kb' }),
    async (req, res) => {
      const sig = req.headers['stripe-signature'];
      let event;
      try {
        event = stripeMod.verifyAndParseEvent(req.body, sig);
      } catch (e) {
        logger.warn('stripe_webhook_signature_invalid', { error: e.message });
        return res.status(400).send(`Webhook signature error: ${e.message}`);
      }
      if (stripeMod.isEventProcessed(event.id)) {
        logger.info('stripe_webhook_duplicate', { event_id: event.id, type: event.type });
        return res.json({ received: true, duplicate: true });
      }
      try {
        if (event.type === 'checkout.session.completed') {
          await stripeMod.handleCheckoutCompleted(event);
        } else if (event.type === 'customer.subscription.updated'
                || event.type === 'customer.subscription.deleted') {
          await stripeMod.handleSubscriptionUpdated(event);
        } else {
          logger.info('stripe_webhook_unhandled', { event_id: event.id, type: event.type });
        }
        res.json({ received: true });
      } catch (e) {
        logger.error('stripe_webhook_handler_failed', { event_id: event.id, type: event.type, error: e.message });
        res.status(500).json({ error: e.message });
      }
    });

  // All other endpoints use parsed JSON.
  app.use(express.json({ limit: '512kb' }));
  app.set('trust proxy', 1);

  // ---- Public health (no auth) ----
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', service: 'cogos-api', version: '0.1.0' });
  });

  // ---- Public landing + signup + success/cancel ----
  app.get('/', (_req, res) => {
    res.type('html').send(landing.renderLandingHtml(packages.list()));
  });
  app.get('/cancel', (_req, res) => res.type('html').send(landing.CANCEL_HTML));

  app.post('/signup', async (req, res) => {
    try {
      const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
      const host = req.headers['x-forwarded-host'] || req.headers.host;
      const origin = `${proto}://${host}`;
      const packageId = (req.query && req.query.package)
        || (req.body && req.body.package)
        || null;
      const session = await stripeMod.createCheckoutSession({ origin, packageId });
      logger.info('stripe_checkout_session_created', {
        session_id: session.id, package_id: packageId,
      });
      // Redirect to Stripe-hosted checkout page
      res.redirect(303, session.url);
    } catch (e) {
      logger.error('stripe_checkout_create_failed', { error: e.message });
      res.status(500).send(`Could not start checkout: ${e.message}`);
    }
  });

  app.get('/success', (req, res) => {
    const sessionId = req.query.session_id;
    if (!sessionId) return res.status(400).send('Missing session_id');
    const issued = stripeMod.getNewlyIssuedKey(sessionId);
    // If webhook hasn't fired yet (race on checkout completion), issued is null.
    res.type('html').send(landing.successHtml({
      apiKey: issued ? issued.api_key : null,
      keyId: issued ? issued.key_id : null,
      expiresAt: issued ? issued.expires_at : null,
    }));
  });

  // ---- Public chat-completions surface ----
  app.get('/v1/models', bearerAuth, handleListModels);
  app.post('/v1/chat/completions', bearerAuth, enforcePackage, handleChatCompletions);

  // ---- Admin: key issuance + listing (gated on X-Admin-Key) ----
  app.post('/admin/keys', adminAuth, (req, res) => {
    const { tenant_id, label, tier } = req.body || {};
    if (!tenant_id) {
      return res.status(400).json({ error: { message: 'tenant_id required' } });
    }
    const { plaintext, record } = keys.issue({ tenantId: tenant_id, label, tier });
    logger.info('key_issued', { id: record.id, tenant_id, tier });
    res.status(201).json({
      api_key: plaintext, // shown ONCE; never retrievable again
      key_id: record.id,
      tenant_id: record.tenant_id,
      tier: record.tier,
      issued_at: record.issued_at,
      warning: 'Save this key now. It will not be shown again.',
    });
  });

  app.get('/admin/keys', adminAuth, (_req, res) => {
    res.json({ keys: keys.list() });
  });

  app.post('/admin/keys/:id/revoke', adminAuth, (req, res) => {
    const ok = keys.revoke(req.params.id);
    if (!ok) return res.status(404).json({ error: { message: 'Key not found' } });
    logger.info('key_revoked', { id: req.params.id });
    res.json({ revoked: true, key_id: req.params.id });
  });

  // Usage log — supports `?since=<unix-ms>` for tailing.
  app.get('/admin/usage', adminAuth, (req, res) => {
    const sinceMs = Number(req.query.since || 0);
    const all = usage.readAll();
    const filtered = sinceMs > 0
      ? all.filter((u) => new Date(u.ts).getTime() > sinceMs)
      : all;
    res.json({
      usage: filtered,
      total_count: all.length,
      filtered_count: filtered.length,
      server_time_ms: Date.now(),
    });
  });

  // ---- Admin: package CRUD (X-Admin-Key, used by Management Console) ----
  // Packages define what each subscription tier gets: monthly USD price,
  // monthly request quota, allowed model tiers. Stripe Products + Prices
  // are kept in sync when STRIPE_SECRET_KEY is configured; otherwise the
  // sync is a no-op (stub mode) so the operator can edit packages before
  // turning on self-serve signup.
  app.get('/admin/packages', adminAuth, (req, res) => {
    const includeInactive = req.query.include_inactive === '1';
    res.json({ packages: packages.list({ includeInactive }) });
  });

  app.post('/admin/packages', adminAuth, async (req, res) => {
    try {
      const pkg = await packages.create(req.body || {});
      res.status(201).json({ package: pkg });
    } catch (e) {
      const status = e.code === 'duplicate_id' ? 409
        : e.code === 'validation_failed' ? 400 : 500;
      logger.warn('admin_packages_create_failed', { error: e.message, status });
      res.status(status).json({
        error: { message: e.message, type: e.code || 'create_failed', errors: e.errors },
      });
    }
  });

  app.put('/admin/packages/:id', adminAuth, async (req, res) => {
    try {
      const pkg = await packages.update(req.params.id, req.body || {});
      res.json({ package: pkg });
    } catch (e) {
      const status = e.code === 'not_found' ? 404
        : e.code === 'validation_failed' ? 400 : 500;
      logger.warn('admin_packages_update_failed', { id: req.params.id, error: e.message, status });
      res.status(status).json({
        error: { message: e.message, type: e.code || 'update_failed', errors: e.errors },
      });
    }
  });

  app.delete('/admin/packages/:id', adminAuth, async (req, res) => {
    try {
      const ok = await packages.softDelete(req.params.id);
      if (!ok) return res.status(404).json({ error: { message: 'Package not found' } });
      res.json({ deactivated: true, id: req.params.id });
    } catch (e) {
      const status = e.code === 'is_default' ? 409 : 500;
      logger.warn('admin_packages_delete_failed', { id: req.params.id, error: e.message });
      res.status(status).json({
        error: { message: e.message, type: e.code || 'delete_failed' },
      });
    }
  });

  // Live dashboard — same-origin HTML that polls /admin/usage every 2s.
  // Admin key supplied by user via password field; never persisted.
  app.get('/admin/live', (_req, res) => {
    res.send(LIVE_DASHBOARD_HTML);
  });

  return app;
}

const LIVE_DASHBOARD_HTML = `<!DOCTYPE html>
<html>
<head>
  <title>cogos-api · live</title>
  <style>
    *{box-sizing:border-box}
    body{font-family:ui-monospace,SF Mono,Menlo,monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:20px;max-width:1200px;margin:0 auto}
    h1{color:#58a6ff;margin:0 0 4px;font-size:18px}
    .sub{color:#8b949e;font-size:11px;margin-bottom:18px}
    .gate{background:#161b22;padding:14px;border:1px solid #30363d;border-radius:6px;margin-bottom:14px}
    .gate label{color:#8b949e;font-size:11px;display:block;margin-bottom:4px;text-transform:uppercase;letter-spacing:.5px}
    .gate input{width:100%;background:#0d1117;color:#c9d1d9;border:1px solid #30363d;padding:8px 10px;font-family:inherit;font-size:13px;border-radius:4px}
    .gate button{margin-top:10px;background:#238636;color:#fff;border:0;padding:8px 18px;border-radius:4px;cursor:pointer;font-family:inherit;font-size:13px}
    .gate button:hover{background:#2ea043}
    .stats{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:14px}
    .stat{background:#161b22;border:1px solid #30363d;padding:12px;border-radius:6px}
    .stat .label{color:#8b949e;font-size:10px;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px}
    .stat .val{color:#58a6ff;font-size:20px;font-weight:600}
    table{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:6px;overflow:hidden;font-size:12px}
    th{background:#0d1117;color:#8b949e;text-align:left;padding:9px 10px;font-weight:600;text-transform:uppercase;font-size:10px;letter-spacing:.5px;border-bottom:1px solid #30363d}
    td{padding:8px 10px;border-bottom:1px solid #21262d}
    tr:last-child td{border-bottom:0}
    tr.new{animation:flash 1s ease-out}
    @keyframes flash{from{background:#1f6feb33}to{background:transparent}}
    .ok{color:#3fb950}.err{color:#f85149}.dim{color:#6e7681}.tier{color:#d29922}
    .empty{padding:40px;text-align:center;color:#6e7681}
    #status{font-size:11px;color:#6e7681;margin-top:8px}
  </style>
</head>
<body>
  <h1>cogos-api · live traffic</h1>
  <div class="sub">Auto-refreshes every 2s. Tab stays open = persistent view.</div>

  <div class="gate" id="gate">
    <label>X-Admin-Key</label>
    <input id="adminKey" type="password" placeholder="cogos-admin-key value from Key Vault"/>
    <button onclick="start()">Watch</button>
  </div>

  <div id="live" style="display:none">
    <div class="stats">
      <div class="stat"><div class="label">total calls</div><div class="val" id="total">0</div></div>
      <div class="stat"><div class="label">success</div><div class="val ok" id="ok">0</div></div>
      <div class="stat"><div class="label">errors</div><div class="val err" id="errs">0</div></div>
      <div class="stat"><div class="label">tokens (in/out)</div><div class="val" id="tok">0/0</div></div>
      <div class="stat"><div class="label">unique tenants</div><div class="val" id="tenants">0</div></div>
    </div>
    <table>
      <thead><tr>
        <th>time</th><th>tenant</th><th>model</th><th>tokens</th><th>ms</th><th>schema</th><th>status</th>
      </tr></thead>
      <tbody id="rows"></tbody>
    </table>
    <div id="status">connecting…</div>
  </div>

  <script>
    let adminKey='', recent=[], lastTs=0;
    const MAX_ROWS=50;
    function fmtTime(iso){return new Date(iso).toLocaleTimeString();}
    function fmtTokens(r){return (r.prompt_tokens||0)+'/'+(r.completion_tokens||0);}
    function start(){
      adminKey=document.getElementById('adminKey').value.trim();
      if(!adminKey){return alert('Enter the admin key');}
      document.getElementById('gate').style.display='none';
      document.getElementById('live').style.display='block';
      tick();
      setInterval(tick,2000);
    }
    async function tick(){
      try{
        const r=await fetch('/admin/usage?since='+lastTs,{headers:{'X-Admin-Key':adminKey}});
        if(r.status===401){document.getElementById('status').textContent='401 — bad admin key';return;}
        const d=await r.json();
        if(d.server_time_ms)lastTs=d.server_time_ms;
        d.usage.forEach(u=>{
          recent.unshift(u);
          if(recent.length>MAX_ROWS)recent.pop();
        });
        render(d);
      }catch(e){document.getElementById('status').textContent='err: '+e.message;}
    }
    function render(d){
      document.getElementById('total').textContent=d.total_count;
      const okCount=recent.filter(u=>u.status==='success').length;
      const errCount=recent.filter(u=>u.status!=='success').length;
      const pTok=recent.reduce((s,u)=>s+(u.prompt_tokens||0),0);
      const cTok=recent.reduce((s,u)=>s+(u.completion_tokens||0),0);
      const tenants=new Set(recent.map(u=>u.tenant_id).filter(Boolean));
      document.getElementById('ok').textContent=okCount;
      document.getElementById('errs').textContent=errCount;
      document.getElementById('tok').textContent=pTok+'/'+cTok;
      document.getElementById('tenants').textContent=tenants.size;
      const tbody=document.getElementById('rows');
      if(recent.length===0){tbody.innerHTML='<tr><td colspan="7" class="empty">no traffic yet — fire a /v1/chat/completions call</td></tr>';return;}
      tbody.innerHTML=recent.map((u,i)=>
        '<tr'+(i<d.usage.length?' class="new"':'')+'>'+
        '<td class="dim">'+fmtTime(u.ts)+'</td>'+
        '<td>'+(u.tenant_id||'—')+'</td>'+
        '<td class="tier">'+(u.model||'')+'</td>'+
        '<td>'+fmtTokens(u)+'</td>'+
        '<td>'+u.latency_ms+'</td>'+
        '<td>'+(u.schema_enforced?'✓':'')+'</td>'+
        '<td class="'+(u.status==='success'?'ok':'err')+'">'+(u.status||'')+'</td>'+
        '</tr>'
      ).join('');
      document.getElementById('status').textContent='last poll: '+new Date().toLocaleTimeString()+' · '+recent.length+' rows in view';
    }
  </script>
</body>
</html>`;

if (require.main === module) {
  const app = createApp();
  const port = Number(process.env.PORT || 4444);
  app.listen(port, async () => {
    logger.info('cogos_api_listening', { port });
    // Pre-seed the default package so quota enforcement has something to
    // resolve against on a fresh deploy. Idempotent.
    try {
      await packages.seedIfEmpty();
    } catch (e) {
      logger.error('package_seed_failed_on_boot', { error: e.message });
    }
  });
}

module.exports = { createApp };
