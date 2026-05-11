'use strict';

require('dotenv').config();
const express = require('express');

const logger = require('./logger');
const { bearerAuth, adminAuth } = require('./auth');
const { handleChatCompletions, handleListModels } = require('./openai-compat');
const keys = require('./keys');
const usage = require('./usage');

function createApp() {
  const app = express();
  app.use(express.json({ limit: '512kb' }));
  app.set('trust proxy', 1);

  // ---- Public health (no auth) ----
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', service: 'cogos-api', version: '0.1.0' });
  });

  // ---- OpenAI-compatible surface ----
  app.get('/v1/models', bearerAuth, handleListModels);
  app.post('/v1/chat/completions', bearerAuth, handleChatCompletions);

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

  app.get('/admin/usage', adminAuth, (_req, res) => {
    res.json({ usage: usage.readAll() });
  });

  return app;
}

if (require.main === module) {
  const app = createApp();
  const port = Number(process.env.PORT || 4444);
  app.listen(port, () => logger.info('cogos_api_listening', { port }));
}

module.exports = { createApp };
