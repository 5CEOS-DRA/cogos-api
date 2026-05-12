'use strict';

// Chat-completions handler — accepts the standard /v1/chat/completions
// request shape that established SDK clients already speak.
//
// Input shape (standard chat-completions request):
//   { model, messages, temperature?, max_tokens?, response_format?, seed?, ... }
//
// Output shape (standard chat-completions response):
//   { id, object: "chat.completion", created, model, choices[], usage{} }
//
// Schema enforcement: if response_format.type === 'json_schema', we pass
// the schema through to Ollama's `format` field (Ollama 0.5+ does
// grammar-constrained decoding). This is the CogOS substrate guarantee.

const crypto = require('crypto');
const axios = require('axios');
const logger = require('./logger');
const usage = require('./usage');

const OLLAMA_URL = () => process.env.OLLAMA_URL || 'http://localhost:11434';
const DEFAULT_MODEL = () => process.env.DEFAULT_MODEL || 'qwen2.5:3b-instruct';
const TIMEOUT = () => Number(process.env.INFERENCE_TIMEOUT_MS || 60_000);

// Tier aliases — caller can specify a CogOS tier instead of a raw model.
const TIER_TO_MODEL = {
  'cogos-tier-b': 'qwen2.5:3b-instruct',
  'cogos-tier-a': 'qwen2.5:7b-instruct',
};

function resolveModel(requested) {
  if (!requested) return DEFAULT_MODEL();
  return TIER_TO_MODEL[requested] || requested;
}

function extractSchema(responseFormat) {
  if (!responseFormat || typeof responseFormat !== 'object') return null;
  if (responseFormat.type !== 'json_schema') return null;
  const js = responseFormat.json_schema;
  if (!js || !js.schema) return null;
  return js.schema;
}

async function handleChatCompletions(req, res) {
  const body = req.body || {};
  const messages = body.messages;
  if (!Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({
      error: { message: '`messages` array required', type: 'invalid_request_error' },
    });
  }

  const model = resolveModel(body.model);
  const schema = extractSchema(body.response_format);
  const requestId = 'chatcmpl-' + crypto.randomBytes(12).toString('hex');

  // Translate to Ollama /api/chat.
  const ollamaPayload = {
    model,
    messages: messages.map((m) => ({ role: m.role, content: m.content })),
    stream: false,
    options: {
      temperature: typeof body.temperature === 'number' ? body.temperature : 0,
      num_predict: typeof body.max_tokens === 'number' ? body.max_tokens : -1,
      seed: typeof body.seed === 'number' ? body.seed : undefined,
    },
  };
  if (schema) ollamaPayload.format = schema;

  const start = Date.now();
  let ollamaRes;
  try {
    ollamaRes = await axios.post(`${OLLAMA_URL()}/api/chat`, ollamaPayload, {
      timeout: TIMEOUT(),
      validateStatus: () => true,
    });
  } catch (e) {
    const latency = Date.now() - start;
    logger.error('ollama_request_failed', { error: e.message, latency });
    usage.record({
      key_id: req.apiKey && req.apiKey.id,
      tenant_id: req.apiKey && req.apiKey.tenant_id,
      model,
      latency_ms: latency,
      status: 'upstream_error',
      schema_enforced: Boolean(schema),
      request_id: requestId,
    });
    return res.status(502).json({
      error: { message: 'Upstream inference engine unreachable', type: 'upstream_error' },
    });
  }
  const latencyMs = Date.now() - start;

  if (ollamaRes.status < 200 || ollamaRes.status >= 300) {
    logger.warn('ollama_non_2xx', { status: ollamaRes.status, body: ollamaRes.data });
    usage.record({
      key_id: req.apiKey && req.apiKey.id,
      tenant_id: req.apiKey && req.apiKey.tenant_id,
      model,
      latency_ms: latencyMs,
      status: 'upstream_' + ollamaRes.status,
      schema_enforced: Boolean(schema),
      request_id: requestId,
    });
    return res.status(502).json({
      error: { message: 'Inference engine returned ' + ollamaRes.status, type: 'upstream_error' },
    });
  }

  const data = ollamaRes.data || {};
  const content = (data.message && data.message.content) || '';
  const promptTokens = data.prompt_eval_count || 0;
  const completionTokens = data.eval_count || 0;

  // Set standard usage headers so clients can do their own accounting
  // without parsing the body. CogOS-specific headers prefixed with X-Cogos-.
  res.set('X-Cogos-Model', model);
  res.set('X-Cogos-Latency-Ms', String(latencyMs));
  res.set('X-Cogos-Schema-Enforced', schema ? '1' : '0');
  res.set('X-Cogos-Request-Id', requestId);

  usage.record({
    key_id: req.apiKey && req.apiKey.id,
    tenant_id: req.apiKey && req.apiKey.tenant_id,
    model,
    prompt_tokens: promptTokens,
    completion_tokens: completionTokens,
    latency_ms: latencyMs,
    status: 'success',
    schema_enforced: Boolean(schema),
    request_id: requestId,
  });

  res.json({
    id: requestId,
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [{
      index: 0,
      message: { role: 'assistant', content },
      finish_reason: data.done_reason || 'stop',
    }],
    usage: {
      prompt_tokens: promptTokens,
      completion_tokens: completionTokens,
      total_tokens: promptTokens + completionTokens,
    },
    // CogOS substrate field — extension, ignored by standard clients
    cogos: {
      schema_enforced: Boolean(schema),
      latency_ms: latencyMs,
      request_id: requestId,
    },
  });
}

// GET /v1/models — standard model list, drawn from Ollama's tags
async function handleListModels(_req, res) {
  try {
    const tagsRes = await axios.get(`${OLLAMA_URL()}/api/tags`, { timeout: 10_000 });
    const models = (tagsRes.data && tagsRes.data.models) || [];
    res.json({
      object: 'list',
      data: models.map((m) => ({
        id: m.name,
        object: 'model',
        created: Math.floor(new Date(m.modified_at || Date.now()).getTime() / 1000),
        owned_by: 'cogos',
      })),
    });
  } catch (e) {
    logger.error('list_models_failed', { error: e.message });
    res.status(502).json({ error: { message: 'Cannot reach inference engine' } });
  }
}

module.exports = { handleChatCompletions, handleListModels, resolveModel, TIER_TO_MODEL };
