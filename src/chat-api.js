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
// Upstream selection:
//   UPSTREAM_PROVIDER=ollama  (default) — calls <UPSTREAM_URL>/api/chat
//   UPSTREAM_PROVIDER=openai            — calls <UPSTREAM_URL>/chat/completions
//                                         with Bearer <UPSTREAM_API_KEY>
// Schema enforcement: if response_format.type === 'json_schema', we forward
// the schema. Ollama 0.5+ uses the `format` field (token-level grammar);
// OpenAI-compatible providers (Fireworks/Together/DeepInfra) use the
// `response_format: json_schema` field they already accept.

const crypto = require('crypto');
const axios = require('axios');
const logger = require('./logger');
const usage = require('./usage');
const packages = require('./packages');
const cryptoSign = require('./crypto-sign');

// Send a JSON response with X-Cogos-Signature when an HMAC secret is
// available on the bound API key. Customer can verify by recomputing
// HMAC-SHA256(hmac_secret, raw_response_body) on their side.
function sendSignedJson(req, res, body) {
  const hmacSecret = req.apiKey && req.apiKey.hmac_secret;
  const bodyBytes = JSON.stringify(body);
  if (hmacSecret) {
    const sig = cryptoSign.sign(hmacSecret, bodyBytes);
    res.set('X-Cogos-Signature', sig);
    res.set('X-Cogos-Signature-Algo', 'hmac-sha256');
  }
  res.type('application/json').send(bodyBytes);
}

const UPSTREAM_PROVIDER = () => (process.env.UPSTREAM_PROVIDER || 'ollama').toLowerCase();
const UPSTREAM_URL = () =>
  process.env.UPSTREAM_URL || process.env.OLLAMA_URL || 'http://localhost:11434';
const UPSTREAM_API_KEY = () => process.env.UPSTREAM_API_KEY || '';
const DEFAULT_MODEL = () => process.env.DEFAULT_MODEL || 'qwen2.5:3b-instruct';
const TIMEOUT = () => Number(process.env.INFERENCE_TIMEOUT_MS || 60_000);

// Tier aliases — caller specifies a CogOS tier; env vars override the
// concrete model name per upstream provider.
const TIER_TO_MODEL = () => ({
  'cogos-tier-b': process.env.UPSTREAM_MODEL_TIER_B || 'qwen2.5:3b-instruct',
  'cogos-tier-a': process.env.UPSTREAM_MODEL_TIER_A || 'qwen2.5:7b-instruct',
});

function resolveModel(requested) {
  if (!requested) return DEFAULT_MODEL();
  const tiers = TIER_TO_MODEL();
  return tiers[requested] || requested;
}

// Count requests this customer has made in the current billing cycle
// (calendar month, UTC). Linear scan of usage.jsonl is fine while
// volumes are modest; swap for a counter file or external store
// once a single tenant routinely makes >100K calls/mo.
function countCurrentCycleRequests(keyId) {
  if (!keyId) return 0;
  const cycleStartMs = Date.parse(packages.currentBillingCycleStart());
  let n = 0;
  for (const u of usage.readAll()) {
    if (u.key_id !== keyId) continue;
    if (u.status !== 'success') continue;
    const ts = Date.parse(u.ts);
    if (Number.isFinite(ts) && ts >= cycleStartMs) n += 1;
  }
  return n;
}

// Enforce package quota + tier allowlist BEFORE forwarding upstream.
// Runs after bearerAuth (which populates req.apiKey).
function enforcePackage(req, res, next) {
  const apiKey = req.apiKey;
  if (!apiKey) {
    return res.status(401).json({
      error: { message: 'Unauthorized', type: 'invalid_api_key' },
    });
  }

  // Find the package that applies to this key. If no packages exist at
  // all (unseeded fresh deploy), allow the call but log a warning — the
  // operator hasn't finished setup.
  const pkg = packages.resolveForKey(apiKey);
  if (!pkg) {
    logger.warn('enforce_package_no_packages_configured', { key_id: apiKey.id });
    return next();
  }

  // Tier allowlist: if the customer requested a known tier alias and
  // the package doesn't grant it, refuse with 403. Raw model identifiers
  // pass through (operators issue keys with raw-model latitude knowingly).
  const requested = (req.body && req.body.model) || null;
  if (requested && /^cogos-tier-[a-z]$/.test(requested)) {
    if (!pkg.allowed_model_tiers.includes(requested)) {
      logger.info('enforce_package_tier_denied', {
        key_id: apiKey.id, package_id: pkg.id, requested,
      });
      return res.status(403).json({
        error: {
          message: `Model "${requested}" is not included in package "${pkg.display_name}". Available tiers: ${pkg.allowed_model_tiers.join(', ')}.`,
          type: 'model_tier_denied',
          package_id: pkg.id,
        },
      });
    }
  }

  // Quota: 0 disables enforcement (unlimited package).
  if (pkg.monthly_request_quota > 0) {
    const used = countCurrentCycleRequests(apiKey.id);
    const remaining = Math.max(0, pkg.monthly_request_quota - used);
    res.set('X-Cogos-Quota-Limit', String(pkg.monthly_request_quota));
    res.set('X-Cogos-Quota-Remaining', String(remaining));
    res.set('X-Cogos-Quota-Reset', packages.nextBillingCycleStart());
    if (remaining <= 0) {
      logger.info('enforce_package_quota_exceeded', {
        key_id: apiKey.id, package_id: pkg.id, used, limit: pkg.monthly_request_quota,
      });
      return res.status(429).json({
        error: {
          message: `Monthly request quota exceeded for package "${pkg.display_name}" (${used} / ${pkg.monthly_request_quota}). Resets ${packages.nextBillingCycleStart()}.`,
          type: 'quota_exceeded',
          package_id: pkg.id,
          limit: pkg.monthly_request_quota,
          used,
          reset: packages.nextBillingCycleStart(),
        },
      });
    }
  }

  // Stash the package on the request so the handler can record it.
  req.cogosPackage = pkg;
  next();
}

function extractSchema(responseFormat) {
  if (!responseFormat || typeof responseFormat !== 'object') return null;
  if (responseFormat.type !== 'json_schema') return null;
  const js = responseFormat.json_schema;
  if (!js || !js.schema) return null;
  return js.schema;
}

// Cheap-but-stable fingerprint of the request messages. Concatenates
// role|content for every message and sha256s the result. The point is
// to give the customer a way to spot duplicate-prompt traffic in their
// audit log WITHOUT us having to store the prompt itself. For sealed
// rows this fingerprint rides inside the envelope along with the
// request_id (so even the fingerprint is not vendor-readable). For
// bearer-only rows it stays in cleartext — the bearer customer already
// chose the legacy posture.
function promptFingerprint(messages) {
  if (!Array.isArray(messages) || messages.length === 0) return null;
  const buf = messages
    .map((m) => `${(m && m.role) || ''}|${(m && m.content) || ''}`)
    .join('\n');
  const h = crypto.createHash('sha256').update(buf).digest('hex');
  return `sha256:${h}`;
}

// Extract the schema "name" (json_schema.name) when present. Useful in
// the audit row so customers can group rows by schema family; rides
// inside the seal envelope alongside the fingerprint.
function schemaName(responseFormat) {
  if (!responseFormat || typeof responseFormat !== 'object') return null;
  if (responseFormat.type !== 'json_schema') return null;
  const js = responseFormat.json_schema;
  if (!js || typeof js.name !== 'string') return null;
  return js.name;
}

async function callOllama({ url, model, messages, schema, temperature, max_tokens, seed }) {
  const payload = {
    model,
    messages: messages.map((m) => ({ role: m.role, content: m.content })),
    stream: false,
    options: {
      temperature,
      num_predict: typeof max_tokens === 'number' ? max_tokens : -1,
      seed: typeof seed === 'number' ? seed : undefined,
    },
  };
  if (schema) payload.format = schema;
  const res = await axios.post(`${url}/api/chat`, payload, {
    timeout: TIMEOUT(),
    validateStatus: () => true,
  });
  const parsed =
    res.status >= 200 && res.status < 300
      ? {
          content: (res.data && res.data.message && res.data.message.content) || '',
          prompt_tokens: (res.data && res.data.prompt_eval_count) || 0,
          completion_tokens: (res.data && res.data.eval_count) || 0,
          finish_reason: (res.data && res.data.done_reason) || 'stop',
        }
      : null;
  return { status: res.status, data: res.data, parsed };
}

async function callOpenAI({ url, key, model, messages, schema, temperature, max_tokens, seed }) {
  const payload = {
    model,
    messages: messages.map((m) => ({ role: m.role, content: m.content })),
    temperature,
    stream: false,
  };
  if (typeof max_tokens === 'number' && max_tokens > 0) payload.max_tokens = max_tokens;
  if (typeof seed === 'number') payload.seed = seed;
  if (schema) {
    payload.response_format = {
      type: 'json_schema',
      json_schema: { name: 'cogos_output', strict: true, schema },
    };
  }
  const headers = { 'Content-Type': 'application/json' };
  if (key) headers['Authorization'] = `Bearer ${key}`;
  const fullUrl = /\/chat\/completions$/.test(url)
    ? url
    : `${url.replace(/\/$/, '')}/chat/completions`;
  const res = await axios.post(fullUrl, payload, {
    headers,
    timeout: TIMEOUT(),
    validateStatus: () => true,
  });
  const choice = res.data && res.data.choices && res.data.choices[0];
  const parsed =
    res.status >= 200 && res.status < 300
      ? {
          content: (choice && choice.message && choice.message.content) || '',
          prompt_tokens: (res.data && res.data.usage && res.data.usage.prompt_tokens) || 0,
          completion_tokens: (res.data && res.data.usage && res.data.usage.completion_tokens) || 0,
          finish_reason: (choice && choice.finish_reason) || 'stop',
        }
      : null;
  return { status: res.status, data: res.data, parsed };
}

async function callUpstream(args) {
  return UPSTREAM_PROVIDER() === 'openai' ? callOpenAI(args) : callOllama(args);
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

  const start = Date.now();
  let upstream;
  try {
    upstream = await callUpstream({
      url: UPSTREAM_URL(),
      key: UPSTREAM_API_KEY(),
      model,
      messages,
      schema,
      temperature: typeof body.temperature === 'number' ? body.temperature : 0,
      max_tokens: body.max_tokens,
      seed: body.seed,
    });
  } catch (e) {
    const latency = Date.now() - start;
    logger.error('upstream_request_failed', {
      provider: UPSTREAM_PROVIDER(),
      error: e.message,
      latency,
    });
    usage.record({
      key_id: req.apiKey && req.apiKey.id,
      tenant_id: req.apiKey && req.apiKey.tenant_id,
      // app_id partitions the audit chain. Falls back to null →
      // resolveAppId() in usage.js turns that into '_default' so a
      // pre-multi-app key still records a concrete app on disk.
      app_id: req.apiKey && req.apiKey.app_id,
      model,
      latency_ms: latency,
      status: 'upstream_error',
      schema_enforced: Boolean(schema),
      request_id: requestId,
      prompt_fingerprint: promptFingerprint(messages),
      schema_name: schemaName(body.response_format),
      // Customer-sealed audit: if this customer issued an ed25519 key
      // they got an x25519 pubkey, which we hold to seal each row's
      // content fields. Bearer-only customers don't have one and the
      // row stays cleartext (sealed:false) — explicit, not silent.
      x25519_pubkey_pem: req.apiKey && req.apiKey.x25519_pubkey_pem,
    });
    return res.status(502).json({
      error: { message: 'Upstream inference engine unreachable', type: 'upstream_error' },
    });
  }
  const latencyMs = Date.now() - start;

  if (!upstream.parsed) {
    logger.warn('upstream_non_2xx', {
      provider: UPSTREAM_PROVIDER(),
      status: upstream.status,
      body: upstream.data,
    });
    usage.record({
      key_id: req.apiKey && req.apiKey.id,
      tenant_id: req.apiKey && req.apiKey.tenant_id,
      app_id: req.apiKey && req.apiKey.app_id,
      model,
      latency_ms: latencyMs,
      status: 'upstream_' + upstream.status,
      schema_enforced: Boolean(schema),
      request_id: requestId,
      prompt_fingerprint: promptFingerprint(messages),
      schema_name: schemaName(body.response_format),
      x25519_pubkey_pem: req.apiKey && req.apiKey.x25519_pubkey_pem,
    });
    return res.status(502).json({
      error: {
        message: 'Inference engine returned ' + upstream.status,
        type: 'upstream_error',
      },
    });
  }

  const { content, prompt_tokens, completion_tokens, finish_reason } = upstream.parsed;

  res.set('X-Cogos-Model', model);
  res.set('X-Cogos-Latency-Ms', String(latencyMs));
  res.set('X-Cogos-Schema-Enforced', schema ? '1' : '0');
  res.set('X-Cogos-Request-Id', requestId);

  usage.record({
    key_id: req.apiKey && req.apiKey.id,
    tenant_id: req.apiKey && req.apiKey.tenant_id,
    app_id: req.apiKey && req.apiKey.app_id,
    model,
    prompt_tokens,
    completion_tokens,
    latency_ms: latencyMs,
    status: 'success',
    schema_enforced: Boolean(schema),
    request_id: requestId,
    prompt_fingerprint: promptFingerprint(messages),
    schema_name: schemaName(body.response_format),
    x25519_pubkey_pem: req.apiKey && req.apiKey.x25519_pubkey_pem,
  });

  sendSignedJson(req, res, {
    id: requestId,
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [
      {
        index: 0,
        message: { role: 'assistant', content },
        finish_reason,
      },
    ],
    usage: {
      prompt_tokens,
      completion_tokens,
      total_tokens: prompt_tokens + completion_tokens,
    },
    cogos: {
      schema_enforced: Boolean(schema),
      latency_ms: latencyMs,
      request_id: requestId,
    },
  });
}

async function handleListModels(req, res) {
  // Customer-facing tier aliases. Honest about what each resolves to.
  const tiers = TIER_TO_MODEL();
  const now = Math.floor(Date.now() / 1000);
  sendSignedJson(req, res, {
    object: 'list',
    data: [
      { id: 'cogos-tier-b', object: 'model', created: now, owned_by: 'cogos',
        cogos_resolves_to: tiers['cogos-tier-b'] },
      { id: 'cogos-tier-a', object: 'model', created: now, owned_by: 'cogos',
        cogos_resolves_to: tiers['cogos-tier-a'] },
    ],
  });
}

module.exports = {
  handleChatCompletions,
  handleListModels,
  enforcePackage,
  resolveModel,
  TIER_TO_MODEL,
  // exported for tests
  _internal: { callOllama, callOpenAI, extractSchema, countCurrentCycleRequests },
};
