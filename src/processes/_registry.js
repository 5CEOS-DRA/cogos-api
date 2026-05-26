'use strict';

/**
 * Process registry · single source of truth for which engines are
 * callable through the substrate.
 *
 * Used by:
 *   - src/routers/process.js · single-invocation POST /v1/process/<name>
 *   - src/routers/compose.js · multi-step POST /v1/compose
 *
 * Both routers MUST consume from this registry so the surface area
 * stays unified — a process either exists for both surfaces or neither.
 *
 * Each entry:
 *   id            · the public process name (matches the URL slug)
 *   model_id      · the usage-record `model` field
 *   route         · the single-invocation URL (for the catalog)
 *   version       · engine version emitted in receipts
 *   doctrine      · the doctrine anchor for this engine
 *   description   · human-readable summary (used by GET /v1/process)
 *   pricing_tier  · 1 | 2 | 3 · the per-call cost band
 *   pricing_usd   · per-call dollar amount · DRAFT until operator-confirmed
 *                   against real customer conversations (see Process Library
 *                   pricing memo 2026-05-26).
 *   pricing_label · short tier descriptor surfaced in catalog UIs
 *   rule_ids      · optional · for rule-firing engines
 *   wrapBody      · optional · pre-engine body injection (e.g. stored state)
 *   engine        · the runStep dispatcher · async (args) => result
 *
 * To add a new process: drop one entry here. Both routers light up; the
 * CLI catalog (`cogos process`) and REPL `/processes` pick up the tier
 * badge automatically.
 *
 * Pricing draft policy: `pricing_draft: true` rides every catalog entry
 * until the operator confirms the dollar amounts. Public-facing surfaces
 * MUST surface the "draft" label so we don't lock numbers in prematurely.
 */

const reconciler = require('./iolta-reconciler');
const conflictEngine = require('./5law-conflict');
const primitive8 = require('./primitive-8');
const stateStore = require('../key-state-store');

const REGISTRY = {
  'iolta-reconcile': {
    id: 'iolta-reconcile',
    model_id: 'process:iolta-reconcile-v1',
    route: '/v1/process/iolta-reconcile',
    version: reconciler.RECONCILER_VERSION,
    doctrine: '5law L4 · ABA Rule 1.15',
    description: 'Three-way IOLTA trust account reconciliation. Bank vs trust-ledger vs per-client sub-ledger, with commingling detection. Pure function, no LLM.',
    pricing_tier: 1,
    pricing_usd:  0.05,
    pricing_label: 'Tier 1 · pure rule engine',
    engine: (body) => {
      const result = reconciler.reconcileThreeWay(body);
      return { ...result, reconciler_version: reconciler.RECONCILER_VERSION };
    },
  },

  '5law-conflict-check': {
    id: '5law-conflict-check',
    model_id: 'process:5law-conflict-check-v1',
    route: '/v1/process/5law-conflict-check',
    version: conflictEngine.RULE_VERSION,
    doctrine: '5law L3 · ABA Rules 1.7 + 1.8 + 1.9 + 1.10',
    description: 'Five-rule conflict detection over a supplied matter graph: direct adversity, former-client-same-matter, former-client-confidential, imputed firm, business interest. Pure function, no LLM, ABA-cited.',
    pricing_tier: 1,
    pricing_usd:  0.05,
    pricing_label: 'Tier 1 · pure rule engine',
    rule_ids: conflictEngine.RULE_IDS,
    // wrapBody · optional pre-engine injection from per-key state.
    // When body.use_stored_state is true, pull firm_matters +
    // parties_by_matter_id from the customer's stored journal instead
    // of requiring them inline. Lets a customer journal-in their firm
    // graph once and run every subsequent check against it.
    wrapBody: (req, body) => {
      if (!body || !body.use_stored_state) return body;
      const tenant_id = req.apiKey && req.apiKey.tenant_id;
      const key_id    = req.apiKey && req.apiKey.id;
      if (!tenant_id || !key_id) return body;  // shouldn't happen post-customerAuth; defense in depth
      const stored = stateStore.conflictInputForKey({ tenant_id, key_id });
      return {
        ...body,
        firm_matters:         stored.firm_matters,
        parties_by_matter_id: stored.parties_by_matter_id,
        // pass through state_version + state_hash so the receipt can
        // commit to which point-in-time of the journal was used
        _state_version: stored.state_version,
        _state_hash:    stored.state_hash,
      };
    },
    engine: (body) => {
      const rows = conflictEngine.detectConflicts(body);
      const out = { rows, rule_version: conflictEngine.RULE_VERSION, rule_ids_checked: conflictEngine.RULE_IDS };
      if (body._state_version != null) out.state_version = body._state_version;
      if (body._state_hash != null)    out.state_hash    = body._state_hash;
      return out;
    },
  },

  'primitive-8-integrity-check': {
    id: 'primitive-8-integrity-check',
    model_id: 'process:primitive-8-integrity-check-v1',
    route: '/v1/process/primitive-8-integrity-check',
    version: primitive8.RULE_VERSION,
    doctrine: 'Primitive 8 · Organizational Integrity v0.1',
    description: 'Two-rule organizational integrity check over supplied commitments + contradictions: RULE_8_03 (commitment drift curve) + RULE_8_04 (contradiction cluster). Pure function, no LLM, doctrine-cited.',
    pricing_tier: 1,
    pricing_usd:  0.05,
    pricing_label: 'Tier 1 · pure rule engine',
    rule_ids: primitive8.RULE_KEYS,
    engine: (body) => {
      // Caller supplies `now` for deterministic windowing. If absent,
      // server clock is used — but that breaks bitwise stability across
      // calls, so we surface it on the response so the caller can pin
      // it next time for reproducible audit.
      const now = body && body.now ? body.now : new Date().toISOString();
      const result = primitive8.evaluate({
        inputs: body || {},
        now,
        enabled_rules: body && Array.isArray(body.enabled_rules) ? body.enabled_rules : undefined,
      });
      return { ...result, server_supplied_now: body && body.now ? null : now };
    },
  },
};

function listProcesses() {
  return Object.values(REGISTRY).map((p) => {
    const out = {
      id: p.id,
      version: p.version,
      status: 'available',
      doctrine: p.doctrine,
      endpoint: p.route,
      method: 'POST',
      model_id: p.model_id,
      description: p.description,
    };
    if (p.pricing_tier != null) {
      out.pricing_tier  = p.pricing_tier;
      out.pricing_usd   = p.pricing_usd;
      out.pricing_label = p.pricing_label;
      out.pricing_draft = true;
    }
    if (p.rule_ids) out.rule_ids = p.rule_ids;
    return out;
  });
}

function getProcess(name) {
  return REGISTRY[name];
}

/**
 * runStep adapter for the compose() primitive.
 * Throws if the name is not in the registry — composition rejects
 * with the structured "step N failed" shape inside compose().
 */
async function runStep(name, args) {
  const p = REGISTRY[name];
  if (!p) {
    throw new Error(`unknown process: ${name}`);
  }
  return p.engine(args);
}

module.exports = {
  REGISTRY,
  listProcesses,
  getProcess,
  runStep,
};
