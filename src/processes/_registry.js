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
 *   id          · the public process name (matches the URL slug)
 *   model_id    · the usage-record `model` field
 *   route       · the single-invocation URL (for the catalog)
 *   version     · engine version emitted in receipts
 *   doctrine    · the doctrine anchor for this engine
 *   description · human-readable summary (used by GET /v1/process)
 *   rule_ids    · optional · for rule-firing engines
 *   engine      · the runStep dispatcher · async (args) => result
 *
 * To add a new process: drop one entry here. Both routers light up.
 */

const reconciler = require('./iolta-reconciler');
const conflictEngine = require('./5law-conflict');

const REGISTRY = {
  'iolta-reconcile': {
    id: 'iolta-reconcile',
    model_id: 'process:iolta-reconcile-v1',
    route: '/v1/process/iolta-reconcile',
    version: reconciler.RECONCILER_VERSION,
    doctrine: '5law L4 · ABA Rule 1.15',
    description: 'Three-way IOLTA trust account reconciliation. Bank vs trust-ledger vs per-client sub-ledger, with commingling detection. Pure function, no LLM.',
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
    rule_ids: conflictEngine.RULE_IDS,
    engine: (body) => {
      const rows = conflictEngine.detectConflicts(body);
      return { rows, rule_version: conflictEngine.RULE_VERSION, rule_ids_checked: conflictEngine.RULE_IDS };
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
