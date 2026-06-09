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
const maDetectors = require('./ma-detectors');
const intFactorMod = require('./int-factor');
const graphReachMod = require('./graph-reachability');
const arcLoadMod = require('./arc-load-task');
const arcSolverMod = require('./arc-basic-solver');
const arcGraphSolverMod = require('./arc-graph-solver');
const arcHybridSolverMod = require('./arc-hybrid-solver');
const arcEvalMod = require('./arc-evaluate');
const arcSweepMod = require('./arc-sweep');
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

  'ma-truth-detectors': {
    id: 'ma-truth-detectors',
    model_id: 'process:ma-truth-detectors-v1',
    route: '/v1/process/ma-truth-detectors',
    version: maDetectors.MAPPER_VERSION,
    doctrine: 'M&A Truth Doctrine · cogOS deterministic detector pack',
    description: 'Four-detector regex pack over M&A finding text: IP-restriction triggers (assignment/CoC), data-residency (GDPR/CCPA/sovereignty), regulatory (HIPAA/PCI/SOC), litigation (active suits/IP/employment). Pure regex, no LLM. First-matching rule wins per detector.',
    pricing_tier: 1,
    pricing_usd:  0.05,
    pricing_label: 'Tier 1 · pure rule engine',
    rule_ids: ['ma_w2_ip_exposure', 'ma_w2_data_residency', 'ma_w2_regulatory_exposure', 'ma_w2_litigation'],
    engine: (body) => {
      // Accept either { finding: {...} } or { findings: [...] }.
      const findings = Array.isArray(body && body.findings) ? body.findings
                     : (body && body.finding ? [body.finding] : []);
      if (findings.length === 0) {
        return { findings: [], rows: [], mapper_version: maDetectors.MAPPER_VERSION };
      }
      const rows = [];
      const annotated = findings.map((f, idx) => {
        const fires = maDetectors.analyzeFinding(f);
        for (const fire of fires) {
          rows.push({ ...fire, finding_index: idx, finding_id: f.id || null });
        }
        return { index: idx, id: f.id || null, fire_count: fires.length };
      });
      return {
        findings: annotated,
        rows,
        total_findings: findings.length,
        total_firings: rows.length,
        mapper_version: maDetectors.MAPPER_VERSION,
      };
    },
  },

  'int-factor': {
    // Per COGOS_PROCESS_DETERMINISM_DOCTRINE_v0.1 §8 · pinned-script
    // Python engine. The script's sha256 ships in every response under
    // `script_hash` and is committed into output_hash → chain_hash.
    // Stdlib-only Python; no third-party imports (PD-HN-8).
    id: 'int-factor',
    model_id: 'process:int-factor-v1',
    route: '/v1/process/int-factor',
    version: intFactorMod.PROCESS_VERSION,
    doctrine: 'PROCESS_DETERMINISM §8 · pinned-script Python',
    description: 'Integer prime factorization in [2, 1e12]. Stdlib Python, byte-pinned script, returns {n, factors, is_prime, now, script_hash}. Requires args.now (ISO-8601) per PD-I2.',
    pricing_tier: 1,
    pricing_usd:  0.05,
    pricing_label: 'Tier 1 · pinned Python · pure',
    engine: (body) => intFactorMod.intFactor(body),
  },

  'basic-graph-reachability': {
    // Per COGOS_PROCESS_DETERMINISM_DOCTRINE_v0.1 §8.8 · pure-JS BFS.
    // Sorted-adjacency + set-once predecessor map gives lex-smallest
    // shortest path; determinism by construction (no subprocess, no
    // RNG, no clock synthesis). Bounds: nodes ∈ [1, 1000], edges ≤ 10000.
    id: 'basic-graph-reachability',
    model_id: 'process:basic-graph-reachability-v1',
    route: '/v1/process/basic-graph-reachability',
    version: graphReachMod.PROCESS_VERSION,
    doctrine: 'PROCESS_DETERMINISM §8.8 · pure-JS combinatorial engine',
    description: 'BFS shortest-path over an undirected graph. Pure JS, no subprocess, deterministic tie-break (lex-smallest path). Returns {reachable, distance, path, nodes, start, target, now, script_hash?}. Requires args.now (ISO-8601) per PD-I2.',
    pricing_tier: 1,
    pricing_usd:  0.05,
    pricing_label: 'Tier 1 · pure JS combinatorial',
    engine: (body) => graphReachMod.basicGraphReachability(body),
  },

  'arc-load-task': {
    // Per COGOS_PROCESS_DETERMINISM_DOCTRINE_v0.1 §10.2 · loads an ARC
    // task JSON from a path-jailed directory inside the cogos-api repo.
    id: 'arc-load-task',
    model_id: 'process:arc-load-task-v1',
    route: '/v1/process/arc-load-task',
    version: arcLoadMod.PROCESS_VERSION,
    doctrine: 'PROCESS_DETERMINISM §10.2 · ARC task loader',
    description: 'Loads an ARC task JSON file (train + test grid pairs) from a path-jailed substrate directory. Returns {task_id, train, test, train_count, test_count, now, task_dir_resolved}. Requires args.task_id (regex-safe) + args.now (ISO-8601) per PD-I2.',
    pricing_tier: 1,
    pricing_usd:  0.05,
    pricing_label: 'Tier 1 · pure JS · path-jailed loader',
    engine: (body) => arcLoadMod.arcLoadTask(body),
  },

  'arc-basic-solver': {
    // Per COGOS_PROCESS_DETERMINISM_DOCTRINE_v0.1 §10.3 · v0.1 trivial
    // transformations (identity, constant_fill). NOT a real ARC solver.
    id: 'arc-basic-solver',
    model_id: 'process:arc-basic-solver-v1',
    route: '/v1/process/arc-basic-solver',
    version: arcSolverMod.PROCESS_VERSION,
    doctrine: 'PROCESS_DETERMINISM §10.3 · ARC v0.1 trivial solver',
    description: 'Applies a trivial deterministic transformation to a grid. v0.1 strategies: identity (output = input) and constant_fill (output = same shape, color color). NOT a pattern-matching solver. Requires args.strategy + args.input_grid + args.now per PD-I2 (and args.color for constant_fill).',
    pricing_tier: 1,
    pricing_usd:  0.05,
    pricing_label: 'Tier 1 · pure JS · v0.1 trivial solver',
    engine: (body) => arcSolverMod.arcBasicSolver(body),
  },

  'arc-graph-solver': {
    // Per COGOS_PROCESS_DETERMINISM_DOCTRINE_v0.1 §10.8 (closes PD-W9) ·
    // 4-connected-component segmentation + simple transforms. Shares the
    // §8.8 BFS discipline with basic-graph-reachability at the code level
    // (does NOT call it across the registry; per-cell HTTP would be O(R*C)).
    id: 'arc-graph-solver',
    model_id: 'process:arc-graph-solver-v1',
    route: '/v1/process/arc-graph-solver',
    version: arcGraphSolverMod.PROCESS_VERSION,
    doctrine: 'PROCESS_DETERMINISM §10.8 · ARC object-segmentation solver',
    description: '4-connected-component segmentation of an ARC grid plus simple transforms. v0.1 strategies: segment (predicted=input + objects[] enumerated) and keep_largest_object (predicted=largest object kept, rest set to background). Requires args.strategy + args.input_grid + args.now per PD-I2. Optional args.background (int 0..9, default 0). Pure JS, no DSL search.',
    pricing_tier: 1,
    pricing_usd:  0.05,
    pricing_label: 'Tier 1 · pure JS · ARC graph solver',
    engine: (body) => arcGraphSolverMod.arcGraphSolver(body),
  },

  'arc-hybrid-solver': {
    // Per COGOS_PROCESS_DETERMINISM_DOCTRINE_v0.1 §10.9 (partially closes
    // PD-W15) · uses §10.8 segmentation stats to pick a constant-fill
    // color WITHOUT taking color from the caller. "Hybrid" =
    // structure-detection feeds value-selection; no LLM, no ensemble.
    id: 'arc-hybrid-solver',
    model_id: 'process:arc-hybrid-solver-v1',
    route: '/v1/process/arc-hybrid-solver',
    version: arcHybridSolverMod.PROCESS_VERSION,
    doctrine: 'PROCESS_DETERMINISM §10.9 · ARC segmentation-informed solver',
    description: 'Segmentation-informed ARC solver. Runs 4-connected component segmentation, then picks a fill color from object stats. v0.1 strategies: majority_color_fill (most-common non-background color over object cells), largest_object_color_fill (color of the largest object), auto (object_count∈{0,1}→identity, ≥2→majority_color_fill). Requires args.strategy + args.input_grid + args.now per PD-I2. Optional args.background (int 0..9, default 0). args.color is forbidden (PD-I13). Pure JS, no DSL search.',
    pricing_tier: 1,
    pricing_usd:  0.05,
    pricing_label: 'Tier 1 · pure JS · ARC hybrid solver',
    engine: (body) => arcHybridSolverMod.arcHybridSolver(body),
  },

  'arc-sweep': {
    // Per COGOS_PROCESS_DETERMINISM_DOCTRINE_v0.1 §10.7 PD-W11 closure ·
    // pure-JS multi-task batch evaluator. Takes a list of (solver,
    // strategy) combos + optional task_ids/task_dir, returns the full
    // results matrix + per-task-best + aggregate rollup. The substrate's
    // honest "conductor score" against the v0.1 strategy set lives here.
    id: 'arc-sweep',
    model_id: 'process:arc-sweep-v1',
    route: '/v1/process/arc-sweep',
    version: arcSweepMod.PROCESS_VERSION,
    doctrine: 'PROCESS_DETERMINISM §10.7 PD-W11 · ARC multi-task batch evaluator',
    description: 'Deterministic multi-task ARC batch evaluator. Iterates a list of (solver, strategy) combos across an ARC corpus directory (default: substrate-shipped data/arc-tasks), returns a sorted results matrix + per-task-best picks + aggregate rollup (total_runs, scored_runs, successes, average_accuracy, tasks_with_perfect_solve). Requires args.combos (non-empty array of {solver, strategy}) + args.now (ISO-8601) per PD-I2. Optional args.task_ids[], args.task_dir, args.pair_index (default 0). Pure JS, byte-deterministic on canonicalized input.',
    pricing_tier: 1,
    pricing_usd:  0.05,
    pricing_label: 'Tier 1 · pure JS · ARC sweep evaluator',
    engine: (body) => arcSweepMod.arcSweep(body),
  },

  'arc-evaluate': {
    // Per COGOS_PROCESS_DETERMINISM_DOCTRINE_v0.1 §10.4 · cell-wise
    // grid comparison. Returns honest accuracy + dims_match.
    id: 'arc-evaluate',
    model_id: 'process:arc-evaluate-v1',
    route: '/v1/process/arc-evaluate',
    version: arcEvalMod.PROCESS_VERSION,
    doctrine: 'PROCESS_DETERMINISM §10.4 · ARC grid evaluator',
    description: 'Cell-wise comparison of a predicted grid against an expected grid. Returns {correct, cells_total, cells_correct, accuracy, dims_match, ...}. Dim mismatch yields accuracy=0. Requires args.predicted + args.expected + args.now per PD-I2.',
    pricing_tier: 1,
    pricing_usd:  0.05,
    pricing_label: 'Tier 1 · pure JS · ARC evaluator',
    engine: (body) => arcEvalMod.arcEvaluate(body),
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
      // Per COGOS_PROCESS_DETERMINISM_DOCTRINE_v0.1 PD-I2 + PD-HN-1:
      // time anchors come from input, never the server clock. Refuse
      // structurally when body.now is absent. The prior fallback
      // (new Date().toISOString() + server_supplied_now informational
      // field) was the affordance that broke compose_hash determinism
      // for every plan that omitted `now`.
      if (!body || !body.now) {
        const err = new Error(
          'primitive-8 requires body.now (ISO-8601 string); the substrate ' +
          'refuses to synthesize from server clock per PROCESS_DETERMINISM PD-I2.'
        );
        err.code = 'missing_now';
        throw err;
      }
      return primitive8.evaluate({
        inputs: body,
        now: body.now,
        enabled_rules: Array.isArray(body.enabled_rules) ? body.enabled_rules : undefined,
      });
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
