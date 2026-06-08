'use strict';

/**
 * Substrate composition · the multi-step workflow primitive.
 *
 * v0.1 (2026-05-26). Locks Canon I1 v0.3's output_hash claim into a
 * SEQUENCE of deterministic process calls with end-to-end receipt
 * chaining. A composition is the smallest substrate object that gives
 * the substrate a "cognitive operating system" shape: not "a function
 * call returns an answer" but "a workflow returns the same answer
 * twice, with a single hash linking every step."
 *
 * The contract:
 *   compose(steps, runStep)
 *
 *   steps:    [{ name, args, refs? }]
 *             Each step names a deterministic process and supplies
 *             its args. Optionally, `refs` substitutes values from a
 *             prior step's result via { argKey: { from_step, path } }.
 *
 *   runStep:  async (name, args) => result
 *             Caller-supplied engine dispatcher. The composer is
 *             engine-agnostic; the caller wires it to the registry it
 *             owns.
 *
 * Returns:
 *   {
 *     composition_version: 1,
 *     results: [step0_result, step1_result, ...],
 *     chain: [
 *       { step, name, output_hash, prev_chain_hash, chain_hash }
 *     ],
 *     compose_hash: <final chain_hash>,
 *   }
 *
 * Determinism contract:
 *   - For a fixed engine version set, calling compose() twice with the
 *     same steps[] produces the same compose_hash, byte for byte.
 *   - Each step's output_hash is computed via canonicalHash() on the
 *     canonicalized step result.
 *   - Chain hash is sha256(prev_chain_hash || step_output_hash). The
 *     prev_chain_hash for step 0 is the canonical hash of the steps[]
 *     array itself — this anchors the chain to the composition's
 *     declared workflow, not just to its outputs. Mutating any step
 *     definition mutates the entire chain.
 *
 * What this module does NOT do:
 *   - Conditionals / loops · v0.1 is linear-sequence only. The substrate
 *     learns to branch in v0.2.
 *   - Concurrent step execution · steps run sequentially because each
 *     step may depend on the prior.
 *   - Cross-tenant composition · the composer is tenant-agnostic;
 *     enforcement happens at the gateway layer that owns auth.
 *   - LLM-anything · this is the deterministic substrate.
 *
 * Failure semantics:
 *   - If runStep throws, compose() rejects with a structured error
 *     identifying which step failed and what the partial chain looks
 *     like up to that point. Partial chains ARE verifiable on their
 *     own — they cover the steps that did run.
 */

const crypto = require('node:crypto');
const { canonicalize, canonicalBytes, canonicalHash } = require('./_canonicalize');

const COMPOSITION_VERSION = 1;

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

// Per CE-I2 of COGOS_COMPOSE_EXTENSIONS_DOCTRINE_v0.1.
// Deterministic placeholder hash for a step that failed under
// on_error:"continue". Depends ONLY on the step's declared name and
// position — NOT on the runtime error. Two runs where step i fails
// the same way produce the same chain_hash for step i. Per CE-HN-4
// the error message MUST NOT be hashed into the chain.
function failureOutputHash(stepIndex, name) {
  return canonicalHash({ failed: true, step: stepIndex, name: String(name) });
}

/**
 * Resolve a dot-path against an object · "rows.0.rule_id" etc.
 * Returns undefined when the path doesn't resolve.
 */
function jsonPath(obj, path) {
  if (path == null || path === '') return obj;
  const parts = String(path).split('.');
  let cur = obj;
  for (const p of parts) {
    if (cur == null) return undefined;
    cur = cur[p];
  }
  return cur;
}

/**
 * Substitute refs from prior step results into a step's args.
 *
 * refs shape: { argKey: { from_step: <int>, path: <dot-path-string> } }
 *
 * Each entry replaces args[argKey] with the value at the named path
 * of the named prior step's result. Path is dot-notation; missing
 * paths produce undefined (which canonicalize drops, so the engine
 * sees an absent field rather than a literal undefined).
 */
function applyRefs(args, refs, priorResults) {
  if (!refs || typeof refs !== 'object') return args;
  // Deep clone via canonicalize so we don't mutate caller's object
  // and so the substitution itself is canonical-bytes stable.
  const out = canonicalize(args || {});
  for (const [argKey, ref] of Object.entries(refs)) {
    if (!ref || typeof ref !== 'object') {
      throw new TypeError(`compose: ref for "${argKey}" must be an object`);
    }
    const idx = ref.from_step;
    if (!Number.isInteger(idx) || idx < 0 || idx >= priorResults.length) {
      throw new TypeError(`compose: ref "${argKey}".from_step (${idx}) is out of range — only ${priorResults.length} step(s) completed`);
    }
    const value = jsonPath(priorResults[idx], ref.path);
    out[argKey] = canonicalize(value);
  }
  return out;
}

/**
 * Validate a steps array · same shape the runStep dispatcher will see.
 * Throws TypeError on malformed shapes.
 */
function validateSteps(steps) {
  if (!Array.isArray(steps)) {
    throw new TypeError('compose: steps must be an array');
  }
  if (steps.length === 0) {
    throw new TypeError('compose: steps must be non-empty');
  }
  for (let i = 0; i < steps.length; i++) {
    const s = steps[i];
    if (!s || typeof s !== 'object') {
      throw new TypeError(`compose: step ${i} must be an object`);
    }
    if (typeof s.name !== 'string' || s.name.length === 0) {
      throw new TypeError(`compose: step ${i}.name must be a non-empty string`);
    }
    if (s.args != null && typeof s.args !== 'object') {
      throw new TypeError(`compose: step ${i}.args must be an object (or absent)`);
    }
    if (s.refs != null && typeof s.refs !== 'object') {
      throw new TypeError(`compose: step ${i}.refs must be an object (or absent)`);
    }
    // CE-Doctrine §5 · per-step failure mode.
    if (s.on_error != null && s.on_error !== 'fail' && s.on_error !== 'continue') {
      throw new TypeError(`compose: step ${i}.on_error must be "fail" or "continue" (or absent)`);
    }
  }
}

/**
 * Main entry · run a composition.
 *
 * @param {Array}    steps    — [{ name, args, refs }]
 * @param {Function} runStep  — async (name, args) => result
 * @returns {Promise<{composition_version, results, chain, compose_hash}>}
 */
async function compose(steps, runStep) {
  if (typeof runStep !== 'function') {
    throw new TypeError('compose: runStep must be a function');
  }
  validateSteps(steps);

  // Anchor the chain to the declared workflow · prev_chain_hash for
  // step 0 is the canonical hash of the steps[] array. Mutating ANY
  // step definition (name, args, ref path, ref source step) propagates
  // through the entire chain. This makes the compose_hash a
  // commitment to "this workflow, on this input set, produced this
  // sequence of outputs."
  const workflowHash = canonicalHash(steps);

  const results       = [];
  const chain         = [];
  const failed_steps  = [];   // CE-I3 · parallel to chain[]; not hashed
  let   prevChainHash = workflowHash;

  for (let i = 0; i < steps.length; i++) {
    const step    = steps[i];
    const onError = step.on_error || 'fail';   // CE §5

    // ── ref-cascade check (CE-I4) ──────────────────────────────────
    // If any ref points at a step whose results[N] is null (failed
    // under continue), short-circuit BEFORE applyRefs.
    let preErr = null;
    if (step.refs && typeof step.refs === 'object') {
      for (const [argKey, ref] of Object.entries(step.refs)) {
        if (ref && Number.isInteger(ref.from_step)
            && ref.from_step >= 0 && ref.from_step < results.length
            && results[ref.from_step] === null) {
          preErr = new TypeError(
            `compose: step ${i} ref "${argKey}".from_step (${ref.from_step}) references a failed step`
          );
          preErr.code = 'REF_DEPENDS_ON_FAILED_STEP';
          break;
        }
      }
    }

    // ── ref resolution ─────────────────────────────────────────────
    let resolvedArgs;
    if (!preErr) {
      try {
        resolvedArgs = applyRefs(step.args || {}, step.refs, results);
      } catch (e) {
        preErr = e;
      }
    }

    if (preErr) {
      if (onError === 'continue') {
        prevChainHash = recordFailure(i, step.name, preErr, 'continue',
          { chain, results, failed_steps }, prevChainHash);
        continue;
      }
      const err = new Error(`compose: step ${i} ref resolution failed · ${preErr.message}`);
      err.failed_step      = i;
      err.partial_chain    = chain.slice();
      err.partial_results  = results.slice();
      throw err;
    }

    // ── step execution ─────────────────────────────────────────────
    let result;
    try {
      result = await runStep(step.name, resolvedArgs);
    } catch (e) {
      if (onError === 'continue') {
        prevChainHash = recordFailure(i, step.name, e, 'continue',
          { chain, results, failed_steps }, prevChainHash);
        continue;
      }
      const err = new Error(`compose: step ${i} (${step.name}) failed · ${e.message}`);
      err.failed_step       = i;
      err.failed_step_name  = step.name;
      err.partial_chain     = chain.slice();
      err.partial_results   = results.slice();
      err.cause             = e;
      throw err;
    }

    // ── success path · BYTE-IDENTICAL to v0.0 (CE-I1) ──────────────
    const canonicalResult = canonicalize(result);
    const stepOutputHash  = canonicalHash(canonicalResult);
    const chainHash       = 'sha256:' + sha256Hex(prevChainHash + stepOutputHash);

    results.push(canonicalResult);
    chain.push({
      step: i,
      name: step.name,
      output_hash:     stepOutputHash,
      prev_chain_hash: prevChainHash,
      chain_hash:      chainHash,
    });
    prevChainHash = chainHash;
  }

  return {
    composition_version: COMPOSITION_VERSION,
    workflow_hash:       workflowHash,
    results,
    chain,
    failed_steps,                       // CE-I3 · always present (empty when no failures)
    compose_hash:        prevChainHash,
  };
}

// Per CE-I2/CE-I3/CE-HN-4. Appends a failure-shaped chain entry +
// a null to results[] + a detail entry to failed_steps[]. Returns the
// new prevChainHash. Caller assigns; we don't mutate caller's local.
function recordFailure(i, name, err, mode, acc, prevChainHash) {
  const outHash   = failureOutputHash(i, name);
  const chainHash = 'sha256:' + sha256Hex(prevChainHash + outHash);
  acc.chain.push({
    step: i,
    name,
    output_hash:     outHash,
    prev_chain_hash: prevChainHash,
    chain_hash:      chainHash,
    status:          'failed',          // CE §6 structural marker
  });
  acc.results.push(null);
  acc.failed_steps.push({
    step: i,
    name,
    on_error: mode,
    error: {
      message: err && err.message ? String(err.message) : 'unknown error',
      code:    err && err.code ? String(err.code) : 'step_execution_failed',
    },
  });
  return chainHash;
}

module.exports = {
  compose,
  COMPOSITION_VERSION,
  // exported for tests + targeted use
  validateSteps,
  applyRefs,
  jsonPath,
};
