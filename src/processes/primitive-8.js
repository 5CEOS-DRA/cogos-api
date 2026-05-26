'use strict';

/**
 * Primitive 8 · Organizational Integrity · Process Library wrapper.
 *
 * Vendored rules · pure-function dispatchers:
 *   - src/processes/primitive-8/rule_8_03.js · Commitment Drift Curve
 *   - src/processes/primitive-8/rule_8_04.js · Contradiction Cluster
 *
 * Upstream source-of-truth lives at
 *   5ceos-platform-internal/backend/services/ma-truth/organizational-integrity/rules/
 *
 * Vendoring contract: rules are byte-equal to upstream (no edits).
 * This wrapper synthesizes the platform's OrganizationalIntegrityEngine
 * behavior WITHOUT the tenant_id requirement — Path B is no-tenant by
 * design, and the tenant_id gate on the platform-side engine is for
 * substrate-audit binding the firing to a deal_id, which is platform-
 * layer concern.
 *
 * Public engine surface for the registry:
 *   evaluate({ inputs, now, enabled_rules? }) → {
 *     rule_version: 1,
 *     evaluated_at: ISO-8601,
 *     rules: [<one entry per rule run>],
 *     fired:     [<rules that fired>],
 *     fired_count, total_rules,
 *   }
 *
 * Inputs shape (composition of both rules' shapes):
 *   {
 *     commitments?:    [{ id, age_days, action_binding, entities, created_at }],
 *     contradictions?: [{ id, surface, occurred_at, cluster_hint?, entities? }],
 *     thresholds?: {
 *       commitment_age_days?:           number,
 *       contradictions_in_window?:      number,
 *       surfaces_involved?:             number,
 *       window_days?:                   number,
 *     },
 *   }
 *
 * Both rules return their own shape; this dispatcher does not flatten
 * them. The customer reads results[N].rule_key + .fired + .evidence
 * directly.
 *
 * Determinism: rules return `evaluated_at` from caller-supplied `now`.
 * The dispatcher sorts results by rule_key so the output array is
 * stable across rule iteration order. canonicalize at the engine layer
 * handles the rest.
 */

const rule_8_03 = require('./primitive-8/rule_8_03');
const rule_8_04 = require('./primitive-8/rule_8_04');

const RULE_VERSION = 1;
const RULE_REGISTRY = {
  RULE_8_03: rule_8_03,
  RULE_8_04: rule_8_04,
};
const RULE_KEYS = Object.freeze(Object.keys(RULE_REGISTRY).sort());

function evaluate({ inputs, now, enabled_rules } = {}) {
  if (!now) {
    throw new TypeError('primitive-8.evaluate: now is required (caller-supplied ISO-8601 or Date)');
  }
  const requested = (Array.isArray(enabled_rules) && enabled_rules.length > 0)
    ? enabled_rules.filter((k) => RULE_REGISTRY[k])
    : RULE_KEYS.slice();

  const results = requested.map((key) => {
    const r = RULE_REGISTRY[key].evaluate({ inputs: inputs || {}, now });
    if (!r || typeof r !== 'object') {
      throw new TypeError(`primitive-8 rule '${key}' returned a non-object`);
    }
    if (r.rule_key !== key) {
      throw new TypeError(`primitive-8 rule '${key}' returned mismatched rule_key='${r.rule_key}'`);
    }
    return r;
  });

  // Stable order
  results.sort((a, b) => a.rule_key.localeCompare(b.rule_key));
  const fired = results.filter((r) => r.fired === true);
  const evaluated_at = (now instanceof Date) ? now.toISOString() : String(now);

  return {
    rule_version: RULE_VERSION,
    evaluated_at,
    rules: results,
    fired,
    fired_count: fired.length,
    total_rules: results.length,
  };
}

module.exports = {
  evaluate,
  RULE_VERSION,
  RULE_KEYS,
};
