'use strict';

/**
 * RULE_8_03 — Commitment Drift Curve.
 *
 * Per docs/PRIMITIVE_8_ORGANIZATIONAL_INTEGRITY_v0.1.md §6 RULE_8_03:
 *
 *   fired ⇔ (
 *     commitment_age_days > T_age              // default 60
 *     AND action_binding IS NULL
 *     AND contradiction_density_in_orbit_trend > 0   // strictly increasing
 *   )
 *
 *   Severity: high.
 *   Defaults: T_age = 60. "density_in_orbit" = count of contradictions
 *   involving the commitment's entities, normalized by window size.
 *
 * Pure function on typed inputs. No DB, no LLM, no wall-clock — `now`
 * is caller-supplied.
 *
 * Inputs shape:
 *   {
 *     commitments: [{
 *       id, age_days, action_binding, entities: [], created_at,
 *     }],
 *     contradictions: [{
 *       id, entities: [], surface, occurred_at,
 *     }],
 *     thresholds?: { age_days?: number },
 *   }
 *
 * Algorithm:
 *   1. Filter commitments where age_days > threshold AND action_binding IS NULL.
 *   2. For each, split the commitment's lifetime into two windows:
 *      [created_at .. midpoint], (midpoint .. now]. Count contradictions
 *      whose entities overlap the commitment's entities in each window.
 *   3. Trend > 0 ⇔ recent_count > older_count.
 *   4. If ANY commitment passes all three predicates, fire.
 *
 * Evidence:
 *   supporting_entities: union of commitment_id + drifted commitment entities
 *   supporting_surfaces: surfaces from orbit contradictions
 *   contradiction_edges: contradiction ids in orbit (recent window)
 *   provenance_chain: empty in v0.1 (canonical_events wiring is route-layer concern)
 *   drift_curve_ids: deterministic curve ids ('drift:' + commitment_id)
 */

const RULE_KEY = 'RULE_8_03';
const DEFAULT_AGE_DAYS = 60;

function toIso(t) {
  if (!t) return null;
  if (t instanceof Date) return t.toISOString();
  return String(t);
}

function tsMs(t) {
  if (!t) return 0;
  if (t instanceof Date) return t.getTime();
  return new Date(String(t)).getTime();
}

function overlaps(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b)) return false;
  if (a.length === 0 || b.length === 0) return false;
  const setA = new Set(a);
  for (const x of b) {
    if (setA.has(x)) return true;
  }
  return false;
}

/**
 * Count contradictions in a half-window that involve any of the
 * commitment's entities. Pure — deterministic ordering by id for the
 * returned id list.
 */
function orbitInWindow({ contradictions, commitmentEntities, lo, hi }) {
  const matched = [];
  for (const c of contradictions) {
    if (!c || !overlaps(c.entities, commitmentEntities)) continue;
    const at = tsMs(c.occurred_at);
    if (at >= lo && at <= hi) matched.push(c);
  }
  // Stable sort by id for deterministic output.
  matched.sort((a, b) => String(a.id).localeCompare(String(b.id)));
  return matched;
}

function evaluate({ inputs, now } = {}) {
  const nowMs = tsMs(now);
  const evaluated_at = toIso(now);

  const commitments = (inputs && Array.isArray(inputs.commitments)) ? inputs.commitments : [];
  const contradictions = (inputs && Array.isArray(inputs.contradictions)) ? inputs.contradictions : [];
  const thresholdAgeDays = (inputs?.thresholds?.age_days != null && Number.isFinite(Number(inputs.thresholds.age_days)))
    ? Number(inputs.thresholds.age_days)
    : DEFAULT_AGE_DAYS;

  const driftedCommitments = [];
  const supportingEntitiesSet = new Set();
  const supportingSurfacesSet = new Set();
  const contradictionEdgesSet = new Set();
  const driftCurveIds = [];

  for (const c of commitments) {
    if (!c) continue;
    if (!(Number(c.age_days) > thresholdAgeDays)) continue;
    if (c.action_binding != null) continue;

    const createdMs = tsMs(c.created_at);
    if (!createdMs || createdMs >= nowMs) continue;

    const midpointMs = createdMs + Math.floor((nowMs - createdMs) / 2);
    const entities = Array.isArray(c.entities) ? c.entities : [];

    const olderWindow = orbitInWindow({
      contradictions,
      commitmentEntities: entities,
      lo: createdMs,
      hi: midpointMs,
    });
    const recentWindow = orbitInWindow({
      contradictions,
      commitmentEntities: entities,
      lo: midpointMs + 1,
      hi: nowMs,
    });

    if (recentWindow.length > olderWindow.length) {
      driftedCommitments.push({ commitment: c, older: olderWindow, recent: recentWindow });
      supportingEntitiesSet.add(c.id);
      for (const e of entities) supportingEntitiesSet.add(e);
      for (const cx of recentWindow) {
        if (cx.surface) supportingSurfacesSet.add(cx.surface);
        if (cx.id) contradictionEdgesSet.add(cx.id);
      }
      driftCurveIds.push(`drift:${c.id}`);
    }
  }

  if (driftedCommitments.length === 0) {
    return {
      rule_key: RULE_KEY,
      fired: false,
      severity: 'low',
      reason: `No commitments crossed the drift threshold (age > ${thresholdAgeDays}d, no action_binding, contradiction orbit trending up).`,
      evidence: {},
      evaluated_at,
    };
  }

  // Stable ordering for deterministic output.
  const supporting_entities = Array.from(supportingEntitiesSet).sort();
  const supporting_surfaces = Array.from(supportingSurfacesSet).sort();
  const contradiction_edges = Array.from(contradictionEdgesSet).sort();
  driftCurveIds.sort();

  return {
    rule_key: RULE_KEY,
    fired: true,
    severity: 'high',
    reason: `${driftedCommitments.length} commitment(s) past age threshold (${thresholdAgeDays}d) with no action_binding and rising contradiction density in orbit.`,
    evidence: {
      drifted_commitment_count: driftedCommitments.length,
      threshold_age_days: thresholdAgeDays,
      supporting_entities,
      supporting_surfaces,
      contradiction_edges,
      provenance_chain: [],
      drift_curve_ids: driftCurveIds,
    },
    evaluated_at,
  };
}

module.exports = { RULE_KEY, evaluate, DEFAULT_AGE_DAYS };
