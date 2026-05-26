'use strict';

/**
 * RULE_8_04 — Contradiction Cluster.
 *
 * Per docs/PRIMITIVE_8_ORGANIZATIONAL_INTEGRITY_v0.1.md §6 RULE_8_04:
 *
 *   fired ⇔ (
 *     contradictions_in_window > N    // default N=12
 *     AND surfaces_involved >= M      // default M=3
 *     AND window_days <= T            // default T=14
 *   )
 *
 *   Severity: high. Bumps to critical when surfaces_involved >= 5.
 *
 * Pure function on typed inputs. No DB, no LLM, no wall-clock.
 *
 * Inputs shape:
 *   {
 *     contradictions: [{
 *       id, surface, occurred_at, cluster_hint?,
 *     }],
 *     thresholds?: {
 *       contradictions_in_window?: number,    // N
 *       surfaces_involved?: number,           // M
 *       window_days?: number,                 // T
 *     },
 *   }
 *
 * Algorithm:
 *   1. Bucket contradictions into a sliding window ending at `now`,
 *      width = T days.
 *   2. If window count > N AND distinct surface count >= M → fire.
 *   3. Cluster id = stable hash of (window_start, window_end). For v0.1
 *      we use the simplest possible identifier: 'cluster:<window_start_iso>'.
 *
 * Evidence:
 *   supporting_entities: empty (cluster is about surfaces, not entities)
 *   supporting_surfaces: distinct surfaces in the cluster window
 *   contradiction_edges: contradiction ids in window
 *   provenance_chain: empty in v0.1
 *   cluster_ids: synthetic identifier
 *   surfaces_involved: count for engine's heat/score amplification logic
 */

const RULE_KEY = 'RULE_8_04';
const DEFAULT_THRESHOLDS = Object.freeze({
  contradictions_in_window: 12,
  surfaces_involved: 3,
  window_days: 14,
});
const CRITICAL_SURFACES_THRESHOLD = 5;

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

function evaluate({ inputs, now } = {}) {
  const nowMs = tsMs(now);
  const evaluated_at = toIso(now);

  const contradictions = (inputs && Array.isArray(inputs.contradictions)) ? inputs.contradictions : [];

  const thresholds = {
    contradictions_in_window: Number.isFinite(Number(inputs?.thresholds?.contradictions_in_window))
      ? Number(inputs.thresholds.contradictions_in_window) : DEFAULT_THRESHOLDS.contradictions_in_window,
    surfaces_involved: Number.isFinite(Number(inputs?.thresholds?.surfaces_involved))
      ? Number(inputs.thresholds.surfaces_involved) : DEFAULT_THRESHOLDS.surfaces_involved,
    window_days: Number.isFinite(Number(inputs?.thresholds?.window_days))
      ? Number(inputs.thresholds.window_days) : DEFAULT_THRESHOLDS.window_days,
  };

  const windowMs = thresholds.window_days * 24 * 60 * 60 * 1000;
  const windowStartMs = nowMs - windowMs;

  // Collect contradictions in window (deterministic id sort).
  const inWindow = [];
  for (const c of contradictions) {
    if (!c || !c.id) continue;
    const at = tsMs(c.occurred_at);
    if (at >= windowStartMs && at <= nowMs) inWindow.push(c);
  }
  inWindow.sort((a, b) => String(a.id).localeCompare(String(b.id)));

  const distinctSurfaces = new Set();
  for (const c of inWindow) {
    if (c.surface) distinctSurfaces.add(c.surface);
  }

  const count = inWindow.length;
  const surfacesInvolved = distinctSurfaces.size;
  const fired = count > thresholds.contradictions_in_window && surfacesInvolved >= thresholds.surfaces_involved;

  if (!fired) {
    return {
      rule_key: RULE_KEY,
      fired: false,
      severity: 'low',
      reason: `Contradiction cluster threshold not met (count=${count}, surfaces=${surfacesInvolved}, window=${thresholds.window_days}d).`,
      evidence: {},
      evaluated_at,
    };
  }

  const severity = surfacesInvolved >= CRITICAL_SURFACES_THRESHOLD ? 'critical' : 'high';
  const supporting_surfaces = Array.from(distinctSurfaces).sort();
  const contradiction_edges = inWindow.map((c) => c.id);
  const cluster_id = `cluster:${new Date(windowStartMs).toISOString()}`;

  return {
    rule_key: RULE_KEY,
    fired: true,
    severity,
    reason: `${count} contradictions across ${surfacesInvolved} surfaces in the last ${thresholds.window_days}d (threshold: > ${thresholds.contradictions_in_window} & >= ${thresholds.surfaces_involved} surfaces).`,
    evidence: {
      supporting_entities: [],
      supporting_surfaces,
      contradiction_edges,
      provenance_chain: [],
      cluster_ids: [cluster_id],
      surfaces_involved: surfacesInvolved,    // engine reads this for heat/score amplification
      contradictions_in_window: count,
      window_days: thresholds.window_days,
    },
    evaluated_at,
  };
}

module.exports = { RULE_KEY, evaluate, DEFAULT_THRESHOLDS };
