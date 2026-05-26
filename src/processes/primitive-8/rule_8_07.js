'use strict';

/**
 * RULE_8_07 — Forecast Persona Absence.
 *
 * Per docs/PRIMITIVE_8_RULE_8_07_FORECAST_PERSONA_ABSENCE_v0.1.md §5:
 *
 *   fired ⇔ (
 *     deal.forecast_category IN {COMMIT, BEST}
 *     AND threshold = resolveThreshold(deal.tenant_id, role, deal.deal_kind) is not null
 *     AND deal.value >= threshold.deal_min
 *     AND emailThreadActive(deal.tenant_id, deal.account_name, role,
 *                           since = now - threshold.quiet_window_days,
 *                           until = now).active = false
 *   )
 *
 *   Severity per §6.3: critical / high / medium based on
 *   (deal.value vs threshold) × (days_quiet vs window thresholds).
 *
 *   v0.1 default window_days is 14, so days_quiet maxes at 14 in a
 *   fresh evaluation — meaning critical / high are unreachable
 *   without tenants overriding their window to 21d / 30d, OR until
 *   v0.2 extends days_quiet with beyond-window lookback. Most v0.1
 *   firings land at 'medium'.
 *
 * Pure function on typed inputs. No DB, no LLM, no wall-clock —
 * `now` is caller-supplied (R8.07-NEVER-3). The DB-touching pieces
 * are siblings outside rules/:
 *   - backend/services/ma-truth/organizational-integrity/thresholdResolver.js
 *   - backend/services/ma-truth/organizational-integrity/emailThreadActivity.js
 *
 * The caller (engine wrapper at step 6) is responsible for:
 *   1. R8.07-PREFLIGHT-1 — coverage gate per tenant
 *   2. Resolving threshold per (tenant, role, deal_kind)
 *   3. Loading activity per (tenant, account, role, window)
 *   4. Calling this function with the assembled inputs
 *   5. Emitting via AnomalyEmitter when fired = true
 *
 * Inputs shape:
 *   {
 *     deal: {
 *       id, tenant_id, account_id, account_name,
 *       value, deal_kind, forecast_category,
 *     },
 *     role,                       // role_category enum value
 *     threshold | null,           // resolveThreshold output
 *     activity,                   // emailThreadActive output
 *   }
 *
 * Output (parent P8 RuleResult contract):
 *   {
 *     rule_key: 'RULE_8_07',
 *     fired: boolean,
 *     severity: 'low' | 'medium' | 'high' | 'critical',
 *     reason: string,
 *     evidence: { ...payload fields per doctrine §6.1... },
 *     evaluated_at: ISO string,
 *   }
 */

const RULE_KEY = 'RULE_8_07';

// Doctrine §5 P-1: only COMMIT and BEST trigger evaluation. Anything
// else (PIPELINE / UPSIDE / unknown / empty) falls into the P-1 branch
// — R8.07-NEVER-4 forbids PIPELINE/UPSIDE from firing without saying
// they share P-1's audit label with everything-else-not-fireable.
const FIREABLE_CATEGORIES = new Set(['COMMIT', 'BEST']);
// Doctrine §5 P-2: TERMINAL states get their own dedicated branch
// per R8.07-NEVER-2. The audit log distinguishes "no signal because
// the deal is done" (P-2) from "no signal because the rep isn't
// confident enough yet" (P-1) — useful when an operator is
// inspecting why this rule didn't fire on a particular deal.
const TERMINAL_CATEGORIES = new Set([
  'CLOSED_WON', 'CLOSED_LOST', 'OMITTED',
]);

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

/**
 * Compute days_quiet given the evaluation `now`, the threshold's
 * window_days, and the activity projector's last_activity_at.
 *
 * Per doctrine §5: when the rule is about to fire, we know
 * `activity.active = false` (no events in window). The projector's
 * `last_activity_at` is therefore null. We report `days_quiet =
 * window_days` as the lower bound — the actual days_quiet is >=
 * window_days but we don't query outside the window in v0.1.
 *
 * When `contacts_considered = 0` (no persona contacts at all),
 * days_quiet is meaningless and we report null. The reason string
 * surfaces this distinction so the operator knows whether the
 * persona is absent vs undeclared.
 */
function computeDaysQuiet({ activity, threshold }) {
  if (!activity || activity.contacts_considered === 0) return null;
  return threshold.quiet_window_days;
}

/**
 * Severity heat per doctrine §6.3.
 *
 *   critical: deal.value >= 5 × threshold AND days_quiet >= 30
 *   high:     deal.value >= 2 × threshold AND days_quiet >= 21
 *   medium:   default firing (deal.value >= threshold AND days_quiet >= window)
 *   low:      never in v0.1
 */
function computeSeverity({ dealValue, threshold, daysQuiet }) {
  if (daysQuiet == null) return 'medium';
  const min = threshold.deal_min;
  if (dealValue >= 5 * min && daysQuiet >= 30) return 'critical';
  if (dealValue >= 2 * min && daysQuiet >= 21) return 'high';
  return 'medium';
}

/**
 * Pure-function evaluator. Caller assembles inputs; this function
 * runs the §5 truth-table and returns the RuleResult.
 */
function evaluate({ inputs, now } = {}) {
  const evaluated_at = toIso(now);
  const deal = inputs?.deal;
  const role = inputs?.role;
  const threshold = inputs?.threshold;
  const activity = inputs?.activity;

  // Defensive null check on the deal — engine wrapper shouldn't
  // reach this with a missing deal, but pure-function discipline
  // prefers returning a structured "not fired" over throwing.
  if (!deal || !role) {
    return {
      rule_key: RULE_KEY,
      fired: false,
      severity: 'low',
      reason: 'Missing deal or role — evaluation skipped.',
      evidence: {},
      evaluated_at,
    };
  }

  const category = String(deal.forecast_category || '').toUpperCase();

  // P-2 / R8.07-NEVER-2: terminal categories (CLOSED_WON / CLOSED_LOST
  // / OMITTED). Checked BEFORE P-1 so terminals get a distinct audit
  // label rather than being lumped into "not fireable."
  if (TERMINAL_CATEGORIES.has(category)) {
    return {
      rule_key: RULE_KEY,
      fired: false,
      severity: 'low',
      reason: `Forecast category '${category}' is excluded from RULE_8_07 evaluation.`,
      evidence: {
        deal_id: deal.id,
        role_expected: role,
        forecast_category: category,
        path: 'P-2',
      },
      evaluated_at,
    };
  }

  // P-1: only COMMIT and BEST. Anything else (including unknown /
  // empty category strings) is skipped.
  if (!FIREABLE_CATEGORIES.has(category)) {
    return {
      rule_key: RULE_KEY,
      fired: false,
      severity: 'low',
      reason: `Forecast category '${category}' is not in {COMMIT, BEST}; rule does not evaluate.`,
      evidence: {
        deal_id: deal.id,
        role_expected: role,
        forecast_category: category,
        path: 'P-1',
      },
      evaluated_at,
    };
  }

  // P-3 / R8.07-UNCONFIGURED-1: no threshold = no fire.
  if (!threshold || threshold.deal_min == null) {
    return {
      rule_key: RULE_KEY,
      fired: false,
      severity: 'low',
      reason: `No threshold configured for role='${role}', deal_kind='${deal.deal_kind || 'ANY'}'.`,
      evidence: {
        deal_id: deal.id,
        role_expected: role,
        deal_kind: deal.deal_kind || null,
        path: 'P-3',
      },
      evaluated_at,
    };
  }

  // P-4: value below threshold.
  const dealValue = Number(deal.value);
  if (!Number.isFinite(dealValue) || dealValue < threshold.deal_min) {
    return {
      rule_key: RULE_KEY,
      fired: false,
      severity: 'low',
      reason: `Deal value ${dealValue} below threshold ${threshold.deal_min} for role='${role}'.`,
      evidence: {
        deal_id: deal.id,
        role_expected: role,
        deal_value: dealValue,
        threshold_used: threshold.deal_min,
        threshold_source: threshold.threshold_source,
        path: 'P-4',
      },
      evaluated_at,
    };
  }

  // P-5: active in window = no fire.
  if (activity && activity.active === true) {
    return {
      rule_key: RULE_KEY,
      fired: false,
      severity: 'low',
      reason: `Role '${role}' has email-thread activity within the ${threshold.quiet_window_days}-day window.`,
      evidence: {
        deal_id: deal.id,
        role_expected: role,
        deal_value: dealValue,
        threshold_used: threshold.deal_min,
        threshold_source: threshold.threshold_source,
        last_thread_activity_at: activity.last_activity_at,
        contacts_considered: activity.contacts_considered,
        window_days: threshold.quiet_window_days,
        path: 'P-5',
      },
      evaluated_at,
    };
  }

  // FIRE. Persona expected, deal qualifies, no activity in window.
  const daysQuiet = computeDaysQuiet({ activity, threshold });
  const severity = computeSeverity({ dealValue, threshold, daysQuiet });

  // Distinct reasons for "role absent" (we have the persona contact,
  // they're just not on the thread) vs "role undeclared" (no
  // deal_target_contacts row at all). Both fire — the second is
  // also operationally a problem the operator needs to know about.
  // Per §15.7 the engine's preflight gate filters out low-curation
  // tenants entirely; if we reach this branch with
  // contacts_considered=0, the tenant IS curated but this
  // particular role isn't populated for this particular account.
  const contactsConsidered = activity?.contacts_considered ?? 0;
  const reason = contactsConsidered === 0
    ? `Role '${role}' is not declared in deal_target_contacts for this account; deal value ${dealValue} qualifies the threshold (${threshold.deal_min}, source=${threshold.threshold_source}).`
    : `Role '${role}' has had no email-thread activity for ${daysQuiet}+ days; deal value ${dealValue} qualifies the threshold (${threshold.deal_min}, source=${threshold.threshold_source}).`;

  // Evidence per doctrine §6.1 AnomalyPayload + parent P8 §M2's
  // four citation arrays. supporting_entities pins the deal + the
  // account + the role; supporting_surfaces names which substrate
  // surfaces the finding cites. contradiction_edges + provenance_chain
  // stay empty for an absence rule.
  const supportingEntities = [];
  if (deal.id) supportingEntities.push(String(deal.id));
  if (deal.account_id) supportingEntities.push(String(deal.account_id));

  return {
    rule_key: RULE_KEY,
    fired: true,
    severity,
    reason,
    evidence: {
      // Parent P8 §M2 citation arrays
      supporting_entities: supportingEntities.sort(),
      supporting_surfaces: ['email_thread', 'forecast'],
      contradiction_edges: [],
      provenance_chain: [],

      // RULE_8_07-specific payload per doctrine §6.1
      deal_id: deal.id || null,
      account_id: deal.account_id || null,
      account_name: deal.account_name || null,
      role_expected: role,
      threshold_used: threshold.deal_min,
      threshold_source: threshold.threshold_source,
      deal_value: dealValue,
      forecast_category: category,
      days_quiet: daysQuiet,
      last_thread_activity_at: activity?.last_activity_at || null,
      contacts_considered: contactsConsidered,
      window_days: threshold.quiet_window_days,
    },
    evaluated_at,
  };
}

module.exports = {
  RULE_KEY,
  evaluate,
  // Exported for engine wrapper + test fixtures.
  FIREABLE_CATEGORIES,
  TERMINAL_CATEGORIES,
};
