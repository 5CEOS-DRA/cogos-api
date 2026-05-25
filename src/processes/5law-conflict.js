'use strict';

/**
 * 5Law Conflict Detection Engine — vendored from 5ceos-platform-internal.
 *
 * VENDORED COPY · source of truth lives at:
 *   5ceos-platform-internal/backend/services/5law/conflictEngine.cjs
 *
 * Pure-function module. Vendored not proxied — one auth boundary, zero
 * RPC latency. Fix upstream and re-copy; never edit in place.
 *
 * 5law Conflict Detection Engine v0.1
 *
 * Implements L3 of docs/5LAW_DOCTRINE_v0.1.md (locked 90a632d6b).
 *
 * Pure-function deterministic engine over the matter graph. No I/O,
 * no LLM, no side effects. Caller provides all data; engine returns
 * ConflictRow[].
 *
 * Five rules per doctrine L3 v0.1 lock:
 *   C_DIRECT_ADVERSITY              ABA Rule 1.7
 *   C_FORMER_CLIENT_SAME_MATTER     ABA Rule 1.9(a)
 *   C_FORMER_CLIENT_CONFIDENTIAL    ABA Rule 1.9(b)
 *   C_IMPUTED_FIRM                  ABA Rule 1.10
 *   C_BUSINESS_INTEREST             ABA Rule 1.8
 *
 * C_POSITIONAL is intentionally NOT in this engine — doctrine defers it
 * to v0.2 state-pack rollout because state-bar opinions diverge on
 * positional conflicts (NY narrower than CA, etc.).
 *
 * Per L3 "How to apply": the engine reads matter graph + parties graph;
 * never reads email body or document content. Email HEADER metadata
 * (From / To / CC / sender domain) may flow into the parties graph
 * upstream — that is a caller concern. This engine only consumes
 * already-resolved Party rows.
 */

const RULE_VERSION = 1;

const RULE_IDS = Object.freeze([
  'C_DIRECT_ADVERSITY',
  'C_FORMER_CLIENT_SAME_MATTER',
  'C_FORMER_CLIENT_CONFIDENTIAL_INFO',
  'C_IMPUTED_FIRM',
  'C_BUSINESS_INTEREST'
]);

const SEVERITY = Object.freeze({
  BLOCKING:        'blocking',
  REQUIRES_SCREEN: 'requires_screen',
  REQUIRES_WAIVER: 'requires_waiver',
  REQUIRES_NOTICE: 'requires_notice'
});

const PARTY_ROLE = Object.freeze({
  CLIENT:           'client',
  FORMER_CLIENT:    'former_client',
  ADVERSE:          'adverse',
  CO_COUNSEL:       'co_counsel',
  OPPOSING_COUNSEL: 'opposing_counsel',
  WITNESS:          'witness',
  EXPERT:           'expert',
  THIRD_PARTY:      'third_party'
});

const MATTER_STATUS = Object.freeze({
  INQUIRY:          'inquiry',
  CONFLICT_CLEARED: 'conflict_cleared',
  ENGAGED:          'engaged',
  ACTIVE:           'active',
  ON_HOLD:          'on_hold',
  CLOSED:           'closed'
});

const ACTIVE_STATUSES = Object.freeze([
  MATTER_STATUS.CONFLICT_CLEARED,
  MATTER_STATUS.ENGAGED,
  MATTER_STATUS.ACTIVE,
  MATTER_STATUS.ON_HOLD
]);

// ────────────────────────────────────────────────────────────────────
// Helpers (exported for tests; deterministic, pure)
// ────────────────────────────────────────────────────────────────────

function normalizeName(name) {
  return String(name || '').toLowerCase().trim().replace(/\s+/g, ' ');
}

function partyIdentifier(party) {
  // contact_id is the strong identity. Falls back to normalized display_name
  // so parties surfaced from email headers without a contact row still match.
  if (party.contact_id) return `contact:${party.contact_id}`;
  const norm = normalizeName(party.display_name);
  return norm ? `name:${norm}` : null;
}

function isPartyActive(party) {
  return !party.effective_to;
}

function isMatterActive(matter) {
  return ACTIVE_STATUSES.includes(matter.status);
}

function isMatterClosed(matter) {
  return matter.status === MATTER_STATUS.CLOSED;
}

function partiesByRoleActive(parties, role) {
  return (parties || []).filter(p => p.party_role === role && isPartyActive(p));
}

function clientOrFormerClient(parties) {
  return (parties || []).filter(p =>
    (p.party_role === PARTY_ROLE.CLIENT || p.party_role === PARTY_ROLE.FORMER_CLIENT)
  );
}

// ────────────────────────────────────────────────────────────────────
// Rule 1.7 — C_DIRECT_ADVERSITY
// ────────────────────────────────────────────────────────────────────

function detectDirectAdversity(input) {
  const { target_matter, target_parties, firm_matters, parties_by_matter_id } = input;

  // Detector fires on intake (inquiry) and on changes to active matters.
  if (!isMatterActive(target_matter) && target_matter.status !== MATTER_STATUS.INQUIRY) {
    return [];
  }

  const adverseInTarget = partiesByRoleActive(target_parties, PARTY_ROLE.ADVERSE);
  if (adverseInTarget.length === 0) return [];

  const rows = [];
  for (const adverse of adverseInTarget) {
    const adverseId = partyIdentifier(adverse);
    if (!adverseId) continue;

    for (const other of firm_matters) {
      if (other.id === target_matter.id) continue;
      if (!isMatterActive(other)) continue;

      const otherClients = partiesByRoleActive(parties_by_matter_id[other.id] || [], PARTY_ROLE.CLIENT);
      const match = otherClients.find(p => partyIdentifier(p) === adverseId);
      if (!match) continue;

      rows.push({
        rule_id: 'C_DIRECT_ADVERSITY',
        rule_version: RULE_VERSION,
        severity: SEVERITY.BLOCKING,
        conflicting_matter_id: other.id,
        parties_involved: [
          { matter_id: target_matter.id, party_id: adverse.id, role: PARTY_ROLE.ADVERSE, identifier: adverseId },
          { matter_id: other.id,         party_id: match.id,   role: PARTY_ROLE.CLIENT,  identifier: adverseId }
        ],
        rationale: `Party "${adverse.display_name}" is adverse in target matter and a current client in active matter ${other.id} (ABA Rule 1.7).`
      });
    }
  }
  return rows;
}

// ────────────────────────────────────────────────────────────────────
// Rule 1.9(a) — C_FORMER_CLIENT_SAME_MATTER
// "Substantially related" proxy for v0.1: same practice_area.
// Doctrine acknowledges this is coarse; refined by state-pack updates.
// ────────────────────────────────────────────────────────────────────

function detectFormerClientSameMatter(input) {
  const { target_matter, target_parties, firm_matters, parties_by_matter_id } = input;

  const adverseInTarget = partiesByRoleActive(target_parties, PARTY_ROLE.ADVERSE);
  if (adverseInTarget.length === 0) return [];

  const rows = [];
  for (const adverse of adverseInTarget) {
    const adverseId = partyIdentifier(adverse);
    if (!adverseId) continue;

    for (const other of firm_matters) {
      if (other.id === target_matter.id) continue;
      if (!isMatterClosed(other)) continue;

      const sameArea = target_matter.practice_area
                       && other.practice_area
                       && target_matter.practice_area === other.practice_area;
      if (!sameArea) continue;

      const otherClients = clientOrFormerClient(parties_by_matter_id[other.id] || []);
      const match = otherClients.find(p => partyIdentifier(p) === adverseId);
      if (!match) continue;

      rows.push({
        rule_id: 'C_FORMER_CLIENT_SAME_MATTER',
        rule_version: RULE_VERSION,
        severity: SEVERITY.REQUIRES_WAIVER,
        conflicting_matter_id: other.id,
        parties_involved: [
          { matter_id: target_matter.id, party_id: adverse.id, role: PARTY_ROLE.ADVERSE,        identifier: adverseId },
          { matter_id: other.id,         party_id: match.id,   role: match.party_role,           identifier: adverseId }
        ],
        rationale: `Party "${adverse.display_name}" is adverse in target matter (practice area "${target_matter.practice_area}") and was a client in closed matter ${other.id} of the same practice area (ABA Rule 1.9(a)).`
      });
    }
  }
  return rows;
}

// ────────────────────────────────────────────────────────────────────
// Rule 1.9(b) — C_FORMER_CLIENT_CONFIDENTIAL_INFO
// The responsible attorney on target matter previously represented the
// adverse party (on any prior matter), implying possession of confidential
// information that may be material.
// ────────────────────────────────────────────────────────────────────

function detectFormerClientConfidential(input) {
  const { target_matter, target_parties, firm_matters, parties_by_matter_id } = input;
  if (!target_matter.responsible_attorney_id) return [];

  const adverseInTarget = partiesByRoleActive(target_parties, PARTY_ROLE.ADVERSE);
  if (adverseInTarget.length === 0) return [];

  const rows = [];
  for (const adverse of adverseInTarget) {
    const adverseId = partyIdentifier(adverse);
    if (!adverseId) continue;

    for (const other of firm_matters) {
      if (other.id === target_matter.id) continue;
      if (other.responsible_attorney_id !== target_matter.responsible_attorney_id) continue;

      const otherClients = clientOrFormerClient(parties_by_matter_id[other.id] || []);
      const match = otherClients.find(p => partyIdentifier(p) === adverseId);
      if (!match) continue;

      rows.push({
        rule_id: 'C_FORMER_CLIENT_CONFIDENTIAL_INFO',
        rule_version: RULE_VERSION,
        severity: SEVERITY.REQUIRES_WAIVER,
        conflicting_matter_id: other.id,
        parties_involved: [
          { matter_id: target_matter.id, party_id: adverse.id, role: PARTY_ROLE.ADVERSE,  identifier: adverseId },
          { matter_id: other.id,         party_id: match.id,   role: match.party_role,     identifier: adverseId },
          { attorney_user_id: target_matter.responsible_attorney_id, kind: 'attorney_prior_representation' }
        ],
        rationale: `Attorney ${target_matter.responsible_attorney_id} (responsible on target) previously represented adverse party "${adverse.display_name}" in matter ${other.id} (ABA Rule 1.9(b)).`
      });
    }
  }
  return rows;
}

// ────────────────────────────────────────────────────────────────────
// Rule 1.10 — C_IMPUTED_FIRM
// Any attorney at the firm has a declared personal interest matching a
// target party. The conflict imputes to the whole firm; curable by
// timely screening under Rule 1.10(a)(2).
//
// Caller provides:
//   firm_attorneys: [{ user_id, ... }]
//   attorney_interests_by_user_id: { [user_id]: party_identifier[] }
//     where party_identifier follows partyIdentifier() format
//     ('contact:<id>' or 'name:<normalized>').
// ────────────────────────────────────────────────────────────────────

function detectImputedFirm(input) {
  const { target_matter, target_parties, firm_attorneys, attorney_interests_by_user_id } = input;
  if (!firm_attorneys || firm_attorneys.length === 0) return [];

  const rows = [];
  for (const attorney of firm_attorneys) {
    const interests = (attorney_interests_by_user_id || {})[attorney.user_id] || [];
    if (interests.length === 0) continue;

    for (const targetParty of target_parties) {
      const partyId = partyIdentifier(targetParty);
      if (!partyId) continue;
      if (!interests.includes(partyId)) continue;

      rows.push({
        rule_id: 'C_IMPUTED_FIRM',
        rule_version: RULE_VERSION,
        severity: SEVERITY.REQUIRES_SCREEN,
        conflicting_matter_id: null,
        parties_involved: [
          { matter_id: target_matter.id, party_id: targetParty.id, role: targetParty.party_role, identifier: partyId },
          { attorney_user_id: attorney.user_id, identifier: partyId, kind: 'personal_interest' }
        ],
        rationale: `Attorney ${attorney.user_id} has a declared personal interest in party "${targetParty.display_name}"; under ABA Rule 1.10 the conflict imputes to the firm. Curable by timely screening under Rule 1.10(a)(2).`
      });
    }
  }
  return rows;
}

// ────────────────────────────────────────────────────────────────────
// Rule 1.8 — C_BUSINESS_INTEREST
// Firm or attorney has a declared material business interest in a
// counterparty.
//
// Caller provides:
//   firm_business_interests: [{ holder_kind, holder_id, party_identifier, is_material }]
//     holder_kind: 'firm' | 'attorney'
//     party_identifier: same shape as partyIdentifier() output
// ────────────────────────────────────────────────────────────────────

function detectBusinessInterest(input) {
  const { target_matter, target_parties, firm_business_interests } = input;
  if (!firm_business_interests || firm_business_interests.length === 0) return [];

  const rows = [];
  for (const interest of firm_business_interests) {
    if (!interest.is_material) continue;

    for (const targetParty of target_parties) {
      const partyId = partyIdentifier(targetParty);
      if (!partyId) continue;
      if (interest.party_identifier !== partyId) continue;

      const holderLabel = interest.holder_kind === 'firm'
        ? 'Firm'
        : `Attorney ${interest.holder_id}`;

      rows.push({
        rule_id: 'C_BUSINESS_INTEREST',
        rule_version: RULE_VERSION,
        severity: SEVERITY.BLOCKING,
        conflicting_matter_id: null,
        parties_involved: [
          { matter_id: target_matter.id, party_id: targetParty.id, role: targetParty.party_role, identifier: partyId },
          { interest_holder_kind: interest.holder_kind, holder_id: interest.holder_id, kind: 'business_interest' }
        ],
        rationale: `${holderLabel} has a material business interest in party "${targetParty.display_name}" (ABA Rule 1.8(a)).`
      });
    }
  }
  return rows;
}

// ────────────────────────────────────────────────────────────────────
// Main dispatcher
// ────────────────────────────────────────────────────────────────────

/**
 * Detect all conflicts for a target matter.
 *
 * @param {object} input
 * @param {object} input.target_matter      The matter being checked (with id, status, practice_area, responsible_attorney_id)
 * @param {Array}  input.target_parties     Party rows for the target matter
 * @param {Array}  [input.firm_matters]     All other matters in the firm graph (active + closed)
 * @param {object} [input.parties_by_matter_id] Map of matter_id → Party[]
 * @param {Array}  [input.firm_attorneys]   [{ user_id }]
 * @param {object} [input.attorney_interests_by_user_id] { [user_id]: party_identifier[] }
 * @param {Array}  [input.firm_business_interests] [{ holder_kind, holder_id, party_identifier, is_material }]
 * @returns {Array} ConflictRow[]
 */
function detectConflicts(input) {
  if (!input || !input.target_matter || !Array.isArray(input.target_parties)) {
    throw new TypeError('detectConflicts: target_matter and target_parties[] are required');
  }

  const safe = {
    target_matter:                  input.target_matter,
    target_parties:                 input.target_parties,
    firm_matters:                   input.firm_matters || [],
    parties_by_matter_id:           input.parties_by_matter_id || {},
    firm_attorneys:                 input.firm_attorneys || [],
    attorney_interests_by_user_id:  input.attorney_interests_by_user_id || {},
    firm_business_interests:        input.firm_business_interests || []
  };

  return [].concat(
    detectDirectAdversity(safe),
    detectFormerClientSameMatter(safe),
    detectFormerClientConfidential(safe),
    detectImputedFirm(safe),
    detectBusinessInterest(safe)
  );
}

module.exports = {
  // main
  detectConflicts,

  // per-rule (exported for tests + targeted re-runs)
  detectDirectAdversity,
  detectFormerClientSameMatter,
  detectFormerClientConfidential,
  detectImputedFirm,
  detectBusinessInterest,

  // constants
  RULE_VERSION,
  RULE_IDS,
  SEVERITY,
  PARTY_ROLE,
  MATTER_STATUS,
  ACTIVE_STATUSES,

  // helpers
  partyIdentifier,
  normalizeName,
  isMatterActive,
  isMatterClosed
};
