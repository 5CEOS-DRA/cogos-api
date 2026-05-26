'use strict';

/**
 * VENDORED COPY from 5ceos-platform-internal/backend/services/ma-truth/
 * detectors/index.js. The detectors are pure regex engines with no
 * external dependencies, so vendoring is byte-equal (no require-path
 * edits needed). Fix upstream and re-copy via scripts/check-vendored.sh.
 *
 * M&A Truth Room — W2 detector pack (cogOS deterministic).
 *
 * Four pure-function detectors scan finding title + description text for
 * the signals named in the LOCKED W2 spec:
 *   - IP exposure         (patents / TMs / trade secrets / licenses)
 *   - Data residency      (GDPR / CCPA / cross-border / data sovereignty)
 *   - Regulatory exposure (gov investigation / consent decree / sanctions)
 *   - Litigation          (pending / threatened / class action / arbitration)
 *
 * Doctrine §7 / feedback_5ceos_prod_artifact_only: NO LLM in scoring path.
 * Each detector is a pure function over the finding text. Mirrors the
 * `dimensionMapper.js` pattern from backend/src/services/divergence/.
 *
 * Each detector emits at most ONE row per finding (the first-matching
 * sub-rule wins, like dimensionMapper). The output is an applicability
 * record suitable for INSERT into ma_truth_detector_applicability.
 *
 * Rule taxonomy is locked. Adding a new sub-rule requires a fresh
 * MAPPER_VERSION bump and a regression test against fixture findings.
 */

const MAPPER_VERSION = 'ma_truth_w2_detectors.v1';

// ──────────────────────────────────────────────────────────────────────
// Detector 1: IP exposure
// ──────────────────────────────────────────────────────────────────────
const IP_RULES = [
  {
    rule_id: 'IP_INFRINGEMENT_ACTIVE',
    severity: 'critical',
    rule_text: 'Active IP infringement allegation, patent assertion, or trade-secret misappropriation referenced in the finding.',
    re: /\b(patent\s+infringement|trade[\-\s]secret\s+misappropriation|copyright\s+infringement|cease\s+and\s+desist|infringing|misappropriated\s+trade\s+secrets?)\b/i,
  },
  {
    rule_id: 'IP_LICENSE_NON_TRANSFERABLE',
    severity: 'material',
    rule_text: 'License terms that may not survive change-of-control: non-transferable, non-assignable, or change-of-control restriction in IP licenses.',
    re: /\b(non[\-\s]transferable|non[\-\s]assignable|may\s+not\s+be\s+assigned|change\s+of\s+control|require[s]?\s+consent\s+for\s+(?:assignment|transfer))\b/i,
  },
  {
    rule_id: 'IP_JOINT_OWNERSHIP',
    severity: 'material',
    rule_text: 'Joint or shared IP ownership clause — typically blocks a clean acquirer post-close exploitation right without renegotiation.',
    re: /\b(joint\s+ownership|jointly\s+owned|shared\s+IP|work[\-\s]for[\-\s]hire\s+(?:not|absent|missing)|invention\s+assignment\s+(?:missing|absent))\b/i,
  },
  {
    rule_id: 'IP_GENERAL_REFERENCE',
    severity: 'minor',
    rule_text: 'General IP reference present in finding (patent, trademark, copyright, trade secret) without specific exposure trigger.',
    re: /\b(patent|trademark|copyright|trade\s+secret|intellectual\s+property|IP\s+(?:portfolio|rights|assignment))\b/i,
  },
];

// ──────────────────────────────────────────────────────────────────────
// Detector 2: Data residency / sovereignty
// ──────────────────────────────────────────────────────────────────────
const DATA_RESIDENCY_RULES = [
  {
    rule_id: 'DATA_RESIDENCY_CROSS_BORDER_REGULATED',
    severity: 'critical',
    rule_text: 'Cross-border personal-data transfer subject to GDPR / CCPA / China DSL — requires SCCs or DPA, structurally affects M&A integration plan.',
    re: /\b(GDPR|CCPA|CPRA|cross[\-\s]border\s+(?:data\s+)?transfer|standard\s+contractual\s+clauses?|SCC[s]?\b|data\s+protection\s+agreement|DPA\b|Schrems\s+II|China\s+DSL|PIPL|LGPD)\b/i,
  },
  {
    rule_id: 'DATA_RESIDENCY_LOCALIZATION_REQUIRED',
    severity: 'material',
    rule_text: 'Data localization requirement: data must be stored in a specific country or region per regulatory mandate.',
    re: /\b(data\s+(?:localization|residency|sovereignty)|store[d]?\s+in\s+(?:EU|US|China|Russia|India)|onshore\s+(?:storage|data)|local\s+data\s+center\s+required)\b/i,
  },
  {
    rule_id: 'DATA_PII_HANDLING_AT_SCALE',
    severity: 'material',
    rule_text: 'Material PII / PHI handling at scale referenced in finding — diligence must confirm encryption-at-rest, access controls, and breach notification SLA.',
    re: /\b(personal\s+(?:identifiable\s+)?information|PII\b|PHI\b|HIPAA|protected\s+health\s+information|personal\s+data\s+(?:processing|handling|records?))\b/i,
  },
  {
    rule_id: 'DATA_GENERAL_REFERENCE',
    severity: 'minor',
    rule_text: 'General data-handling reference in finding without specific residency / localization trigger.',
    re: /\b(data\s+protection|privacy\s+(?:policy|law|regulation)|data\s+breach\s+notification)\b/i,
  },
];

// ──────────────────────────────────────────────────────────────────────
// Detector 3: Regulatory exposure
// ──────────────────────────────────────────────────────────────────────
const REGULATORY_RULES = [
  {
    rule_id: 'REG_ENFORCEMENT_ACTIVE',
    severity: 'critical',
    rule_text: 'Active regulatory enforcement: ongoing investigation, consent decree, settlement order, or compliance monitor.',
    re: /\b(consent\s+decree|deferred\s+prosecution\s+agreement|DPA\s+(?:with|by)\s+(?:DOJ|SEC)|under\s+investigation|active\s+investigation|monitor[s]?hip|compliance\s+monitor|enforcement\s+action|cease[\-\s]and[\-\s]desist\s+order)\b/i,
  },
  {
    rule_id: 'REG_FCPA_SANCTIONS_ANTITRUST',
    severity: 'critical',
    rule_text: 'FCPA / OFAC / antitrust exposure specifically referenced — these categories of regulatory exposure are structurally hard to remediate and typically priced into a deal.',
    re: /\b(FCPA|Foreign\s+Corrupt\s+Practices\s+Act|OFAC|economic\s+sanctions|anti[\-\s]?trust|antitrust|Sherman\s+Act|Clayton\s+Act|HSR\s+filing|Hart[\-\s]Scott[\-\s]Rodino|EU\s+(?:Competition|Commission))\b/i,
  },
  {
    rule_id: 'REG_SUBPOENA_INQUIRY',
    severity: 'material',
    rule_text: 'Subpoena, CID (civil investigative demand), or formal regulatory inquiry referenced — pre-enforcement signal that diligence must confirm scope of.',
    re: /\b(subpoena[ed]?|civil\s+investigative\s+demand|CID\s+(?:from|by)|grand\s+jury|formal\s+(?:inquiry|request)|document\s+preservation\s+(?:notice|order)|hold\s+notice)\b/i,
  },
  {
    rule_id: 'REG_AGENCY_REFERENCE',
    severity: 'minor',
    rule_text: 'Regulatory-agency reference present in finding (SEC, FDA, EPA, FTC, EEOC, IRS, etc.) without specific enforcement trigger.',
    re: /\b(SEC\b|FDA\b|EPA\b|FTC\b|EEOC|IRS\b|OSHA|CFPB|NLRB|state\s+attorney\s+general)\b/i,
  },
];

// ──────────────────────────────────────────────────────────────────────
// Detector 4: Litigation (pending / threatened)
// ──────────────────────────────────────────────────────────────────────
const LITIGATION_RULES = [
  {
    rule_id: 'LIT_ACTIVE_CASE',
    severity: 'critical',
    rule_text: 'Active named litigation: docket number / court / named-case reference.',
    re: /\b(?:v\.|vs\.|versus)\s+[A-Z][A-Za-z0-9&.,\-\s]{2,40}|\bcase\s+no\.?\s+\d|docket\s+(?:no\.?|number)|filed\s+(?:a\s+)?(?:complaint|suit|lawsuit|action)\s+(?:in|against)|pending\s+(?:lawsuit|litigation|action|case|matter)/i,
  },
  {
    rule_id: 'LIT_CLASS_ACTION',
    severity: 'critical',
    rule_text: 'Class action / putative class / mass tort referenced — typical magnitude orders larger than single-plaintiff matters.',
    re: /\b(class\s+action|putative\s+class|certify\s+(?:a\s+)?class|class\s+certification|mass\s+tort|multidistrict\s+litigation|MDL\b)\b/i,
  },
  {
    rule_id: 'LIT_THREATENED',
    severity: 'material',
    rule_text: 'Threatened / pre-suit posture: demand letter, threatened litigation, or pre-litigation hold.',
    re: /\b(demand\s+letter|threatened\s+(?:lawsuit|litigation|to\s+sue|legal\s+action)|cease\s+and\s+desist|notice\s+of\s+(?:claim|intent)|pre[\-\s]litigation\s+(?:hold|notice)|tender\s+of\s+defense)\b/i,
  },
  {
    rule_id: 'LIT_ARBITRATION_MEDIATION',
    severity: 'material',
    rule_text: 'Arbitration or mediation referenced — alternate-dispute-resolution forum signals an active or imminent dispute outside court.',
    re: /\b(arbitration\s+(?:demand|notice|award|hearing)|mediation\s+(?:demand|notice)|AAA\s+arbitration|JAMS\s+arbitration|FINRA\s+arbitration|ICC\s+arbitration)\b/i,
  },
];

const DETECTORS = [
  { detector: 'ma_w2_ip_exposure',         rules: IP_RULES },
  { detector: 'ma_w2_data_residency',      rules: DATA_RESIDENCY_RULES },
  { detector: 'ma_w2_regulatory_exposure', rules: REGULATORY_RULES },
  { detector: 'ma_w2_litigation',          rules: LITIGATION_RULES },
];

/**
 * Build a finding-text view that all detectors scan. Pure.
 */
function findingText(finding) {
  if (!finding) return '';
  return [
    finding.title,
    finding.description,
    finding.claim_a,
    finding.claim_b,
    finding.follow_up_question,
  ].filter(Boolean).join(' \n ');
}

/**
 * Run one detector's ordered sub-rules against finding text.
 * Returns the first-matching rule output, or null.
 */
function runOneDetector(text, detectorEntry) {
  for (const rule of detectorEntry.rules) {
    const match = rule.re.exec(text);
    if (match) {
      return {
        detector: detectorEntry.detector,
        severity: rule.severity,
        rule_id: rule.rule_id,
        rule_text: rule.rule_text,
        evidence_signals: [{ matched: match[0].slice(0, 120), index: match.index }],
      };
    }
  }
  return null;
}

/**
 * Run all detectors against a finding. Returns array of applicability rows
 * (one per detector that fired).
 */
function analyzeFinding(finding) {
  const text = findingText(finding);
  if (!text) return [];
  const out = [];
  for (const d of DETECTORS) {
    const hit = runOneDetector(text, d);
    if (hit) out.push(hit);
  }
  return out;
}

module.exports = {
  MAPPER_VERSION,
  DETECTORS,
  IP_RULES,
  DATA_RESIDENCY_RULES,
  REGULATORY_RULES,
  LITIGATION_RULES,
  findingText,
  runOneDetector,
  analyzeFinding,
};
