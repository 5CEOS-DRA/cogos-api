# SOC 2 readiness — `cogos-api`

Last reviewed: 2026-05-14

This directory is the on-ramp for a SOC 2 Type I audit. It is **not** an attestation, an opinion, or a certificate. It is the connective tissue an auditor expects to find when they walk into the codebase: policy documents, evidence pointers, and a control mapping that ties our existing artifacts (signed images, hash-chained audit log, append-only key store, etc.) to the AICPA Trust Service Criteria (TSC).

If you are an auditor reading this: start with [§2 What's here](#2-whats-here), then [`control-mapping.csv`](./control-mapping.csv). The control mapping is the index. Every cell points at either a file, an HTTP endpoint, or an interview prompt.

If you are a customer's security reviewer reading this: every claim we make in this directory maps to something verifiable in [`SECURITY.md`](../../SECURITY.md) or in the source tree. Nothing here is aspirational copy.

---

## 1. Scope

This directory covers the SOC 2 **Security** principle (the "Common Criteria", `CC*`) as a baseline, plus the four additional Trust Service Categories at a category-summary level:

| TSC category | Scope here |
|---|---|
| Security (Common Criteria, CC1–CC9) | Full per-TSC mapping. This is the audit target. |
| Availability (A1.1–A1.3) | Category-summary row in `control-mapping.csv`. See [`business-continuity-plan.md`](./business-continuity-plan.md). |
| Confidentiality (C1.1–C1.2) | Category-summary row. See [`data-classification-policy.md`](./data-classification-policy.md). |
| Processing Integrity (PI1.1–PI1.5) | Category-summary row. The schema-enforced decoding claim in `SECURITY.md` §3.8 is the primary control. |
| Privacy (P1–P8) | Category-summary row. We are a processor, not a controller. See `data-classification-policy.md`. |

The audit target is **Type I** (point-in-time design assessment), scheduled for engagement kickoff this month. Type II (period-of-coverage operating-effectiveness test) is a future engagement once 6+ months of evidence has accumulated.

---

## 2. What's here

### Policies

| Policy | TSC coverage | Plain-English purpose |
|---|---|---|
| [access-control-policy.md](./access-control-policy.md) | CC6.1, CC6.2, CC6.3 | Who can touch what, how identity is established, how privilege is granted and removed. |
| [change-management-policy.md](./change-management-policy.md) | CC8.1 | How a code change becomes a production artifact, and what's recorded on the way. |
| [incident-response-plan.md](./incident-response-plan.md) | CC7.1, CC7.2, CC7.3, CC7.4 | What happens when something goes wrong, who's notified, how fast. |
| [data-classification-policy.md](./data-classification-policy.md) | C1.1, C1.2, P1.1 | What data classes exist, how each is handled, and which never persists. |
| [risk-assessment.md](./risk-assessment.md) | CC3.1, CC3.2, CC3.3, CC3.4 | Top 10 risks identified, honest residual-risk ranking, mitigations in place. |
| [vendor-management-policy.md](./vendor-management-policy.md) | CC9.2 | Sub-processors used, what they see, review cadence, off-boarding plan. |
| [personnel-security-policy.md](./personnel-security-policy.md) | CC1.1, CC1.2, CC1.3, CC1.4 | Solo-operator caveat handled honestly; what training, screening, and separation-of-duties look like at this stage. |
| [business-continuity-plan.md](./business-continuity-plan.md) | A1.2, A1.3 | Rollback path, audit-log durability, region availability, recovery procedures. |

### Evidence index

[`control-mapping.csv`](./control-mapping.csv) — one row per TSC criterion, columns:

- `tsc_id`
- `tsc_description`
- `our_control` — what we actually do
- `evidence_location` — file path, endpoint, or interview prompt
- `status` — `in-place` / `in-progress` / `not-applicable`
- `last_tested` — date or "TBD pre-audit"

This is the spreadsheet an auditor's tooling consumes. The same data is also served as JSON via [`GET /admin/soc2/control-status`](#3-evidence-endpoints).

---

## 3. Evidence endpoints

Two operator-only HTTP endpoints exist for the auditor to pull a point-in-time snapshot of the live environment. Both require `X-Admin-Key`.

| Endpoint | Purpose |
|---|---|
| `GET /admin/soc2/evidence-bundle` | Returns: current image tag, cosign signature status, last 100 admin-action log entries, audit-chain head row count, anomaly-log row count, list of env var **names** (never values), uptime, revision name. Run once at audit start and once at audit close to demonstrate "no surprise changes during the engagement." |
| `GET /admin/soc2/control-status` | Returns the contents of `control-mapping.csv` as JSON, so the auditor's audit-management tooling can ingest it without parsing CSV. |

Both routes use the existing `adminAuth` middleware in `src/auth.js`. Neither emits secrets, response bodies, or env var values.

---

## 4. What this directory is **not**

- **Not a certification.** We have not yet engaged the auditor. This is the pre-engagement on-ramp.
- **Not marketing copy.** Every policy is written like a vendor template. Read them critically — if a line sounds aspirational, flag it.
- **Not a substitute for the auditor's own evidence collection.** They will request raw access, ask for screen-shares, and verify the live endpoints. This directory makes that quick; it does not replace it.

---

## 5. Review cadence

Each policy in this directory carries `Last reviewed: YYYY-MM-DD` at the top and `Reviewed annually or when control surface changes materially` at the bottom. The control surface changes materially when:

- A new sub-processor is added or removed
- A control implementation changes (e.g. admin auth flow is replaced)
- A risk in `risk-assessment.md` shifts from residual to mitigated, or a new one appears
- An incident response under `incident-response-plan.md` triggered a post-mortem that changes a process

In all such cases, update the relevant policy AND bump the `Last reviewed:` header, AND if the change affects what an auditor would test, add a row to a CHANGELOG section at the bottom of the affected file.

---

## 6. Operator-action-required before audit kickoff

This list is the honest pre-audit punch list. Items here must close before an auditor walks in, OR be explicitly waived in writing.

- [ ] Security-awareness training: complete the operator's annual training and record the date in `personnel-security-policy.md` §4. Currently shown as "TBD, scheduled at SOC 2 engagement kickoff."
- [ ] External penetration test: engage a firm for at least one external pentest. Currently `risk-assessment.md` R-09 is open.
- [ ] Rate limiting on `/v1/*`: ship a basic per-tenant rate limit. Currently `risk-assessment.md` R-03 is open and the anomaly detector is shadow-mode only.
- [ ] Vendor agreement review: confirm Azure, Stripe, GitHub DPAs are countersigned and on file.
- [ ] Cosign signing live: confirm `COSIGN_KEY_FILE` is set on the next deploy so images are signed from that release forward (see `STATE.md` follow-up).
- [ ] Run `GET /admin/soc2/evidence-bundle` and save the JSON to `~/audit-evidence/pre-audit-snapshot-YYYY-MM-DD.json`. This is the "T-0" baseline the auditor compares against at audit close.

---

Reviewed annually or when control surface changes materially.
