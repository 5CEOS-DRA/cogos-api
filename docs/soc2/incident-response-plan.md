# Incident Response Plan

Last reviewed: 2026-05-14

This plan covers **TSC CC7.1** (system component vulnerabilities are identified), **CC7.2** (system component anomalies are analyzed), **CC7.3** (response and recovery from identified incidents), and **CC7.4** (incident response evaluation and improvement).

The audience is a SOC 2 auditor evaluating design and a future on-call operator. The plan is intentionally short and operational, not procedural-theater.

---

## 1. Scope

This plan applies to security incidents affecting:

- The production `cogos-api` gateway and its data
- Customer keys, audit logs, or any artifact stored on our substrate
- The deployment pipeline (image registry, signing keys, Container App revisions)
- The sub-processor surface (Azure, Stripe, GitHub) when an incident there affects us

It does **not** apply to general operational issues (slow inference latency, model output dissatisfaction, billing disputes) — those route through standard support at `support@5ceos.com` without the `[SECURITY]` prefix.

---

## 2. Definitions

| Term | Meaning |
|---|---|
| Incident | Any confirmed or strongly suspected event that violates the security claims in `SECURITY.md` §3 or exposes customer data outside its intended boundary |
| Vulnerability | A code defect, configuration drift, or design flaw that could lead to an incident if exploited; not yet exploited |
| Disclosure | A report of a vulnerability or incident received via the `[SECURITY]` channel in `SECURITY.md` §1 |
| Anomaly | A signal from `src/anomaly.js` that some traffic pattern crossed a threshold; a possible precursor to an incident, not an incident itself |

---

## 3. Severity scale

We use **CVSS v4.0**, mapped to High/Medium/Low for human communication:

| Severity | CVSS v4.0 | Examples |
|---|---|---|
| Critical | 9.0–10.0 | Live customer key disclosure, audit-chain forgery, signing-key compromise |
| High | 7.0–8.9 | Tenant-isolation break, admin-auth bypass, persistent prompt-injection that exfiltrates customer-supplied schemas |
| Medium | 4.0–6.9 | Information disclosure (non-secret), bypass of a non-critical control |
| Low | 0.1–3.9 | Defense-in-depth gaps that don't compromise a primary control |

The numeric vector is the source of truth; the bucket label is for ticket subject lines.

---

## 4. Detection sources (CC7.1, CC7.2)

The plan's detection surface is the union of:

### 4.1 External disclosures

Email to `support@5ceos.com` with `[SECURITY]` subject prefix is the primary external channel. See `SECURITY.md` §1.

### 4.2 Anomaly detector (shadow mode)

`src/anomaly.js` runs in shadow mode (does not block traffic, only logs). It fires on:

- Auth 4xx rate per IP (>10 in 60s) → `auth_brute_force_suspected`
- Honeypot hit rate per IP (>3 in 60s) → `scanner_active`
- Schema violation rate per tenant (>20 in 60s) → `schema_failure_spike`
- Latency p99 drift (this-minute > 3× 24h median) → `latency_drift_detected`

Each fire appends one row to `data/anomalies.jsonl`. The roadmap to flip the detector to fail-closed is in `STATE.md` "Future-work bucket" — currently blocked on ~1 week of real-traffic calibration data to avoid false-positive DoS.

### 4.3 Audit-chain verification

The hash-chained audit log (`data/usage.jsonl`) is verifiable by any tenant via `GET /v1/audit`. A `chain_ok: false` response indicates either tampering or a bug; both are incidents.

### 4.4 Cosign verify failures

A `cosign verify` failure against a running image hash indicates either a signing-key compromise, a registry MITM, or a tag-overwrite incident. This is monitored externally by any party running the verify recipe in `SECURITY.md` §3.2.

### 4.5 Container App platform alerts

Azure Container Apps emits health-probe-failure events, revision-deploy-failure events, and ingress-rate-limit events to the platform log. These are surfaced via `az containerapp logs` and reviewed on-demand. There is no automated paging today — see §6.4 for the residual gap.

---

## 5. Response SLA (CC7.3)

Pulled from `SECURITY.md` §1 "Response SLA" and binding here:

| Stage | SLA |
|---|---|
| Acknowledgment (a human has read the report) | **72 hours** |
| Initial triage and severity rating | 7 days |
| Fix landed in `main` (confirmed High/Critical) | 30 days |
| Coordinated public disclosure window | **90 days** from initial report |

For Critical incidents, the 72-hour ack target is the worst-case; the operational target is < 6 hours. For High incidents, < 24 hours. The 72h SLA exists so that night-and-weekend reports aren't dropped, not as a working target.

---

## 6. Response process (CC7.3)

### 6.1 Triage

On receipt of a disclosure or detection of an internal signal:

1. **Read the report**, ack to the reporter within SLA (72h)
2. **Compute severity** (CVSS v4.0 vector first, bucket label second)
3. **Reproduce** if the reporter included a curl repro or PoC
4. **Open an internal incident note** with: date, summary, severity, reporter (if any), repro steps, affected surface

The incident note is markdown in an operator-local file, not in the public repo. Incidents that result in a security-relevant code change get a `SECURITY-NOTICE.md` entry on the change-publication side.

### 6.2 Containment

Containment depends on the incident class:

- **Customer key disclosure (theirs)**: revoke the key via `POST /admin/keys/:id/revoke`. Coordinate with the customer to issue a replacement.
- **Customer key disclosure (ours — e.g. a log leak)**: revoke ALL active keys for the affected tenant; reissue. Audit `data/usage.jsonl` for any access between disclosure time and revocation time.
- **`ADMIN_KEY` compromise**: rotate via Key Vault secret-version bump + Container App revision update. Immediate, single command.
- **Cosign key compromise**: rotate the keypair, publish the new pubkey at `/cosign.pub`, sign all subsequent images with the new key. Old signatures remain verifiable as long as the prior pubkey is also published.
- **Audit-chain forgery**: do **not** try to "fix" the chain. The break is the incident artifact. Capture the break index, file a forensic note, and publish a `SECURITY-NOTICE.md` with the affected tenant and timestamp range.
- **Image-registry tampering**: revert the Container App to a known-good prior tag; verify cosign on every tag in the registry; rebuild from source.

### 6.3 Eradication and recovery

After containment, the recovery loop is:

1. Identify root cause (code defect, configuration drift, key exposure path, etc.)
2. Land a fix in `main` (squash merge from feat/fix branch)
3. Add a regression test if the defect class is testable
4. Deploy via `scripts/deploy-update.sh` (the only authorized path; see `change-management-policy.md`)
5. Verify the fix in production via smoke test

For High/Critical incidents, the fix-in-main target is **30 days**.

### 6.4 Customer notification

If an incident exposed customer data, customer keys, or per-tenant audit chains, the affected tenants are notified directly via the email on file with their Stripe customer record. Notification target: **within 72 hours of confirmation**, unless law-enforcement coordination requires a delay (in which case the affected customers receive an after-the-fact notification with the delay reason disclosed).

Notification content includes:

- What happened
- What data was affected
- What we have done (containment, rotation, fix-deployed timestamp)
- What the customer should do (rotate their own credentials, audit their usage log)
- A reference to the eventual public `SECURITY-NOTICE.md` entry

### 6.5 Public disclosure

For incidents that warrant public disclosure (per the 90-day window in `SECURITY.md` §1 SLA), a `SECURITY-NOTICE.md` entry is published in the repo and called out in release notes. Researchers who responsibly disclosed are credited in `SECURITY.md` §5 "Hall of Thanks" if they want the credit.

---

## 7. Lessons learned (CC7.4)

After every incident (regardless of severity), a brief post-mortem is captured:

- Timeline (detect → ack → contain → fix → notify → close)
- What worked
- What didn't
- Process changes recommended

Process changes that affect a control in `control-mapping.csv` trigger a revision to the relevant policy in this directory and a bump to that policy's `Last reviewed:` date.

The post-mortem itself is operator-local; the **changes it drives** are public via git history.

---

## 8. Known residual gaps (CC7.1)

Honestly disclosed:

- **No automated paging**: the operator is not paged automatically on a fail-closed health probe failure, an audit-chain break, or a sustained anomaly fire. Detection-to-acknowledgment time depends on human checking. Compensating control: the determinism bench and customer-side audit-chain verification provide external pressure that detects issues even when the operator is asleep.
- **Anomaly detector is shadow-mode**: signals are logged but not blocked. Fail-closed flip is on the roadmap; see `STATE.md` "Future-work bucket".
- **No external pentest yet**: `risk-assessment.md` R-09. An external pentest is an operator-action item before SOC 2 audit kickoff.

---

## 9. Review

This plan is reviewed at least annually. The next review date is 2027-05-14. Material changes — new anomaly signal, new detection source, change to the customer-notification process, change to the SLA — trigger an immediate review.

Reviewed annually or when control surface changes materially.
