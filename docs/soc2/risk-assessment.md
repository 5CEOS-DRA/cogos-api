# Risk Assessment

Last reviewed: 2026-05-14

This document covers **TSC CC3.1** (objectives for risk), **CC3.2** (identification of risks), **CC3.3** (analysis of risks), and **CC3.4** (assessment of changes that could affect the system of internal control).

The audience is a SOC 2 auditor evaluating design and the operator using this as a working punch list. The ranking is **honest** — residual-risk values reflect the actual posture, not a marketing version of it. If a risk is open, it's marked open.

---

## 1. Risk objectives

The objectives this assessment evaluates:

1. **Customer secrets remain confidential.** Bearer keys, HMAC secrets, ed25519 private keys are never exposed beyond the customer who issued them.
2. **Customer prompt and response content remain confidential.** Never persisted at rest.
3. **The audit log is tamper-evident.** Tenants can detect any rewrite of their own slice.
4. **The deployment pipeline is authentic.** Customers can prove the running image was built and signed by us.
5. **The service is available.** Production uptime sufficient for the published latency claims.
6. **Sub-processors do not exceed the surface they're given.** Stripe sees billing; Azure runs the substrate; GitHub holds source. None gets more than their slice.

A risk in this register is anything that could compromise one of those objectives.

---

## 2. Methodology

For each risk, we record:

- **ID**: stable identifier (`R-NN`)
- **Description**: one-paragraph plain English
- **Likelihood**: Low / Medium / High (qualitative)
- **Impact**: Low / Medium / High / Critical
- **Mitigation**: control(s) in place today
- **Residual**: Low / Medium / High after mitigation
- **Status**: Open / Monitored / Closed
- **Owner**: who owns the next action (operator at current scale)

Likelihood and impact are deliberately qualitative — at single-operator scale, quantitative scoring is theater. The qualitative call is the call the operator actually makes.

---

## 3. Top 10 risks

### R-01 — Customer-side key leak

**Description**: A customer commits their `sk-cogos-...` key to a public GitHub repo, leaks it via a malicious browser extension, or exfiltrates it from a laptop compromise. The leak is on their side, not ours.

**Likelihood**: Medium (this happens to every API vendor)
**Impact**: Medium (single-tenant blast radius; we revoke + reissue)
**Mitigation**:
- Constant-time hash compare prevents enumeration even with partial knowledge
- `POST /admin/keys/:id/revoke` is immediate
- Per-tenant `/v1/audit` lets the customer detect anomalous usage themselves
- `SECURITY.md` §4.1 explicitly disclaims responsibility for customer-side compromise and documents the customer's controls
- Ed25519 scheme is offered as an alternative — no reusable secret on the customer side

**Residual**: **Low**
**Status**: Monitored
**Owner**: customer (we provide controls, they own use)

---

### R-02 — `ADMIN_KEY` compromise

**Description**: The `ADMIN_KEY` shared secret leaks via operator workstation compromise, accidental commit, log exposure, or operator-side phishing.

**Likelihood**: Low (one operator, one key, kept in Azure Key Vault)
**Impact**: Critical (admin endpoints allow key issuance and revocation across the entire tenant set)
**Mitigation**:
- Constant-time compare via `crypto.timingSafeEqual` prevents brute-force enumeration
- Rotation is a single Key Vault secret bump + Container App revision update
- No live admin dashboard means no browser session-hijack path
- Operator workstation has full-disk encryption and 2FA on the Azure tenancy
- Key Vault access policy limits which principals can read the secret

**Residual**: **Medium** — even with all controls, a single-operator shared-secret model has more residual risk than a multi-operator JIT-elevation model. Mitigation roadmap: offline admin ceremony (signed config diffs) per `scripts/admin-ceremony/README.md` retires the live admin endpoints entirely.

**Status**: Open (mitigation roadmap is "Future-work bucket" in `STATE.md`)
**Owner**: operator

---

### R-03 — Rate-limit gap on `/v1/*`

**Description**: There is no per-tenant or per-IP rate limit on `/v1/chat/completions` or `/v1/audit`. A misbehaving customer (or compromised key) could DoS the upstream inference container or run up someone else's bill (if they have someone else's key).

**Likelihood**: Medium (the path of least resistance for a casual attacker)
**Impact**: Medium (degrades availability; financial impact via inference cost; not a confidentiality compromise)
**Mitigation**:
- Anomaly detector tracks `schema_violation_rate` and `auth_4xx_rate`, fires on threshold cross — but in shadow mode, does not block
- Cloudflare edge handles L3/L4 floods (per `SECURITY.md` §2 out-of-scope row)
- Per-tenant package quotas exist at the billing-period level (`src/packages.js`); does not address sub-minute burst

**Residual**: **High** — this is one of the two operator-action items we're calling out as gaps before audit kickoff. A basic token-bucket per tenant is the next implementation step.

**Status**: **Open** — operator action required before SOC 2 audit kickoff
**Owner**: operator

---

### R-04 — Anomaly detector in shadow mode

**Description**: `src/anomaly.js` observes traffic and logs threshold crossings but does not block. A sustained attack pattern is logged but not stopped at the request boundary.

**Likelihood**: Medium (attacks happen; shadow mode means they aren't blocked at the gateway)
**Impact**: Medium (degraded availability + reconnaissance value to the attacker)
**Mitigation**:
- Detector emits all four signal types (auth brute force, scanner, schema spike, latency drift)
- Each fire writes to `data/anomalies.jsonl` for forensic analysis
- Cloudflare edge L3/L4 protection still applies
- Fail-closed flip is on the roadmap (~1 week of real-traffic calibration data needed)

**Residual**: **Medium** — accepted residual until the fail-closed flip ships
**Status**: Open
**Owner**: operator

---

### R-05 — Cosign signing-key compromise

**Description**: The cosign private key in Azure Key Vault leaks (KV breach, operator workstation compromise during a deploy when the key is loaded). An attacker could sign a malicious image and have customers' `cosign verify` succeed against it.

**Likelihood**: Low (the key lives in HSM-backed KV and is loaded transiently by `scripts/deploy-update.sh`)
**Impact**: Critical (defeats the image-provenance claim)
**Mitigation**:
- Key Vault HSM-backed storage
- Access policy limits which principals can read the secret
- Operator-only access; loaded transiently for the duration of one signing operation
- Rotation procedure documented in `scripts/cosign-setup.sh` and `scripts/cosign-upload-to-kv.sh`
- Old signatures remain verifiable as long as the prior pubkey is published — rotation does not break customer verification

**Residual**: **Low**
**Status**: Monitored
**Owner**: operator

---

### R-06 — Audit-chain forgery via direct disk write

**Description**: An attacker with shell access to the Container App's persistent volume rewrites `data/usage.jsonl` to remove rows that document their activity.

**Likelihood**: Very Low (no shell in the distroless container; volume access requires Azure RBAC compromise)
**Impact**: High (defeats the per-tenant audit chain claim)
**Mitigation**:
- Distroless runtime (no shell) means in-container compromise cannot run `vi` against the log
- Container App volume access requires Azure RBAC role on the Container App resource
- Hash chain detects any row rewrite — the next legitimate append would compute a `prev_hash` mismatch
- Customer-side `/v1/audit` returns `chain_ok: false` on any break, surfacing the forgery
- Future card publishes hourly global head hash to public Azure Blob — once shipped, forgery is detectable by third parties

**Residual**: **Low**
**Status**: Monitored
**Owner**: operator

---

### R-07 — LLM output is shape-correct but semantically wrong

**Description**: Schema-enforced decoding guarantees the response conforms to the supplied JSON Schema, but the model can return a schema-valid lie. A customer using output for medical, legal, or financial decisions can be misled.

**Likelihood**: High (this happens on every LLM call to some degree; whether it's harmful depends on use)
**Impact**: Variable — low for chat-style use; potentially Critical for autonomous decisioning
**Mitigation**:
- `SECURITY.md` §4.2 explicitly disclaims this
- `data-classification-policy.md` §6 reiterates it
- Cookbook recipes recommend domain validation on values, not just shape
- The customer agreement reserves customer-side responsibility for content correctness

**Residual**: **Medium** — accepted as a product property, not a defect. The mitigation is honest disclosure, not defense.
**Status**: Monitored
**Owner**: customer (we disclose; they own validation)

---

### R-08 — Stripe webhook bypass

**Description**: An attacker forges a `checkout.session.completed` body to trigger key issuance without paying.

**Likelihood**: Low (Stripe-Signature verification is required on every webhook delivery)
**Impact**: High (free key issuance; potential abuse at scale)
**Mitigation**:
- `stripeMod.verifyAndParseEvent(req.body, sig)` rejects any body without a valid signature against `STRIPE_WEBHOOK_SECRET`
- The webhook handler uses `express.raw` to preserve the body bytes for signature verification (verified in `src/index.js`)
- Idempotency check via `stripeMod.isEventProcessed(event.id)` prevents replay even if a signature were obtained
- `STRIPE_WEBHOOK_SECRET` rotation is a Stripe-dashboard action + Container App env update

**Residual**: **Low**
**Status**: Monitored
**Owner**: operator

---

### R-09 — Lack of external penetration test

**Description**: We have not yet engaged an external firm to perform a pentest. Self-attestation alone is weaker evidence than independent verification for many of the controls in this register.

**Likelihood**: n/a (this is a process gap, not a threat)
**Impact**: Medium (audit-evidence gap; not a runtime security gap)
**Mitigation**:
- The codebase is open to NDA review per `SECURITY.md` §3.1
- Public-bench infrastructure (`llm-determinism-bench`) provides one form of external verification
- Researchers can test the live endpoint within safe-harbor scope per `SECURITY.md` §1
- The plan is to engage a pentest firm before SOC 2 Type II coverage period begins

**Residual**: **Medium** — until the pentest engagement closes
**Status**: **Open** — operator action required before SOC 2 audit kickoff
**Owner**: operator

---

### R-10 — Single-region deployment

**Description**: `cogos-api` and `cogos-inference` run in a single Azure region (us-east). A regional outage means a full service outage.

**Likelihood**: Low (Azure regional outages are infrequent)
**Impact**: High (full availability hit during the duration of the outage)
**Mitigation**:
- Container Apps managed cert + auto-restart on revision failure
- Rollback procedure documented in `scripts/deploy-update.sh` and `business-continuity-plan.md`
- Audit log is durable on the Azure Files volume (LRS by default; ZRS upgrade is on the roadmap)
- Multi-region failover is on the roadmap — currently a known limitation

**Residual**: **Medium**
**Status**: Open (acceptable at current scale; revisit when customer count or contractual SLA requires)
**Owner**: operator

---

## 4. Summary table

| ID | Risk | Likelihood | Impact | Residual | Status |
|---|---|---|---|---|---|
| R-01 | Customer-side key leak | Medium | Medium | Low | Monitored |
| R-02 | `ADMIN_KEY` compromise | Low | Critical | Medium | Open |
| R-03 | No `/v1/*` rate limit | Medium | Medium | **High** | **Open** |
| R-04 | Anomaly detector shadow-mode | Medium | Medium | Medium | Open |
| R-05 | Cosign-key compromise | Low | Critical | Low | Monitored |
| R-06 | Audit-chain forgery | Very Low | High | Low | Monitored |
| R-07 | LLM schema-valid lies | High | Variable | Medium | Monitored |
| R-08 | Stripe webhook bypass | Low | High | Low | Monitored |
| R-09 | No external pentest | n/a | Medium | **Medium** | **Open** |
| R-10 | Single-region deployment | Low | High | Medium | Open |

**Honest summary**: R-03 (rate limit gap), R-09 (no external pentest), and R-02 (admin-key model) are the three most material open risks. R-03 should be closed with code before SOC 2 audit kickoff. R-09 should be opened with a firm engagement before audit kickoff. R-02's mitigation roadmap (offline admin ceremony) is longer-term.

---

## 5. Review cadence

This register is reviewed at least quarterly. Material changes — a new risk identified, a residual ranking changing, a status moving from Open to Closed — trigger an immediate revision. The next scheduled review is 2026-08-14.

The register is also reviewed after every security incident (per `incident-response-plan.md` §7).

Reviewed annually or when control surface changes materially.
