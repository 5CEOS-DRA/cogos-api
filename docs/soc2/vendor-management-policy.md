# Vendor Management Policy

Last reviewed: 2026-05-14

This policy covers **TSC CC9.2** (the entity assesses and manages risks associated with vendors and business partners). It lists every sub-processor `cogos-api` depends on, what data each sees, the security commitments we rely on from them, the cadence at which we review those commitments, and the off-boarding plan for each.

The audience is a SOC 2 auditor evaluating the design and a customer's privacy/security reviewer cross-checking our sub-processor list against theirs.

---

## 1. Scope

This policy applies to every external service in the dependency graph of `cogos-api` that:

- Stores, processes, or transmits customer data on our behalf, OR
- Has privileged access to our deployment pipeline, OR
- Is named in our public privacy notice as a sub-processor

The current list is short. It is intentionally kept short — every additional sub-processor is a new attack surface and a new audit dependency.

---

## 2. Sub-processor list

### 2.1 Microsoft Azure (substrate provider)

**Services used:**
- Azure Container Apps (`cogos-api` and `cogos-inference` Container Apps)
- Azure Container Registry (`cogos5ceos.azurecr.io`)
- Azure Key Vault (`cogos-kv-16d2bb`)
- Azure Files (persistent volume for `data/`)
- Azure Log Analytics (Container App logs)
- Azure Active Directory (operator authentication to Azure)

**Data shared:**
- Customer prompts and responses **in transit only**, not at rest (Container Apps memory)
- Customer keys (hashes), HMAC secrets, audit log rows, anomaly log rows — **at rest** on Azure Files volume
- `ADMIN_KEY`, cosign signing private key, future Stripe secrets — at rest in Azure Key Vault
- Container App logs (Winston/Console output) — in Azure Log Analytics

**Security commitments referenced:**
- Microsoft Online Services Data Protection Addendum (DPA), incorporated by reference into our Azure tenancy agreement
- Microsoft Azure SOC 2 Type II report (current; pulled from the Service Trust Portal)
- Microsoft Azure ISO 27001 certification
- Microsoft Azure GDPR compliance posture (Microsoft acts as processor under our controller capacity for customer data)

**Review cadence:** Annual. Pull the latest SOC 2 Type II and ISO 27001 reports from the Service Trust Portal each year and verify scope still covers the services we use. Material changes trigger an immediate re-review.

**Off-boarding plan:** Multi-step migration is required. Replacement substrate candidates: AWS (ECS Fargate or App Runner), GCP (Cloud Run), or self-hosted Kubernetes. Off-boarding involves rebuilding the container image, migrating the persistent volume, reissuing customer keys (since the storage substrate changes), and updating the DNS record. Estimated effort: 3–5 operator-days, plus customer-comms lead time. Required posture: every customer rotates their key as part of the migration; old keys (with hashes computed against the old substrate's clock) are revoked when the new substrate goes live.

---

### 2.2 Stripe (payments processor)

**Services used:**
- Stripe Checkout (customer subscription signup flow)
- Stripe Customer Portal (customer-facing subscription management)
- Stripe Webhooks (subscription event delivery to our gateway)
- Stripe Products + Prices API (synced from our `packages.json` when `STRIPE_SECRET_KEY` is configured)

**Data shared:**
- Customer email (collected by Stripe at checkout; surfaced to us in the customer record)
- Customer subscription metadata (Stripe customer ID, subscription ID, status)
- Payment data — Stripe is the controller for this; we never touch a PAN, CVV, or expiration

We do **not** share customer prompts, responses, or audit-log content with Stripe. Stripe sees the billing surface only.

**Security commitments referenced:**
- Stripe Data Processing Agreement
- Stripe PCI DSS Level 1 attestation (current; pulled from Stripe's compliance portal)
- Stripe SOC 1 and SOC 2 Type II reports
- Stripe GDPR / CCPA compliance posture

**Review cadence:** Annual. Stripe's compliance portal is the authoritative source.

**Off-boarding plan:** Replacement candidates: Paddle, Lemon Squeezy, direct credit-card processing via Adyen. Off-boarding involves migrating active subscriptions (Stripe export → import to new processor where supported; otherwise customer-side re-subscribe), updating the `/signup` flow, updating webhook signature verification to the new processor's scheme, and updating the `/portal` redirect. Estimated effort: 5–10 operator-days, plus customer-comms lead time.

---

### 2.3 GitHub (source repository host)

**Services used:**
- `cogos-api` private repository
- GitHub Issues (when used for non-security tracking; security issues route via `[SECURITY]` email per `SECURITY.md` §1)
- GitHub Releases (not currently used; release-publishing planned alongside OSS-flip if/when that happens)

**Data shared:**
- All `cogos-api` source code
- Commit history including operator identity and `Co-Authored-By:` trailers
- Repository metadata (collaborators, branch protection rules, settings)

We do **not** share customer keys, customer data, audit log content, or operator secrets with GitHub. The `.gitignore` excludes `data/`, `.env`, `.env.local` — verified by audit of the repo's `.gitignore` and `git status` on `main`.

**Security commitments referenced:**
- GitHub Enterprise Cloud Data Processing Addendum
- GitHub SOC 1 and SOC 2 Type II reports
- GitHub ISO 27001:2013 certification

**Review cadence:** Annual.

**Off-boarding plan:** Replacement candidates: GitLab, Bitbucket, self-hosted Gitea, self-hosted Forgejo. Off-boarding involves pushing the full repo history to the new host, updating any developer tooling (the `gh` CLI usage in `scripts/`), and rotating any GitHub-issued tokens (PATs, deploy keys). Estimated effort: 1–2 operator-days. The `github-token` secret in Azure Key Vault is reserved for legacy VM-based deploy paths and can be revoked once that path is fully decommissioned.

---

## 3. NOT sub-processors (informational)

The following are intentionally **not** in the sub-processor list because they do not see customer data:

- **Cloudflare** — operates at the L3/L4 layer for volumetric DoS protection (per `SECURITY.md` §2 out-of-scope). Sees encrypted TLS traffic only; no customer data.
- **Inference model authors (Alibaba/Qwen team)** — we run their weights locally; they never see our traffic. Out of scope per `SECURITY.md` §2.
- **Operator's email provider (5CEOS internal AWS WorkMail)** — handles `support@5ceos.com` correspondence; not in the gateway data path.

---

## 4. Review process

### 4.1 Annual review checklist

For each sub-processor listed in §2:

- [ ] Pull current SOC 2 Type II report from the vendor's compliance portal
- [ ] Verify the report's scope still covers the services we use
- [ ] Verify no material changes in the auditor's opinion (qualified → unqualified or vice versa)
- [ ] Confirm the vendor's DPA is current (countersigned, dated, on file with the operator)
- [ ] Confirm no breach disclosures from the vendor in the past 12 months
- [ ] If any item fails, open a vendor-review incident and remediate before re-attesting

### 4.2 Material change triggers

In addition to the annual cadence, an immediate review is triggered by:

- A vendor publishes a breach notification
- A vendor's SOC 2 report transitions from unqualified to qualified
- A vendor's DPA is materially amended
- A vendor introduces a new service tier we adopt (e.g. switching from Container Apps to AKS would be a new service)
- A vendor enters or exits a jurisdiction relevant to our customer base

---

## 5. Adding a new sub-processor

Before any new sub-processor is added to the dependency graph, the operator:

1. Verifies the vendor has a current SOC 2 or ISO 27001 attestation
2. Reviews their DPA and countersigns
3. Adds them to §2 of this document with the data-shared row honestly populated
4. Updates the customer-facing privacy notice if the addition is material
5. Notifies affected customers per the customer-agreement change-notification clause

No vendor is added under deadline. The change-management process in `change-management-policy.md` applies.

---

## 6. Review

This policy is reviewed at least annually. The next review date is 2027-05-14. Material sub-processor additions, removals, or changes-of-scope trigger an immediate review.

Reviewed annually or when control surface changes materially.
