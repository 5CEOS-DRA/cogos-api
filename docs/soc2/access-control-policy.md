# Access Control Policy

Last reviewed: 2026-05-14

This policy covers **TSC CC6.1** (logical access controls), **TSC CC6.2** (registration and authorization of users), and **TSC CC6.3** (modification and removal of access). It describes how identity is established on the `cogos-api` gateway, how privileged access is granted and revoked, and how those decisions are audited.

The audience is a SOC 2 auditor evaluating design effectiveness. The policy is descriptive of the live system, not aspirational.

---

## 1. Scope

This policy applies to:

- The production `cogos-api` gateway (`cogos.5ceos.com`, deployed to Azure Container Apps)
- The sibling `cogos-inference` Container App (internal-only ingress, model serving)
- The supporting Azure resources (Key Vault `cogos-kv-16d2bb`, Container Registry `cogos5ceos.azurecr.io`, Resource Group `brain5-aca2`)
- The source repository (`cogos-api`)
- The operator workstation used to drive `scripts/deploy-update.sh`

It does **not** apply to customer-side key handling (out of scope per `SECURITY.md` §4.1) or to vendor-internal access controls (covered by sub-processor SOC 2 reports under `vendor-management-policy.md`).

---

## 2. Identity classes

The gateway recognizes three distinct identity classes. Each has its own authentication mechanism, audit trail, and revocation path.

### 2.1 Customer identity (CC6.1)

Customers authenticate to `/v1/*` endpoints with one of two schemes:

- **Bearer token**: `Authorization: Bearer sk-cogos-<32-hex>`. The plaintext is shown exactly once at issue time (Stripe `/success` page, or `/admin/keys` response). Only `sha256(plaintext)` is persisted in `data/keys.json`. A database dump does not yield usable keys.
- **Ed25519 keypair**: `Authorization: CogOS-Ed25519 keyId=<id>,sig=<base64>,ts=<unix_ms>`. The server generates the keypair on issuance, returns the private PEM once, and persists only the public PEM. The customer holds no reusable secret on our side — every request is signed over `METHOD\npath\nts\nbody_sha256` with a 5-minute replay window.

Both schemes are constant-time-compared at the auth layer. Customer auth state lives in `req.apiKey` and is scoped strictly to one tenant: customer A cannot read customer B's audit log or usage rows. The `tenant_id` field on `req.apiKey` is the authorization key for every downstream query.

### 2.2 Operator (administrative) identity (CC6.1, CC6.3)

Operator access to `/admin/*` endpoints requires the `X-Admin-Key` header. The value is compared constant-time (`crypto.timingSafeEqual`) against `process.env.ADMIN_KEY`, which is sourced from Azure Key Vault secret `cogos-admin-key` at Container App revision-create time.

Rotation is a single env-var change followed by a revision update. Old key invalidates immediately on the new revision; the old revision continues serving with the old key only until traffic shifts (zero-downtime rolling update).

Currently the operator population is one person (Denny Adams) — see `personnel-security-policy.md` for the solo-operator caveat and compensating controls.

### 2.3 Service identity (CC6.1)

Internal service-to-service calls (gateway → inference container) use Container Apps internal ingress. There is no external network path to the inference container; auth is by Azure-managed network boundary, not by token. This is the smallest practical attack surface for the model serving layer.

The Stripe webhook is a fourth identity class but is gated by `Stripe-Signature` HMAC verification, not by a shared secret in plaintext. See `change-management-policy.md` for how the webhook secret is rotated.

---

## 3. Registration and authorization of users (CC6.2)

### 3.1 Customer registration

Customers self-register via Stripe Checkout:

1. POST `/signup` with a `package` query parameter creates a Stripe Checkout session.
2. On `checkout.session.completed` webhook delivery (verified by `Stripe-Signature`), the gateway issues a new customer key bound to the Stripe customer ID.
3. The customer is redirected to `/success` where the plaintext key, HMAC secret, and (for ed25519) private PEM are displayed **once** for a 24-hour window. After that window the success URL returns a stale-session message; the operator must reissue via `/admin/keys`.

### 3.2 Operator registration

The operator population is closed. Adding an operator is a multi-step ceremony — see `personnel-security-policy.md` §3. It requires:

- A new `ADMIN_KEY` value generated on a clean machine
- An Azure RBAC role assignment on the Resource Group and Key Vault
- A GitHub Collaborator add with `Maintain` (not `Admin`) permission
- A cosign signing key share (if the new operator will deploy)

No automated provisioning path exists. This is intentional at the current scale.

### 3.3 Authorization model

The model is **role-binary**: a request is either authenticated as a customer (tenant-scoped, can only see own data) or as the operator (full read on all admin endpoints, full CRUD on packages and keys). There is no intermediate role. This is appropriate at the current operator count; a future card will introduce read-only operator roles when the team grows.

---

## 4. Modification and removal of access (CC6.3)

### 4.1 Customer key revocation

`POST /admin/keys/:id/revoke` flips the `active` flag on the record and stamps `revoked_at`. The next request authenticated with that key returns 401. Revocation is immediate — there is no cache to invalidate.

A Stripe subscription event (`customer.subscription.deleted` or status transition to `canceled` / `unpaid`) triggers automatic revocation via `src/stripe.js` → `updateStripeStatus({active: false})`. The operator does not have to intervene for billing-driven revocations.

### 4.2 Operator key rotation

`ADMIN_KEY` rotation is a Key Vault secret-version bump followed by `az containerapp update --set-env-vars ADMIN_KEY=<new>`. The old value is invalid the moment the new revision serves traffic. Rotation cadence is at minimum annual, and immediately upon any suspected compromise or operator-population change.

The cosign private key rotation procedure is documented in `scripts/cosign-setup.sh` and `scripts/cosign-upload-to-kv.sh`. Rotation also publishes a new `cosign.pub` to `https://cogos.5ceos.com/cosign.pub`; old signatures remain verifiable as long as the prior pubkey is also published (multi-key verify pattern).

### 4.3 Off-boarding (operator)

Off-boarding an operator means:

1. Revoke their Azure RBAC assignment
2. Remove them from the GitHub `cogos-api` repository
3. Rotate `ADMIN_KEY` (in case the off-boarding individual ever held it)
4. Rotate any cosign signing keys they had access to
5. Record the off-boarding event in `risk-assessment.md` if it changes the residual-risk picture

There is currently no formal off-boarding ticket — see `personnel-security-policy.md` for the solo-operator caveat and the auditable git history compensating control.

---

## 5. Privileged access (CC6.3)

### 5.1 No live admin dashboard

There is no `/admin/live`, no `/admin/console`, no browser-facing admin surface. Operator actions are CLI-only (`curl` against `/admin/*` with `X-Admin-Key`). This is asserted by:

```bash
curl -I https://cogos.5ceos.com/admin/live   # → 404
```

The decision to not ship a live admin dashboard is doctrinal — a dashboard would be a session-fixation target, a CSRF target, and a phishing target. CLI-only operator surface eliminates those classes entirely.

### 5.2 No-live-admin doctrine

In addition, the `scripts/admin-ceremony/README.md` design retires the live `/admin/keys` HTTP endpoints in favor of signed-config-diff workflows. That migration is in progress (see `STATE.md` "Future-work bucket"). The current live endpoints are gated by `X-Admin-Key`, but the long-term target is offline ceremony with signed diffs verified at server boot. Auditor: ask about timeline at interview.

### 5.3 MFA caveat

The operator workstation uses local OS-level disk encryption and a passphrase-protected SSH agent. Azure CLI sessions are 2FA-gated at the Azure AD layer. The `ADMIN_KEY` itself is a 256-bit shared secret with constant-time compare — not an MFA factor. We do not claim MFA on the `X-Admin-Key` flow because there isn't one; the compensating controls are the 256-bit-secret entropy and the absence of a browser surface.

This is an honest disclosure. An auditor evaluating CC6.1 MFA controls should treat this as a known gap and ask about timeline.

---

## 6. Audit trail

Every action listed in this policy emits one of:

- A line in the `logger.info('...')` stream (Winston, JSON format, stdout)
- A row in the `data/usage.jsonl` hash-chained audit log
- A row in `data/anomalies.jsonl` if the action correlated with an anomaly signal
- A row in `data/keys.json` (issuance / revocation)

The audit trail is queryable per-tenant at `/v1/audit` (customer-scoped) and at `/admin/usage` (operator-scoped). The `/admin/soc2/evidence-bundle` endpoint summarizes the audit-chain head and anomaly log row counts for the auditor's point-in-time snapshot.

---

## 7. Review

This policy is reviewed at least annually. The next review date is 2027-05-14. Material control-surface changes (new identity class, new auth scheme, removal of an existing scheme, change to the operator population) trigger an immediate review regardless of cadence.

Reviewed annually or when control surface changes materially.
