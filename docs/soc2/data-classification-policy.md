# Data Classification Policy

Last reviewed: 2026-05-14

This policy covers **TSC C1.1** (confidentiality — protection of information designated as confidential), **TSC C1.2** (disposal of confidential information), and **TSC P1.1** (privacy notice). It describes what data classes `cogos-api` handles, how each class is stored or not stored, and what disposal looks like for each.

The audience is a SOC 2 auditor evaluating design and a customer's privacy/security reviewer verifying scope.

---

## 1. Scope

This policy classifies all data that flows through or is stored by `cogos-api`. It covers data:

- In flight between the customer and the gateway
- At rest on the Container App's persistent file system (Azure Files volume) and in Azure Key Vault
- In transit between the gateway and the sibling `cogos-inference` Container App
- In transit between the gateway and external sub-processors (Stripe, Azure platform)

---

## 2. Data classes

| Class | Examples | Retention | Storage | Crypto at rest |
|---|---|---|---|---|
| **Customer secrets (operator-issued)** | API key plaintext, HMAC secret, ed25519 private PEM | NEVER stored at rest after issuance — shown to customer once | (none) | n/a |
| **Customer secrets (operator-retained)** | sha256 hash of bearer key, ed25519 public PEM, HMAC secret | Until key revoked + retention window | `data/keys.json` (mode 0600) on Container App volume | Azure-managed-disk encryption (platform layer) |
| **Customer prompts / responses (in flight)** | LLM request bodies, LLM response bodies | NEVER stored at rest | (none — only in process memory for the duration of one request) | n/a |
| **Customer usage metadata** | Tenant ID, key ID, model, token counts, latency, status, timestamp | Long-term retention (audit substrate; current target is indefinite) | `data/usage.jsonl` (hash-chained, mode 0600) | Azure-managed-disk encryption |
| **Customer billing data** | Stripe customer ID, subscription ID, status, email | As long as subscription active + accounting retention | `data/keys.json` (linked to key record) | Azure-managed-disk encryption |
| **Operator secrets** | `ADMIN_KEY`, cosign signing private key, Stripe API keys, JWT secret (reserved) | Until rotation | Azure Key Vault `cogos-kv-16d2bb` | Azure Key Vault HSM-backed |
| **Anomaly log** | Subject type/value, signal kind, severity, summary, timestamp | Long-term (forensic substrate) | `data/anomalies.jsonl` (mode 0600) | Azure-managed-disk encryption |
| **Configuration** | Container App env var names, package definitions, deploy revision history | Indefinite (operational) | Azure platform metadata + `data/packages.json` | Platform |
| **Logs (Winston/Console)** | Structured JSON event lines | Container Apps log retention (default 30 days) | Azure Log Analytics workspace | Platform |

The most important rows are the bold-italic ones below.

### 2.1 Customer prompts and responses — never stored at rest

`cogos-api` does **not** persist the body of `/v1/chat/completions` requests or responses. They live in process memory for the duration of one HTTP request, are forwarded to the upstream inference engine over an internal-only network path, and the response is returned to the customer. After the response is written to the socket, the request body and response body are eligible for GC.

What we **do** record is the metadata: tenant, key, model, token counts, latency, status, request ID, `schema_enforced` flag. That goes in `data/usage.jsonl` and is the substrate for billing, the audit chain, and the per-tenant audit query at `/v1/audit`. The substrate is the metadata — the content is never stored at rest.

This is the single most important confidentiality claim we make. The auditor should verify it by reading `src/chat-api.js` and `src/usage.js` and confirming there is no path from a `messages[].content` value to a persistent write.

### 2.2 Customer secrets — issued once, never re-disclosed

Bearer API keys (`sk-cogos-...`), HMAC secrets, and ed25519 private PEMs are generated on `POST /admin/keys` (or via the Stripe webhook → key-issuance handler), returned in the response (or shown on the `/success` page), and **never returned again**. Only sha256 hashes (bearer) or public PEMs (ed25519) are persisted in `data/keys.json`. A database leak does not yield usable keys — see `SECURITY.md` §3.5.

### 2.3 Audit log — hash-chained, per-tenant, queryable

`data/usage.jsonl` is append-only and hash-chained per tenant. Each row carries `prev_hash` and `row_hash` fields; verification logic is in `src/usage.js` `verifyChain()`. A customer can pull their own slice via `GET /v1/audit` and run client-side verification. Tampering is detectable; the chain ID for a tenant is itself the integrity proof.

---

## 3. Confidentiality controls (C1.1)

### 3.1 In transit

- All customer-facing traffic is TLS 1.2+ (Container Apps managed cert; HSTS preload header set by `src/index.js` security middleware)
- Gateway → inference container: internal-only ingress within the Container Apps environment; no external network path
- Gateway → Azure Key Vault: TLS via Azure SDK
- Gateway → Stripe: TLS via Stripe SDK

### 3.2 At rest

- All Container App volumes use Azure-managed-disk encryption at the platform layer
- Azure Key Vault stores `ADMIN_KEY`, `cosign-private-key`, and future JWT secret with HSM-backed encryption
- `data/keys.json`, `data/usage.jsonl`, `data/anomalies.jsonl`, `data/packages.json` are mode 0600 (owner-read-write only)

### 3.3 In process

- Customer auth secrets are not logged. `src/auth.js` never emits the Authorization header value to any log destination.
- The `/admin/usage` and `/admin/keys` endpoints filter `key_hash` and `hmac_secret` out of list responses.
- The `/admin/soc2/evidence-bundle` endpoint returns env var **names** but never values — see implementation in `src/index.js`.

---

## 4. Disposal (C1.2)

### 4.1 Customer key revocation

When a key is revoked (via `POST /admin/keys/:id/revoke` or by a Stripe subscription cancellation), the `active` flag flips false and `revoked_at` is stamped. The record is retained for audit purposes — `data/keys.json` has no physical-delete path, only logical-delete.

This is a deliberate choice: a deleted record loses the binding between past usage events and the customer they belong to. Retention with `active=false` preserves the binding while preventing the key from authenticating new requests.

### 4.2 Subscription off-boarding

When a Stripe subscription is canceled (or `customer.subscription.deleted` fires), all keys for that customer are revoked automatically via `src/stripe.js` `handleSubscriptionUpdated`. The customer's billing metadata is retained per the accounting-records retention period.

### 4.3 Hard-delete

There is currently no automated hard-delete path for customer records. A customer's right-to-deletion (GDPR Art. 17, CCPA equivalent) is satisfied by:

1. Operator runs a manual purge of the customer's records from `data/keys.json` and `data/usage.jsonl`
2. The audit-chain rows for that tenant are retained until the legitimate-business-interest retention window expires (currently target: 12 months); upon expiry the operator purges them
3. The deletion event is itself logged in the operator's incident note

This is a known gap relative to a fully-automated GDPR pipeline. The compensating control is the small customer count at current scale; the residual is tracked in `risk-assessment.md`.

### 4.4 Anomaly log disposal

`data/anomalies.jsonl` is retained for forensic purposes. There is no automatic rotation today. Future work: rotate weekly into compressed archives in Azure Blob with a 1-year retention policy.

### 4.5 Container disposal

When a Container App revision is decommissioned (rolling update completes traffic shift, then auto-prunes old revisions per platform policy), the underlying compute is reclaimed by Azure. The Azure Files volume persists across revisions; only the compute is recycled.

---

## 5. Privacy posture (P1.1)

### 5.1 Processor vs controller

For customer prompt content and any PII it may contain, `cogos-api` operates as a **processor** under the customer's lawful basis. The customer is the controller; we process the prompt to produce the response, log only the metadata, and have no independent business reason to read prompt content.

For customer-account data (email, billing), we are a **joint controller** with Stripe. Stripe is the controller for payment data; we are the controller for our derived records (key issuance, usage attribution, support correspondence).

### 5.2 Privacy notice

Our public privacy notice is at `https://cogos.5ceos.com/privacy` (served by `src/legal.js`). It is the customer-facing version of this policy.

### 5.3 Sub-processor list

Sub-processors are listed in `vendor-management-policy.md`. The customer is notified of material changes to the sub-processor list per the change-notification clause in the customer agreement.

### 5.4 Data subject requests

Right-to-access, right-to-deletion, and right-to-rectification requests come in via `support@5ceos.com` and are handled by the operator within 30 days. At current customer scale this is manual; an automated DSAR pipeline is on the longer-term roadmap.

---

## 6. Determinism and content integrity

A note on processing integrity (TSC PI1.1, PI1.4) that affects classification:

The schema-enforced decoding claim (`SECURITY.md` §3.8) constrains the **shape** of LLM output. It does **not** constrain its truth value. Schema-valid lies are possible. This is a known limitation, disclosed in `SECURITY.md` §4.2 and again in `risk-assessment.md` R-07. Customers using our output for high-stakes decisions need domain validation on the values, not just the shape.

This affects classification because: even if a response is metadata-classified as "successful," its content is **not** something we attest to the correctness of. The classification is operational (was the call delivered?), not semantic (was the answer right?).

---

## 7. Review

This policy is reviewed at least annually. The next review date is 2027-05-14. Material changes — new data class, new retention, new sub-processor, change to the never-store-content invariant — trigger an immediate review.

Reviewed annually or when control surface changes materially.
