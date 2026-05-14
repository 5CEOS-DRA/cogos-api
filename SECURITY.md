# Security Policy

`cogos-api` is the public gateway of **CogOS** — a deterministic uptime loop for production AI. We hold this codebase to the same standard we ask customers to hold their inference paths to: **observable by default, auditable on demand, no "trust us."**

This document is what a security researcher or a CISO reads first. It tells you:

1. How to report a vulnerability
2. What's in scope and what isn't
3. Which security claims we make today that you can verify yourself, right now, from a terminal
4. What we explicitly **don't** defend against (the honest list)
5. How we acknowledge researchers who help us tighten the loop

If you came here to file a vulnerability, jump to [§1 Reporting a vulnerability](#1-reporting-a-vulnerability).

---

## 1. Reporting a vulnerability

### Primary channel

**Email: `support@5ceos.com` — subject prefix: `[SECURITY]`**

Use the `[SECURITY]` subject prefix to route triage out of the normal support queue. Do **not** use GitHub issues, social channels, or any other public path — those slow triage and risk public exposure of an unpatched issue. A dedicated `security@5ceos.com` alias may be provisioned once disclosure volume warrants it; until then the `[SECURITY]` prefix is the trigger.

### Encrypted disclosure

Send disclosures in plaintext to the address above; we will respond from a verifiable signed address and you can encrypt subsequent rounds against a fingerprint we hand back. We deliberately do not publish a long-lived PGP key — disclosure handlers rotate, and a stale published key is a worse trust signal than an ephemeral signed reply.

### What to include

A high-signal report is:

- A one-line summary of the issue (severity in your own words)
- The endpoint, code path, or artifact affected (URL, commit SHA, image tag if relevant)
- A **minimal reproduction** — ideally a `curl` invocation or a 20-line script
- The expected vs. observed behavior
- CVSS v4.0 vector if you have one (we will compute one ourselves if not)
- Whether you intend to publish, and your preferred disclosure window if it differs from the default below

Screenshots are fine; logs and packet captures are better.

### Response SLA

| Stage | SLA |
|---|---|
| Acknowledgment (a human has read it) | **72 hours** |
| Initial triage + severity rating | 7 days |
| Fix landed in `main` (for confirmed High/Critical) | 30 days |
| Coordinated public disclosure window | **90 days** from initial report |

We may ask for an extension on the 90-day window for genuinely difficult fixes; we will not ask for an extension to delay an embarrassment.

### Severity scale

We use **CVSS v4.0**. We map back to High/Medium/Low for human-readable communication, but the numeric vector is the source of truth.

### Safe harbor

Good-faith research that:

- Stays inside the scope listed in [§2 Scope](#2-scope)
- Uses **only your own** API key and tenant
- Does not exfiltrate or attempt to access other customers' data
- Stops as soon as a vulnerability is confirmed (does not pivot, escalate, or persist)
- Reports privately via the channel above

…will not be the subject of legal action from 5CEOS or its affiliates. We will publicly thank you in [§5 Hall of Thanks](#5-hall-of-thanks) if you want the credit and won't if you don't.

---

## 2. Scope

### In scope

| Surface | Where to look |
|---|---|
| Gateway code in this repo | [`github.com/5CEOS-DRA/cogos-api`](https://github.com/5CEOS-DRA/cogos-api) |
| Deployed production endpoints | `https://cogos.5ceos.com/*` |
| Public landing, demo, and whitepaper pages | `/`, `/demo`, `/whitepaper` |
| Health endpoint | `/health` |
| Customer-key auth flow | `Authorization: Bearer sk-cogos-…` on `/v1/*` |
| Admin auth flow | `X-Admin-Key` header on `/admin/*` |
| Stripe webhook signature verification | `POST /stripe/webhook` |
| Response signature (`X-Cogos-Signature`) verification logic | every `/v1/*` response |
| Constrained-decode bypass (output not conforming to a supplied JSON Schema) | `POST /v1/chat/completions` with `response_format` |
| Image build + signing pipeline | `scripts/deploy-update.sh`, `Dockerfile` |

### Out of scope

| Surface | Why |
|---|---|
| Third-party model weights (Qwen 2.5, any future open-weight model we serve) | Upstream of us. Report at the model author's tracker. |
| Customer-side key compromise (their laptop, their CI, their secret manager) | We can't help if their key is leaked. We **can** revoke a key on request — see `/admin/keys/:id/revoke`. |
| Social engineering of 5CEOS staff or customers | Out-of-band; report to `support@5ceos.com` with `[SECURITY]` subject prefix as standard abuse if you observe it, but it's not a code-defect bounty target. |
| Physical access to 5CEOS infrastructure | Not in the threat model of an OSS gateway. |
| Volumetric denial of service (L3/L4 floods, hash collision floods, etc.) | Handled at the Cloudflare edge; report via [Cloudflare's abuse flow](https://www.cloudflare.com/abuse/) so the trace data lands in the right place. |
| Issues in third-party OSS dependencies (Express, Stripe SDK, etc.) | Report **upstream first**, then ping us so we can pull the patched version once published. |
| Hosted inference providers we forward to (when `UPSTREAM_PROVIDER=openai` points at someone else's API) | Their security boundary, not ours. |

---

## 3. Verifiable security claims

Every claim below maps to a command you can run **right now** to check us. If a claim is rolling out and not fully shipped today, we say so explicitly and mark it `TODO`.

### 3.1 OSS gateway source

**Claim:** The gateway code you talk to in production is exactly the code in this repo. No closed-source business logic sits between the customer request and the inference engine on the audited path.

**Verify:**

```bash
git clone https://github.com/5CEOS-DRA/cogos-api.git
cd cogos-api
# Inspect the request path:
grep -n "v1/chat/completions" src/*.js
```

The deployed image is built from this tree via `scripts/deploy-update.sh`; the image-signing claim in §3.2 lets you bind a specific revision to a specific commit.

---

### 3.2 Image signature (cosign)

**Claim:** Every deployed image is signed with a 5CEOS-controlled cosign key before it is rolled to the Container App. Customers can verify the deployed image hash against the public key.

**Verify:**

```bash
cosign verify \
  --key https://cogos.5ceos.com/cosign.pub \
  cogos5ceos.azurecr.io/cogos-api:vN
```

…where `vN` is the current image tag (visible in the Azure portal, or via `az containerapp show` if you have read access).

**Status:** **Rolling out in deploy cadence.** Signing is wired in `scripts/deploy-update.sh` as of this week; the public key publication at `https://cogos.5ceos.com/cosign.pub` and the first enforced-verify release tag are `TODO` and will be announced in a `SECURITY-NOTICE.md` change here. Verify against any release ≥ that announced version. The first few signatures may be best-effort while the keypair is bootstrapped — `cosign verify` against earlier images will return "no matching signatures."

---

### 3.3 Response signature (HMAC)

**Claim:** Every successful `/v1/*` response carries an `X-Cogos-Signature` header. The signature is an HMAC over the response body, keyed by a per-tenant secret issued at the same time as the customer's API key. A customer can verify that the body they received was emitted by us and not a man-in-the-middle.

**Verify (server side):** the HMAC code path lives in this repo — read it before you trust it.

**Verify (client side):**

```bash
# Issue a key (this prints both api_key and signing_secret once)
curl -sX POST https://cogos.5ceos.com/admin/keys \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"myorg","tier":"starter"}'

# Make a call and capture the signature header
curl -isX POST https://cogos.5ceos.com/v1/chat/completions \
  -H "Authorization: Bearer sk-cogos-…" \
  -H "Content-Type: application/json" \
  -d '{"model":"cogos-tier-b","messages":[{"role":"user","content":"ping"}]}' \
  | tee /tmp/resp.txt

# Extract body and signature; verify with HMAC-SHA256(secret, body) — recipe at /cookbook#verify-signature
```

The receipe at `https://cogos.5ceos.com/cookbook#verify-signature` includes a 12-line Python and Node snippet; both produce a single byte-for-byte equality check against the header.

**Status:** Shipped.

---

### 3.4 Open determinism bench

**Claim:** The "same call in, same bytes out" claim on our landing page is auditable by anyone, not just by us. We publish the bench, you can run it against the live endpoint, and the resulting CSV is the public artifact.

**Verify:**

```bash
git clone https://github.com/5CEOS-DRA/llm-determinism-bench.git
cd llm-determinism-bench
# Read the README — it points at any cogos.5ceos.com deployment
# and emits a CSV with hash-per-request rows.
```

If a deployment drifts, the CSV shows it the same day. We re-run this on a published cadence and post the artifact; you don't have to take our word for "we re-ran it."

**Status:** Shipped (the bench repo is OSS, the cadence run is published).

---

### 3.5 Customer-key auth flow

**Claim:** Customer API keys are stored as sha256 hashes; the plaintext key is shown to the customer exactly once at issue time and never returned again. A database leak of `data/keys.json` does **not** leak usable keys.

**Verify:**

```bash
# In this repo:
grep -n "createHash\|sha256" src/*.js
# Inspect the issue path; confirm hashing happens before write,
# and that /admin/keys list endpoints return the hash, never the plaintext.
```

`data/keys.json` is mode `0600` and gitignored; on the production substrate this maps to the equivalent restricted storage tier.

**Status:** Shipped.

---

### 3.6 Admin auth flow

**Claim:** Admin operations (issue / revoke key, list keys, read usage) require `X-Admin-Key: <ADMIN_KEY-env>`. Rotation is a single env-var change; revocation is immediate.

**Verify:**

```bash
# Should 401:
curl -sI https://cogos.5ceos.com/admin/keys

# Should 200 if you have the env value:
curl -sI -H "X-Admin-Key: <admin-key>" https://cogos.5ceos.com/admin/keys
```

**Status:** Shipped.

---

### 3.7 Stripe webhook signature verification

**Claim:** Inbound webhooks at `POST /stripe/webhook` are gated on a valid `Stripe-Signature` header verified against `STRIPE_WEBHOOK_SECRET`. An attacker who can forge a `checkout.session.completed` body without a valid signature cannot trigger key issuance.

**Verify:**

```bash
# Should 400 (signature missing/invalid):
curl -sI -X POST https://cogos.5ceos.com/stripe/webhook \
  -H "Content-Type: application/json" -d '{}'
```

The verification path lives in this repo — read it before you trust it.

**Status:** Shipped.

---

### 3.8 Schema-enforced output

**Claim:** When a request includes `response_format: { type: "json_schema", json_schema: ... }`, the output is grammar-constrained at the token level by the upstream inference engine. Non-conforming output is **physically impossible**, not retried or filtered after the fact.

> **Important caveat:** schema-enforcement constrains the **shape** of the output, not its **truth value**. The model can still output a schema-valid lie. See [§4 What we don't defend against](#4-what-we-explicitly-dont-defend-against).

**Verify:** issue a `/v1/chat/completions` with a strict schema requiring `{ "answer": integer }`, then attempt prompts that would normally elicit a string answer ("explain why 2+2=4"). The response body conforms to the schema by construction.

**Status:** Shipped.

---

## 4. What we explicitly don't defend against

A security policy that claims to defend against everything is a security policy you can't trust. Here's the honest list. If your threat model includes any of these, you need a control upstream of us, not a feature from us.

### 4.1 Customer's own key compromise

If your `sk-cogos-…` key leaks — committed to a public repo, exfiltrated from a developer laptop, captured by a malicious browser extension — we cannot retroactively help. We **can** revoke the key on request (instant), rotate the issuing secret, and replay your usage log to identify anomalous traffic. We cannot un-leak the key.

**Your control:** treat the key like a database password. Store it in a secrets manager. Rotate on staff offboarding. Watch your `/admin/usage` log.

### 4.2 Model output safety / hallucination

We constrain output **shape** (schema). We do **not** constrain output **truth**. A model can return `{ "patient_diagnosis": "fictional condition the model invented" }` and pass schema validation. We make no warranty that the model's reasoning is correct, accurate, current, or non-fabricated.

**Your control:** treat LLM output as untrusted input. Run domain validation on the values, not just the shape.

### 4.3 Prompt injection at the LLM level

If a customer concatenates untrusted external text (a web page, a user-submitted document, an email body) into the prompt, an attacker can inject instructions that steer the model. Constrained decode forces the **output schema** to be valid; it does not prevent the model from doing what the injected instruction says, within that schema.

**Your control:** never pass untrusted text directly into the prompt slot. Separate "instructions you control" from "data the model summarizes" using the conventions documented at `/cookbook#prompt-injection`.

### 4.4 Constant-time inference / timing channels

We do **not** defend against sub-second timing-channel attacks on the inference path. Response latency is observable (`X-Cogos-Latency-Ms` is in every response) and varies with input length, model tier, and upstream load. An attacker with high-volume query access can, in principle, infer some properties of the upstream model state from timing.

**Your control:** if you need constant-time semantics, you need a different architecture (homomorphic encryption, secure enclaves, batched-fixed-latency wrappers). We don't pretend to offer this.

### 4.5 Determined nation-state insider on our side

Cosign image signing, OSS source code, append-only provenance logs, and published determinism benches **limit** the blast radius of a malicious insider — they don't **eliminate** it. A determined insider with the cosign key and CI access could ship a compromised image once, before detection. The combination of public source + published image hash + open bench means **the lie has a finite half-life**; it does not mean the lie cannot exist for the first few hours.

**Your control:** treat any single deployment as trustworthy on the timescale of the publication cadence — not on the timescale of a single request. If you need stronger isolation, run the gateway in your own infra (the OSS license permits this; reach out for a deployment guide).

### 4.6 Determinism under upstream provider changes

If you configure `UPSTREAM_PROVIDER=openai` against a hosted provider that silently swaps a model snapshot under a stable name, the determinism claim **fails on that path**. Our local-Ollama deployment with pinned weights is deterministic. A hosted-API deployment is deterministic **only** for as long as the provider's snapshot is stable.

**Your control:** pin to specific model snapshots upstream when the provider exposes them; run our bench against your deployment to confirm.

---

## 5. Hall of Thanks

Researchers who have responsibly disclosed an issue and asked to be credited will be listed here, with the date of report, severity, and a one-line description of the issue.

**Be the first.**

---

## Change log

Material changes to this document — new in-scope surfaces, scope removals, threat-model revisions, SLA changes — are summarized in `SECURITY-NOTICE.md` (created on first such change) and called out in the repo's release notes. The current document is the source of truth at `HEAD`; historic versions are recoverable via `git log -- SECURITY.md`.
