# Change Management Policy

Last reviewed: 2026-05-14

This policy covers **TSC CC8.1** (authorization, design, development, configuration, documentation, testing, approval, and implementation of changes). It describes how a code change becomes a production artifact at `cogos-api`, and what records that path leaves.

The audience is a SOC 2 auditor evaluating design effectiveness. Every claim here points at a file in the source tree or an artifact in our deployment pipeline.

---

## 1. Scope

This policy covers changes to:

- The `cogos-api` Node.js source (`src/**`)
- The container image (`Dockerfile`)
- The deployment script (`scripts/deploy-update.sh`)
- The Container App configuration (env vars, ingress rules, scaling rules)
- The package definitions (`data/packages.json` / `src/packages.js`)
- The Stripe Product/Price catalog (when sync'd from packages)

It does **not** cover:

- Customer-side configuration changes (out of scope)
- Sub-processor changes (covered by `vendor-management-policy.md`)
- Inference model weight updates (treated as a special change class; see §6)

---

## 2. Authorization

### 2.1 Source changes

All source changes land via a `feat/*` or `fix/*` branch merged into `main`. The branch model is:

- Branches are short-lived (hours to days, never weeks)
- Merges to `main` are squash-merges or fast-forward, never merge commits with unrelated history
- The `main` branch is the deployment-target branch; nothing is deployed off a feature branch

The repository is currently private. Source-read access for customers and auditors is available under NDA per `SECURITY.md` §3.1. A future flip to public OSS is deferred per `SECURITY_HARDENING_PLAN.md`.

### 2.2 Authorization gate

The operator is the sole author and approver at the current scale. This is honestly disclosed in `personnel-security-policy.md` as a separation-of-duties gap, with the following compensating controls:

- Every commit is signed in git (verifiable via `git log --show-signature`)
- Every commit is auditable via the public/private repo history with `Co-Authored-By:` trailers identifying any LLM-assisted authorship
- Every production deployment runs `scripts/deploy-update.sh`, which is the single authorized path
- The deploy script enforces a typed-token gate the operator must enter manually — see §3.3 below

When the operator population grows beyond one, this policy gets a "two-person review" amendment.

---

## 3. Production deployment path

### 3.1 The only authorized path

**`scripts/deploy-update.sh` is the only way code reaches production.** Auditor: ask to see the script. It is the literal definition of what runs on a deploy.

The script:

1. Verifies the working tree is clean and on `main`
2. Reads the current image tag, increments to `v<N+1>`
3. Builds the image via `az acr build` (no local Docker required; build runs in Azure)
4. Signs the image via `cosign sign` against the cosign private key (currently from `COSIGN_KEY_FILE`; KV-sourced when set)
5. Updates the Container App revision via `az containerapp update --image cogos5ceos.azurecr.io/cogos-api:v<N+1>`
6. Verifies the new revision serves `/health` 200 before declaring success
7. Records the deploy in the operator's local journal (not in-repo to avoid noisy commits)

### 3.2 Image immutability

Container images in `cogos5ceos.azurecr.io` are tagged once and never overwritten. A rebuild bumps the tag. Rolling back is changing the Container App image reference to the prior tag — the prior image is byte-identical to its original build.

Cosign signatures bind each image hash to its tag. A customer or auditor verifies a running image with:

```bash
cosign verify \
  --key https://cogos.5ceos.com/cosign.pub \
  cogos5ceos.azurecr.io/cogos-api:v<N>
```

(Note: cosign signing went live in this hardening sprint; images prior to that point may return "no matching signatures." See `STATE.md` for the cutover release.)

### 3.3 Manual TTY gate

`scripts/deploy-update.sh` includes a manual prompt that the operator must type a confirmation token into. This is intentionally NOT automatable — it ensures every deploy has a human-in-the-loop decision moment. Auditor: this is the closest equivalent we have to a two-person review at solo-operator scale.

The deploy script does NOT run in CI. We have not wired GitHub Actions to deploy. This is deliberate: a CI compromise should never directly own production.

---

## 4. Testing

### 4.1 Pre-merge testing

`npm test` runs the full Jest suite (119 tests at the time of this policy revision). Every test must pass before a branch can be merged to `main`. This is enforced by operator discipline, not by a branch-protection rule (the repo is private; branch protection on a single-operator repo adds friction without adding signal).

Test coverage includes:

- Auth flow tests (`tests/auth.test.js`, `tests/ed25519.test.js`)
- Audit-chain integrity tests (`tests/audit.test.js`, `tests/usage.test.js`)
- API surface tests (`tests/api.test.js`)
- Stripe integration tests, mocked at the SDK layer (`tests/stripe.test.js`)
- Honeypot, anomaly detector, package CRUD, response signing

### 4.2 Determinism bench

Outside the unit-test loop, the open-source [`llm-determinism-bench`](https://github.com/5CEOS-DRA/llm-determinism-bench) is run against the live endpoint on a published cadence. Drift in inference output shows up in the CSV the same day. This is the public-verifiable counterpart to internal QA.

### 4.3 Smoke test

`bash scripts/smoke-api.sh` runs an end-to-end check against the live endpoint after every deploy. It hits `/v1/models`, `/v1/chat/completions`, and `/v1/audit` with a real issued key and verifies the responses.

---

## 5. Configuration management

### 5.1 Environment variables

Production env vars are set on the Container App revision via `az containerapp update --set-env-vars`. The current set is documented in `STATE.md` §"Container App env vars (production)". Auditor: ask to see this section.

Secrets (`ADMIN_KEY`, `COSIGN_PUBKEY_PEM`, future `STRIPE_SECRET_KEY`) are sourced from Azure Key Vault `cogos-kv-16d2bb`. The Container App references the secret by name, not by value — no plaintext secret ever appears in `az` command history.

### 5.2 Package catalog changes

`data/packages.json` is editable via the `/admin/packages` CRUD endpoints (X-Admin-Key gated). Each create / update / delete logs:

- `admin_packages_create_failed` / `admin_packages_update_failed` / `admin_packages_delete_failed` on failure
- An info-level event on success
- The packaged change reaches Stripe (when `STRIPE_SECRET_KEY` is set) via the sync code in `src/packages.js`

Pricing changes require explicit operator sign-off — see `SECURITY_HARDENING_PLAN.md` §"Coordination rules" rule 6.

---

## 6. Special change classes

### 6.1 Inference model updates

Updating the Tier A or Tier B model is an env-var change (`UPSTREAM_MODEL_TIER_A`, `UPSTREAM_MODEL_TIER_B`) followed by a Container App revision update. **Determinism is preserved only when the upstream model snapshot is stable** — this is documented in `SECURITY.md` §4.6 and `data-classification-policy.md` §6.

The sibling `cogos-inference` Container App holds the model weights baked in. A model update means rebuilding that image with new weights. Operator: never silent-update a model; always bump the inference image tag so customers running the determinism bench can correlate drift to a specific date.

### 6.2 Schema changes

Changes to the audit-log hash chain payload (`src/usage.js` `canonicalChainPayload`) are **chain-breaking**. The fixed-order JSON serialization is load-bearing — see the comment block in `src/usage.js`. A schema change must:

1. Be documented as a chain-epoch boundary
2. Bump the epoch counter in the canonical payload (currently implicit; future versions will make this explicit)
3. Re-run any external chain-verifier scripts against the new format

This is the change class with the highest blast radius. Auditor: ask for the most recent schema-change rationale in the git log if applicable.

---

## 7. Rollback procedure

Rollback to a prior image is documented in the footer of `scripts/deploy-update.sh`. The procedure is:

1. Identify the prior tag (e.g. `v12` if the current is `v13`)
2. Run `az containerapp update --name cogos-api --resource-group brain5-aca2 --image cogos5ceos.azurecr.io/cogos-api:v12`
3. Verify `/health` 200 on the new revision
4. Confirm `cosign verify` against the rolled-back tag still passes (it should — signatures persist)

Rollback time target: < 5 minutes from decision to verified-serving prior version.

---

## 8. Audit trail

Every change in this policy leaves at least one of:

- A commit in the `cogos-api` git history (with `Co-Authored-By:` trailers where LLM-assisted)
- A Container App revision in Azure (immutable, queryable via `az containerapp revision list`)
- An ACR image tag (immutable)
- A cosign signature (verifiable via `cosign verify`)
- A Winston log line (admin endpoint actions)

The `/admin/soc2/evidence-bundle` endpoint snapshots the current image tag, signature status, and recent admin actions into a single JSON blob the auditor can capture.

---

## 9. Review

This policy is reviewed at least annually. The next review date is 2027-05-14. Material change-process modifications (new authorization gates, CI/CD wired in, deploy-script changes that affect the testing gate) trigger an immediate review.

Reviewed annually or when control surface changes materially.
