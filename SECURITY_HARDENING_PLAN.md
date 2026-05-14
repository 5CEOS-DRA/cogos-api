# CogOS Security Hardening — Sibling Claude Briefing

**Status as of 2026-05-14:** the "more verifiable than competitors" hardening
sprint is in flight. Two of six moves landed. Four more are independently
shippable by sibling Claude sessions without colliding.

This file is the single source of truth. Pick a card, comment that you're
working on it (or just commit on a feature branch), ship it.

---

## ✅ DONE

### #5 — Strongest possible CSP + security headers · `1a5f...` (this commit chain)

`src/index.js` now has a `securityHeaders` middleware on every response:

- CSP: `default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self' https://checkout.stripe.com; base-uri 'none'; frame-ancestors 'none'; connect-src 'self'`
- HSTS: `max-age=63072000; includeSubDomains; preload`
- X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, Cross-Origin-{Opener,Resource}-Policy

The only inline-script removal needed was the `Copy key` button on `/success` — refactored to use `data-copy` attribute + external `/js/copy.js`. No new dependencies. Mozilla Observatory should rate A+.

### #1 — Open-source-prep audit (this session)

Sanity pass complete:
- No embedded secrets (all live in env / Container App secrets)
- Refactored "Denny's directive" comment to "operator directive" for OSS feel
- Updated `enterprise@5ceos.com` reference in comment to `support@5ceos.com` (matches no-sales doctrine)
- Azure subscription ID + RG name + ACR name are in script defaults but are NOT secrets per Azure docs (identifying info, not auth)
- Dockerfile is generic, no embedded creds
- `.gitignore` properly excludes `data/`, `.env`, `.env.local`

**To finish #1:** Denny flips the GitHub repo from PRIVATE to PUBLIC. That's the single remaining action — the codebase is OSS-ready.

---

## 🟡 OPEN — pick one

### #2 — HMAC-signed responses (3-4h, owner: TBD)

Goal: every `/v1/chat/completions` response gets an `X-Cogos-Signature: <hmac>` header. Customer's SDK verifies the signature against a per-key HMAC secret returned at issue time. Tamper-detection on every byte in transit.

**Plan:**
- On key issuance (`keys.js`), generate a 32-byte HMAC secret alongside the API key. Return BOTH on success page (and via admin API).
- In `chat-api.js` response pipeline, compute `HMAC-SHA256(secret, response_body_canonical)` and set the header.
- Canonical form: stable JSON serialization of `{id, model, choices, usage, cogos}` — write a helper in `crypto.js`.
- Add a verifier function to the `llm-determinism-bench` repo so customers can drop it in.
- Update `/cookbook` page with a verification recipe.
- Test: 5 calls, verify each signature client-side.

**Files to touch:** `src/keys.js` (extend record), `src/chat-api.js` (sign on response), new `src/crypto.js`, `src/landing.js` (success page shows HMAC secret), bench repo (verifier), `src/cookbook.js` (recipe #7).

### #3 — Public hash-chain checkpoints (4-6h, owner: TBD)

Goal: every audit log append updates a hash chain. Hourly, the head hash is published to `https://cogos.5ceos.com/audit/checkpoint/<unix_ts>`. Customers can verify their tenant's audit log is intact going back to any prior checkpoint.

**Plan:**
- In `usage.js` (the audit log), each appended row includes `prev_hash` (hash of all prior rows for that tenant) and `row_hash` (sha256 of canonical row + prev_hash). Genesis row has prev_hash = zero.
- New endpoint `GET /v1/audit/verify` (bearer auth, scoped to tenant) returns the customer's full chain so they can verify locally.
- New endpoint `GET /audit/checkpoint/latest` (public, no auth) returns the global head hash + timestamp.
- Background process (could be in-process every N writes, or a separate Container Apps Job hourly) computes the head and posts to a public Azure Blob URL.
- Bench repo gets a `verify-chain.py` script.

**Files to touch:** `src/usage.js` (extend append + add chain compute), `src/index.js` (new endpoints), new Azure resource (public blob container `cogos-audit-checkpoints`), bench repo (verifier).

**Architectural note:** the chain is per-tenant (each tenant has their own hash chain). The "global" checkpoint is the merkle-root-style aggregation of all tenant heads at that hour. Simpler v1: just publish the global hash of the entire usage.json file, customers verify their slice via the per-tenant verify endpoint.

### #4 — Cosign-signed container images (2-3h, owner: TBD)

Goal: every image pushed to ACR is cosigned. Customers (or anyone) can verify the running image was built and signed by us — no MITM, no swapped image in the registry.

**Plan:**
- Generate a cosign key pair locally (one-time, store cosign.key in Azure Key Vault, publish cosign.pub at `https://cogos.5ceos.com/cosign.pub`).
- Add a `cosign sign` step to `scripts/deploy-update.sh` after `az acr build`.
- Document verification in a new `SECURITY.md` (verify command: `cosign verify --key https://cogos.5ceos.com/cosign.pub cogos5ceos.azurecr.io/cogos-api:vN`).
- Add ACR policy enforcing signed images on pull (Container Apps will refuse unsigned images).
- Update `/whitepaper` §3 with the verification claim.

**Files to touch:** `scripts/deploy-update.sh`, new `SECURITY.md`, new `public/cosign.pub` (or serve via route), `src/whitepaper.js`.

### #6 — Per-tenant audit query API (2-3h, owner: TBD)

Goal: `GET /v1/audit` (bearer auth) returns the customer's own audit log entries, paginated. They can re-run the local hash-chain verification (#3) themselves. Full transparency to their own usage history.

**Plan:**
- New endpoint `GET /v1/audit?since=<unix_ms>&limit=<n>` in `src/index.js`.
- Auth: standard bearer (existing middleware).
- Response: array of audit entries scoped to the requesting tenant only.
- Pagination via `next_cursor` field.
- Update `/cookbook` with a "fetch your own audit" recipe.
- Test: customer A cannot see customer B's entries.

**Files to touch:** `src/index.js` (route), `src/usage.js` (add `readByTenant` filter), `src/cookbook.js` (recipe #8), new test in `tests/audit.test.js`.

---

## Coordination rules

1. **Pick a card by editing this file** — change "owner: TBD" to "owner: <session-id>" at the top of your card. Commit + push immediately so other sessions see it. If you abandon the work, change owner back to TBD.

2. **Branch per card** — `feat/sec-2-hmac`, `feat/sec-3-checkpoints`, etc. Don't all push to main.

3. **Commit hygiene** — use the `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>` trailer.

4. **Tests before commit** — `npx jest --runInBand` should still show 48+ green. Add new tests for any new endpoint.

5. **No deploy from sibling sessions without Denny's go.** Push to the branch, open a PR, let Denny merge + deploy. Each card's PR description must include "deploy verifier" curl commands.

6. **Don't touch packages.json on prod** unless required for the card. Pricing changes need separate sign-off.

7. **NEVER paste secrets in chat or commit messages** — same hard-never as today's session learned the hard way.

---

## Final state when all 6 ship

The CogOS security pitch becomes:

> *We sign every response. We sign every image. We open-sourced the gateway. We publish hash-chain checkpoints to a public URL. You can read our code, verify our images, query your own audit log, and re-run our determinism bench. There is no place where you have to take our word — every layer is independently verifiable.*

That's a transparency posture no LLM hosted competitor currently matches.
