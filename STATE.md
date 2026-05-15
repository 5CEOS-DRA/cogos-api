# State of cogos-api — snapshot as of 2026-05-14

This file is the operator's "what's actually shipped" reference. It's deliberately not the marketing copy, the whitepaper, or the SECURITY_HARDENING_PLAN roadmap — it's the answer to *"if I sat down at this repo cold tomorrow, what is currently live, what's in main but not yet exercised, and what's still future work?"*

Update this file (or write a new dated snapshot next to it) whenever the production posture changes materially. Prior snapshots are useful as history, so prefer adding a new file over rewriting this one when the delta is large.

---

## What's live in production (cogos.5ceos.com)

**Deployment target:** Azure Container Apps
- Subscription: `690985d3-9a58-4cd7-9e5e-4a38c0246242`
- Resource group: `brain5-aca2`
- App: `cogos-api`
- Environment: `b5-eastus`
- Public FQDN: `cogos-api.proudsea-75ca2c6f.eastus.azurecontainerapps.io`
- Custom domain: `cogos.5ceos.com` (managed cert `cogos-5ceos-com-cert`)
- Current image: `cogos5ceos.azurecr.io/cogos-api:v13`
- Image base: `gcr.io/distroless/nodejs20-debian12:nonroot` (no shell, no package manager, uid 65532)
- Active revision: `cogos-api--0000025` (100% traffic, Healthy)
- Rollback target: `cogos5ceos.azurecr.io/cogos-api:v12` (the pre-hardening image)

**Inference backend:** `cogos-inference` (sibling Container App, internal-only ingress)
- Image: Ollama runtime with `qwen2.5:3b-instruct` (Tier B) + `qwen2.5:7b-instruct` (Tier A) baked
- Routing: deterministic via `tierForTask(taskShape) → tier`, no learned behavior

### Verifiable security claims (each has a curl/cosign command)

| Claim | Verify with |
|---|---|
| Every `/v1/*` response carries `X-Cogos-Signature: hmac-sha256(hmac_secret, body)` | `curl -i https://cogos.5ceos.com/v1/models -H "Authorization: Bearer <key>"` → look at headers |
| Customer can use Ed25519 keypair auth instead of bearer (we store only the pubkey) | `POST /admin/keys` with `{"scheme":"ed25519",…}` |
| Per-tenant audit log is hash-chained | `GET /v1/audit?since=0` → response includes `chain_ok: true` |
| Container image is cosignable | `cosign verify --key https://cogos.5ceos.com/cosign.pub cogos5ceos.azurecr.io/cogos-api:v<N>` *(v13 not signed; signing begins on the next deploy with `COSIGN_KEY_FILE` set)* |
| Cosign pubkey is publicly fetchable | `curl https://cogos.5ceos.com/cosign.pub` → live PEM |
| Admin-key compare is constant-time | Source: `src/auth.js` uses `crypto.timingSafeEqual` |
| No live admin dashboard exposed | `curl -I https://cogos.5ceos.com/admin/live` → 404 |
| Scanner-target paths return canary content | `curl https://cogos.5ceos.com/.env` → fake env with AKIAIOSFODNN7EXAMPLE canary |
| Anomaly detector in shadow mode | Logs to `data/anomalies.jsonl`; doesn't block. See `src/anomaly.js` |
| Distroless runtime — no shell in container | `docker run --rm cogos5ceos.azurecr.io/cogos-api:v13 sh` → fails (no sh) |
| HMAC + attestation key at rest | Envelope-encrypted with a KV-resolved DEK; disk breach yields ciphertext | source: `src/dek.js`, `src/keys.js`, `src/attestation.js` |

### Endpoints currently served

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/` | — | Landing page |
| GET | `/health` | — | Liveness (JSON or HTML, content-negotiated) |
| GET | `/whitepaper` | — | Technical whitepaper |
| GET | `/demo` | — | 90-second proof |
| GET | `/cookbook` | — | Six archetypal recipes + signature-verify recipe |
| GET | `/terms`, `/privacy`, `/aup` | — | Legal |
| GET | `/cosign.pub` | — | Cosign verification pubkey (PEM) |
| POST | `/signup` | — | Stripe Checkout session |
| GET | `/success` | — | Post-payment landing (shows API key + HMAC secret + Ed25519 private PEM for 24h) |
| GET | `/cancel` | — | Stripe cancel landing |
| POST | `/stripe/webhook` | Stripe-Signature | Subscription events |
| GET | `/v1/models` | Bearer or Ed25519 | OpenAI-compatible model list |
| POST | `/v1/chat/completions` | Bearer or Ed25519 | The product. Schema-locked decoding |
| GET | `/v1/audit` | Bearer or Ed25519 | Tenant's own hash-chained audit slice |
| POST | `/admin/keys` | X-Admin-Key | Issue customer key (`scheme: bearer|ed25519`) |
| GET | `/admin/keys` | X-Admin-Key | List issued keys (hashes never returned) |
| POST | `/admin/keys/:id/revoke` | X-Admin-Key | Soft-delete |
| GET | `/admin/usage` | X-Admin-Key | Append-only usage log read |
| GET | `/admin/packages` | X-Admin-Key | Package CRUD |
| POST | `/admin/packages` | X-Admin-Key | ↓ |
| PUT | `/admin/packages/:id` | X-Admin-Key | ↓ |
| DELETE | `/admin/packages/:id` | X-Admin-Key | ↓ |
| GET | `<honeypot paths>` | — | 23 paths return canary content + log to `logger.warn('honeypot_hit')` |

Honeypot paths: `/.env`, `/.env.local`, `/.env.production`, `/.git/config`, `/.git/HEAD`, `/.aws/credentials`, `/.aws/config`, `/wp-admin`, `/wp-admin/`, `/wp-login.php`, `/xmlrpc.php`, `/phpmyadmin/`, `/phpmyadmin/index.php`, `/server-status`, `/server-info`, `/admin.php`, `/administrator/`, `/login.php`, `/.DS_Store`, `/sitemap.xml.gz`, `/backup.sql`, `/database.sql`, `/dump.sql`, plus regex `/api/v(0|2|3)/*` returning 401.

---

## Key-vault state (Azure Key Vault `cogos-kv-16d2bb`)

| Secret name | Purpose |
|---|---|
| `cosign-private-key` | Cosign signing private key (encrypted PEM, password-protected) |
| `cogos-admin-key` | `ADMIN_KEY` value used by the gateway for X-Admin-Key compare |
| `jwt-secret` | Reserved for future JWT-based auth (not yet used by production code) |
| `github-token` | PAT used by the (retired) VM-based deploy in `deploy/`; can be revoked once that path is decommissioned |

---

## Container App env vars (production)

Set on the running revision via `az containerapp update --set-env-vars`:

- `COSIGN_PUBKEY_PEM` — full PEM string of the cosign public key (served at `/cosign.pub`)
- `NODE_ENV=production`
- `PORT=4444`
- `ADMIN_KEY` — pulled from KV at deploy time

Not yet set but supported by the code:
- `COSIGN_PUBKEY_FILE` — alternative to `COSIGN_PUBKEY_PEM`, points at a file in the container
- `ANOMALIES_FILE` — overrides default `data/anomalies.jsonl` path for the anomaly log
- `KEYS_FILE`, `USAGE_FILE`, `PACKAGES_FILE`, `STRIPE_EVENTS_FILE` — data file overrides

---

## At-rest encryption: Data Encryption Key (DEK)

HMAC secrets (one per customer record in `data/keys.json`) and the persisted attestation signing private PEM (`data/attestation-key.pem`) are envelope-encrypted under a Data Encryption Key resolved at startup. See `src/dek.js` for the substrate (AES-256-GCM, 12-byte random nonce per seal, 16-byte auth tag).

DEK source priority (first match wins):

1. `COGOS_DEK_HEX` env — 64-char hex string (32 raw bytes). Production wires this from Key Vault via Container App secret reference.
2. `COGOS_DEK_FILE` env — path to a file containing the hex DEK or raw 32 bytes. Used by operator scripts that mount the secret as a file.
3. On-disk fallback at `data/.dek` (mode 0600). Generated lazily on first access so dev + early-prod runs work without KV wiring.

The startup log line `dek_resolved {source: env|file|generated}` surfaces which path resolved. The key value itself is never logged.

**Operator action — flip from on-disk-generated DEK to KV-resolved:** set `COGOS_DEK_HEX` env on the Container App from a KV secret reference (e.g. `@Microsoft.KeyVault(SecretUri=...)`), then `az containerapp update --set-env-vars COGOS_DEK_HEX=<secret-ref>`. Existing records keep working because the in-process DEK doesn't change — the key value in KV must match the value previously generated. To rotate the DEK itself, see the TODO below.

**TODO — DEK rotation + legacy re-encrypt:**
- DEK rotation today is a stop-the-world story: rotating the DEK requires decrypting every sealed record with the old key and re-sealing under the new one. A `scripts/rotate-dek.sh` would let an operator do this offline; not built yet.
- Legacy records (issued before this card) carry cleartext `hmac_secret` on disk. They are migrated to the sealed shape on the next `verify()` touch (i.e. the next request authenticated by that key). Records that never touch verify stay cleartext until a force-migrate script is built.

---

## What's in `main` but not yet exercised in prod

Nothing significant — everything in `main` as of `c9f4bc3` is live on revision `0000025`. The follow-ups are:

1. **Cosign sign-on-deploy** — the deploy script's signing step is in place but `COSIGN_KEY_FILE` isn't set on the deployer's machine for the next deploy. Set `export COSIGN_KEY_FILE=$PWD/cosign.key` (or pull from KV) before the next `bash scripts/deploy-update.sh` and images start getting signed.
2. **Rate limit + anomaly fail-closed (v17, pentest F2 closure)** — both layers land in the next image, but `ANOMALY_FAIL_CLOSED=1` stays unset until ~1 week of shadow-mode telemetry confirms the default thresholds (auth_4xx > 10/min/IP, honeypot > 3/min/IP) don't false-positive legitimate traffic. The per-IP token-bucket (100/min global, 30/min `/admin/*`) and per-tenant bucket (1000/min on `/v1/*`) are **on by default** the moment v17 ships — they're cheap and conservative.

---

## Pentest findings — closed

| Finding | Severity | Closed in | How |
|---|---|---|---|
| F2: No application-layer rate limiting | MEDIUM | v17 (2026-05-14) | Two-layer defence: (a) explicit token-bucket rate limiter `src/rate-limit.js` mounted per-IP (100/min global, 30/min `/admin/*`) and per-tenant (1000/min on `/v1/*`); (b) anomaly detector `src/anomaly.js` flipped to fail-closed under `ANOMALY_FAIL_CLOSED=1`, where `auth_brute_force_suspected` fires a 5-min IP ban and `scanner_active` fires a 15-min ban that `rateLimitByIp` consults via `anomaly.isBlocked()`. Schema-violation and latency-drift signals stay log-only — they're per-tenant/global signals that would punish paying customers for upstream blips. 429 carries `Retry-After`. |

---

## Operator follow-ups still owned by Denny

- Monitor `support@5ceos.com` for `[SECURITY]` subject prefix disclosures (per SECURITY.md §1)
- Decide whether to bind `cogos.5ceos.com` to a CDN / Front Door layer (currently bare Container Apps managed cert)
- Decide retention policy for `cosign.key` on this laptop (`rm` it now that KV has a copy, or keep for convenience on every deploy)

---

## Future-work bucket (not started)

| Item | Scope | Blocker |
|---|---|---|
| **Operator analytics — Management Console "CogOS Analytics" tab** *(2026-05-15 request)* | Google-Analytics-shaped view of substrate activity: signups/day (free + paid), API calls/hr, anomaly hits, honeypot hits, rate-limit 429s, daily-cap 429s, active tenants, revenue (Stripe). Two-part: (a) cogos-api side — new `/admin/analytics/*` endpoints returning aggregated time-series JSON; (b) `5ceos-platform-internal` side — new "CogOS Analytics" Management Console tab that fetches + charts. | Two-repo coordination. cogos-api side is ~3-4h agent work; Management Console side depends on 5ceos-platform-internal's UI patterns |
| Public hash-chain head checkpoint endpoint | Add `GET /audit/checkpoint/latest`, optionally publish to Azure Blob hourly via Container App Job | None — straightforward; just hasn't shipped |
| Isolate-per-request (Week 4) | WASM/Wasmtime port of `src/chat-api.js` handler; runs in fresh isolate per request, no persistent state, no host syscall surface | ~1 focused week of work; not parallelizable |
| Cookbook recipe for Ed25519 signing | Python + Node recipe added to `/cookbook`, anchor `#ed25519-sign` | Small follow-up; SDK examples |
| Customer-side audit-verify Python script | Lives in `llm-determinism-bench` repo (not cogos-api); replays a tenant's audit slice + verifies chain | Separate repo, separate session |
| Offline admin ceremony (real implementation) | Replace live `/admin/keys` endpoints with signed-config-diff workflow per `scripts/admin-ceremony/README.md` | Design + server boot-time verifier; bigger card |

---

## Quick verify-everything command

```
bash scripts/smoke-api.sh        # uses an issued key to hit /v1/models, /v1/chat/completions, /v1/audit
```

Or hand-rolled:

```
curl -s https://cogos.5ceos.com/health
curl -s https://cogos.5ceos.com/cosign.pub | head -3
curl -sI https://cogos.5ceos.com/admin/live   # → 404
curl -s https://cogos.5ceos.com/.env | head -3   # → canary content
curl -sI https://cogos.5ceos.com/v1/audit       # → 401 (auth required, route exists)
```

---

## Reference

- SECURITY_HARDENING_PLAN.md — original 6-card roadmap (mostly complete now)
- SECURITY.md — disclosure policy, scope, verifiable claims
- README.md — endpoint table + upstream selection
- scripts/cosign-setup.sh — Step 1 keypair generation
- scripts/cosign-upload-to-kv.sh — Step 2 KV upload
- scripts/deploy-update.sh — rolling-revision deploy + cosign sign step
- scripts/admin-ceremony/README.md — design target for retiring live admin endpoints
