# Business Continuity Plan

Last reviewed: 2026-05-14

This plan covers **TSC A1.2** (environmental protections, including physical and procedural safeguards) and **TSC A1.3** (recovery from environmental and procedural failures). It documents the recovery path for `cogos-api` when something goes wrong with the substrate, the data, or the deployment itself.

The audience is a SOC 2 auditor evaluating availability commitments and an operator using this as a runbook during recovery.

---

## 1. Availability commitments

`cogos-api` does not currently publish a contractual SLA on uptime. The gateway is designed to run with no scheduled maintenance windows; Azure Container Apps performs rolling revision updates with zero downtime under normal conditions.

**Operational target**: 99% monthly availability, measured at the customer-facing edge (`https://cogos.5ceos.com/health`). This is an internal target, not a customer-facing commitment. A contractual SLA appears in customer agreements only for enterprise-tier subscriptions, negotiated case-by-case.

---

## 2. Architecture overview

The production substrate is:

- **Azure region**: `eastus` (single region — see §7 for the residual-risk note)
- **Resource group**: `brain5-aca2`
- **Container Apps environment**: `b5-eastus`
- **Gateway container**: `cogos-api`, public ingress with managed TLS cert
- **Inference container**: `cogos-inference`, internal-only ingress
- **Persistent volume**: Azure Files (LRS — locally-redundant storage by default in `eastus`)
- **Secret store**: Azure Key Vault `cogos-kv-16d2bb`
- **Image registry**: Azure Container Registry `cogos5ceos.azurecr.io`

A topology diagram lives in operator-local engineering notes (not in-repo to avoid stale-diagram drift); the auditor can request it at interview.

---

## 3. Failure classes and recovery

### 3.1 Code defect causing 5xx on /v1/*

**Detection**: Customer reports + `/health` may still return 200 (defect is in `/v1/*` path, not in health probe).

**Containment**: Roll back to the prior Container App revision.

**Procedure**:

```
# 1. Identify the current and prior revisions
az containerapp revision list \
  --name cogos-api \
  --resource-group brain5-aca2 \
  --output table

# 2. Shift 100% traffic to the prior revision
az containerapp revision set-mode \
  --name cogos-api \
  --resource-group brain5-aca2 \
  --mode single

az containerapp ingress traffic set \
  --name cogos-api \
  --resource-group brain5-aca2 \
  --revision-weight <prior-revision-name>=100
```

**Target time-to-recover**: < 5 minutes.

**Rollback target**: Currently `cogos5ceos.azurecr.io/cogos-api:v12` per `STATE.md`. The rollback procedure is also documented in the footer of `scripts/deploy-update.sh`.

---

### 3.2 Container App restart / region outage

**Detection**: Azure platform health alert, OR customer report of total outage, OR external monitor failing.

**Containment**: Azure Container Apps auto-restarts unhealthy containers. For a regional outage, no auto-failover exists today — see §7.

**Procedure (auto-restart, in-region)**: No operator action required. The Container App revision auto-restarts on health-probe failure. Operator verifies health is restored after the platform completes its action.

**Procedure (regional outage)**: Manual failover to a backup region is not currently provisioned. The recovery is "wait for Azure to restore the region." Azure RPO/RTO commitments apply; see Microsoft Online Services SLA. Customer-comms cadence during a regional outage: status update every hour via `support@5ceos.com` and (when implemented) the `/health` page.

**Target time-to-recover**: For in-region: < 10 minutes (Azure auto-restart). For regional outage: dependent on Azure restoration.

---

### 3.3 Persistent volume corruption / loss

**Detection**: `data/keys.json` or `data/usage.jsonl` fails to read or returns garbled content; `chain_ok: false` returned to a tenant on `/v1/audit`; key auth starts failing for previously-valid keys.

**Containment**: Stop write traffic to the volume (if practical) to prevent further corruption.

**Procedure**:

1. Capture a snapshot of the corrupted volume content for forensics (do not overwrite)
2. Restore from Azure Files backup (current setting: LRS with default Azure backup policy; tier-up to ZRS or GRS is on the roadmap)
3. After restore, run `verifyChain()` against `data/usage.jsonl` to confirm chain integrity
4. Notify affected tenants per `incident-response-plan.md` §6.4 — corruption that lost rows is a confidentiality-and-integrity incident, not just availability

**Target time-to-recover**: < 1 hour, dependent on backup currency.

**Residual gap**: Azure Files LRS does not protect against regional disaster. ZRS upgrade is on the operator-action list — see `risk-assessment.md` R-10.

---

### 3.4 Inference container outage

**Detection**: `/v1/chat/completions` returns 5xx with upstream-related error messages; `/v1/models` may still succeed since it doesn't proxy.

**Containment**: Restart `cogos-inference` container.

**Procedure**: `az containerapp revision restart --name cogos-inference --resource-group brain5-aca2 --revision <name>`. If restart doesn't recover, redeploy the inference image. The inference container's model weights are baked into the image; no separate volume to restore.

**Target time-to-recover**: < 5 minutes for restart; < 15 minutes for redeploy.

---

### 3.5 Signing-key loss

**Detection**: Operator cannot decrypt the cosign private key in Azure Key Vault, or the key version is accidentally deleted.

**Containment**: Generate a new cosign keypair using `scripts/cosign-setup.sh`. Upload the new private key to Key Vault using `scripts/cosign-upload-to-kv.sh`. Publish the new public key at `/cosign.pub` by updating the `COSIGN_PUBKEY_PEM` env var on the Container App revision.

**Procedure**:

1. Generate new keypair on a clean machine
2. Upload new private key to Key Vault as new secret version
3. Update Container App env to publish the new pubkey at `/cosign.pub`
4. Sign all subsequent images with the new key
5. Notify customers via `SECURITY-NOTICE.md` that the cosign key rotated; existing customer-side verification scripts need to fetch the new pubkey

**Target time-to-recover**: Half a day. New deploys can sign with the new key immediately; the customer-side verifier transition has lag if customers hard-coded the prior pubkey.

---

### 3.6 Total Azure-tenancy loss

**Description**: Operator's Azure tenancy is suspended (billing failure, account compromise that triggers Azure-side lockdown).

**Detection**: Operator cannot log into the Azure portal; CLI operations fail with authorization errors.

**Containment**: Contact Microsoft Azure Support immediately.

**Procedure**: This is the most severe failure class. Recovery depends entirely on Microsoft's ability to restore tenancy access. There is no operator-controlled recovery path. The compensating control is: the source code is in GitHub (separate platform), customer keys can be reissued on a new substrate, and Stripe holds the billing/customer-id relationship independent of our substrate.

**Target time-to-recover**: Days, dependent on Microsoft. This is the worst-case scenario and is one reason multi-cloud / fully self-hosted is on the longer-term roadmap.

---

## 4. Backup posture

| Asset | Backup | Cadence | Verified-restore tested |
|---|---|---|---|
| Source code | GitHub repo (origin/main) | Real-time on push | Yes (any clone is a restore-test) |
| Container images | ACR — immutable tags | Every deploy | Implicit (each tag is a re-deployable snapshot) |
| `data/keys.json`, `data/usage.jsonl`, `data/anomalies.jsonl`, `data/packages.json` | Azure Files snapshot | Azure default (currently relying on platform-default; explicit policy TBD) | **Not yet tested** — operator-action item |
| Azure Key Vault secrets | Soft-delete enabled (Key Vault default) | Continuous | Yes (Microsoft platform-tested) |
| Container App revision config | Stored in Azure platform state | Continuous | Yes (`az containerapp revision list`) |

**Honestly disclosed gap**: an explicit operator-tested restore of the persistent volume has not been performed. The auditor should record this as an operator-action item.

---

## 5. Audit log durability

The audit log (`data/usage.jsonl`) is the highest-criticality data class for SOC 2 evidence purposes — it's the substrate the hash-chain claim and the per-tenant audit query both depend on.

**Durability today**:

- Stored on Azure Files (LRS in `eastus`)
- Mode 0600 (owner-only access on the container's filesystem)
- Hash-chained per tenant (`prev_hash` / `row_hash` on each row) — tamper-evident
- No automated off-substrate backup at present

**Durability roadmap**:

- Hourly export to Azure Blob storage with multi-region redundancy
- Public hash-checkpoint endpoint (`/audit/checkpoint/<ts>`) that publishes the merkle-root of all tenant heads (see `SECURITY_HARDENING_PLAN.md` card #3 — "Future-work bucket" in `STATE.md`)

When the checkpoint endpoint ships, audit-log forgery becomes detectable by any third party with access to the public URL — not just by the customer pulling their own slice.

---

## 6. Communication during continuity events

| Event class | Customer notification | Internal notification |
|---|---|---|
| Auto-recovered in-region (< 10 min) | None unless customer asks | Operator-local log only |
| Manual rollback (5–15 min) | None unless customer-reported | Operator-local log + git commit revert if applicable |
| Regional outage | Email update every hour during outage | Operator-local log |
| Persistent volume corruption | Direct customer notification per `incident-response-plan.md` §6.4 | `SECURITY-NOTICE.md` entry |
| Tenancy loss | Direct customer notification with timeline ASAP | Stripe customer email list as backup channel |

---

## 7. Known residual gaps

Honestly disclosed for the auditor:

- **Single region**: see `risk-assessment.md` R-10. Multi-region failover is on the roadmap.
- **Azure Files LRS**: locally-redundant within `eastus` only. ZRS or GRS upgrade is operator-action.
- **No automated paging**: no PagerDuty / Opsgenie wire-up. Operator-on-call relies on manual monitoring.
- **Untested restore**: explicit verified-restore of `data/` has not been performed.
- **No customer-facing status page**: when implemented, will live at `https://status.cogos.5ceos.com/` or equivalent.

These are the items most likely to be raised in a Type II availability-effectiveness review. They're acceptable for Type I (design assessment); they would need to be closed or compensated for Type II.

---

## 8. Plan testing

The continuity plan is tested at least annually via a tabletop exercise: operator walks through each failure class in §3, identifies which step would block first if it actually happened, and documents the result. Findings update §3 and §7.

Last tested: **TBD pre-audit** (the next tabletop is scheduled at SOC 2 engagement kickoff).

---

## 9. Review

This plan is reviewed at least annually. The next review date is 2027-05-14. A test failure, an actual continuity event, or a material change to the substrate (new region, new sub-processor, new persistence class) triggers an immediate revision.

Reviewed annually or when control surface changes materially.
