# cogos-api On-Call Runbook

One-operator on-call (Denny). When a page fires from Action Group
`cogos-ops`, this is the page you flip to.

The page itself is paid for by `scripts/setup-monitoring.sh` — that
script wires 5 alert rules and an Action Group that emails/SMSes
`adams.denny@gmail.com` + `denny.adams@5ceos.com`.

```
SUB=690985d3-9a58-4cd7-9e5e-4a38c0246242
RG=brain5-aca2
APP=cogos-api
```

Deep health check (X-Admin-Key gated):

```
curl -s -H "X-Admin-Key: $ADMIN_KEY" https://cogos.5ceos.com/admin/health/deep | jq .
```

Public hash-chain verify (no auth):

```
curl -s https://cogos.5ceos.com/audit/checkpoint/verify | jq .
```

---

## Alert (a) — `cogos-gateway-5xx`  (severity 1, page now)

**What it means.** HTTP 5xx rate exceeded 5/minute averaged over a
5-minute window on the `cogos-api` Container App. The gateway is broken
or in a crash loop. Customers are seeing errors right now.

**What to check first.**

1. Hit the public root: `curl -sI https://cogos.5ceos.com/`. 200 means
   the gateway is up; rule probably already self-healed. 5xx or
   connection refused means it's down.
2. Recent revisions:

   ```
   az containerapp revision list --subscription $SUB -g $RG -n $APP \
     --query '[].{name:name, active:properties.active, replicas:properties.replicas, traffic:properties.trafficWeight, created:properties.createdTime}' \
     -o table
   ```

3. Container logs (last 100 lines):

   ```
   az containerapp logs show --subscription $SUB -g $RG -n $APP --tail 100
   ```

**How to recover.**

- If the latest revision is failing on boot, fail back to the previous
  revision by setting traffic weight 100 on the prior:

  ```
  az containerapp revision activate --subscription $SUB -g $RG -n $APP --revision <prev-revision-name>
  ```

- If the rolling restart will clear it (e.g. transient upstream Ollama
  hiccup), `bash scripts/deploy-update.sh` re-rolls to a fresh container
  image without code changes — same idempotent path used for every
  deploy.

**When to escalate.** Nobody to escalate to — Denny is the on-call.
Switch to "post-mortem mode": capture the logs and the failing
revision name, then fail back. Followup: open a TODO in
`STATE_2026_05_16.md` for the root cause.

---

## Alert (b) — `cogos-inference-latency-p99`  (severity 2, within 1h)

**What it means.** Average response time has been >15s over a 5-minute
window. Inference is degraded — customers are still being served, but
their requests are taking 10-20x longer than the warm-path target
(1.6-1.9s).

**What to check first.**

1. Is the sibling `cogos-inference` container alive?

   ```
   az containerapp show --subscription $SUB -g $RG -n cogos-inference \
     --query 'properties.runningStatus' -o tsv
   ```

2. Recent latency from the deep health endpoint:

   ```
   curl -s -H "X-Admin-Key: $ADMIN_KEY" https://cogos.5ceos.com/admin/health/deep | jq '.inference_p99_5min_ms'
   ```

3. Did we scale to zero? CPU+memory utilization:

   ```
   az monitor metrics list --subscription $SUB --resource $APP_ID \
     --metric "CpuUsage,MemoryWorkingSet" --interval PT1M
   ```

**How to recover.**

- Cold-start path is ~7.5s on CPU, warm is ~1.6-1.9s — if the gateway
  scaled to zero and then took traffic, a single cold call can push
  p99 over 15s. If utilization is back to normal, the alert will
  self-clear within the next eval window.
- If `cogos-inference` is degraded specifically, restart it:

  ```
  az containerapp revision restart --subscription $SUB -g $RG \
    -n cogos-inference --revision <current-revision>
  ```

**When to escalate.** Doctrine says "operator-owned inference only" —
there's no third-party hosted LLM fallback. If the inference container
is stuck and a restart doesn't help, the answer is to roll forward
`cogos-inference` from its repo (Qwen 2.5 3B image), not to flip a
provider switch.

---

## Alert (c) — `cogos-daily-cap-spike`  (severity 3, within a few hours)

**What it means.** More than 50 `daily_quota_exceeded` events fired in
an hour. Someone is burning free-tier quota fast; possible abuse, or
one customer just got picked up by an aggressive crawler.

**What to check first.**

1. Tenants triggering the cap. From the laptop:

   ```
   curl -s -H "X-Admin-Key: $ADMIN_KEY" \
     "https://cogos.5ceos.com/admin/analytics/rate-limits?since_ms=$(($(date +%s%3N)-3600000))" | jq .
   ```

2. Cross-reference top-by-usage tenants:

   ```
   curl -s -H "X-Admin-Key: $ADMIN_KEY" \
     "https://cogos.5ceos.com/admin/analytics/tenants?since_ms=$(($(date +%s%3N)-3600000))" | jq '.top_by_usage'
   ```

3. Anomaly correlations — same source IP repeatedly?

**How to recover.**

- Single-tenant outlier: revoke the key:

  ```
  curl -s -X POST -H "X-Admin-Key: $ADMIN_KEY" \
    https://cogos.5ceos.com/admin/keys/<key-id>/revoke
  ```

- Bulk pattern (scanner hitting many free keys): raise the per-IP rate
  limit cap via env override on the Container App, redeploy with
  `scripts/deploy-update.sh`.

**When to escalate.** No escalation needed for sev 3 — handle on the
next business day if it didn't fully self-clear.

---

## Alert (d) — `cogos-anomaly-burst`  (severity 2, within 1h)

**What it means.** More than 10 anomaly events (`scanner_active` or
`auth_brute_force_suspected`) in 5 minutes. Active probing of the
gateway is in progress.

**What to check first.**

1. Recent anomalies:

   ```
   curl -s -H "X-Admin-Key: $ADMIN_KEY" \
     "https://cogos.5ceos.com/admin/analytics/anomalies?since_ms=$(($(date +%s%3N)-3600000))" | jq .
   ```

2. Honeypot hits — what paths did they try?

   ```
   curl -s -H "X-Admin-Key: $ADMIN_KEY" \
     "https://cogos.5ceos.com/admin/analytics/honeypots?since_ms=$(($(date +%s%3N)-3600000))" | jq '.top_paths'
   ```

3. The anomaly subsystem auto-bans repeat offenders for a configurable
   window (see `src/anomaly.js` BAN_MS_*). Check whether the burst is
   already being absorbed by automatic bans.

**How to recover.**

- The anomaly + rate-limit + honeypot stack is fail-closed by design.
  Most bursts are absorbed without operator action. If a specific IP
  is bypassing the heuristic, escalate to a CIDR block at the Azure
  Front Door / ACA ingress layer (TODO: document the exact `az
  network` command set — currently manual).

**When to escalate.** If the burst includes any sign of authentication
brute-force on real keys (look for repeated `auth_4xx` counters tied
to the same `key_id`), revoke + reissue the affected customer's key
proactively.

---

## Alert (e) — `cogos-audit-chain-breach`  (severity 1, page now)

**What it means.** `/audit/checkpoint/verify` returned `ok: false`. The
per-tenant audit hash chain has a break — either a row was tampered
with, a row is missing, or the checkpoint hash itself doesn't match
the recomputed value. This is a customer-visible trust primitive and
the whole point of CogOS's pitch — investigate IMMEDIATELY.

**What to check first.**

1. Run verify directly (it's a public endpoint, no auth):

   ```
   curl -s https://cogos.5ceos.com/audit/checkpoint/verify | jq .
   ```

   The response shape (`broke_at_index`, `reason`,
   `expected_prev_hash`, `found_row_hash`, etc.) tells you exactly
   which row broke continuity and what the mismatch is. See
   `src/usage.js` `verifyChain()` for the failure-mode dictionary.

2. Latest checkpoint vs the live head:

   ```
   curl -s https://cogos.5ceos.com/audit/checkpoint/latest | jq .
   curl -s https://cogos.5ceos.com/audit/checkpoints | jq '.checkpoints[-3:]'
   ```

3. Deep health for the underlying state:

   ```
   curl -s -H "X-Admin-Key: $ADMIN_KEY" https://cogos.5ceos.com/admin/health/deep | jq '.chain_ok, .audit_writes_per_min'
   ```

**How to recover.**

- DO NOT rewrite `usage.jsonl`. The chain breakage IS the substrate
  truth right now — write-rewriting it destroys the audit primitive
  faster than the original break did.
- Capture a snapshot of `usage.jsonl`, `data/audit-checkpoints.jsonl`,
  and the recent Container App logs. Move them into a forensic copy
  (`data/forensic-YYYYMMDD/`) so they survive the next rolling
  restart.
- Identify the source of the break: was a row hand-edited? Did disk
  corruption land on a specific revision? Was there a deploy that
  rotated the data volume?
- Once the cause is known, document a "chain epoch boundary" event
  (the next genesis row gets a fresh prev_hash=ZERO) and publish a
  signed `INCIDENT-YYYYMMDD.md` from the operator account explaining
  what broke and why the new chain segment starts at the boundary.

**When to escalate.** This is the alert that compromises the product's
trust pitch. After capturing forensics, escalate by publishing the
incident — public-by-design is the right move on a transparency
primitive. Don't quietly patch and pretend.

---

## TODO (not implemented in this card)

- Slack incoming-webhook integration on the action group
- OpsGenie escalation policy for >15min unacked sev-1
- On-call rotation (currently single-operator)
- Custom-metric push of `usage.jsonl`-derived latency_ms via the
  Application Insights TrackMetric API so the latency alert can move
  from `avg ResponseTime` (Azure-platform proxy) to a true p99 over
  our own observation set
- Availability Test (web-test) hitting `/admin/health/deep` from
  multiple Azure regions — Application Insights supports this via
  `az monitor app-insights web-test create`; not automated by
  `setup-monitoring.sh` yet because it requires an X-Admin-Key value
  that we deliberately don't hardcode in the script
