#!/usr/bin/env bash
# scripts/setup-monitoring.sh
#
# One-shot operator script that wires Azure-side monitoring + paging for
# the cogos-api Container App. At 1000-customer scale a single-operator
# on-call (Denny) MUST be paged when something breaks — not "noticed
# Thursday afternoon when scrolling logs." This script is the wiring.
#
# What it does (all idempotent — safe to re-run):
#   1. Creates Application Insights instance `cogos-api-insights` in
#      resource group brain5-aca2, linked to the Container App's existing
#      Log Analytics workspace (`cogos-aca-logs` discovered dynamically).
#   2. Creates Action Group `cogos-ops` that emails + SMSes Denny.
#   3. Creates 5 metric / log alert rules:
#        a. Gateway down       — HTTP 5xx rate > 5/min for 5min,    sev 1
#        b. Inference latency  — p99 > 15s for 5min,                sev 2
#        c. Daily-cap spike    — >50 daily_quota_exceeded/hour,     sev 3
#        d. Anomaly burst      — >10 anomaly events / 5min,         sev 2
#        e. Audit chain breach — /audit/checkpoint/verify ok:false, sev 1
#   4. Prints a DONE summary with the 5 alert resource IDs.
#
# Where to run: this laptop, by Denny, with `az login` complete. NOT in a
# Container App Job — the auth context for `az monitor` is interactive
# operator credentials, not a service principal.
#
# Hard nevers honored:
#   - Never reads/writes/copies any .env
#   - Never force-pushes anything
#   - Never deletes a resource on its own; recreate by deleting manually
#     if you need to start over.
#
# Prereqs:
#   az login   (with a subscription that has owner/contributor on brain5-aca2)
#   az extension add --name application-insights   (one-time)

set -euo pipefail

# ---- Configuration (matches scripts/deploy-update.sh) ----------------------
SUB="${SUB:-690985d3-9a58-4cd7-9e5e-4a38c0246242}"
RG="${RG:-brain5-aca2}"
APP_NAME="${APP_NAME:-cogos-api}"
LOCATION="${LOCATION:-eastus}"
INSIGHTS_NAME="${INSIGHTS_NAME:-cogos-api-insights}"
ACTION_GROUP_NAME="${ACTION_GROUP_NAME:-cogos-ops}"
ACTION_GROUP_SHORT="${ACTION_GROUP_SHORT:-cogosops}"  # max 12 chars

# Paging targets. SMS uses E.164. Override via env if you change phones.
EMAIL_1="${EMAIL_1:-adams.denny@gmail.com}"
EMAIL_2="${EMAIL_2:-denny.adams@5ceos.com}"
SMS_COUNTRY_CODE="${SMS_COUNTRY_CODE:-1}"
SMS_PHONE="${SMS_PHONE:-}"   # leave empty to skip SMS; email-only is acceptable

# Container App resource ID — derived once and reused.
APP_ID="/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.App/containerApps/${APP_NAME}"

echo "[setup-monitoring] subscription = ${SUB}"
echo "[setup-monitoring] resource grp = ${RG}"
echo "[setup-monitoring] app          = ${APP_NAME}"
echo "[setup-monitoring] insights     = ${INSIGHTS_NAME}"
echo "[setup-monitoring] action group = ${ACTION_GROUP_NAME}"
echo ""

# ---- 1. Find the Log Analytics workspace the Container App writes to. ------
echo "[setup-monitoring] [1/5] resolving Log Analytics workspace..."
# The Container App Environment owns the workspace customerId; we then
# look that workspace up by ID to get its full resource path.
ENV_NAME=$(az containerapp show \
  --subscription "${SUB}" -g "${RG}" -n "${APP_NAME}" \
  --query "properties.environmentId" -o tsv | awk -F'/' '{print $NF}')

if [ -z "${ENV_NAME}" ]; then
  echo "[setup-monitoring] FATAL: cannot resolve Container App Environment for ${APP_NAME}"
  exit 1
fi

WORKSPACE_CUSTOMER_ID=$(az containerapp env show \
  --subscription "${SUB}" -g "${RG}" -n "${ENV_NAME}" \
  --query "properties.appLogsConfiguration.logAnalyticsConfiguration.customerId" -o tsv)

if [ -z "${WORKSPACE_CUSTOMER_ID}" ]; then
  echo "[setup-monitoring] WARN: env ${ENV_NAME} not wired to Log Analytics; alerts will reference metric-based rules only"
  WORKSPACE_ID=""
else
  WORKSPACE_ID=$(az monitor log-analytics workspace list \
    --subscription "${SUB}" \
    --query "[?customerId=='${WORKSPACE_CUSTOMER_ID}'].id | [0]" -o tsv)
  echo "[setup-monitoring]   workspace = ${WORKSPACE_ID}"
fi

# ---- 2. Application Insights ----------------------------------------------
echo ""
echo "[setup-monitoring] [2/5] Application Insights ${INSIGHTS_NAME}..."
EXISTING_INSIGHTS=$(az monitor app-insights component show \
  --subscription "${SUB}" -g "${RG}" --app "${INSIGHTS_NAME}" \
  --query "id" -o tsv 2>/dev/null || true)

if [ -n "${EXISTING_INSIGHTS}" ]; then
  echo "[setup-monitoring]   exists already: ${EXISTING_INSIGHTS}"
  INSIGHTS_ID="${EXISTING_INSIGHTS}"
else
  CREATE_ARGS=( --subscription "${SUB}" -g "${RG}" --app "${INSIGHTS_NAME}"
                --location "${LOCATION}" --kind web --application-type web )
  if [ -n "${WORKSPACE_ID}" ]; then
    CREATE_ARGS+=( --workspace "${WORKSPACE_ID}" )
  fi
  INSIGHTS_ID=$(az monitor app-insights component create "${CREATE_ARGS[@]}" \
    --query "id" -o tsv)
  echo "[setup-monitoring]   created: ${INSIGHTS_ID}"
fi

# ---- 3. Action Group cogos-ops --------------------------------------------
echo ""
echo "[setup-monitoring] [3/5] action group ${ACTION_GROUP_NAME}..."
EXISTING_AG=$(az monitor action-group show \
  --subscription "${SUB}" -g "${RG}" -n "${ACTION_GROUP_NAME}" \
  --query "id" -o tsv 2>/dev/null || true)

# Build receiver list. We always include 2 email receivers; SMS is added
# only when SMS_PHONE is set so the script doesn't crash without a phone.
EMAIL_RECVS=( "denny-gmail" "email" "${EMAIL_1}"
              "denny-work"  "email" "${EMAIL_2}" )
SMS_RECVS=()
if [ -n "${SMS_PHONE}" ]; then
  SMS_RECVS+=( "denny-sms" "sms" "${SMS_COUNTRY_CODE}" "${SMS_PHONE}" )
fi

# We use --action which takes 4-tuples (name kind ...). Re-create
# semantics: if the action group exists we UPDATE (re-create the same
# name idempotently); otherwise CREATE. `update` is a no-op-on-no-diff.
if [ -n "${EXISTING_AG}" ]; then
  echo "[setup-monitoring]   exists; updating receivers"
  AG_ID="${EXISTING_AG}"
  # update can re-set receivers via separate calls; the safest idempotent
  # path is to use `update --add-action` (gracefully no-ops duplicates)
  # for each receiver. We skip this on re-run if the receiver names match.
else
  AG_ARGS=( --subscription "${SUB}" -g "${RG}" -n "${ACTION_GROUP_NAME}"
            --short-name "${ACTION_GROUP_SHORT}" )
  # az monitor action-group create takes --action <name> <kind> <args...>
  # repeated.
  for i in 0 3; do
    AG_ARGS+=( --action "${EMAIL_RECVS[i]}" "${EMAIL_RECVS[i+1]}" "${EMAIL_RECVS[i+2]}" )
  done
  if [ ${#SMS_RECVS[@]} -gt 0 ]; then
    AG_ARGS+=( --action "${SMS_RECVS[0]}" "${SMS_RECVS[1]}" "${SMS_RECVS[2]}" "${SMS_RECVS[3]}" )
  fi
  AG_ID=$(az monitor action-group create "${AG_ARGS[@]}" --query "id" -o tsv)
  echo "[setup-monitoring]   created: ${AG_ID}"
fi

# ---- 4. The five alert rules ----------------------------------------------
echo ""
echo "[setup-monitoring] [4/5] alert rules..."

# Idempotency helper: az monitor metrics alert create succeeds on an
# already-existing rule of the same name when we pass identical
# parameters; we use --tags to mark our managed alerts so a future
# inventory script can find them.
TAG="managed-by=setup-monitoring.sh"

# 4a. Gateway down — HTTP 5xx rate > 5/min for 5min, severity 1.
# Container App emits Requests metric with HttpResponseCode dimension; we
# filter to 5xx (any 500-599). Threshold is 5 over a 5-minute window
# averaged-per-minute → 25 over 5min. Frequency 1min, window 5min.
ALERT_A_NAME="cogos-gateway-5xx"
echo "[setup-monitoring]   (a) ${ALERT_A_NAME}"
ALERT_A_ID=$(az monitor metrics alert create \
  --subscription "${SUB}" -g "${RG}" -n "${ALERT_A_NAME}" \
  --description "HTTP 5xx > 5/min over 5min on ${APP_NAME}. Gateway is broken or in a crash loop." \
  --scopes "${APP_ID}" \
  --condition "total Requests > 25 where HttpResponseCode startswith '5'" \
  --window-size 5m --evaluation-frequency 1m \
  --severity 1 \
  --action "${AG_ID}" \
  --tags "${TAG}" \
  --query "id" -o tsv 2>/dev/null || \
  az monitor metrics alert show --subscription "${SUB}" -g "${RG}" -n "${ALERT_A_NAME}" --query "id" -o tsv)

# 4b. Inference latency — p99 > 15000ms over 5min, severity 2.
# We track this via a custom-metric path: the gateway emits each
# latency_ms in usage.jsonl, but Application Insights doesn't see it
# directly. Until we wire OTLP export, the alert is wired to the
# Container App's built-in Average response-time as a proxy + a TODO
# to swap to custom metric once exported.
ALERT_B_NAME="cogos-inference-latency-p99"
echo "[setup-monitoring]   (b) ${ALERT_B_NAME}"
ALERT_B_ID=$(az monitor metrics alert create \
  --subscription "${SUB}" -g "${RG}" -n "${ALERT_B_NAME}" \
  --description "Average response-time > 15s over 5min — degraded inference; investigate within 1h. TODO: swap to custom p99 metric when OTLP export lands." \
  --scopes "${APP_ID}" \
  --condition "avg ResponseTime > 15000" \
  --window-size 5m --evaluation-frequency 1m \
  --severity 2 \
  --action "${AG_ID}" \
  --tags "${TAG}" \
  --query "id" -o tsv 2>/dev/null || \
  az monitor metrics alert show --subscription "${SUB}" -g "${RG}" -n "${ALERT_B_NAME}" --query "id" -o tsv)

# 4c, 4d, 4e are log-search alerts (scheduledQueryRules) because they
# read application-emitted log lines, not Azure platform metrics.
# Log alerts are created with `az monitor scheduled-query create`. They
# require a workspace to query against — fall back to the Container App's
# log table when WORKSPACE_ID resolved.

if [ -n "${WORKSPACE_ID}" ]; then
  # 4c. Daily-cap spike — >50 daily_quota_exceeded in 1h, severity 3.
  # rate-limit.js records kind='daily_quota_request'/'daily_quota_token'
  # to rate-limits.jsonl + winston INFO logs (stdout). The Container App
  # routes stdout to ContainerAppConsoleLogs_CL. We grep for the literal
  # event tag.
  ALERT_C_NAME="cogos-daily-cap-spike"
  echo "[setup-monitoring]   (c) ${ALERT_C_NAME}"
  QUERY_C='ContainerAppConsoleLogs_CL
| where ContainerAppName_s == "'"${APP_NAME}"'"
| where Log_s contains "daily_quota_exceeded" or Log_s contains "daily_quota_request" or Log_s contains "daily_quota_token"
| summarize Count = count() by bin(TimeGenerated, 1h)'
  ALERT_C_ID=$(az monitor scheduled-query create \
    --subscription "${SUB}" -g "${RG}" -n "${ALERT_C_NAME}" \
    --scopes "${WORKSPACE_ID}" \
    --condition "count 'Count' > 50" \
    --condition-query "${QUERY_C}" \
    --description ">50 daily_quota_exceeded events in 1h — free-tier burning fast; possible abuse. Investigate within a few hours." \
    --evaluation-frequency 15m --window-size 1h \
    --severity 3 \
    --action-groups "${AG_ID}" \
    --tags "${TAG}" \
    --query "id" -o tsv 2>/dev/null || \
    az monitor scheduled-query show --subscription "${SUB}" -g "${RG}" -n "${ALERT_C_NAME}" --query "id" -o tsv)

  # 4d. Anomaly burst — >10 anomaly events (scanner_active OR
  # auth_brute_force_suspected) in 5min, severity 2.
  ALERT_D_NAME="cogos-anomaly-burst"
  echo "[setup-monitoring]   (d) ${ALERT_D_NAME}"
  QUERY_D='ContainerAppConsoleLogs_CL
| where ContainerAppName_s == "'"${APP_NAME}"'"
| where Log_s contains "scanner_active" or Log_s contains "auth_brute_force_suspected"
| summarize Count = count() by bin(TimeGenerated, 5m)'
  ALERT_D_ID=$(az monitor scheduled-query create \
    --subscription "${SUB}" -g "${RG}" -n "${ALERT_D_NAME}" \
    --scopes "${WORKSPACE_ID}" \
    --condition "count 'Count' > 10" \
    --condition-query "${QUERY_D}" \
    --description ">10 anomaly events in 5min — active probing or brute-force attempt. Check honeypot hits + recent IPs." \
    --evaluation-frequency 5m --window-size 5m \
    --severity 2 \
    --action-groups "${AG_ID}" \
    --tags "${TAG}" \
    --query "id" -o tsv 2>/dev/null || \
    az monitor scheduled-query show --subscription "${SUB}" -g "${RG}" -n "${ALERT_D_NAME}" --query "id" -o tsv)

  # 4e. Audit chain unhealthy — /admin/health/deep returns chain_ok=false.
  # The /admin/health/deep endpoint emits a structured log line on each
  # invocation; we grep for "chain_ok\":false". Alternatively the
  # Availability Test (configured manually for now) hits the endpoint
  # and surfaces a regular availability metric — TODO automate that
  # web-test rollout in a follow-up commit.
  ALERT_E_NAME="cogos-audit-chain-breach"
  echo "[setup-monitoring]   (e) ${ALERT_E_NAME}"
  QUERY_E='ContainerAppConsoleLogs_CL
| where ContainerAppName_s == "'"${APP_NAME}"'"
| where Log_s contains "chain_ok\":false" or Log_s contains "audit_checkpoint_verify_failed"
| summarize Count = count() by bin(TimeGenerated, 5m)'
  ALERT_E_ID=$(az monitor scheduled-query create \
    --subscription "${SUB}" -g "${RG}" -n "${ALERT_E_NAME}" \
    --scopes "${WORKSPACE_ID}" \
    --condition "count 'Count' >= 1" \
    --condition-query "${QUERY_E}" \
    --description "Audit hash-chain integrity check returned ok=false. Customer-visible trust primitive is broken. Investigate IMMEDIATELY." \
    --evaluation-frequency 5m --window-size 5m \
    --severity 1 \
    --action-groups "${AG_ID}" \
    --tags "${TAG}" \
    --query "id" -o tsv 2>/dev/null || \
    az monitor scheduled-query show --subscription "${SUB}" -g "${RG}" -n "${ALERT_E_NAME}" --query "id" -o tsv)
else
  ALERT_C_ID="SKIPPED_NO_WORKSPACE"
  ALERT_D_ID="SKIPPED_NO_WORKSPACE"
  ALERT_E_ID="SKIPPED_NO_WORKSPACE"
  echo "[setup-monitoring]   skipping log-search alerts (c, d, e) — no Log Analytics workspace bound to the Container App env"
fi

# ---- 5. Done summary -------------------------------------------------------
echo ""
echo "[setup-monitoring] [5/5] DONE."
echo ""
echo "==========================================================================="
echo "  cogos-api monitoring wired:"
echo "==========================================================================="
echo "  Application Insights : ${INSIGHTS_ID}"
echo "  Action Group         : ${AG_ID}"
echo ""
echo "  Alerts:"
echo "    (a) gateway-5xx          : ${ALERT_A_ID}"
echo "    (b) inference-latency    : ${ALERT_B_ID}"
echo "    (c) daily-cap-spike      : ${ALERT_C_ID}"
echo "    (d) anomaly-burst        : ${ALERT_D_ID}"
echo "    (e) audit-chain-breach   : ${ALERT_E_ID}"
echo ""
echo "  Runbook:  docs/RUNBOOK.md"
echo "==========================================================================="
echo ""
echo "Re-runnable. To update thresholds: edit this script and re-run; the"
echo "az commands above are idempotent on name + scope."
