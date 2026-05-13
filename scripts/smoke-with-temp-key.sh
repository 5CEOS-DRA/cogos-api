#!/usr/bin/env bash
# Self-contained API smoke test using a temporary admin-issued key.
# Steps:
#   1. POST /admin/keys to issue a fresh sk-cogos-... bound to a temp tenant
#   2. Run the full /v1/* smoke test against the live gateway
#   3. POST /admin/keys/<id>/revoke to invalidate the key immediately
#
# The temp key only ever lives in this script's memory + the audit log.
# Never echoed to scrollback, never written to disk, never exported beyond
# the COGOS_API_KEY var consumed by the inner smoke script.
#
# Usage:
#   COGOS_ADMIN_KEY=... bash scripts/smoke-with-temp-key.sh
#   COGOS_ADMIN_KEY=... BASE=https://cogos.5ceos.com bash scripts/smoke-with-temp-key.sh

set -u

BASE="${BASE:-https://cogos.5ceos.com}"
ADMIN="${COGOS_ADMIN_KEY:-}"
TENANT="${SMOKE_TENANT:-smoke-test-temp-$(date +%s)}"

if [ -z "$ADMIN" ]; then
  echo "ERROR: COGOS_ADMIN_KEY not set."
  echo "Run with:  COGOS_ADMIN_KEY=... bash scripts/smoke-with-temp-key.sh"
  exit 1
fi

if [ -t 1 ]; then G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; N='\033[0m'
else G=''; R=''; Y=''; N=''; fi

echo ""
echo "=== Issuing temporary key for tenant=${TENANT} ==="
ISSUE=$(curl -s -w "\nHTTP_CODE=%{http_code}" \
  -X POST -H "X-Admin-Key: ${ADMIN}" \
  -H "Content-Type: application/json" \
  -d "{\"tenant_id\":\"${TENANT}\",\"label\":\"smoke-test\",\"tier\":\"cogos-tier-b\"}" \
  "${BASE}/admin/keys")

ISSUE_CODE=$(echo "$ISSUE" | grep "HTTP_CODE=" | sed 's/HTTP_CODE=//')
ISSUE_BODY=$(echo "$ISSUE" | grep -v "HTTP_CODE=")

if [ "$ISSUE_CODE" != "201" ]; then
  printf "${R}✗${N} key issuance failed: HTTP %s\n" "$ISSUE_CODE"
  echo "  body: $ISSUE_BODY"
  exit 1
fi

# Extract api_key + key_id without echoing them
TEMP_KEY=$(echo "$ISSUE_BODY" | grep -oE '"api_key":"[^"]+"' | sed 's/"api_key":"//;s/"$//')
KEY_ID=$(echo "$ISSUE_BODY" | grep -oE '"key_id":"[^"]+"' | sed 's/"key_id":"//;s/"$//')

if [ -z "$TEMP_KEY" ] || [ -z "$KEY_ID" ]; then
  printf "${R}✗${N} could not extract api_key / key_id from response\n"
  echo "  body: $ISSUE_BODY"
  exit 1
fi

printf "${G}✓${N} issued key_id=%s\n" "$KEY_ID"
echo ""

# Trap so we ALWAYS revoke, even if the smoke test fails or is interrupted
revoke() {
  echo ""
  echo "=== Revoking temporary key (key_id=${KEY_ID}) ==="
  REVOKE=$(curl -s -w "\nHTTP_CODE=%{http_code}" \
    -X POST -H "X-Admin-Key: ${ADMIN}" \
    "${BASE}/admin/keys/${KEY_ID}/revoke")
  REVOKE_CODE=$(echo "$REVOKE" | grep "HTTP_CODE=" | sed 's/HTTP_CODE=//')
  if [ "$REVOKE_CODE" = "200" ]; then
    printf "${G}✓${N} revoked.\n"
  else
    printf "${R}✗${N} revoke failed: HTTP %s — REVOKE MANUALLY: key_id=%s\n" "$REVOKE_CODE" "$KEY_ID"
  fi
}
trap revoke EXIT INT TERM

# Run the inner smoke test with the temp key
COGOS_API_KEY="$TEMP_KEY" BASE="$BASE" bash "$(dirname "$0")/smoke-api.sh"
SMOKE_EXIT=$?

# revoke runs via trap on exit
exit $SMOKE_EXIT
