#!/usr/bin/env bash
# Rotate the cogos-api admin key on the live Container App.
#
# Generates a fresh 64-hex value LOCALLY (never echoed to scrollback or
# command line), pushes it to Azure Container Apps as the `admin-key`
# secret, triggers a new revision so the running container picks it up,
# and prints the new key ONCE so you can save it to your password manager.
# Old key invalidates as soon as the new revision starts serving traffic.
#
# Usage:
#   bash scripts/rotate-admin-key.sh
#
# That's it. No env vars to set, no values to paste.

set -u

SUB="${SUB:-690985d3-9a58-4cd7-9e5e-4a38c0246242}"
RG="${RG:-brain5-aca2}"
APP_NAME="${APP_NAME:-cogos-api}"
SECRET_NAME="${SECRET_NAME:-admin-key}"
PUBLIC_HOST="${PUBLIC_HOST:-cogos.5ceos.com}"

if [ -t 1 ]; then G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; N='\033[0m'
else G=''; R=''; Y=''; N=''; fi

echo ""
echo "=== Generating new 64-hex admin key locally ==="
NEW_KEY=$(openssl rand -hex 32)
if [ ${#NEW_KEY} -ne 64 ]; then
  printf "${R}✗${N} key generation failed (length %d)\n" "${#NEW_KEY}"
  exit 1
fi
printf "${G}✓${N} generated (length 64)\n"

echo ""
echo "=== Pushing to Container App secret '${SECRET_NAME}' ==="
az containerapp secret set \
  --subscription "${SUB}" -g "${RG}" -n "${APP_NAME}" \
  --secrets "${SECRET_NAME}=${NEW_KEY}" \
  -o none
printf "${G}✓${N} secret updated\n"

echo ""
echo "=== Triggering new revision so container reloads the secret ==="
# Bumping a tag-less env var doesn't restart the revision; need to force
# a new revision. Adding a no-op revision-suffix annotation does the trick.
SUFFIX="rotate-$(date +%s)"
az containerapp update \
  --subscription "${SUB}" -g "${RG}" -n "${APP_NAME}" \
  --revision-suffix "${SUFFIX}" \
  --query "{revision:properties.latestRevisionName, status:properties.runningStatus}" \
  -o table

echo ""
echo "=== Waiting 10s for revision to come up... ==="
sleep 10
HEALTH_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "https://${PUBLIC_HOST}/health")
if [ "$HEALTH_CODE" = "200" ]; then
  printf "${G}✓${N} new revision serving traffic (/health = 200)\n"
else
  printf "${Y}!${N} /health returned %s — give the revision another minute and re-check\n" "$HEALTH_CODE"
fi

echo ""
echo "============================================================"
echo "  NEW ADMIN KEY — copy now, save to password manager:"
echo ""
echo "      ${NEW_KEY}"
echo ""
echo "  Will not be re-displayed. Use as:"
echo "      export COGOS_ADMIN_KEY=${NEW_KEY}"
echo "  (Type the export yourself — leading space keeps it out of history.)"
echo "============================================================"
echo ""
echo "Old key (${Y}whatever was leaked${N}) is now invalid. Verify by trying"
echo "the old key against /admin/keys — should return 401."
