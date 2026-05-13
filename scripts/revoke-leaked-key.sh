#!/usr/bin/env bash
# Revoke ALL active customer keys on a given tenant. Use to clean up
# after a key got pasted into a chat or otherwise leaked.
#
# Default tenant is "smoke-test" (the one sibling Claude provisioned
# for the API smoke check). Override with TENANT=<name>.
#
# Requires the admin key in your shell env. Never echoes it.
#
# Usage:
#   COGOS_ADMIN_KEY=... bash scripts/revoke-leaked-key.sh
#   COGOS_ADMIN_KEY=... TENANT=other-tenant bash scripts/revoke-leaked-key.sh

set -u

BASE="${BASE:-https://cogos.5ceos.com}"
ADMIN="${COGOS_ADMIN_KEY:-}"
TENANT="${TENANT:-smoke-test}"

if [ -z "$ADMIN" ]; then
  echo "ERROR: COGOS_ADMIN_KEY not set in your shell env."
  exit 1
fi

if [ -t 1 ]; then G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; N='\033[0m'
else G=''; R=''; Y=''; N=''; fi

echo ""
echo "=== Listing all keys on tenant=${TENANT} ==="
LIST=$(curl -s -H "X-Admin-Key: ${ADMIN}" "${BASE}/admin/keys")

# Pull active key_ids on the target tenant
KEY_IDS=$(echo "$LIST" \
  | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    for k in d.get('keys', []):
        if k.get('tenant_id') == '${TENANT}' and not k.get('revoked_at'):
            print(k['id'])
except Exception as e:
    sys.stderr.write(f'parse failed: {e}\n')
    sys.exit(1)
")

if [ -z "$KEY_IDS" ]; then
  printf "${Y}!${N} no active keys on tenant=${TENANT}. Nothing to revoke.\n"
  exit 0
fi

COUNT=$(echo "$KEY_IDS" | grep -c .)
echo "Found ${COUNT} active key(s):"
echo "$KEY_IDS" | sed 's/^/  /'
echo ""
read -r -p "Revoke all ${COUNT}? [y/N] " ANSWER
if [ "$ANSWER" != "y" ] && [ "$ANSWER" != "Y" ]; then
  echo "Aborted."
  exit 0
fi

echo ""
FAILS=0
while IFS= read -r kid; do
  [ -z "$kid" ] && continue
  RESP=$(curl -s -w "%{http_code}" -X POST -H "X-Admin-Key: ${ADMIN}" "${BASE}/admin/keys/${kid}/revoke" -o /tmp/_rk_body)
  if [ "$RESP" = "200" ]; then
    printf "  ${G}✓${N} revoked %s\n" "$kid"
  else
    printf "  ${R}✗${N} %s revoke failed (HTTP %s)\n" "$kid" "$RESP"
    FAILS=$((FAILS+1))
  fi
done <<< "$KEY_IDS"

rm -f /tmp/_rk_body
echo ""
if [ "$FAILS" = "0" ]; then
  printf "${G}=== all ${COUNT} key(s) revoked ===${N}\n"
else
  printf "${R}=== ${FAILS} revoke(s) failed — re-run, or revoke manually ===${N}\n"
  exit 1
fi
