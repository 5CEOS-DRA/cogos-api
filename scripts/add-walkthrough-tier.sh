#!/usr/bin/env bash
# Add a $5/mo "Walk-Through" tier to the live cogos-api so you can walk
# the full customer signup flow yourself: hero → Stripe Checkout →
# /success page → real sk-cogos-... key → smoke test that key.
#
# Requires the post-rotation admin key in your shell env. Never echoes it.
#
# Usage:
#   COGOS_ADMIN_KEY=... bash scripts/add-walkthrough-tier.sh

set -u

BASE="${BASE:-https://cogos.5ceos.com}"
ADMIN="${COGOS_ADMIN_KEY:-}"

if [ -z "$ADMIN" ]; then
  echo "ERROR: COGOS_ADMIN_KEY not set in your shell env."
  echo "Run: COGOS_ADMIN_KEY=... bash scripts/add-walkthrough-tier.sh"
  exit 1
fi

if [ -t 1 ]; then G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; N='\033[0m'
else G=''; R=''; Y=''; N=''; fi

# A minimal, throwaway tier. Tier B only (smoke test uses tier B).
# Quota deliberately tiny so accidental use can't run up a bill.
PAYLOAD=$(cat <<'EOF'
{
  "id": "walkthrough",
  "display_name": "Walk-Through",
  "description": "Founder smoke-test tier. Not for customers.",
  "monthly_usd": 5,
  "monthly_request_quota": 1000,
  "allowed_model_tiers": ["cogos-tier-b"],
  "active": true,
  "is_default": false
}
EOF
)

echo ""
echo "=== Creating walkthrough tier on ${BASE} ==="
RESP=$(curl -s -w "\nHTTP_CODE=%{http_code}" \
  -X POST -H "X-Admin-Key: ${ADMIN}" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" \
  "${BASE}/admin/packages")

CODE=$(echo "$RESP" | grep "HTTP_CODE=" | sed 's/HTTP_CODE=//')
BODY=$(echo "$RESP" | grep -v "HTTP_CODE=")

case "$CODE" in
  201)
    printf "${G}✓${N} created.\n"
    echo "  $BODY" | head -c 300; echo
    ;;
  409)
    printf "${Y}!${N} walkthrough tier already exists. Skipping create.\n"
    ;;
  *)
    printf "${R}✗${N} create failed: HTTP %s\n" "$CODE"
    echo "  body: $BODY"
    exit 1
    ;;
esac

echo ""
echo "=== Walk the flow ==="
echo ""
echo "  1. Open in browser:  ${BASE}"
echo "  2. Scroll to Pricing — Walk-Through (\$5/mo) should appear as a 6th tier."
echo "  3. Click 'Start →' on that tier — Stripe Checkout opens."
echo "  4. Complete checkout (your own card). Confirms the prod Stripe wiring."
echo "  5. /success page renders with your sk-cogos-... key + the curl example."
echo "  6. Copy the key, then:"
echo ""
echo "      export COGOS_API_KEY=sk-cogos-..."
echo "      bash scripts/smoke-api.sh"
echo ""
echo "  7. When done: cancel the subscription via the 'Manage subscription'"
echo "     link on the success page (Stripe customer portal)."
echo ""
echo "Cleanup later:"
echo "  curl -X DELETE -H \"X-Admin-Key: \$COGOS_ADMIN_KEY\" \\"
echo "    ${BASE}/admin/packages/walkthrough"
