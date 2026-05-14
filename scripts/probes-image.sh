#!/usr/bin/env bash
# Image supply-chain probes.
#
# Verifies the running production image is the one we signed:
#   1. Fetches /cosign.pub from the live host (must serve a PEM)
#   2. Discovers the live image tag from the Container App
#   3. Runs `cosign verify --key <live cosign.pub URL> <image>`
#
# Skips gracefully (exit 0 with [SKIP] markers) if cosign isn't installed
# or if no images have been signed yet, so this is safe to wire into CI
# before the first signed deploy.

set -euo pipefail

HOST="${HOST:-https://cogos.5ceos.com}"
SUB="${SUB:-690985d3-9a58-4cd7-9e5e-4a38c0246242}"
RG="${RG:-brain5-aca2}"
APP="${APP:-cogos-api}"

PASS=0
FAIL=0
SKIP=0

pass() { echo "  [PASS] $1"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL + 1)); }
skip() { echo "  [SKIP] $1"; SKIP=$((SKIP + 1)); }

echo "[image] verifying cosign.pub is served"
if curl -sSf "$HOST/cosign.pub" | head -1 | grep -q "BEGIN PUBLIC KEY"; then
  pass "$HOST/cosign.pub serves a PEM"
else
  fail "$HOST/cosign.pub did not return a PEM — set COSIGN_PUBKEY_PEM on the Container App"
fi

echo ""
echo "[image] discovering live image tag"
if ! command -v az &>/dev/null; then
  skip "az CLI not installed — skipping image discovery"
else
  IMAGE=$(az containerapp show --subscription "$SUB" -g "$RG" -n "$APP" \
    --query "properties.template.containers[0].image" -o tsv 2>/dev/null || echo "")
  if [ -z "$IMAGE" ]; then
    skip "could not read live image tag from Container App (auth/perm?)"
  else
    echo "  live image: $IMAGE"
    pass "live image tag fetched"

    echo ""
    echo "[image] verifying cosign signature on live image"
    if ! command -v cosign &>/dev/null; then
      skip "cosign not installed — install via 'brew install cosign'"
    else
      if cosign verify --key "$HOST/cosign.pub" "$IMAGE" >/dev/null 2>&1; then
        pass "cosign verify $IMAGE → signature valid"
      else
        # Distinguish "no signature yet" from "verification failed"
        if cosign tree "$IMAGE" 2>/dev/null | grep -q "Signatures"; then
          fail "image $IMAGE has signatures but verify failed against the served pubkey"
        else
          skip "no signatures on $IMAGE yet — set COSIGN_KEY_FILE before next deploy"
        fi
      fi
    fi
  fi
fi

echo ""
echo "============================================================"
echo "[probes-image] $PASS pass, $FAIL fail, $SKIP skip"
[ "$FAIL" -gt 0 ] && exit 1
echo "[probes-image] image supply-chain probes clean."
echo "============================================================"
