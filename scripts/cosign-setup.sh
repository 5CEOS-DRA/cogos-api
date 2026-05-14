#!/usr/bin/env bash
# One-shot cosign setup for cogos-api.
#
# What it does:
#   1. brew install cosign (if missing)
#   2. cosign generate-key-pair (asks you for a password TWICE, interactively)
#   3. Publishes cosign.pub to the cogos-api Container App as COSIGN_PUBKEY_PEM env
#   4. Verifies https://cogos.5ceos.com/cosign.pub serves the pubkey
#
# What it does NOT do:
#   - Upload the private key to Azure Key Vault — printed as a follow-up command
#   - Sign any image — happens automatically on the NEXT deploy if you
#     `export COSIGN_KEY_FILE=$PWD/cosign.key` before running deploy-update.sh
#
# Idempotency: refuses to run if cosign.key or cosign.pub already exist in $PWD.
# That guard exists so you don't accidentally overwrite a key already in KV.

set -euo pipefail

SUB="690985d3-9a58-4cd7-9e5e-4a38c0246242"
RG="brain5-aca2"
APP="cogos-api"
KV_NAME="cogos-kv-16d2bb"

if [ -f cosign.key ] || [ -f cosign.pub ]; then
  echo "[step1] cosign.key or cosign.pub already exists in $PWD."
  echo "[step1] If you meant to regenerate, delete them first:"
  echo "          rm cosign.key cosign.pub"
  echo "[step1] If a key is already in Key Vault, fetch it instead of regenerating:"
  echo "          az keyvault secret show --vault-name $KV_NAME --name cosign-private-key --query value -o tsv > cosign.key"
  exit 1
fi

if ! command -v cosign &>/dev/null; then
  echo "[step1] installing cosign via brew..."
  brew install cosign
fi

echo ""
echo "[step1] generating cosign keypair."
echo "[step1] you will be prompted for a password TWICE."
echo "[step1] write the password down somewhere offline-backed-up; you'll need it"
echo "[step1] every time you sign a release."
echo ""
cosign generate-key-pair

echo ""
echo "[step1] publishing cosign.pub to Container App env (multi-line preserved)..."
az containerapp update \
  --subscription "$SUB" \
  -g "$RG" \
  -n "$APP" \
  --set-env-vars "COSIGN_PUBKEY_PEM=$(cat cosign.pub)" \
  --query "{revision:properties.latestRevisionName, image:properties.template.containers[0].image}" \
  -o table

echo ""
echo "[step1] waiting 30s for revision rollover to settle..."
sleep 30

echo "[step1] verifying https://cogos.5ceos.com/cosign.pub..."
if curl -sf https://cogos.5ceos.com/cosign.pub | head -1 | grep -q "BEGIN PUBLIC KEY"; then
  echo "[step1] DONE. Pubkey is serving live."
  echo ""
  echo "  cosign verify --key https://cogos.5ceos.com/cosign.pub cogos5ceos.azurecr.io/cogos-api:v13"
  echo ""
  echo "  (v13 isn't signed yet — sign-on-deploy starts the next time you run"
  echo "   deploy-update.sh with COSIGN_KEY_FILE set; see Step 2 below.)"
else
  echo "[step1] pubkey URL not serving yet — revision may still be rolling. Retry in 60s:"
  echo "          curl https://cogos.5ceos.com/cosign.pub"
fi

echo ""
echo "============================================================"
echo "[step1] private key is at: $PWD/cosign.key"
echo "============================================================"
echo ""
echo "Step 2 — upload private key to Key Vault (so a new dev box can sign):"
echo "  az keyvault secret set --vault-name $KV_NAME --name cosign-private-key --file cosign.key"
echo ""
echo "Step 3 — sign on every deploy from now on:"
echo "  export COSIGN_KEY_FILE=\$PWD/cosign.key"
echo "  export COSIGN_PASSWORD=<the password you typed above>"
echo "  bash scripts/deploy-update.sh"
echo ""
echo "  (or store the password in KV too and load it from there in your shell rc)"
