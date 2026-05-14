#!/usr/bin/env bash
# One-shot: store your cosign signing password in Key Vault so
# scripts/deploy-update.sh signs images automatically without you having
# to export COSIGN_PASSWORD in every shell.
#
# Reads from stdin (so the password never appears in shell history,
# argv, or process listings). Idempotent: re-running overwrites the
# existing KV secret.

set -euo pipefail

KV_NAME="cogos-kv-16d2bb"
SECRET_NAME="cosign-password"

echo "[cosign-pw] paste the cosign password you typed into cosign-setup.sh,"
echo "[cosign-pw] then press Enter. Nothing is echoed."
read -s -r PW
echo ""

if [ -z "$PW" ]; then
  echo "[cosign-pw] empty password — aborting"
  exit 1
fi

az keyvault secret set \
  --vault-name "$KV_NAME" \
  --name "$SECRET_NAME" \
  --value "$PW" \
  --query "{name:name,updated:attributes.updated}" \
  -o table

unset PW

echo ""
echo "[cosign-pw] DONE. Next deploy will sign automatically. Test it now:"
echo "  bash scripts/deploy-update.sh"
echo "  cosign verify --key https://cogos.5ceos.com/cosign.pub cogos5ceos.azurecr.io/cogos-api:<NEW_TAG>"
