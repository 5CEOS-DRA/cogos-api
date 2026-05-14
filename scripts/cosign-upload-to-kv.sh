#!/usr/bin/env bash
# Upload the local cosign.key to Azure Key Vault.
# Run this AFTER scripts/cosign-setup.sh has created the keypair.
# Idempotent: re-running overwrites the existing KV secret with the local file.

set -euo pipefail

KV_NAME="cogos-kv-16d2bb"
SECRET_NAME="cosign-private-key"
KEY_FILE="${KEY_FILE:-$HOME/dev/cogos-api/cosign.key}"

if [ ! -f "$KEY_FILE" ]; then
  echo "[step2] cosign.key not found at: $KEY_FILE"
  echo "[step2] run scripts/cosign-setup.sh first, or set KEY_FILE=/path/to/cosign.key"
  exit 1
fi

echo "[step2] uploading $KEY_FILE to Key Vault '$KV_NAME' as secret '$SECRET_NAME'..."
az keyvault secret set \
  --vault-name "$KV_NAME" \
  --name "$SECRET_NAME" \
  --file "$KEY_FILE" \
  --query "{id:id, name:name, updated:attributes.updated}" \
  -o table

echo ""
echo "[step2] DONE. Verify with:"
echo "  az keyvault secret show --vault-name $KV_NAME --name $SECRET_NAME --query 'attributes.updated' -o tsv"
echo ""
echo "[step2] You can now safely 'rm $KEY_FILE' from this laptop if you want."
echo "[step2] To restore on another machine:"
echo "  az keyvault secret show --vault-name $KV_NAME --name $SECRET_NAME --query value -o tsv > cosign.key"
echo "  chmod 600 cosign.key"
