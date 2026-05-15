#!/usr/bin/env bash
# Regenerate the cosign keypair with NO password (Denny doesn't remember
# the password from the original cosign-setup.sh run, and we have no
# customers verifying the existing pubkey yet, so rotation is free).
#
# Backs up the encrypted key, generates a fresh one with empty password,
# uploads the new private + empty-string-password to Key Vault, updates
# the Container App env var, and reminds you to redeploy to actually
# sign an image.
#
# After this runs, every `bash scripts/deploy-update.sh` produces a
# signed image automatically — no env var to set, no password to remember.

set -euo pipefail

SUB="${SUB:-690985d3-9a58-4cd7-9e5e-4a38c0246242}"
RG="${RG:-brain5-aca2}"
APP="${APP:-cogos-api}"
KV_NAME="${KV_NAME:-cogos-kv-16d2bb}"

if ! command -v cosign &>/dev/null; then
  echo "[regen] cosign not installed — brew install cosign first"
  exit 1
fi

cd "$(dirname "$0")/.."

# 1. Back up existing key (if any) to a timestamped file
if [ -f cosign.key ]; then
  BAK="cosign.key.bak.$(date +%Y%m%d-%H%M%S)"
  mv cosign.key "$BAK"
  echo "[regen] backed up old cosign.key → $BAK"
fi
rm -f cosign.pub

# 2. Generate fresh keypair with empty password
echo "[regen] generating fresh keypair with empty password..."
COSIGN_PASSWORD="" cosign generate-key-pair
chmod 600 cosign.key

# 3. Upload new private key to Key Vault
echo "[regen] uploading new private key to KV..."
az keyvault secret set --vault-name "$KV_NAME" --name cosign-private-key --file cosign.key --query "name" -o tsv

# 4. Mark the cosign-password as "empty" in KV. KV refuses to store an
#    empty string, so we use the sentinel "__EMPTY__" and have the deploy
#    script translate that back to "" before passing to cosign. Anyone
#    fetching the secret directly sees a clear marker, not random text.
echo "[regen] setting cosign-password sentinel in KV..."
az keyvault secret set --vault-name "$KV_NAME" --name cosign-password --value "__EMPTY__" --query "name" -o tsv

# 5. Update Container App env var with the new pubkey
echo "[regen] updating Container App COSIGN_PUBKEY_PEM..."
az containerapp update \
  --subscription "$SUB" -g "$RG" -n "$APP" \
  --set-env-vars "COSIGN_PUBKEY_PEM=$(cat cosign.pub)" \
  --query "{revision:properties.latestRevisionName}" \
  -o table

echo ""
echo "[regen] DONE."
echo "[regen]   next deploy will sign images automatically:"
echo "[regen]     bash scripts/deploy-update.sh"
echo "[regen]   then verify:"
echo "[regen]     cosign verify --key https://cogos.5ceos.com/cosign.pub cogos5ceos.azurecr.io/cogos-api:vN"
