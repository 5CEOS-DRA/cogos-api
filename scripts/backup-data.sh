#!/usr/bin/env bash
# Nightly backup of the cogos-api Azure Files data mount → Azure Blob.
# Snapshots packages.json, keys.json, usage.json, processed_events.json
# into a date-stamped folder in the cogos-data-backups blob container.
#
# Run nightly via cron / Azure Logic App / GitHub Actions schedule.
# Manual: bash scripts/backup-data.sh
#
# Restore (if needed): download the date-stamped folder from blob and
# az storage file upload-batch back into the cogos-data file share.

set -euo pipefail

SUB="${SUB:-690985d3-9a58-4cd7-9e5e-4a38c0246242}"
RG="${RG:-brain5-aca2}"
SOURCE_STORAGE="${SOURCE_STORAGE:-cogos5ceos}"  # the storage account
SOURCE_SHARE="${SOURCE_SHARE:-cogos-data}"      # Azure Files share name
BACKUP_CONTAINER="${BACKUP_CONTAINER:-cogos-data-backups}"
DATE_STAMP="$(date -u +%Y-%m-%d-%H%M%S)"

if [ -t 1 ]; then G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; N='\033[0m'
else G=''; R=''; Y=''; N=''; fi

echo ""
echo "=== cogos-api data backup ==="
echo "[backup] timestamp:   ${DATE_STAMP}"
echo "[backup] source:      ${SOURCE_STORAGE} / ${SOURCE_SHARE}"
echo "[backup] destination: ${SOURCE_STORAGE} / ${BACKUP_CONTAINER} / ${DATE_STAMP}/"
echo ""

# Resolve the storage account key once (kept in shell var, never echoed)
STORAGE_KEY=$(az storage account keys list \
  --subscription "${SUB}" -g "${RG}" -n "${SOURCE_STORAGE}" \
  --query '[0].value' -o tsv 2>/dev/null)
if [ -z "$STORAGE_KEY" ]; then
  printf "${R}✗${N} could not fetch storage account key for ${SOURCE_STORAGE}\n"
  exit 1
fi
printf "${G}✓${N} storage key resolved\n"

# Ensure backup container exists (idempotent)
az storage container create \
  --account-name "${SOURCE_STORAGE}" --account-key "${STORAGE_KEY}" \
  --name "${BACKUP_CONTAINER}" \
  --output none 2>/dev/null || true
printf "${G}✓${N} backup container exists\n"

# Stream each JSON file from Azure Files → Azure Blob
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo ""
echo "[backup] downloading data share to local temp..."
az storage file download-batch \
  --account-name "${SOURCE_STORAGE}" --account-key "${STORAGE_KEY}" \
  --source "${SOURCE_SHARE}" \
  --destination "${TEMP_DIR}" \
  --output none

FILE_COUNT=$(find "$TEMP_DIR" -type f | wc -l | tr -d ' ')
printf "${G}✓${N} pulled ${FILE_COUNT} file(s) locally\n"

echo ""
echo "[backup] uploading to backup container under ${DATE_STAMP}/..."
az storage blob upload-batch \
  --account-name "${SOURCE_STORAGE}" --account-key "${STORAGE_KEY}" \
  --destination "${BACKUP_CONTAINER}" \
  --destination-path "${DATE_STAMP}" \
  --source "${TEMP_DIR}" \
  --output none
printf "${G}✓${N} uploaded\n"

# Compute total bytes for the audit line
TOTAL_BYTES=$(find "$TEMP_DIR" -type f -exec wc -c {} + | tail -1 | awk '{print $1}')

echo ""
echo "[backup] ${G}DONE${N}"
echo "[backup] timestamp:    ${DATE_STAMP}"
echo "[backup] files copied: ${FILE_COUNT}"
echo "[backup] total bytes:  ${TOTAL_BYTES}"
echo ""
echo "Restore (if needed):"
echo "  az storage blob download-batch \\"
echo "    --account-name ${SOURCE_STORAGE} \\"
echo "    --source ${BACKUP_CONTAINER} --pattern '${DATE_STAMP}/*' \\"
echo "    --destination /tmp/cogos-restore"
