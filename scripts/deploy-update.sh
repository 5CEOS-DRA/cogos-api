#!/usr/bin/env bash
# Build + push + roll the cogos-api Container App.
# Uses Azure-side build (`az acr build`) so no local Docker daemon needed.
# Bumps the image tag, updates the container app, then curls the live URLs
# to verify.
#
# Re-run any time to deploy whatever's on origin/main right now.

set -euo pipefail

SUB="${SUB:-690985d3-9a58-4cd7-9e5e-4a38c0246242}"
RG="${RG:-brain5-aca2}"
APP_NAME="${APP_NAME:-cogos-api}"
ACR_NAME="${ACR_NAME:-cogos5ceos}"
PUBLIC_HOST="${PUBLIC_HOST:-cogos.5ceos.com}"

# Read the currently-deployed tag and bump it.
CURRENT_IMAGE=$(az containerapp show \
  --subscription "${SUB}" -g "${RG}" -n "${APP_NAME}" \
  --query "properties.template.containers[0].image" -o tsv)
echo "[deploy] current image: ${CURRENT_IMAGE}"

CURRENT_TAG="${CURRENT_IMAGE##*:}"          # e.g. "v9"
CURRENT_TAG_NUM="${CURRENT_TAG#v}"          # e.g. "9"
NEXT_TAG="v$((CURRENT_TAG_NUM + 1))"        # e.g. "v10"
NEW_IMAGE="${ACR_NAME}.azurecr.io/${APP_NAME}:${NEXT_TAG}"
echo "[deploy] new image:     ${NEW_IMAGE}"
echo ""

# Build remotely in ACR. No local Docker required.
echo "[deploy] [1/3] az acr build (remote build + push, ~60-120s)..."
az acr build \
  --subscription "${SUB}" \
  --registry "${ACR_NAME}" \
  --image "${APP_NAME}:${NEXT_TAG}" \
  --file Dockerfile \
  .

echo ""
echo "[deploy] [1.5/3] cosign sign ${NEW_IMAGE}..."
if [ -n "${COSIGN_KEY_FILE:-}" ] && [ -f "${COSIGN_KEY_FILE}" ]; then
  if command -v cosign &>/dev/null; then
    COSIGN_PASSWORD="${COSIGN_PASSWORD:-}" cosign sign --yes --key "${COSIGN_KEY_FILE}" "${NEW_IMAGE}" || echo "[deploy] WARN: cosign sign exited non-zero — proceeding without enforcement (week-0 additive)"
  else
    echo "[deploy] WARN: cosign not installed locally — skipping sign step. brew install cosign"
  fi
else
  echo "[deploy] WARN: COSIGN_KEY_FILE unset — image NOT signed."
  echo "[deploy]       Run once to set up: cosign generate-key-pair && export COSIGN_KEY_FILE=\$PWD/cosign.key"
fi

echo ""
echo "[deploy] [2/3] az containerapp update (revision roll, ~30s)..."
az containerapp update \
  --subscription "${SUB}" -g "${RG}" -n "${APP_NAME}" \
  --image "${NEW_IMAGE}" \
  --query "{revision:properties.latestRevisionName, image:properties.template.containers[0].image}" \
  -o table

echo ""
echo "[deploy] [3/3] verifying live URLs..."
echo ""

for path in / /whitepaper /demo /health; do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 12 "https://${PUBLIC_HOST}${path}")
  printf "  %-15s %s\n" "${path}" "${code}"
done

echo ""
echo "[deploy] all 4 lines above should read 200."
echo "[deploy] rollback if needed:"
echo "  az containerapp update --subscription ${SUB} -g ${RG} -n ${APP_NAME} --image ${CURRENT_IMAGE}"

echo ""
echo "[deploy] customer-visible verify command:"
echo "  cosign verify --key https://cogos.5ceos.com/cosign.pub ${NEW_IMAGE}"
