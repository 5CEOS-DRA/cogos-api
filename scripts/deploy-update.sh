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
# Auto-detect cosign.key in $PWD if COSIGN_KEY_FILE is unset — common
# case after running scripts/cosign-setup.sh in the same directory.
if [ -z "${COSIGN_KEY_FILE:-}" ] && [ -f "$PWD/cosign.key" ]; then
  COSIGN_KEY_FILE="$PWD/cosign.key"
  echo "[deploy] auto-detected COSIGN_KEY_FILE=$COSIGN_KEY_FILE"
fi

# Authenticate cosign to ACR via a refresh token. The previous flow assumed
# 'az acr login' had cached Docker creds; without a running Docker daemon
# that path silently degrades and cosign falls back to anonymous OAuth,
# which ACR refuses with 401 Unauthorized. --expose-token mints a refresh
# token that we feed into cosign login -- no Docker required.
if [ -n "${COSIGN_KEY_FILE:-}" ] && [ -f "${COSIGN_KEY_FILE}" ] && command -v cosign &>/dev/null; then
  echo "[deploy] obtaining ACR refresh token for cosign..."
  ACR_TOKEN=$(az acr login \
    --subscription "${SUB}" \
    --name "${ACR_NAME}" \
    --expose-token \
    --query accessToken -o tsv 2>/dev/null || true)
  if [ -n "${ACR_TOKEN}" ]; then
    # ACR's refresh-token auth requires the literal user 00000000-0000-0000-0000-000000000000
    if echo "${ACR_TOKEN}" | cosign login "${ACR_NAME}.azurecr.io" \
         -u 00000000-0000-0000-0000-000000000000 --password-stdin >/dev/null 2>&1; then
      echo "[deploy] ✓ cosign authenticated to ${ACR_NAME}.azurecr.io"
    else
      echo "[deploy] WARN: cosign login to ACR failed (got token but login rejected)"
    fi
  else
    echo "[deploy] WARN: az acr login --expose-token returned empty -- cosign sign will likely 401"
  fi
fi
# Auto-fetch COSIGN_PASSWORD from Key Vault if unset locally. Lets a
# single bash deploy-update.sh sign automatically without exporting the
# password into the shell on every machine.
if [ -z "${COSIGN_PASSWORD+set}" ] && [ -n "${COSIGN_KEY_FILE:-}" ]; then
  KV_PW=$(az keyvault secret show --vault-name cogos-kv-16d2bb --name cosign-password --query value -o tsv 2>/dev/null || true)
  if [ -n "$KV_PW" ]; then
    # KV refuses empty-string secrets, so cosign-regenerate stores
    # __EMPTY__ as a sentinel meaning "no password protection." Translate
    # it back so cosign sees the real empty string.
    if [ "$KV_PW" = "__EMPTY__" ]; then COSIGN_PASSWORD=""; else COSIGN_PASSWORD="$KV_PW"; fi
    export COSIGN_PASSWORD
    echo "[deploy] auto-fetched COSIGN_PASSWORD from Key Vault"
  fi
fi
# FAIL-CLOSED COSIGN POLICY (2026-06-10):
#
# The public-facing CogOSHero "Cosign-verified supply chain" guarantee sits
# under a header that literally says "Every guarantee is machine-checkable."
# So the deploy MUST refuse to ship an unsigned image unless an operator
# explicitly opts out for this one deploy.
#
# Four failure paths that previously warn-and-continued:
#   (a) sign succeeded · verify FAILED      (line 100 in the old script)
#   (b) sign EXITED NON-ZERO                (line 105)
#   (c) cosign binary not installed         (line 110)
#   (d) COSIGN_KEY_FILE unset                (line 113)
# Each now exits 1 instead.
#
# Operator override: set ALLOW_UNSIGNED_DEPLOY=1 in env to bypass this
# guard for one run. Logged loudly so the deploy can't pretend it was
# signed. Intended for: cosign tooling regressions, KV outage, the rare
# emergency rollback during a cosign incident. NOT for routine use.
ALLOW_UNSIGNED="${ALLOW_UNSIGNED_DEPLOY:-0}"
deploy_fail_closed() {
  local reason="$1"
  local hint="$2"
  if [ "${ALLOW_UNSIGNED}" = "1" ]; then
    echo "[deploy] ⚠ COSIGN FAIL but ALLOW_UNSIGNED_DEPLOY=1 — proceeding UNSIGNED"
    echo "[deploy]   reason: ${reason}"
    echo "[deploy]   The page-stated 'Cosign-verified supply chain' guarantee does NOT hold for this image."
    echo "[deploy]   Re-sign manually post-deploy and re-verify before ANY customer-facing claim about this revision."
    return 0
  fi
  echo "[deploy] ✗ COSIGN FAIL-CLOSED: ${reason}"
  echo "[deploy]   Deploy aborted. Image NOT signed; refusing to ship under a 'Cosign-verified' claim."
  echo "[deploy]   ${hint}"
  echo "[deploy]   Emergency override (logs the violation): ALLOW_UNSIGNED_DEPLOY=1 bash scripts/deploy-update.sh"
  exit 1
}

if [ -z "${COSIGN_KEY_FILE:-}" ] || [ ! -f "${COSIGN_KEY_FILE}" ]; then
  deploy_fail_closed \
    "COSIGN_KEY_FILE unset or missing" \
    "Run once: cosign generate-key-pair && export COSIGN_KEY_FILE=\$PWD/cosign.key"
fi
if ! command -v cosign &>/dev/null; then
  deploy_fail_closed \
    "cosign binary not installed on this machine" \
    "Install: brew install cosign"
fi
# Capture sign output + exit code. Stale COSIGN_PASSWORD in shell env is
# the most common cause of silent sign failures.
if ! COSIGN_PASSWORD="${COSIGN_PASSWORD:-}" cosign sign --yes --key "${COSIGN_KEY_FILE}" "${NEW_IMAGE}" 2>&1 | tail -3; then
  deploy_fail_closed \
    "cosign sign exited non-zero on ${NEW_IMAGE}" \
    "Likely stale COSIGN_PASSWORD in shell env. Try: unset COSIGN_PASSWORD && bash scripts/deploy-update.sh"
fi
# Verify-after-sign: prove the signature is actually published in ACR
# before continuing. If sign output looked fine but ACR rejected the
# upload, this catches it.
if ! ( cosign verify --key "${COSIGN_KEY_FILE%.key}.pub" "${NEW_IMAGE}" >/dev/null 2>&1 \
       || cosign verify --key "https://cogos.5ceos.com/cosign.pub" "${NEW_IMAGE}" >/dev/null 2>&1 ); then
  deploy_fail_closed \
    "cosign sign appeared to succeed but verify FAILED on ${NEW_IMAGE}" \
    "Re-sign: COSIGN_PASSWORD=\"\" cosign sign --yes --key \"${COSIGN_KEY_FILE}\" \"${NEW_IMAGE}\""
fi
echo "[deploy] ✓ cosign signature verified on ${NEW_IMAGE}"

echo ""
echo "[deploy] [2/3] az containerapp update (revision roll, ~30s)..."
# Set COGOS_IMAGE_TAG on the env so /trust's "Image tag" tile renders the
# tag of THIS deploy. Without it, src/trust.js falls back to the static
# package.json version (e.g. "0.1.0") which drifts from the live tag.
az containerapp update \
  --subscription "${SUB}" -g "${RG}" -n "${APP_NAME}" \
  --image "${NEW_IMAGE}" \
  --set-env-vars "COGOS_IMAGE_TAG=${NEXT_TAG}" \
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
