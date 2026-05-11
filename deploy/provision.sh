#!/usr/bin/env bash
# cogos-api Azure provisioning script.
#
# Run from your Mac AFTER the NCASv3_T4 quota is approved.
# Idempotent: if the VM already exists, skips creation and re-runs cloud-init
# is not possible (cloud-init is first-boot-only); use 'az vm run-command' or
# re-create the VM for a fresh bootstrap.
#
# Streams cloud-init output to your terminal so you watch the boot live.

set -euo pipefail

# --- config (override via env) ---
SUB="${SUB:-690985d3-9a58-4cd7-9e5e-4a38c0246242}"
RG="${RG:-cogos-rg}"
REGION="${REGION:-eastus2}"           # T4 quota is in eastus2
VM_NAME="${VM_NAME:-cogos-vm}"
VM_SIZE="${VM_SIZE:-Standard_NC4as_T4_v3}"
IMAGE="${IMAGE:-microsoft-dsvm:ubuntu-hpc:2204:latest}"    # NVIDIA drivers + CUDA preinstalled
ADMIN_USER="${ADMIN_USER:-azureuser}"
KV_NAME="${KV_NAME:-cogos-kv-16d2bb}"
PUBLIC_FQDN="${PUBLIC_FQDN:-cogos.5ceos.com}"
# DNS label gives the VM an Azure-managed FQDN like cogos-vm.eastus2.cloudapp.azure.com
DNS_LABEL="${DNS_LABEL:-cogos-${RANDOM}}"
SSH_KEY_PATH="${SSH_KEY_PATH:-$HOME/.ssh/id_rsa.pub}"

echo "=== cogos-api provisioning ==="
echo "  subscription: $SUB"
echo "  resource group: $RG"
echo "  region: $REGION"
echo "  vm: $VM_NAME ($VM_SIZE)"
echo "  image: $IMAGE"
echo "  public FQDN: $PUBLIC_FQDN"
echo ""

# --- pre-flight ---
echo "[pre-flight] verifying GPU quota..."
QUOTA=$(az rest --method get \
  --url "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Compute/locations/$REGION/providers/Microsoft.Quota/quotas/Standard%20NCASv3_T4%20Family?api-version=2023-02-01" \
  --query 'properties.limit.value' -o tsv 2>/dev/null || echo "0")
if [ "$QUOTA" -lt 4 ]; then
  echo "ERROR: NCASv3_T4 quota is $QUOTA. Need >= 4 (one NC4as_T4_v3). Wait for quota approval."
  exit 1
fi
echo "[pre-flight] quota OK ($QUOTA vCPUs)"

# Ensure GITHUB_TOKEN is in Key Vault so cloud-init can clone the private repo
echo "[pre-flight] ensuring github-token is in Key Vault..."
if ! az keyvault secret show --vault-name "$KV_NAME" --name github-token --query value -o tsv &>/dev/null; then
  if [ -f ~/.operator-bus.secrets ]; then
    # shellcheck disable=SC1090
    source ~/.operator-bus.secrets
  fi
  if [ -z "${GITHUB_TOKEN:-}" ]; then
    GITHUB_TOKEN=$(gh auth token)
  fi
  az keyvault secret set --vault-name "$KV_NAME" --name github-token --value "$GITHUB_TOKEN" -o none
  echo "[pre-flight] github-token uploaded to KV"
else
  echo "[pre-flight] github-token already in KV"
fi

# --- ssh key ---
if [ ! -f "$SSH_KEY_PATH" ]; then
  echo "[pre-flight] no ssh key at $SSH_KEY_PATH — generating one..."
  ssh-keygen -t rsa -b 4096 -f "${SSH_KEY_PATH%.pub}" -N "" -C "cogos-deploy"
fi

# --- check if VM exists ---
if az vm show -g "$RG" -n "$VM_NAME" -o none 2>/dev/null; then
  echo ""
  echo "WARN: VM '$VM_NAME' already exists in '$RG'."
  echo "      Cloud-init only runs at first boot. To re-bootstrap:"
  echo "        az vm delete -g $RG -n $VM_NAME --yes"
  echo "        bash $0"
  echo ""
  PUBLIC_IP=$(az vm show -g "$RG" -n "$VM_NAME" -d --query publicIps -o tsv)
  echo "Existing public IP: $PUBLIC_IP"
  exit 0
fi

# --- render cloud-init with substituted vars ---
echo "[provision] rendering cloud-init with KV=$KV_NAME, FQDN=$PUBLIC_FQDN..."
TMPDIR=$(mktemp -d)
CLOUDINIT="$TMPDIR/cloud-init.rendered.yaml"
sed -e "s|\${KV_NAME}|$KV_NAME|g" \
    -e "s|\${PUBLIC_FQDN}|$PUBLIC_FQDN|g" \
    "$(dirname "$0")/cloud-init.yaml" > "$CLOUDINIT"

# --- create the VM with managed identity + custom data ---
echo "[provision] creating VM (this takes 2-5 min)..."
az vm create \
  -g "$RG" \
  -n "$VM_NAME" \
  --image "$IMAGE" \
  --size "$VM_SIZE" \
  --admin-username "$ADMIN_USER" \
  --ssh-key-values "$SSH_KEY_PATH" \
  --public-ip-sku Standard \
  --public-ip-address-dns-name "$DNS_LABEL" \
  --assign-identity '[system]' \
  --custom-data "$CLOUDINIT" \
  --nsg-rule SSH \
  --query '{id:id, publicIp:publicIpAddress, fqdn:fqdns}' \
  -o table

# --- grant managed identity Key Vault Secrets User ---
echo "[provision] granting VM managed identity Key Vault Secrets User..."
VM_IDENTITY=$(az vm identity show -g "$RG" -n "$VM_NAME" --query principalId -o tsv)
KV_SCOPE="/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.KeyVault/vaults/$KV_NAME"
az role assignment create \
  --assignee "$VM_IDENTITY" \
  --role "Key Vault Secrets User" \
  --scope "$KV_SCOPE" \
  --query '{principal:principalId, role:roleDefinitionName}' -o table

# --- open HTTPS + HTTP ports ---
echo "[provision] opening 80 + 443 on NSG..."
az vm open-port -g "$RG" -n "$VM_NAME" --port 80  --priority 900  -o none
az vm open-port -g "$RG" -n "$VM_NAME" --port 443 --priority 901  -o none

# --- gather connection info ---
PUBLIC_IP=$(az vm show -g "$RG" -n "$VM_NAME" -d --query publicIps -o tsv)
AZURE_FQDN=$(az vm show -g "$RG" -n "$VM_NAME" -d --query fqdns -o tsv)

echo ""
echo "============================================================"
echo "  VM created"
echo "============================================================"
echo "  public IP:   $PUBLIC_IP"
echo "  Azure FQDN:  $AZURE_FQDN"
echo "  ssh:         ssh $ADMIN_USER@$PUBLIC_IP"
echo ""
echo "  Wire DNS:    $PUBLIC_FQDN CNAME → $AZURE_FQDN"
echo "  (or A record → $PUBLIC_IP)"
echo "============================================================"

# --- watch cloud-init progress live ---
echo ""
echo "[watch] streaming cloud-init bootstrap output (Ctrl+C to detach; the VM keeps building)..."
echo "       wait ~30s for sshd to come up first..."
sleep 30
echo ""

# Loop until cloud-init signals done, tailing output every 5s
ATTEMPTS=0
MAX_ATTEMPTS=120  # 10 minutes max
while [ $ATTEMPTS -lt $MAX_ATTEMPTS ]; do
  # Use az vm run-command to fetch the latest tail of the bootstrap log
  STATUS=$(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    "$ADMIN_USER@$PUBLIC_IP" \
    "cat /var/log/cogos-bootstrap.log 2>/dev/null | tail -3; echo '---'; systemctl is-active cogos-api 2>/dev/null || echo inactive" \
    2>/dev/null || echo "ssh-not-ready")

  echo "$STATUS"

  if echo "$STATUS" | grep -q '^active$'; then
    echo ""
    echo "============================================================"
    echo "  cogos-api is ACTIVE on the VM"
    echo "============================================================"
    echo ""
    echo "  Test it:"
    echo "    curl http://$PUBLIC_IP:4444/health"
    echo ""
    echo "  Once DNS points $PUBLIC_FQDN at $AZURE_FQDN (or $PUBLIC_IP):"
    echo "    curl https://$PUBLIC_FQDN/health"
    echo ""
    echo "  Live admin dashboard (after DNS):"
    echo "    https://$PUBLIC_FQDN/admin/live"
    break
  fi
  if echo "$STATUS" | grep -q "bootstrap complete"; then
    echo ""
    echo "============================================================"
    echo "  bootstrap complete; verifying service..."
    echo "============================================================"
  fi
  sleep 5
  ATTEMPTS=$((ATTEMPTS + 1))
done

if [ $ATTEMPTS -ge $MAX_ATTEMPTS ]; then
  echo ""
  echo "WARN: cloud-init did not signal completion within 10 minutes."
  echo "      SSH in to debug:  ssh $ADMIN_USER@$PUBLIC_IP"
  echo "      Bootstrap log:    cat /var/log/cogos-bootstrap.log"
  echo "      Cloud-init log:   cat /var/log/cloud-init-output.log"
  exit 1
fi
