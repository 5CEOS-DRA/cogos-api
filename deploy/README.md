# deploy/

Azure provisioning for cogos-api.

## Prerequisites

- `az` CLI logged in (`az login`)
- `gh` CLI logged in (the deploy needs your GitHub token to let the VM clone the private repo)
- **NCASv3_T4 quota approved** in `eastus2` for at least 4 vCPUs (one `NC4as_T4_v3` instance)
- A Key Vault provisioned and populated with secrets: `jwt-secret`, `cogos-admin-key`, `github-token` (the script will upload github-token if missing)
- An SSH public key (the script generates one at `~/.ssh/id_rsa` if missing)

## Usage

```bash
cd deploy
bash provision.sh
```

That's it. The script:

1. Verifies your GPU quota is approved
2. Uploads your GitHub token to Key Vault (if not already there) so cloud-init can clone the private repo
3. Creates an `NC4as_T4_v3` VM in `eastus2` with system-assigned managed identity
4. Attaches `cloud-init.yaml` as custom data (runs on first boot, installs everything)
5. Grants the VM's managed identity `Key Vault Secrets User` role on the Key Vault
6. Opens NSG ports 80 + 443 + 22
7. **Tails the cloud-init log to your terminal** so you watch the bootstrap live
8. Prints the public IP and Azure FQDN when cogos-api becomes `active` under systemd

Total time: ~10 minutes (2-5 min VM provisioning + ~5 min cloud-init bootstrap).

## What cloud-init.yaml does on the VM

- Installs Node 20, Caddy, Azure CLI, Ollama
- Pulls `qwen2.5:3b-instruct` and `qwen2.5:7b-instruct` (the cogOS Tier B + Tier A models)
- Logs into Azure via managed identity, pulls secrets from Key Vault
- Clones `5CEOS-DRA/cogos-api` from GitHub using the PAT from KV
- Writes `/opt/cogos-api/.env` with secrets (mode 0600)
- Starts cogos-api under systemd (`cogos-api.service`)
- Configures Caddy as reverse proxy on `cogos.5ceos.com` (Let's Encrypt automatic)
- All logs to `/var/log/cogos-bootstrap.log` (for live watching)

## After provisioning

**Wire DNS:**

Once `provision.sh` prints the Azure FQDN, create a CNAME at your DNS provider:

```
cogos.5ceos.com  CNAME  cogos-XXXXX.eastus2.cloudapp.azure.com
```

Within seconds, Caddy on the VM will fetch a Let's Encrypt cert for `cogos.5ceos.com` and serve HTTPS.

**Verify:**

```bash
curl https://cogos.5ceos.com/health
# → {"status":"ok","service":"cogos-api","version":"0.1.0"}
```

**Watch traffic in real-time:**

```
https://cogos.5ceos.com/admin/live
```

Auto-refreshing dashboard showing every inference call as it lands.

**Issue your first customer key:**

```bash
ADMIN_KEY=$(az keyvault secret show --vault-name cogos-kv-16d2bb --name cogos-admin-key --query value -o tsv)
curl -X POST https://cogos.5ceos.com/admin/keys \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"first-customer","tier":"starter"}' | jq
```

## Re-deploy code only (without re-creating VM)

```bash
ssh azureuser@<vm-ip> "cd /opt/cogos-api && sudo -u cogos git pull && sudo systemctl restart cogos-api"
```

## Tearing down

```bash
az vm delete -g cogos-rg -n cogos-vm --yes
az network public-ip delete -g cogos-rg -n cogos-vmPublicIP   # the VM's public IP
az network nsg delete -g cogos-rg -n cogos-vmNSG                # security group
# Key Vault + Resource Group survive — re-deploy reuses them.
```

## Cost (NC4as_T4_v3 in eastus2)

- On-demand: ~$526/mo (24/7)
- 1-year reserved: ~$320/mo
- 3-year reserved: ~$210/mo
- Spot: ~$80-200/mo (preemptible)

For first 10-50 customers: a single on-demand instance is fine; your $4K Founders Hub credit covers 8 months of always-on.
