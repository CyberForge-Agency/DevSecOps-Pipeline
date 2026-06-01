# CyberForge Pipeline - Cost Management

## 1. Current Azure Resources & Monthly Costs

All resources are deployed in **Poland Central** (EU) under the `cyberforge-staging-rg` resource group.

| Resource | SKU / Tier | Estimated Monthly Cost | Notes |
|----------|-----------|----------------------|-------|
| Azure Container Registry | Basic | ~$5/mo | `admin_enabled = false`, public access for GitHub runners |
| Container Apps (app) | Consumption (Serverless) | ~$0-3/mo idle, ~$12-16/mo active | `min_replicas = 0`, `max_replicas = 3`, 0.25 vCPU / 0.5 Gi |
| Container Apps Environment | Consumption | (included above) | Managed environment |
| Log Analytics Workspace | PerGB2018 | ~$0.50-1/mo | 90-day retention, small app logs |
| Key Vault | Standard | ~$0/mo (negligible) | Purge protection enabled, RBAC auth, minimal operations |
| Storage Account (evidence) | Standard LRS | ~$0.50-1/mo | Versioning enabled, WORM immutability, 365-day soft delete |
| Storage Account (tfstate) | Standard LRS | ~$0.10/mo | Terraform remote state backend |

### Cost Summary

| Scenario | Estimated Monthly Total |
|----------|------------------------|
| **Idle** (no traffic, scale-to-zero) | **~$6-8/mo** |
| **Active** (continuous traffic, replicas running) | **~$18-23/mo** |

---

## 2. Budget Safeguard

A **$50/month budget** should be configured in the Azure portal or via Terraform with alerts at:

- **50%** ($25) - Informational notification
- **80%** ($40) - Warning notification
- **100%** ($50) - Critical notification, review resource usage immediately

To configure via Azure CLI:

```bash
az consumption budget create \
  --budget-name "cyberforge-staging-budget" \
  --resource-group "cyberforge-staging-rg" \
  --amount 50 \
  --time-grain Monthly \
  --start-date "$(date +%Y-%m)-01" \
  --end-date "2027-12-31" \
  --category Cost
```

---

## 3. Cost Optimization Tips

### Already configured

- **Container Apps `min_replicas = 0`** - scales to zero when idle, no compute charges during inactivity
- **ACR Basic SKU** - cheapest tier, sufficient for a single pipeline with low pull frequency
- **LRS storage** - no geo-replication; acceptable for staging environments
- **Lifecycle management** - evidence blobs move to **Cool tier after 30 days** via `azurerm_storage_management_policy`, reducing storage costs for older evidence packs
- **Standard Key Vault** - no premium HSM charges; RBAC-based access eliminates vault policy overhead

### Additional recommendations

- **Log Analytics** - stay under the **5 GB/day free ingestion tier**; current app logs are well below this threshold
- **Container Apps scaling** - `max_replicas = 3` caps burst costs; adjust down to `1` if traffic is minimal
- **ACR image cleanup** - periodically purge untagged/old images to stay within the Basic tier's 10 GiB storage limit:
  ```bash
  az acr run --cmd "acr purge --filter 'app:.*' --ago 30d --untagged" \
    --registry cyberforgestagingacr /dev/null
  ```
- **Blob versioning** - while enabled for compliance, monitor version count; excessive versions increase storage costs
- **Reserved instances** - not applicable at current scale; revisit if moving to dedicated Container Apps plans

---

## 4. When to Scale Up (Production)

When moving from staging to production, consider the following upgrades:

| Component | Staging | Production | Reason |
|-----------|---------|------------|--------|
| ACR SKU | Basic | **Standard** | Higher throughput, geo-replication support, webhooks |
| Storage replication | LRS | **GRS** | Cross-region redundancy for evidence packs (compliance) |
| Container Apps plan | Consumption | **Dedicated** | Guaranteed compute, VNET integration, no cold starts |
| Log Analytics | PerGB2018 | **Commitment tier** | Cost savings at higher ingestion volumes (100+ GB/day) |
| Key Vault | Standard | **Premium** | HSM-backed keys for cryptographic operations |
| Monitoring | Log Analytics only | **Azure Sentinel** | Full SIEM capabilities, threat detection, incident response |
| Networking | Public | **Private endpoints + VNET** | Zero public attack surface |
| WAF | None | **Azure Front Door + WAF** | DDoS protection, geo-filtering, rate limiting |

---

## 5. Teardown Procedure (Reference Only)

> **WARNING**: This section is for reference only. Do NOT execute these commands unless a deliberate decision has been made to decommission the environment.

### Step 1: Destroy application resources (Terraform-managed)

```bash
cd infra/
terraform plan -destroy -out=destroy.tfplan
terraform apply destroy.tfplan
```

### Step 2: Destroy tfstate resource group

```bash
az group delete --name "cyberforge-tfstate-rg" --yes --no-wait
```

### Step 3: Remove OIDC app registration

```bash
# List the app registration first
az ad app list --display-name "cyberforge" --query "[].{appId:appId, displayName:displayName}"

# Delete the app registration
az ad app delete --id <APP_ID>
```

### Important caveats

- **WORM-locked blobs** (immutability policy with `immutability_period_in_days = 1825`) **cannot be deleted** until the 5-year retention period expires. The storage account and container will remain until all immutability locks have expired.
- **Key Vault with purge protection** (`purge_protection_enabled = true`, `soft_delete_retention_days = 90`) retains the vault name for **90 days** after deletion. You cannot reuse the same Key Vault name during this period.
- **Role assignments** created by Terraform (e.g., `AcrPull` for Container App managed identity) are removed with the principal, but orphaned assignments may need manual cleanup.
- **DNS names** for Container Apps are released immediately upon deletion but may take time to become available for reuse.

---

## 6. Free Credits & Cost-Free Services

### Azure free account

- **$200 credit** for the first 30 days (new accounts)
- **Always-free tier** services include:
  - 750 hours/month of B1s VMs (not used here, but available)
  - 5 GB of LRS Blob storage
  - 5 GB/day of Log Analytics ingestion
  - 250 MB of Azure Cosmos DB (not used)
  - 10 web, mobile, or API apps with Azure App Service

### GitHub free tier

- **2,000 CI/CD minutes/month** on GitHub Actions (public repos: unlimited)
- **GitHub Advanced Security** included for public repos
- **500 MB** of GitHub Packages storage

### Cost monitoring

Run `scripts/cost-check.sh` to view current resource usage and estimated spend at any time.
