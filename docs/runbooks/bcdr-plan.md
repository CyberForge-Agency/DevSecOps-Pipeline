# Business Continuity and Disaster Recovery (BC/DR) Plan

**Document Owner:** CTO
**Last Updated:** 2026-04-13
**Review Cadence:** Annually, after major incidents, or after infrastructure changes
**ISO 27001 Reference:** A.5.29, A.5.30, A.8.13, A.8.14
**DORA Reference:** Art. 11 (ICT business continuity), Art. 12 (Backup policies)

---

## 1. Purpose

This document defines the backup strategy, recovery procedures, and continuity planning for the CyberForge DevSecOps Pipeline platform. It ensures compliance with DORA Article 11 (business continuity management) and Article 12 (backup policies).

---

## 2. Scope

This plan covers the following components:

| Component | Description |
|---|---|
| Terraform State | Infrastructure-as-Code state stored in Azure Blob Storage |
| ACR Images | Container images stored in Azure Container Registry |
| Evidence Packs | Compliance evidence stored in Azure Blob Storage (WORM) |
| Pipeline Configuration | GitHub Actions workflows, OPA policies, scripts |
| Application Code | Source code in GitHub repository |

---

## 3. Backup Strategy

### 3.1 Terraform State

| Property | Value |
|---|---|
| Storage Location | Azure Blob Storage (dedicated tfstate storage account) |
| Replication | GRS (Geo-Redundant Storage) -- data replicated to paired Azure region |
| Versioning | Enabled -- every state change creates a new version |
| Soft Delete | 365-day retention for blobs and containers |
| Deletion Protection | `azurerm_management_lock` (CanNotDelete) on the resource group |
| Backup Frequency | Automatic (every `terraform apply` creates a new version) |
| Backup Validation | Periodic `terraform plan` in staging confirms state integrity |

**Recovery Point Objective (RPO): 0** -- every state change is versioned, no data loss possible unless both primary and secondary regions fail simultaneously.

### 3.2 ACR Container Images

| Property | Value |
|---|---|
| Storage Location | Azure Container Registry (Premium SKU recommended for geo-replication) |
| Immutability | Images referenced by SHA digest (content-addressable, cannot be overwritten) |
| Tagging | Every build produces a unique tag (`sha-<commit>`) plus `latest` |
| Signing | Cosign keyless signing with SLSA provenance attestation |
| SBOM | CycloneDX SBOM attached to every image |
| Retention | No automatic deletion policy -- images persist until manually removed |

**RPO: 0** -- images are immutable by SHA. Any image ever pushed can be pulled by its digest. Pipeline can rebuild any image from source at a specific commit.

### 3.3 Evidence Packs

| Property | Value |
|---|---|
| Storage Location | Azure Blob Storage (`evidence-packs` container) |
| Replication | Configurable via `var.replication_type` (GRS recommended for production) |
| WORM Policy | Time-based immutability (1825 days / 5 years) |
| Versioning | Enabled -- all blob versions retained |
| Soft Delete | 365-day retention |
| Append-Only | `protected_append_writes_all_enabled = true` |
| Lifecycle Tiering | Cool tier after 30 days (cost optimization) |

**RPO: 0** -- blobs are immutable and versioned. Data cannot be lost unless both primary and secondary regions fail.

### 3.4 Pipeline Configuration and Source Code

| Property | Value |
|---|---|
| Storage Location | GitHub (git repository) |
| Replication | GitHub's built-in redundancy; developer local clones serve as additional backups |
| Versioning | Git commit history (complete, immutable history) |
| Branch Protection | Main branch requires 2 approvals, signed commits, no force push |
| Backup | Every developer clone is a full backup of the repository |

**RPO: 0** -- distributed git means every clone is a complete backup.

---

## 4. RTO/RPO Targets

| Component | RTO (Recovery Time) | RPO (Recovery Point) | Justification |
|---|---|---|---|
| **Container App** | 30 minutes | 0 (no data loss) | Redeployment from ACR image by SHA. Terraform recreates infra. |
| **Evidence Packs** | 24 hours | 0 (no data loss) | GRS provides automatic failover. Manual intervention only if primary region is unavailable. |
| **Pipeline** | 4 hours | 0 (no data loss) | Fork/clone repo to new GitHub org. Reconfigure OIDC federation. Terraform recreates Azure infra. |
| **Terraform State** | 1 hour | 0 (no data loss) | Restore from versioned blob or GRS secondary. |
| **ACR Images** | 2 hours | 0 (no data loss) | Rebuild from source if registry unavailable. Geo-replicated if Premium SKU. |

---

## 5. Restore Procedures

### 5.1 Container App Restoration

**Scenario:** Container App is unavailable or corrupted.

```bash
# Step 1: Verify the target image exists in ACR
az acr repository show-tags \
  --name <ACR_NAME> \
  --repository <APP_NAME> \
  --output table

# Step 2: Redeploy from known-good image
az containerapp update \
  --name <APP_NAME> \
  --resource-group <RG_NAME> \
  --image <ACR_LOGIN_SERVER>/<APP_NAME>:<KNOWN_GOOD_TAG>

# Step 3: Verify deployment
az containerapp show \
  --name <APP_NAME> \
  --resource-group <RG_NAME> \
  --query "properties.latestRevisionFqdn" -o tsv

# Step 4: If the Container App Environment itself is destroyed
cd infra
terraform apply -var="container_image=<ACR_LOGIN_SERVER>/<APP_NAME>:<TAG>"
```

**Estimated time:** 15-30 minutes.

### 5.2 Terraform State Restoration

**Scenario:** Terraform state is corrupted or accidentally deleted.

```bash
# Option A: Restore from blob versioning
# List versions of the state file
az storage blob list \
  --account-name <TFSTATE_ACCOUNT> \
  --container-name tfstate \
  --include v \
  --prefix "pipeline.terraform.tfstate" \
  --output table

# Promote a previous version to current
az storage blob copy start \
  --account-name <TFSTATE_ACCOUNT> \
  --destination-container tfstate \
  --destination-blob "pipeline.terraform.tfstate" \
  --source-uri "https://<TFSTATE_ACCOUNT>.blob.core.windows.net/tfstate/pipeline.terraform.tfstate?versionid=<VERSION_ID>"

# Option B: Restore from GRS secondary (if primary region unavailable)
# Initiate storage account failover
az storage account failover \
  --name <TFSTATE_ACCOUNT> \
  --resource-group <TFSTATE_RG>

# Option C: Re-import all resources into fresh state
terraform init
terraform import azurerm_resource_group.this /subscriptions/<SUB_ID>/resourceGroups/<RG_NAME>
# ... import each resource
```

**Estimated time:** 15 minutes (Option A), 1 hour (Option B), 2-4 hours (Option C).

### 5.3 Evidence Pack Restoration

**Scenario:** Evidence storage account unavailable (region outage).

```bash
# Option A: Wait for Azure region recovery (evidence is immutable, no data loss)

# Option B: Initiate GRS failover (if configured)
az storage account failover \
  --name <EVIDENCE_ACCOUNT> \
  --resource-group <RG_NAME>

# Option C: Restore from blob versioning (if accidental soft-delete)
az storage blob undelete \
  --account-name <EVIDENCE_ACCOUNT> \
  --container-name evidence-packs \
  --name <BLOB_NAME>
```

**Estimated time:** Varies by scenario. GRS failover: ~1 hour. Region recovery: depends on Azure.

### 5.4 Pipeline Restoration

**Scenario:** GitHub is unavailable or repository is compromised.

```bash
# Step 1: Clone from any developer's local copy
git clone /path/to/local/clone new-repo
cd new-repo

# Step 2: Push to a new GitHub organization or alternative git host
git remote set-url origin https://github.com/<NEW_ORG>/<REPO>.git
git push --all origin
git push --tags origin

# Step 3: Reconfigure GitHub Actions
# - Create new OIDC federation in Azure AD for the new org
# - Update branch protection rules
# - Re-add repository secrets (if any -- should be none with OIDC)
# - Verify workflows pass

# Step 4: Reconfigure Terraform backend
terraform init -backend-config="..." -reconfigure
```

**Estimated time:** 2-4 hours (includes OIDC reconfiguration).

### 5.5 ACR Image Restoration

**Scenario:** Container image not available in ACR.

```bash
# Option A: Rebuild from source
git checkout <COMMIT_SHA>
docker build -t <ACR_LOGIN_SERVER>/<APP_NAME>:<TAG> .
az acr login --name <ACR_NAME>
docker push <ACR_LOGIN_SERVER>/<APP_NAME>:<TAG>

# Option B: Pull from geo-replicated ACR (if Premium SKU)
# Images are automatically available from the replica

# Option C: Use the CI/CD pipeline to rebuild
# Trigger a pipeline run on the desired commit
gh workflow run pipeline.yml --ref <COMMIT_SHA>
```

**Estimated time:** 30 minutes (Option A), immediate (Option B), 15 minutes (Option C).

---

## 6. BC/DR Test Plan

### 6.1 Test Schedule

| Test Type | Frequency | Last Tested | Next Scheduled |
|---|---|---|---|
| Tabletop exercise (all scenarios) | Annually | Not yet conducted | TBD |
| Container App failover drill | Semi-annually | Not yet conducted | TBD |
| Terraform state restore drill | Annually | Not yet conducted | TBD |
| Pipeline rebuild drill | Annually | Not yet conducted | TBD |
| Evidence storage failover drill | Annually (if GRS) | Not yet conducted | TBD |

### 6.2 Drill Procedure Template

For each BC/DR drill, follow this template:

#### Pre-Drill

1. **Scope:** Define which scenario is being tested
2. **Participants:** List all team members involved
3. **Environment:** Confirm drill runs in staging (never production)
4. **Success criteria:** Define measurable pass/fail criteria
5. **Rollback plan:** Document how to undo drill actions

#### During Drill

1. **Start time:** Record UTC timestamp
2. **Actions taken:** Log each step with timestamps
3. **Issues encountered:** Document any blockers or unexpected behavior
4. **Actual recovery time:** Measure against RTO target
5. **Data loss assessment:** Verify against RPO target

#### Post-Drill

1. **Pass/fail assessment:** Did recovery meet RTO/RPO targets?
2. **Lessons learned:** What worked, what did not
3. **Corrective actions:** List improvements to make
4. **Evidence:** Archive drill logs to evidence storage
5. **Sign-off:** Drill lead and management approval

### 6.3 Drill Evidence Format

Each drill must produce an evidence artifact containing:

```
bcdr-drill-<YYYY-MM-DD>/
  drill-plan.md          -- Pre-drill scope and success criteria
  drill-log.md           -- Timestamped action log
  drill-results.md       -- Post-drill assessment
  screenshots/           -- Screenshots of recovery steps (optional)
  metrics.json           -- RTO/RPO measurements
```

Upload to the evidence storage account:

```bash
tar czf "bcdr-drill-$(date +%Y-%m-%d).tar.gz" bcdr-drill-*/
az storage blob upload \
  --account-name <EVIDENCE_ACCOUNT> \
  --container-name evidence-packs \
  --name "bcdr-drills/bcdr-drill-$(date +%Y-%m-%d).tar.gz" \
  --file "bcdr-drill-$(date +%Y-%m-%d).tar.gz" \
  --auth-mode login
```

---

## 7. Dependencies and Assumptions

| Assumption | Risk if Invalid | Mitigation |
|---|---|---|
| Azure region does not suffer complete data loss | Evidence and state could be lost | GRS replication to paired region |
| GitHub remains available | Pipeline cannot execute | Local git clones; documented restore procedure |
| Developer local clones exist | Repository cannot be restored from backup | Policy: at least 2 developers maintain local clones |
| OIDC federation can be reconfigured | Pipeline cannot authenticate to Azure | Document federation setup; keep client ID and tenant ID in secure backup |
| ACR images can be rebuilt from source | Old images unavailable | Retain build scripts and Dockerfiles in version control |
