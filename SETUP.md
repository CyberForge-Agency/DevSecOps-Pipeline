# CyberForge Pipeline Setup (GitHub + Azure)

This guide covers the first real GitHub/Azure rollout for the implemented pipeline in this repository.

It focuses on:

- exact GitHub repository variables used by the workflows
- Azure OIDC (no static cloud secrets)
- minimum Azure RBAC needed for the current workflow design
- first-run bootstrap sequence and rollout checklist

## 1. What Is Already Implemented

This repository already includes:

- `app/` demo app (Node.js/TypeScript/Express)
- `.github/workflows/` reusable workflows (Phases 1-6) + `pipeline.yml`
- `infra/` Terraform for Azure (ACR, Container Apps, Key Vault, Storage, WORM policy)
- `policies/` OPA policies
- `scripts/` evidence-pack helper scripts

Additional docs:

- `docs/README.md` (documentation index)
- `docs/compliance-matrix.md` (framework → control → evidence mapping)

## 2. Important Bootstrap Dependency (Read First)

The pipeline pushes a container image to ACR in **Phase 2** (`build-and-scan.yml`) before the deploy phase runs Terraform.

That means:

- **ACR must already exist** before the first full `push`/`workflow_dispatch` run
- `ACR_NAME` and `ACR_REGISTRY` must already be configured in GitHub variables

Recommended bootstrap approach:

1. Create Terraform backend storage manually
2. Configure GitHub OIDC app + repo variables (`AZURE_*`, `TFSTATE_*`)
3. Run **Terraform once** (locally or from a temporary admin session) to create ACR/storage/etc.
4. Set `ACR_NAME`, `ACR_REGISTRY`, `EVIDENCE_STORAGE_ACCOUNT` from Terraform outputs
5. Run the full pipeline in GitHub

## 3. GitHub Repository Setup

## 3.1 Actions Settings

In GitHub repository settings:

- `Settings -> Actions -> General`
- Set **Workflow permissions** to: `Read and write permissions`

Reason:

- workflows need write permissions for issues, attestations, artifacts, SARIF upload, etc.

## 3.2 Environments

Create GitHub Environments:

- `staging` (required)
- `production` (optional now, but supported by `workflow_dispatch`)

Recommended protections:

- Required reviewers for `production`
- Optional wait timer for `production`

Note:

- The deploy workflow runs with `environment: staging|production`
- This affects the OIDC subject used by GitHub -> Azure tokens

## 3.3 Repository Variables (Exact Names)

Create these **repository variables** (`Settings -> Secrets and variables -> Actions -> Variables`):

| Variable | Required | Used By | Description / Example |
|---|---|---|---|
| `AZURE_CLIENT_ID` | Yes | build/sign/deploy/evidence | App registration (service principal) client ID used by OIDC |
| `AZURE_TENANT_ID` | Yes | build/sign/deploy/evidence | Azure/Entra tenant ID |
| `AZURE_SUBSCRIPTION_ID` | Yes | build/sign/deploy/evidence | Azure subscription ID |
| `ACR_NAME` | Yes for push/main runs | build/sign/deploy | ACR resource name (e.g. `cyberforgestagingacr`) |
| `ACR_REGISTRY` | Yes for push/main runs | build-and-scan | ACR login server (e.g. `cyberforgestagingacr.azurecr.io`) |
| `EVIDENCE_STORAGE_ACCOUNT` | Yes for Phase 6 archive | evidence-pack | Storage account name that holds `evidence-packs` container |
| `TFSTATE_RESOURCE_GROUP` | Recommended (deploy remote backend) | deploy | Resource group containing Terraform backend storage |
| `TFSTATE_STORAGE_ACCOUNT` | Recommended (deploy remote backend) | deploy | Storage account used for Terraform state |
| `TFSTATE_CONTAINER` | Recommended (deploy remote backend) | deploy | Blob container for tfstate (e.g. `tfstate`) |
| `TFSTATE_KEY` | Recommended (deploy remote backend) | deploy | State object key (e.g. `pipeline.terraform.tfstate`) |

Notes:

- Use **repository variables** (not environment-only variables) for the `AZURE_*`, `ACR_*`, and backend values.
- Some jobs using these vars are **not** environment-scoped (Phase 2/3/6), so environment-only variables may not be visible there.

## 3.4 Repository Secrets

No custom cloud secrets are required for the current workflow design.

- The pipeline uses **OIDC** via `azure/login`
- `secrets.GITHUB_TOKEN` is the built-in GitHub token (already available)

## 3.5 Branch Protection / Governance

Apply repository governance using:

- `.github/CODEOWNERS`
- `.github/branch-protection.json`

Important:

- After the first PR run, confirm the **actual check names** shown in GitHub and compare to `.github/branch-protection.json`
- Reusable workflows sometimes produce check names that differ slightly from planned names

## 4. Azure Setup

## 4.1 Terraform Backend (Bootstrap, Manual)

Create backend resources first (outside this repo's Terraform, because Terraform needs a backend before it can use it).

Required backend resources:

- Resource Group (example: `cyberforge-tfstate-rg`)
- Storage Account (example: `cyberforgetfstate`)
- Blob Container (example: `tfstate`)

Example (Azure CLI):

```bash
az group create -n cyberforge-tfstate-rg -l polandcentral

az storage account create \
  -g cyberforge-tfstate-rg \
  -n cyberforgetfstate \
  -l polandcentral \
  --sku Standard_LRS \
  --kind StorageV2

az storage container create \
  --name tfstate \
  --account-name cyberforgetfstate \
  --auth-mode login
```

Then set the corresponding GitHub repo variables:

- `TFSTATE_RESOURCE_GROUP=cyberforge-tfstate-rg`
- `TFSTATE_STORAGE_ACCOUNT=cyberforgetfstate`
- `TFSTATE_CONTAINER=tfstate`
- `TFSTATE_KEY=pipeline.terraform.tfstate`

## 4.2 Azure App Registration + Service Principal (OIDC)

Create one Azure app registration / service principal for the pipeline (simplest first-run setup).

You need:

- `AZURE_CLIENT_ID`
- `AZURE_TENANT_ID`
- `AZURE_SUBSCRIPTION_ID`

You can create this via Azure Portal or Azure CLI.

## 4.3 Federated Credentials (GitHub OIDC)

Add federated credentials to the Azure app registration for GitHub Actions.

Minimum recommended credentials for current workflow behavior:

1. **Main branch pushes** (used by Phases 2/3/6 and any non-environment-scoped jobs)
2. **Staging environment** (used by deploy job because it runs with `environment: staging`)
3. **Production environment** (optional now, if you plan to use `workflow_dispatch` with `production`)

### Subject values (important)

Use these GitHub OIDC `sub` subjects:

- Main branch:
  - `repo:<OWNER>/<REPO>:ref:refs/heads/main`
- Staging environment:
  - `repo:<OWNER>/<REPO>:environment:staging`
- Production environment (optional):
  - `repo:<OWNER>/<REPO>:environment:production`

Audience:

- `api://AzureADTokenExchange`

If deploy fails with OIDC auth but build/sign succeeds, this usually means the **environment subject** credential is missing.

## 4.4 Azure RBAC (Minimum for Current Workflow Design)

For the **single-service-principal** setup used by current workflows, assign these roles:

### Control plane (Terraform)

Scope: target subscription (or a dedicated target resource group, if pre-created)

- `Contributor`
- `User Access Administrator` (required because Terraform creates role assignments, e.g. ACR pull assignment for Container Apps)

Alternative (broader, simpler but less strict):

- `Owner` (instead of the two roles above)

### ACR data plane (build/sign/deploy)

Scope: target ACR resource

- `AcrPush`

Reason:

- Phase 2 pushes images
- Phase 3 attaches signatures/attestations
- Deploy/sign phases perform `az acr login`

(`AcrPush` includes pull access, so a separate `AcrPull` assignment for the pipeline SPN is usually not needed.)

### Evidence storage data plane (Phase 6)

Scope: evidence storage account (or specific container)

- `Storage Blob Data Contributor`

Reason:

- Phase 6 uploads evidence packs with `az storage blob upload --auth-mode login`

### Terraform backend storage data plane

Scope: tfstate storage account

- `Storage Blob Data Contributor`

Reason:

- AzureRM backend needs blob access for reading/writing Terraform state

## 5. Bootstrap the Infrastructure (One-Time)

After backend + OIDC + basic RBAC are ready, run Terraform once to create core resources before the first full pipeline run.

This can be done locally (recommended for bootstrap) using the same backend values you configured for GitHub.

Example:

```bash
cd infra

terraform init \
  -backend-config="resource_group_name=<TFSTATE_RESOURCE_GROUP>" \
  -backend-config="storage_account_name=<TFSTATE_STORAGE_ACCOUNT>" \
  -backend-config="container_name=<TFSTATE_CONTAINER>" \
  -backend-config="key=<TFSTATE_KEY>"

terraform apply -auto-approve
```

This creates (via the repo Terraform):

- ACR
- Key Vault
- Evidence storage account + container + immutability policy
- Container Apps environment + app

Then capture outputs:

```bash
terraform output -raw acr_login_server
terraform output -raw evidence_storage_account
```

Set GitHub repo variables from those outputs:

- `ACR_REGISTRY` = `terraform output -raw acr_login_server`
- `EVIDENCE_STORAGE_ACCOUNT` = `terraform output -raw evidence_storage_account`
- `ACR_NAME` = ACR resource name (from Azure Portal/CLI or derived from Terraform naming; easiest via Azure CLI list/filter)

## 6. First Rollout Checklist (Recommended)

## 6.1 Local final checks

- Install `actionlint` and run:
  - `actionlint .github/workflows/*.yml`
- Install `opa` and run:
  - `opa test policies/ -v`

## 6.2 GitHub repo checks

- Repo variables created (all `AZURE_*`, `ACR_*`, `EVIDENCE_STORAGE_ACCOUNT`, `TFSTATE_*`)
- Actions workflow permissions set to read/write
- `staging` environment exists
- Branch protection applied (or at least documented for later application)

## 6.3 First pipeline runs

1. Open a PR to `main`
   - Confirms Phase 1 + 2 reusable workflows run correctly
   - Confirms PR-only logic (TruffleHog diff scan, commit signing check) behaves as expected

2. Merge to `main` (or trigger `workflow_dispatch` with `staging`)
   - Confirms Phase 1-6 orchestration
   - Confirms Azure OIDC auth in non-environment + environment-scoped jobs
   - Confirms sign/attest/provenance/evidence artifact flow
   - Confirms deploy + smoke test + DAST + evidence upload

## 6.4 Post-run verification

After the first successful full run, verify:

- ACR contains the pushed image (SHA tag)
- Cosign signatures / attestations exist
- Terraform state is in remote backend (if configured)
- Evidence pack artifact exists in GitHub Actions
- Evidence pack blob exists in `evidence-packs` container
- DAST behavior is acceptable (issue creation on HIGH/CRITICAL only)

## 7. Troubleshooting (Common First-Run Failures)

## 7.1 `azure/login` OIDC failure

Symptoms:

- `AADSTS70021`, `No matching federated identity record`, or token exchange failure

Usually means:

- wrong GitHub org/repo in subject
- missing `main` branch federated credential
- missing `staging` environment federated credential

## 7.2 `az acr login` or push/attest fails

Usually means:

- `ACR_NAME` / `ACR_REGISTRY` is wrong
- ACR does not exist yet (bootstrap not done)
- pipeline SPN is missing `AcrPush`

## 7.3 Terraform backend init fails in deploy workflow

Usually means:

- one or more `TFSTATE_*` variables are missing
- pipeline SPN lacks blob access on tfstate storage account

Current deploy workflow behavior:

- falls back to `terraform init -backend=false` if backend vars are incomplete

## 7.4 Evidence pack Azure Blob upload fails

Usually means:

- `EVIDENCE_STORAGE_ACCOUNT` is wrong
- pipeline SPN lacks `Storage Blob Data Contributor` on evidence storage

## 7.5 Branch protection required checks do not match

Usually means:

- check names in `.github/branch-protection.json` differ from actual GitHub check display names

Fix:

- inspect the real check names from the first PR run
- update `.github/branch-protection.json` accordingly before enforcing

## 8. Security / Compliance Notes

- This setup uses **OIDC** and avoids static cloud credentials
- The pipeline is **compliance-enabling**, not full DORA/NIS2/ISO/SOC2 compliance by itself
- Phase F workstreams (SIEM, incident reporting, IAM governance, BC/DR, supplier risk, ISMS/SOC2 docs) are still required for production readiness
- See `docs/README.md` for the full documentation map
