# Cloud Security Posture (CSPM) — CIS-Mapped Posture of the Azure Infrastructure

| Field          | Value                                                                 |
|----------------|-----------------------------------------------------------------------|
| Document Owner | Security Lead                                                          |
| Approved By    | CyberForge Management                                                  |
| Version        | 1.0                                                                    |
| Effective Date | 2026-06-16                                                            |
| Review Cycle   | Annually, or after significant infrastructure change                  |
| Compliance     | NIS2 Art.21(2)(i); DORA Art.9; ISO/IEC 27001:2022 A.8.9; CIS Microsoft Azure Foundations Benchmark v3.0.0 |
| Spec mapping   | evidence-pack-specification.md:149 (Part C.14 "CSPM posture"); §4 stage "Runtime / cloud posture" (evidence-pack-specification.md:198) |

---

## 1. Purpose and honesty boundary

The master spec requires a **Cloud posture (CSPM)** row (Part C.14): *"Cloud configured to
benchmark · Continuous (Prowler/Custodian) · NIS2 21(2)(i); DORA 9; CIS/ISO 8.9 · CIS Foundations
mapped; criticals remediated; drift alerted"* (evidence-pack-specification.md:149). Spec §4
explicitly **rejects** a *"Point-in-time screenshot from audit week"* for this stage
(evidence-pack-specification.md:198).

This document maps the **declared** Azure infrastructure (`Pipeline/infra/**`, Terraform) to the
**CIS Microsoft Azure Foundations Benchmark v3.0.0** and to ISO/IEC 27001:2022 Annex A 8.9
(Configuration management). It is the design-stage posture baseline.

> **STATUS — design-stage (no live scan).** No continuous CSPM tool (Prowler / Cloud Custodian /
> Microsoft Defender for Cloud) currently runs against the deployed subscription, and no
> `evidence/cloud-posture.json` artifact is produced or signed at this time. The CIS mappings below
> are **derived statically from the Terraform source**, not from a runtime scan of live Azure
> resources. **Continuous posture assessment and drift alerting are TARGET-STATE** (see §6).
>
> Per the spec's honesty constraint, the audit-document CSPM/runtime wording is labelled
> "design-stage" and MUST NOT be presented as a continuous, drift-alerted posture until the live
> scan in §5 is wired. Static IaC analysis of `infra/**` (Checkov) DOES run in CI; that is a
> *pre-deploy* control, distinct from runtime CSPM of the *deployed* tenant, which is what Part C.14
> asks for.

---

## 2. Why CSPM is distinct from the existing IaC scan

The pipeline already performs **pre-deploy IaC scanning** (Checkov over `infra/**`), which maps to
the spec's separate "IaC scan" row (evidence-pack-specification.md:139, §4 "IaC scan" stage). That
proves the *intended* configuration is secure **before** apply.

CSPM (Part C.14) is a **different control**: it assesses the **actually-deployed** cloud resources
**after** apply, continuously, and detects **drift** — out-of-band changes made directly in Azure
that bypass Terraform. IaC scanning cannot see drift; CSPM is the only control that does. ISO
27001:2022 A.8.9 requires configurations to be *"established, documented, implemented, **monitored
and reviewed**"* — the monitor-and-review half is precisely runtime CSPM, not pre-deploy IaC scan.

| Aspect            | IaC scan (existing, C.IaC row)        | CSPM posture (this doc, C.14)                |
|-------------------|---------------------------------------|----------------------------------------------|
| Target            | Terraform source in Git               | Live Azure resources in the subscription     |
| Timing            | Pre-merge / pre-apply                 | Post-apply, continuous                        |
| Detects drift?    | No                                    | Yes (the defining property)                   |
| Tool              | Checkov                               | Prowler (Azure) / Defender for Cloud (TARGET)|
| ISO 8.9 half      | "established / implemented"           | "monitored and reviewed"                      |

---

## 3. Scope — resources in the posture boundary

Derived from `Pipeline/infra/main.tf` and its modules (read-only). All resources are deployed to a
single resource group `${project}-${environment}-rg` (`infra/main.tf:13-17`).

| Resource (Terraform)                         | Azure type                          | Source (read-only)                              |
|----------------------------------------------|-------------------------------------|-------------------------------------------------|
| Container Registry                           | `azurerm_container_registry`        | `infra/modules/acr/main.tf:1-11`                |
| Key Vault                                    | `azurerm_key_vault`                 | `infra/modules/keyvault/main.tf:1-12`           |
| Storage Account (evidence)                   | `azurerm_storage_account`           | `infra/modules/storage/main.tf:1-22`            |
| Storage Container (WORM)                      | `azurerm_storage_container_immutability_policy` | `infra/modules/storage/main.tf:24-37` |
| Container App + environment                  | `azurerm_container_app(_environment)` | `infra/modules/container-apps/main.tf:10-71`  |
| Log Analytics workspace                      | `azurerm_log_analytics_workspace`   | `infra/modules/container-apps/main.tf:1-8`      |
| Monitor alerts + action group               | `azurerm_monitor_*`                 | `infra/modules/monitoring/main.tf:7-144`        |
| Resource-group delete lock                   | `azurerm_management_lock`           | `infra/main.tf:71-76`                            |

The CIS Microsoft Azure Foundations Benchmark v3.0.0 organises controls into nine top-level
sections; the sections relevant to the deployed footprint are **2 Security (Defender / Key Vault)**,
**3 Storage Accounts**, **5 Logging and Monitoring**, **8 AppService**, and **9 Miscellaneous
(resource locks)**. Sections **1 Identity**, **4 Database Services**, **6 Networking**, and **7
Virtual Machines** are partially or not-applicable to this footprint (no VMs, no managed DB, no
custom VNet) and are flagged accordingly below.

---

## 4. CIS Azure Foundations v3.0.0 → declared-config mapping

Each row maps a CIS Azure Foundations v3.0.0 control area to the **declared** Terraform state.
`status` is the *design-stage* assessment from the IaC source; a live Prowler scan (§5) would
*confirm or contradict* each row against the running tenant. `severity` follows CIS scoring
conventions (CRITICAL reserved for exploitable exposure of the evidence/secret store).

| CIS area (v3.0.0)                              | CIS § (illustrative) | Declared config (source)                                                                 | Design-stage status | Severity if not met |
|-----------------------------------------------|----------------------|------------------------------------------------------------------------------------------|---------------------|---------------------|
| Storage — secure transfer (HTTPS) required    | 3.x (Storage)        | `min_tls_version = "TLS1_2"` (`storage/main.tf:7`); `allow_nested_items_to_be_public=false` (:8) | PASS (declared)     | HIGH                |
| Storage — public blob access disabled         | 3.x (Storage)        | `allow_nested_items_to_be_public=false` (:8); container `container_access_type="private"` (:27) | PASS (declared)     | CRITICAL            |
| Storage — soft delete / versioning enabled    | 3.x (Storage)        | `versioning_enabled=true` (:12); delete/container retention 365d (:14-21)                 | PASS (declared)     | MEDIUM              |
| Storage — immutability (WORM) for evidence    | 3.x / 9.x            | `azurerm_storage_container_immutability_policy` (`storage/main.tf:32-37`) gated `> 0`     | PASS (declared)*    | HIGH                |
| Storage — public network access restricted    | 3.x / 6.x            | No private-endpoint/firewall set; account defaults to public network                       | TARGET-STATE (gap)  | HIGH                |
| Key Vault — purge protection enabled          | 2.x (Key Vault)      | `purge_protection_enabled=true` (`keyvault/main.tf:8`)                                    | PASS (declared)     | HIGH                |
| Key Vault — soft delete retention configured  | 2.x (Key Vault)      | `soft_delete_retention_days=90` (`keyvault/main.tf:7`)                                    | PASS (declared)     | MEDIUM              |
| Key Vault — RBAC authorization (no access-policy sprawl) | 2.x        | `rbac_authorization_enabled=true` (`keyvault/main.tf:9`)                                  | PASS (declared)     | MEDIUM              |
| Key Vault — private network / firewall        | 2.x / 6.x            | `public_network_access_enabled=true` (`keyvault/main.tf:10`)                              | TARGET-STATE (gap)  | HIGH                |
| Registry — admin user disabled                | 2.x / 8.x            | `admin_enabled=false` (`acr/main.tf:6`)                                                   | PASS (declared)     | HIGH                |
| Registry — public network access restricted   | 2.x / 6.x            | `public_network_access_enabled=true` (`acr/main.tf:9`, GitHub-hosted runner constraint)  | TARGET-STATE (gap)  | MEDIUM              |
| AppService/Container App — HTTPS only ingress | 8.x (AppService)     | `ingress.transport="auto"` (`container-apps/main.tf:60`); platform terminates TLS         | PARTIAL (review)    | MEDIUM              |
| AppService/Container App — managed identity used | 8.x / 1.x         | `identity { type="SystemAssigned" }` + `AcrPull` RBAC (`container-apps/main.tf:25-27,74-78`) | PASS (declared)  | MEDIUM              |
| Logging — central Log Analytics workspace     | 5.x (Logging/Mon.)   | `azurerm_log_analytics_workspace` 90d retention (`container-apps/main.tf:1-8`)            | PASS (declared)     | HIGH                |
| Logging — activity-log / failure alerting     | 5.x                  | Three scheduled-query alerts + action group (`monitoring/main.tf:23-144`)                 | PARTIAL (review)†   | MEDIUM              |
| Logging — log retention >= benchmark minimum  | 5.x                  | LA workspace `retention_in_days=90` (`container-apps/main.tf:6`)                          | REVIEW‡             | MEDIUM              |
| Identity — central RBAC, no static cloud creds | 1.x (Identity)      | OIDC federation in CI (`deploy.yml`, `azure/login` no secret); no SP secrets in TF        | PASS (declared)     | HIGH                |
| Identity — MFA / conditional access           | 1.x                  | Tenant-level control, not in `infra/**`                                                   | OUT-OF-SCOPE (tenant)| n/a                |
| Defender for Cloud — plans enabled            | 2.x (Defender)       | Not declared in `infra/**`                                                                | TARGET-STATE (gap)  | HIGH                |
| Networking — NSG / restricted ingress         | 6.x (Networking)     | No custom VNet/NSG; Container Apps managed network                                        | NOT-APPLICABLE      | n/a                 |
| Database services                             | 4.x (Database)       | No managed DB deployed                                                                    | NOT-APPLICABLE      | n/a                 |
| Virtual machines                              | 7.x (VMs)            | No VMs deployed (serverless Container Apps)                                               | NOT-APPLICABLE      | n/a                 |
| Misc — resource lock on critical assets       | 9.x (Misc.)          | `azurerm_management_lock` CanNotDelete on RG (`infra/main.tf:71-76`)                      | PASS (declared)     | LOW                 |

\* WORM is gated `count = var.immutability_period_days > 0 ? 1 : 0` (`storage/main.tf:33`); if the
variable is 0 the policy is absent — a live scan would correctly report it as not-met.
† Alerts cover deployment/error/image-pull failures (`monitoring/main.tf`); they are *operational*
alerts, not CIS *security* activity-log alerts (e.g. NSG/policy/Key-Vault change alerts), so this is
a partial match pending dedicated security activity-log alert rules.
‡ CIS Logging guidance commonly expects retention of at least 90 days (often 365d/1y for activity
logs); 90d meets the floor but should be reviewed against the applicable benchmark profile.

**Design-stage summary (from declared config, NOT a live scan):**
CRITICAL not-met: **0** · HIGH gaps (TARGET-STATE): **4** (storage/KV/Defender network exposure +
Defender plans) · NOT-APPLICABLE: **3 sections** · REVIEW/PARTIAL: **3**.

> The **CRITICAL count surfaced into the compliance matrix** for the design-stage row is **0**
> against declared config. This is the static figure ONLY; it is NOT evidence of the live tenant's
> posture and MUST be relabelled with a measured count once §5 runs.

---

## 5. TARGET-STATE — live CSPM scan emitting a signed `cloud-posture.json`

The following is the **planned** wiring to satisfy Part C.14 with a real scan. It is **not yet
implemented**; wiring into the protected workflow YAMLs is a separate post-integration task (see
"Follow-up" of this task's closeout).

### 5.1 Scanner and authentication (no static secrets)

Use **Prowler** for Azure (open-source CSPM; supports CIS Azure Foundations v2.0/2.1/**3.0**/4.0
compliance profiles out of the box). Run it scoped to the deployed subscription / resource group via
the **existing OIDC identity** already used by `deploy.yml`:

1. `azure/login@<sha>` authenticates the runner with `client-id`/`tenant-id`/`subscription-id` and
   `permissions: id-token: write` — the exact pattern at `deploy.yml:43-47` (no static secret).
2. After login the runner has valid `az` CLI credentials, so Prowler runs with **`--az-cli-auth`**
   (the OIDC-compatible path; `--sp-env-auth` would require a stored secret and is NOT used).
3. The federated principal needs **Reader** on the subscription (plus the Prowler custom role for a
   handful of checks, and Microsoft Graph `Directory.Read.All` / `AuditLog.Read.All` /
   `Policy.Read.All` for any Entra-ID checks) — read-only, least-privilege.

```bash
# TARGET-STATE — not yet wired into deploy.yml / cloud-posture.yml
prowler azure --az-cli-auth \
  --subscription-id "$AZURE_SUBSCRIPTION_ID" \
  --compliance cis_3.0_azure \
  --output-formats json-ocsf \
  --output-directory evidence/cspm-raw
```

### 5.2 Consolidation into `evidence/cloud-posture.json`

A converter transforms Prowler's per-check output into the consolidated artifact with one row per
control: `{cis_control, status, severity}` (the shape called for in the task DoD), plus a header
summarising the CRITICAL-misconfig count.

```json
{
  "schema_version": 1,
  "scanner": "prowler",
  "scanner_version": "<pinned>",
  "compliance": "cis_3.0_azure",
  "subscription_id": "<redacted>",
  "scanned_at": "<RFC3339>",
  "summary": { "critical": 0, "high": 0, "medium": 0, "pass": 0, "manual": 0 },
  "rows": [
    { "cis_control": "3.1", "status": "PASS", "severity": "high", "resource": "<storage-acct>" }
  ]
}
```

### 5.3 Validator `scripts/validators/cloud_posture.py` (TARGET-STATE)

A validator using the shared T-33 envelope (`scripts/validators/libcompliance.py`) parses
`cloud-posture.json` and emits one envelope line:

- `measured` = `summary.critical` (the CRITICAL-misconfig count).
- `tier` = **BLOCKING** for production runs (a non-zero CRITICAL count FAILs and stops
  seal/deploy); **EVIDENCE-ONLY** otherwise (records the number without breaking the build) — the
  same BLOCKING/EVIDENCE-ONLY split documented in `libcompliance.py:30-43`.
- `status` = PASS only when a scan actually ran AND `summary.critical == 0`; absence of a scan is
  INDETERMINATE / MISSING, never a silent PASS (`libcompliance.py:9-11`).

Verification once implemented (per the task block):
`python3 Pipeline/scripts/validators/cloud_posture.py evidence/cloud-posture.json`.

### 5.4 Signing and Merkle inclusion (TARGET-STATE)

When a live scan runs, `cloud-posture.json` is added to the evidence directory before the seal step
so it is hashed into the manifest and committed-to by the Merkle root, and cosign-signed alongside
the other artifacts (handled by the integrity-chain stream, not this doc).

### 5.5 Continuous operation and drift alerting (TARGET-STATE)

Part C.14's "Continuous … drift alerted" criterion requires the scan to run on a schedule (e.g. a
`cloud-posture.yml` cron, or post-apply in `deploy.yml`) and to **alert on drift** between
consecutive scans (newly-failing CIS controls). Until a scheduled scan and a drift-diff/alert exist,
**continuous posture and drift alerting remain TARGET-STATE** — the doc must not claim them. The
existing `azurerm_monitor_*` alerts (`monitoring/main.tf`) are operational, not posture-drift,
alerts; a future Microsoft Defender for Cloud regulatory-compliance dashboard or an activity-log
alert on resource-configuration changes would close the drift-alerting gap.

---

## 6. Gap register (design-stage → target)

| # | Gap                                                              | Severity | Closure action                                                                       |
|---|------------------------------------------------------------------|----------|--------------------------------------------------------------------------------------|
| 1 | No live CSPM scan runs against the deployed tenant               | HIGH     | Wire Prowler (`--az-cli-auth` over existing OIDC) into `cloud-posture.yml`/`deploy.yml` (post-M0) |
| 2 | No `evidence/cloud-posture.json` produced or signed             | HIGH     | Add the consolidation step + `scripts/validators/cloud_posture.py` (T-33 envelope)   |
| 3 | No drift detection / drift alerting (only operational alerts)   | HIGH     | Scheduled scan + drift-diff alert OR Defender for Cloud compliance dashboard          |
| 4 | Storage / Key Vault / ACR allow public network access           | HIGH/MED | Private endpoints + network firewall (balanced against GitHub-hosted-runner reach)    |
| 5 | Microsoft Defender for Cloud plans not declared in `infra/**`   | HIGH     | Enable Defender plans for storage/containers/Key Vault; assert via CSPM               |
| 6 | No dedicated CIS security activity-log alert rules              | MEDIUM   | Add NSG/Key-Vault/policy-change activity-log alerts to the monitoring module          |

---

## 7. Regulatory mapping

| Regime / standard           | Clause                  | How this posture maps                                                            |
|-----------------------------|-------------------------|---------------------------------------------------------------------------------|
| NIS2                        | Art.21(2)(i)            | Basic cyber hygiene + secure configuration of network/information systems        |
| DORA                        | Art.9 (Protection & prevention) | ICT systems configured to minimise attack surface; continuous monitoring (target) |
| ISO/IEC 27001:2022 Annex A  | A.8.9 Configuration management | Configs established/documented/implemented (IaC) + monitored/reviewed (CSPM, target) |
| CIS Microsoft Azure Foundations | v3.0.0               | §2/§3/§5/§8/§9 mapped to declared config (§4); live confirmation via Prowler `cis_3.0_azure` (target) |

ISO 27001:2022 A.8.9 control text: *"Configurations, including security configurations, of hardware,
software, services and networks should be established, documented, implemented, monitored and
reviewed."* The **monitored and reviewed** clause is satisfied only when the live CSPM scan (§5) is
operating; until then it is design-stage.

---

## 8. References

- evidence-pack-specification.md:149 (Part C.14 "CSPM posture"); :198 (§4 "Runtime / cloud posture")
- `Pipeline/infra/**` (Terraform source, read-only) — see §3 for per-file citations
- `Pipeline/scripts/validators/libcompliance.py` (shared T-33 validator envelope)
- CIS Microsoft Azure Foundations Benchmark v3.0.0 — https://www.cisecurity.org/benchmark/azure
  (section structure cross-checked against the MITRE InSpec baseline:
  https://github.com/mitre/azure-foundations-cis-baseline — 9 sections, 159 controls)
- Prowler Azure CSPM + CIS profiles — https://docs.prowler.com/user-guide/providers/azure/authentication
  and https://prowler.com/blog/azure-cspm-with-prowler-strengthening-your-cloud-security-posture
- ISO/IEC 27001:2022 Annex A 8.9 Configuration management — https://www.isms.online/iso-27001/annex-a-2022/8-9-configuration-management-2022/
