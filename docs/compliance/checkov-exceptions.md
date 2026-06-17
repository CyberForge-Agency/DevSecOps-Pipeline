<!-- markdownlint-disable MD013 -->
# Checkov IaC Exception Register

**Document Owner:** Security Lead (Szymon Mytych)
**Last Reviewed:** 2026-06-16
**Review Cadence:** Quarterly (all `Active` entries), plus ad-hoc when a skip is added/removed
**Enforced by:** `scripts/validate-checkov-skips.py` (run in `.github/workflows/security-gate.yml`, IaC Security job, before `checkov`)

## Purpose

The IaC Security gate (`security-gate.yml` → `iac-security` job) runs Checkov against
`infra/` and **blocks** on any policy failure (`set -o pipefail`). A small number of
Checkov checks are skipped via `CHECKOV_SKIP_CHECKS`. A bare skip list is
indistinguishable from quietly making the gate green, so this register records, per
skipped check: the **reason**, the **compensating control**, the **owner**, and an
**expiry date**.

This mirrors the Trivy suppression policy (`app/.trivyignore` + `scripts/lint-trivyignore.py`):
suppressions must be justified and time-boxed, and a machine enforces it.

## How this is enforced (the gate is honest)

`scripts/validate-checkov-skips.py` runs **before** Checkov in CI and fails the IaC job if:

1. the active `CHECKOV_SKIP_CHECKS` list in `security-gate.yml` and the `Active` rows in
   this register **drift** (a skip with no register row, or an `Active` row that is no
   longer skipped); or
2. any `Active` entry is missing a required field (Check ID, Reason, Compensating Control,
   Owner, Expiry); or
3. any `Active` entry's **Expiry date is in the past** (the waiver has lapsed).

Deleting a justification, back-dating an expiry, or adding a skip without a row therefore
**fails CI** — exactly the property T-04 / T-76 require.

> **Re-run-without-the-skip proof.** Every entry below was produced by running
> `checkov -d infra/ --framework terraform` with the skip list **removed**, so the
> "what this blocks" / resource columns reflect the real finding, not a guess. As of
> 2026-06-16 the un-skipped scan reports exactly these 19 findings and no others.

## Disposition summary

| Disposition | Count | Meaning |
|-------------|-------|---------|
| `Active` (architectural) | 14 | Skip stands: not satisfiable on the current Basic-SKU / GitHub-hosted-runner / public-endpoint reference architecture without a SKU or networking change that is out of scope for this pipeline. Compensating control documented. |
| `Active` (cost/scope) | 2 | Skip stands for a reference/demo deployment; flagged for production review (`CKV_AZURE_206`, `CKV_AZURE_165` overlap with HA). |
| `Fixable — pending un-skip` | 2 | A verified Terraform fix exists; the skip is time-boxed with a **short expiry** so it is removed once the storage Terraform change lands. These are NOT permanent exceptions. |
| `Removed (fixed)` | 0 | (Will move here once the storage lane applies the fix and the skip is deleted.) |

The two `Fixable — pending un-skip` rows (`CKV2_AZURE_40`, `CKV2_AZURE_41`) make the gate
**strictly stricter than an open-ended skip**: their short expiry forces the underlying
Terraform fix rather than silencing the control forever. The exact fix is recorded in the
"Remediation" section below and was verified locally with Checkov 3.3.1.

## Exception Register

> Required fields per `Active` / `Fixable` row: **Check ID**, **Reason**, **Compensating Control**, **Owner**, **Expiry**. The validator parses this table.

| Check ID | Resource | What it blocks | Reason (why skipped) | Compensating Control | Owner | Expiry | Status |
|----------|----------|----------------|----------------------|----------------------|-------|--------|--------|
| CKV_AZURE_139 | azurerm_container_registry | ACR public networking must be disabled | ACR is **Basic SKU**; private networking (Private Endpoint / firewall) requires **Premium SKU**, and the build/push runs on GitHub-hosted runners with dynamic egress IPs that cannot reach a private endpoint without a self-hosted runner or VNet peering — out of scope for this reference pipeline. | `admin_enabled = false` (token/OIDC auth only); AcrPull granted to the Container App's system-assigned identity via RBAC, not anonymous; images are Cosign-signed and verified at deploy (sign-and-attest gate). | Szymon Mytych | 2026-12-31 | Active |
| CKV_AZURE_163 | azurerm_container_registry | Vulnerability scanning (Microsoft Defender for ACR) enabled | Defender for Containers is a **subscription-level runtime setting**, not a `azurerm_container_registry` attribute on Basic SKU; it is enabled out-of-band where the subscription has Defender. | Image vulnerability scanning is performed **in-pipeline** by Trivy (build-and-scan gate, CRITICAL+HIGH blocking) before push, which is stronger and earlier than registry-side scanning. | Szymon Mytych | 2026-12-31 | Active |
| CKV_AZURE_164 | azurerm_container_registry | ACR content trust (signed/trusted images) | ACR content trust (Docker Notary v1) requires **Premium SKU**; the registry is Basic. | Image integrity is provided by **Cosign keyless signing + SLSA provenance attestation** (sign-and-attest gate) and verified at deploy — a stronger supply-chain control than ACR content trust. | Szymon Mytych | 2026-12-31 | Active |
| CKV_AZURE_165 | azurerm_container_registry | Geo-replicated registry for multi-region | Geo-replication requires **Premium SKU**; this is a **single-region** reference deployment. | Image is reproducibly rebuildable from source (pinned SHAs, SLSA provenance); no multi-region SLA is claimed. Revisit if a multi-region production deployment is in scope. | Szymon Mytych | 2026-12-31 | Active |
| CKV_AZURE_166 | azurerm_container_registry | Image quarantine / scan / mark-verified | Quarantine pattern requires **Premium SKU** features; registry is Basic. | Trivy gate blocks vulnerable images **before** they are pushed; only signed, attested images are deployed. Quarantine would be redundant with the pre-push gate. | Szymon Mytych | 2026-12-31 | Active |
| CKV_AZURE_167 | azurerm_container_registry | Retention policy for untagged manifests | Registry retention policies require **Premium SKU**; registry is Basic. | Low untagged-manifest accumulation risk for a single app pipeline; manifests are cleaned manually/periodically. Cost impact is negligible at Basic. | Szymon Mytych | 2026-12-31 | Active |
| CKV_AZURE_233 | azurerm_container_registry | Zone-redundant registry | Zone redundancy requires **Premium SKU**; registry is Basic, single region. | No multi-AZ availability SLA is claimed; image is reproducibly rebuildable. Revisit for production HA. | Szymon Mytych | 2026-12-31 | Active |
| CKV_AZURE_237 | azurerm_container_registry | Dedicated data endpoints | Dedicated data endpoints require **Premium SKU**; registry is Basic. | Not required without private networking (see CKV_AZURE_139); pulls use the system-assigned identity over TLS. | Szymon Mytych | 2026-12-31 | Active |
| CKV_AZURE_109 | azurerm_key_vault | Key Vault firewall (network_acls default deny) | A default-deny `network_acls` block would lock out the GitHub-hosted runners (dynamic egress IPs) that read/write secrets during deploy, and the Container App without a VNet integration. | RBAC authorization enabled (`rbac_authorization_enabled = true`); `purge_protection_enabled = true`; 90-day soft-delete; access is least-privilege via Azure AD + OIDC, no access policies / shared secrets. | Szymon Mytych | 2026-12-31 | Active |
| CKV_AZURE_189 | azurerm_key_vault | Key Vault public network access disabled | `public_network_access_enabled = false` requires a Private Endpoint reachable from the runner/app; GitHub-hosted runners cannot reach a private endpoint without self-hosted runners or VNet peering — out of scope. | Same as CKV_AZURE_109: RBAC-only auth, purge protection, soft-delete, Azure AD/OIDC. Public endpoint is auth-gated, not anonymous. | Szymon Mytych | 2026-12-31 | Active |
| CKV2_AZURE_32 | azurerm_key_vault | Key Vault private endpoint configured | Requires a VNet + Private Endpoint; the reference architecture is VNet-less (GitHub-hosted runners + Container Apps managed environment). | Same compensating controls as CKV_AZURE_109 / _189. Revisit if a VNet-integrated production deployment is in scope. | Szymon Mytych | 2026-12-31 | Active |
| CKV_AZURE_59 | azurerm_storage_account | Storage account disallows public access | `public_network_access_enabled = false` requires a Private Endpoint reachable from the runners that upload evidence packs; out of scope for GitHub-hosted runners. | `allow_nested_items_to_be_public = false` (no anonymous blob/container access); container `access_type = private`; `min_tls_version = TLS1_2`; access is Azure AD / OIDC, not anonymous. WORM immutability protects integrity regardless of network. | Szymon Mytych | 2026-12-31 | Active |
| CKV2_AZURE_33 | azurerm_storage_account | Storage account private endpoint configured | Same VNet-less constraint as the Key Vault private-endpoint check; no VNet in the reference architecture. | Private-blob, TLS1.2, Azure AD auth, WORM immutability + versioning + delete-retention. Revisit for VNet-integrated production. | Szymon Mytych | 2026-12-31 | Active |
| CKV2_AZURE_1 | azurerm_storage_account | Critical data encrypted with Customer-Managed Key (CMK) | CMK requires a Key Vault key + key rotation wiring; Azure encrypts all storage at rest with **Microsoft-managed keys** by default. CMK is a defensible deferral for a reference pipeline, not a gap in encryption-at-rest. | Encryption at rest is **always on** (Microsoft-managed keys, AES-256); Key Vault already exists with purge protection, so CMK is a low-effort future upgrade. Flagged for production hardening. | Szymon Mytych | 2026-12-31 | Active |
| CKV2_AZURE_21 | azurerm_storage_container | Blob service read-request logging enabled | Blob read-logging requires an `azurerm_monitor_diagnostic_setting` against the blob service, which targets the Log Analytics workspace created in the container-apps module — a cross-module wiring deferred to the monitoring lane. | Storage write/delete operations are protected by WORM immutability + versioning; access is Azure AD audited at the control plane (Activity Log). Read-access logging is an observability enhancement, not an integrity control. | Szymon Mytych | 2026-12-31 | Active |
| CKV_AZURE_33 | azurerm_storage_account | Queue service logging enabled | The storage account uses **only the Blob service** (evidence-packs container); **no Queue service** is provisioned or used, so queue logging is not applicable. | N/A — no queue endpoints exist. Candidate to disable the queue service entirely in a future hardening pass (would make this check vacuously pass). | Szymon Mytych | 2026-12-31 | Active |
| CKV_AZURE_206 | azurerm_storage_account | Storage replication (>= GRS) | Default `replication_type = LRS` for a single-region reference deployment; GRS roughly doubles storage cost and is a production HA/DR decision, not a reference-pipeline default. | WORM immutability + versioning + 365-day delete-retention + `CanNotDelete` management lock protect against accidental loss within the region. **`replication_type` is a module variable** — set GRS/ZRS for production. Flagged for production review. | Szymon Mytych | 2026-09-30 | Active |
| CKV2_AZURE_40 | azurerm_storage_account | Storage account disallows Shared Key authorization | **FIXABLE.** A verified Terraform fix exists (`shared_access_key_enabled = false` + provider `storage_use_azuread = true`). Time-boxed with a short expiry so the fix lands rather than the control being silenced indefinitely. The fix touches `infra/modules/storage/main.tf` + `infra/providers.tf`, owned by the storage Terraform lane (T-46 / §6.5), so it is staged here, not applied in this lane. | Until applied: backend already uses `use_azuread_auth = true`; control-plane access is OIDC/Azure AD. The compensating control is weaker than the fix — hence the short expiry. | Szymon Mytych | 2026-07-31 | Fixable — pending un-skip |
| CKV2_AZURE_41 | azurerm_storage_account | Storage account configured with SAS expiration policy | **FIXABLE.** A verified Terraform fix exists (add a `sas_policy { expiration_period = "01.00:00:00"; expiration_action = "Log" }` block). Time-boxed with a short expiry. Staged here because it touches the storage lane's `main.tf`. | Until applied: no application code mints account SAS tokens (access is Azure AD / OIDC), so the practical SAS exposure is low; the fix removes the residual risk. | Szymon Mytych | 2026-07-31 | Fixable — pending un-skip |

## Remediation (verified fixes for the `Fixable` rows)

These were validated locally with **Checkov 3.3.1** by patching a copy of `infra/` and
re-running the scan: the two checks moved from FAILED to PASSED, total findings dropped
19 → 17, and the gate still exits non-zero when any other skip is removed. Once the
storage Terraform lane applies them, delete the two `Fixable` rows above and the two IDs
from `CHECKOV_SKIP_CHECKS` (the validator then enforces the smaller list).

`infra/providers.tf` — add to the `provider "azurerm"` block (required so Terraform can
manage the blob container over Azure AD once Shared Key is off; the infra uses only the
Blob service, which fully supports Azure AD data-plane auth):

```hcl
provider "azurerm" {
  storage_use_azuread = true   # required when shared_access_key_enabled = false
  features { ... }
}
```

`infra/modules/storage/main.tf` — add to `resource "azurerm_storage_account" "this"`:

```hcl
  shared_access_key_enabled = false   # CKV2_AZURE_40 — Azure AD / OIDC only

  sas_policy {                        # CKV2_AZURE_41 — bound SAS lifetime
    expiration_period = "01.00:00:00" # 1 day
    expiration_action = "Log"
  }
```

> **Human sign-off required.** Szymon must (a) countersign each `Active` justification as
> an accepted risk, and (b) schedule the storage-lane Terraform change so the two
> `Fixable` rows are removed before their 2026-07-31 expiry. If the change has not landed
> by then, CI will fail (expired waiver) — which is the intended forcing function.

## Status Definitions

| Status | Meaning |
|--------|---------|
| **Active** | Skip is accepted with a compensating control. Re-reviewed quarterly; must have a future expiry. |
| **Fixable — pending un-skip** | A verified fix exists; the skip is short-expiry and will be removed once the fix lands. Not a permanent exception. |
| **Removed (fixed)** | The underlying Terraform was fixed and the check now passes; the skip was deleted. (Kept here for audit history only — such rows are NOT in the active skip list.) |

## Compliance Mapping

| Requirement | Framework Reference |
|-------------|---------------------|
| Documented, time-boxed exceptions log | spec §5 (exceptions log) / §8 (no unbounded exceptions) |
| IaC misconfiguration management | spec §4 IaC row; struktura.md:160 (mapped to CIS; gate blocks) |
| ICT risk acceptance with compensating controls | DORA Art.16.1.a; ISO 27001 Clause 6.1.2; SOC 2 CC3.2 |

## Related Documents

- `.github/workflows/security-gate.yml` — `iac-security` job (reads `CHECKOV_SKIP_CHECKS`, runs the validator)
- `scripts/validate-checkov-skips.py` — the enforcing validator
- `docs/compliance/exception-register.md` — master security exception register (CVE waivers)
- `app/.trivyignore` + `scripts/lint-trivyignore.py` — the analogous Trivy suppression policy
