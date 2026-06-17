# Evidence Retention & WORM Policy (A.5)

> Input document for the A.5 `assert-retention` validator
> (`scripts/tfplan-to-retention-input.py`). The validator does **not** parse this
> file at runtime — it reads the Terraform plan as the source of truth — but this
> document is the human-readable statement of the threshold the validator enforces
> and the provenance of the 1825-day constant.

## 1. Statutory minimum

| Field | Value |
| --- | --- |
| Minimum evidence retention | **1825 days (5 years)** |
| WORM (immutability) required | **Yes** |
| Deletion schedule required | **Yes** |
| Threshold constant location | `policies/retention-policy.rego:5` (`minimum_retention_days := 1825`) |
| Enforced by | `scripts/tfplan-to-retention-input.py` (BLOCKING) + `policies/retention-policy.rego` |

### Provenance of the 5-year figure

The 1825-day floor is the organisation's stated retention threshold for audit
evidence. It is grounded in:

- **DORA (EU 2022/2554)** Art.11–12 (response/recovery, backup and restoration)
  and the audit-defensibility expectations across the ICT risk-management chapter,
  which require financial entities to preserve tamper-evident records for the
  duration over which they may be examined.
- **RODO/GDPR Art.5(1)(e)** storage limitation — data is retained only as long as
  necessary, so a **deletion schedule** must also exist (the policy denies an
  empty schedule).

**Honesty note (regulation-truth, EVIDENCE-ONLY):** DORA Art.12 does not state a
literal "1825 day" number; the 5-year figure is the organisation's interpretation
of the record-keeping window and should be confirmed with legal/compliance for the
specific entity. What the pipeline can prove deterministically is that the
*configured* retention in infrastructure meets-or-exceeds this stated threshold —
that part is **BLOCKING**.

## 2. What the validator checks (and its scope)

`tfplan-to-retention-input.py` reads `terraform show -json <plan>` and extracts:

| OPA-input field | Source resource (azurerm) | Attribute |
| --- | --- | --- |
| `retention_days` | `azurerm_storage_container_immutability_policy` | `immutability_period_in_days` (falls back to lifecycle delete threshold if WORM absent) |
| `worm_enabled` | `azurerm_storage_container_immutability_policy` | resource present with period > 0 |
| `deletion_schedule` | `azurerm_storage_management_policy` | `rule[].actions[].base_blob[].delete_after_days_since_modification_greater_than` |

PASS requires **all three**: `retention_days >= 1825`, `worm_enabled == true`, and
a non-empty `deletion_schedule` (mirrors `retention-policy.rego` `compliant`).

### Pipeline-verifiable vs evidence-only scope

| Aspect | Tier | Why |
| --- | --- | --- |
| Configured retention meets 1825-day threshold | **BLOCKING** | deterministically parseable from the plan JSON |
| WORM immutability declared | **BLOCKING** | presence of the immutability resource with period > 0 |
| Deletion schedule declared | **BLOCKING** | parseable from the lifecycle policy |
| Plan was actually **applied** / live container truly carries an enforced lock | **EVIDENCE-ONLY** | a plan proves *intent*, not applied state; live enforcement is asserted from state/RBAC export, not from a speculative plan |
| 1825 is the *legally required* minimum (vs a configured one) | **EVIDENCE-ONLY** | regulation-truth, not pipeline-verifiable; see provenance note above |

## 3. Current infrastructure state (verified)

`infra/modules/storage/`:

| Setting | File | Value |
| --- | --- | --- |
| `immutability_period_days` (WORM) | `variables.tf:22-26` / `main.tf:35` | `1825` |
| `retention_days` (lifecycle delete) | `variables.tf:16-20`, root `main.tf:42` | `1825` |
| `protected_append_writes_all_enabled` | `main.tf:36` | `true` |
| Lifecycle delete rule | `main.tf:43-58` | `delete_after_days_since_modification_greater_than = var.retention_days` |

These satisfy the policy: `retention_days = 1825`, `worm_enabled = true`,
deletion schedule present.

## 4. Regression guard

Any future change that lowers `immutability_period_days` or `retention_days` below
1825, removes the immutability policy, or drops the lifecycle delete rule causes
the validator (and the wired `opa eval` step) to **FAIL** the deploy. This is the
control that keeps the dormant 1825-day policy connected to live infra
(COMPANY-AUDIT §3.5).
