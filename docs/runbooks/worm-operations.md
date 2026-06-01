# WORM (Write-Once-Read-Many) Operations Runbook

**Document Owner:** DevOps Lead
**Last Updated:** 2026-04-13
**Review Cadence:** Annually or after changes to storage configuration
**Terraform Source:** `infra/modules/storage/main.tf`

---

## 1. How the Immutability Policy Works

### 1.1 Architecture Overview

The CyberForge evidence storage uses Azure Blob Storage with a **container-level time-based immutability policy** (WORM). This policy is managed by Terraform via the `azurerm_storage_container_immutability_policy` resource.

Key properties of the current configuration:

| Property | Value | Source |
|---|---|---|
| Container Name | `evidence-packs` | `azurerm_storage_container.evidence` |
| Immutability Period | 1825 days (5 years) | `var.immutability_period_days` |
| Protected Append Writes | Enabled (all) | `protected_append_writes_all_enabled = true` |
| Policy State | **Unlocked** | Terraform creates policies in unlocked state |
| Versioning | Enabled | `blob_properties.versioning_enabled = true` |
| Soft Delete (blob) | 365 days | `delete_retention_policy.days = 365` |
| Soft Delete (container) | 365 days | `container_delete_retention_policy.days = 365` |
| Replication | Configurable (default: LRS) | `var.replication_type` |

### 1.2 Unlocked vs. Locked Policy

Azure immutability policies have two states:

| State | Behavior |
|---|---|
| **Unlocked** (current) | Blobs cannot be modified or deleted during the retention period. However, the policy itself can be modified (extend retention) or deleted by an admin. Terraform can manage the policy. |
| **Locked** (irreversible) | Same blob-level protection, but the policy itself **cannot be shortened, deleted, or modified** -- only extended. This is **irreversible** and meets SEC 17a-4(f) / CFTC requirements. Terraform can no longer delete or shorten the policy. |

### 1.3 What Happens to Blobs Under WORM

When a blob is written to the `evidence-packs` container:

1. The blob is **immutable** for the configured retention period (1825 days from creation)
2. **Read** operations work normally
3. **Overwrite** operations are blocked with HTTP 409 (BlobImmutableDueToPolicy)
4. **Delete** operations are blocked with HTTP 409 (BlobImmutableDueToPolicy)
5. **Append** operations are allowed (because `protected_append_writes_all_enabled = true`) -- this permits writing evidence pack manifests and audit logs incrementally
6. After the retention period expires, the blob can be deleted but not modified

---

## 2. Lock Procedure

> **WARNING: LOCKING IS IRREVERSIBLE. Once locked, the immutability policy cannot be removed or shortened. This action cannot be undone by Microsoft Support, Terraform, or any administrator.**

### 2.1 Prerequisites

Before locking:

- [ ] The immutability period (`immutability_period_days`) is set to the final, approved value
- [ ] The storage account is in the **production** environment
- [ ] Management has formally approved the lock (documented in a PR or issue)
- [ ] All staging/testing validation is complete
- [ ] The Terraform state reflects the correct unlocked policy
- [ ] You understand that Terraform can no longer delete or shorten this policy after locking

### 2.2 Lock Command

```bash
# Step 1: Get the policy ETag (required for the lock command)
ETAG=$(az storage container immutability-policy show \
  --account-name <STORAGE_ACCOUNT_NAME> \
  --container-name evidence-packs \
  --query etag -o tsv)

echo "Policy ETag: $ETAG"

# Step 2: Lock the policy (IRREVERSIBLE)
az storage container immutability-policy lock \
  --account-name <STORAGE_ACCOUNT_NAME> \
  --container-name evidence-packs \
  --if-match "$ETAG"
```

### 2.3 Post-Lock Terraform Considerations

After locking, update the Terraform configuration to prevent drift:

1. Add a `lifecycle` block to the immutability policy resource to prevent Terraform from attempting to delete it:

```hcl
resource "azurerm_storage_container_immutability_policy" "evidence_worm" {
  # ... existing config ...

  lifecycle {
    prevent_destroy = true
  }
}
```

2. Terraform can still **extend** the retention period on a locked policy, but cannot shorten or remove it.

---

## 3. Verification Commands

### 3.1 Check Policy State

```bash
# View the immutability policy and its lock state
az storage container immutability-policy show \
  --account-name <STORAGE_ACCOUNT_NAME> \
  --container-name evidence-packs \
  --output table
```

Expected output columns:
- `immutabilityPeriodSinceCreationInDays`: Should be 1825
- `state`: `Unlocked` or `Locked`
- `allowProtectedAppendWritesAll`: Should be `true`

### 3.2 Verify Blob Immutability

```bash
# Attempt to delete a blob (should fail with 409)
az storage blob delete \
  --account-name <STORAGE_ACCOUNT_NAME> \
  --container-name evidence-packs \
  --name <BLOB_NAME> \
  --auth-mode login

# Expected error:
# (BlobImmutableDueToPolicy) This operation is not permitted
# because the blob is immutable due to a policy.
```

### 3.3 Verify Append Works

```bash
# Append to an existing append blob (should succeed)
echo "audit-entry: $(date -u +%Y-%m-%dT%H:%M:%SZ)" | \
az storage blob upload \
  --account-name <STORAGE_ACCOUNT_NAME> \
  --container-name evidence-packs \
  --name test-append.log \
  --type append \
  --auth-mode login
```

### 3.4 List Blob Versions

```bash
az storage blob list \
  --account-name <STORAGE_ACCOUNT_NAME> \
  --container-name evidence-packs \
  --include v \
  --output table
```

---

## 4. What Happens When You Try to Modify/Delete Locked Blobs

| Operation | Result | HTTP Status |
|---|---|---|
| Read blob | Allowed | 200 OK |
| List blobs | Allowed | 200 OK |
| Upload new blob | Allowed | 201 Created |
| Overwrite existing blob | **Blocked** | 409 Conflict (BlobImmutableDueToPolicy) |
| Delete blob | **Blocked** | 409 Conflict (BlobImmutableDueToPolicy) |
| Set blob metadata | **Blocked** | 409 Conflict (BlobImmutableDueToPolicy) |
| Set blob tier | Allowed (tier changes are permitted) | 200 OK |
| Append to append blob | Allowed (if `protected_append_writes_all_enabled`) | 201 Created |
| Delete container | **Blocked** (if any blobs are under retention) | 409 Conflict |
| Delete storage account | **Blocked** (if container has locked policy) | 409 Conflict |

### 4.1 Impact on Terraform

- `terraform destroy` will **fail** if the policy is locked and blobs exist under retention
- `terraform apply` with a shorter retention period will **fail** on a locked policy
- `terraform apply` with a longer retention period will **succeed** on a locked policy (extension is allowed)

---

## 5. Environment-Specific Guidance

### 5.1 Staging and Testing

> **DO NOT LOCK the immutability policy in staging or testing environments.**

Reasons:
- Locked policies prevent cleanup of test data
- Test storage accounts with locked policies cannot be destroyed
- You will incur ongoing storage costs for data that cannot be deleted

For staging/testing, keep the policy **unlocked** or set `immutability_period_days = 0` to disable it entirely.

### 5.2 Production -- When to Lock

Lock the immutability policy **only** when all of the following conditions are met:

1. **Final review complete:** The retention period (1825 days / 5 years) has been validated against legal, regulatory, and contractual requirements
2. **Terraform configuration stable:** No pending changes to the storage module that would require policy deletion
3. **Management approval obtained:** Written approval from the CTO or CISO (documented in a GitHub issue or PR)
4. **Compliance requirement confirmed:** An auditor or compliance officer has confirmed that a locked policy is required (e.g., for SEC 17a-4(f), DORA Article 12, or contractual WORM requirements)
5. **Backup strategy verified:** The BCDR plan accounts for the fact that evidence data cannot be deleted for 5 years

### 5.3 Recommended Lock Timeline

| Milestone | Action |
|---|---|
| Initial deployment | Keep unlocked; validate evidence pack generation |
| After first successful audit dry-run | Keep unlocked; confirm retention period is correct |
| After first real audit or client requirement | Evaluate locking with management and legal |
| Production steady-state with compliance obligation | Lock the policy |

---

## 6. Troubleshooting

### 6.1 Cannot Delete Storage Account

**Cause:** Locked immutability policy with blobs still under retention.
**Resolution:** Wait for all blobs to exceed their retention period, then delete. There is no workaround -- this is by design.

### 6.2 Terraform Plan Shows Policy Deletion

**Cause:** Someone changed `immutability_period_days` to 0 or removed the policy resource.
**Resolution:** If the policy is locked, the apply will fail. Revert the Terraform change. If unlocked, the apply will succeed and remove the policy -- verify this is intentional.

### 6.3 Evidence Pack Upload Fails with 409

**Cause:** Attempting to overwrite an existing blob.
**Resolution:** Use unique blob names (e.g., include timestamp or commit SHA). The evidence pack workflow already does this with the naming pattern `evidence-<sha>-<timestamp>.tar.gz`.
