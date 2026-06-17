resource "azurerm_storage_account" "this" {
  name                            = var.storage_account_name
  resource_group_name             = var.resource_group_name
  location                        = var.location
  account_tier                    = "Standard"
  account_replication_type        = var.replication_type
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  # Network hardening: when var.network_hardened = true, disable public network
  # access so the account is reachable only via private endpoints / explicit IP
  # rules (regulated clients). Default false keeps the current public behavior —
  # nothing changes unless opted in.
  public_network_access_enabled = !var.network_hardened
  tags                          = var.tags

  blob_properties {
    versioning_enabled = true

    container_delete_retention_policy {
      days = 365
    }

    delete_retention_policy {
      days = 365
    }
  }
}

resource "azurerm_storage_container" "evidence" {
  name                  = "evidence-packs"
  storage_account_id    = azurerm_storage_account.this.id
  container_access_type = "private"
}

# Container-level immutability policy (WORM) for compliance.
# Time-based retention prevents modification and deletion during the retention period.
# The period (var.immutability_period_days, default 1825 = 5 years) is the floor
# baked to meet the longest in-scope Polish statutory minimum in
# var.retention_minima_days (AML 5y, tax 5y, accounting 5y, DORA/NIS2 5y+) — see
# docs/poland-appendix.md §6.4 (spec 6.4 / 7.5). A variable validation rejects any
# period below that maximum so a future edit cannot silently breach the floor.
# NOTE: by default this sets retention only — WORM is created UNLOCKED (locked =
# false) and is NOT true, tamper-proof WORM until the policy is locked. The lock
# is gated on var.lock_worm and defaults to false; this is the documented state.
# ⚠️ IRREVERSIBLE: setting var.lock_worm = true permanently locks the time-based
# immutability policy. The lock is a ONE-WAY operation — it cannot be undone, the
# retention period can then only be extended (never shortened), and the container
# cannot be deleted while data is within the locked retention window. This is a
# deliberate owner decision (T-46/T-104), made explicit and opt-in here.
resource "azurerm_storage_container_immutability_policy" "evidence_worm" {
  count                                 = var.immutability_period_days > 0 ? 1 : 0
  storage_container_resource_manager_id = azurerm_storage_container.evidence.id
  immutability_period_in_days           = var.immutability_period_days
  protected_append_writes_all_enabled   = true
  locked                                = var.lock_worm
}

# Lifecycle policy for COST TIERING only — WORM (and legal hold) govern deletion.
#
# Single source of truth: var.immutability_period_days drives both the WORM
# retention period (above) and, if a delete is ever opted into, the lifecycle
# delete age. By default enable_lifecycle_delete = false, so this policy NEVER
# deletes evidence — it only tiers blobs to cool storage for cost savings. This
# removes the §6.5-A footgun where two independent retention variables could
# drift and a WORM-disabled (immutability_period_days == 0) deployment could
# delete the only unprotected copy.
#
# When enable_lifecycle_delete = true, the delete fires strictly AFTER the WORM
# period (immutability_period_days + delete_grace_days) and a precondition
# forbids enabling delete while WORM is disabled.
resource "azurerm_storage_management_policy" "lifecycle_retention" {
  storage_account_id = azurerm_storage_account.this.id

  lifecycle {
    precondition {
      condition     = !(var.enable_lifecycle_delete && var.immutability_period_days == 0)
      error_message = "enable_lifecycle_delete must not be true while WORM is disabled (immutability_period_days == 0): the lifecycle policy would delete the only unprotected copy of the evidence. Either keep enable_lifecycle_delete = false, or set immutability_period_days > 0 so WORM protects the data before deletion."
    }
  }

  rule {
    name    = "evidence-retention"
    enabled = true

    filters {
      prefix_match = ["evidence-packs/"]
      blob_types   = ["blockBlob"]
    }

    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than = 30

        # Delete is opt-in and, when enabled, fires strictly after the WORM
        # period (immutability_period_days + delete_grace_days). When disabled,
        # null OMITS the delete action entirely so WORM/legal hold govern end of
        # retention. (azurerm treats 0/-1 as invalid; null is the correct way to
        # leave the action unset — see provider issue hashicorp/terraform-provider-azurerm#6158.)
        delete_after_days_since_modification_greater_than = var.enable_lifecycle_delete ? var.immutability_period_days + var.delete_grace_days : null
      }
    }
  }
}
