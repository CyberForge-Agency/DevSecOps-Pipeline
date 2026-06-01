resource "azurerm_storage_account" "this" {
  name                            = var.storage_account_name
  resource_group_name             = var.resource_group_name
  location                        = var.location
  account_tier                    = "Standard"
  account_replication_type        = var.replication_type
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  tags                            = var.tags

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
resource "azurerm_storage_container_immutability_policy" "evidence_worm" {
  count                                 = var.immutability_period_days > 0 ? 1 : 0
  storage_container_resource_manager_id = azurerm_storage_container.evidence.id
  immutability_period_in_days           = var.immutability_period_days
  protected_append_writes_all_enabled   = true
}

# Lifecycle retention for tiering (cost optimization) — separate from WORM.
resource "azurerm_storage_management_policy" "lifecycle_retention" {
  storage_account_id = azurerm_storage_account.this.id

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
        delete_after_days_since_modification_greater_than        = var.retention_days
      }
    }
  }
}
