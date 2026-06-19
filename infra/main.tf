locals {
  tags = {
    project     = var.project_name
    environment = var.environment
    managed_by  = "terraform"
    compliance  = "dora,nis2,iso27001,soc2"
  }
  resource_prefix = "${var.project_name}-${var.environment}"
}

data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "this" {
  name     = "${local.resource_prefix}-rg"
  location = var.location
  tags     = local.tags
}

module "acr" {
  source              = "./modules/acr"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  acr_name            = replace("${local.resource_prefix}acr", "-", "")
  tags                = local.tags
}

module "keyvault" {
  source              = "./modules/keyvault"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  keyvault_name       = "${local.resource_prefix}-kv"
  tenant_id           = data.azurerm_client_config.current.tenant_id
  tags                = local.tags
}

module "storage" {
  source              = "./modules/storage"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  # Azure Storage account names must be 3-24 chars, lowercase alphanumeric only.
  storage_account_name = substr(replace("${local.resource_prefix}evidence", "-", ""), 0, 24)
  # Single source of truth for retention: immutability_period_days governs both WORM
  # protection and (only if enable_lifecycle_delete is opted into) the lifecycle delete age.
  # Default keeps WORM at 5 years and lifecycle delete OFF, so WORM/legal hold govern deletion.
  #
  # 1825 days = 5 years is the statutory floor justified against the LONGEST
  # in-scope Polish data class (docs/poland-appendix.md §6.4; spec 6.4 / 7.5):
  #   - AML/CFT records: 5y — art. 49 ust. o przeciwdziałaniu praniu pieniędzy
  #     (Dz.U. 2018 poz. 723), extendable on KGIIF request. ⚠️ confirm.
  #   - Tax books: 5y (przedawnienie) — art. 70 § 1 / art. 86 § 1 Ordynacji
  #     podatkowej. ⚠️ confirm loss-year extension.
  #   - Accounting books: 5y — art. 74 ust. 2 pkt 1 ust. o rachunkowości.
  #   - DORA/NIS2 ICT-risk records: 5y+ — DORA (EU 2022/2554) / KSC (Dz.U. 2026
  #     poz. 252). ⚠️ confirm exact period per record type.
  # Permanent (financial statements, art. 74 ust. 1 ust. o rachunkowości) and
  # 10–50y (payroll/ZUS) classes are OUT of this store's scope and are NOT met by
  # the 1825-day floor — ⚠️ confirm the evidence store excludes them or extend
  # retention for the affected artifacts. The module's variable validation rejects
  # any period below the longest in-scope minimum (per var.retention_minima_days).
  # Retention only; the irreversible WORM lock is the owner's call (T-46).
  immutability_period_days = 1825
  # WORM lock (T-46/T-104) and network hardening (T-106) are opt-in and default
  # false so behavior is unchanged unless explicitly enabled.
  # ⚠️ PROD: set lock_worm = true ONLY after the owner sign-off — locking is a
  # one-way, irreversible operation (see modules/storage/main.tf).
  lock_worm        = false
  network_hardened = false
  tags             = local.tags
}

module "container_apps" {
  source              = "./modules/container-apps"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  environment_name    = "${local.resource_prefix}-env"
  app_name            = "${local.resource_prefix}-app"
  image               = var.container_image
  acr_login_server    = module.acr.acr_login_server
  acr_id              = module.acr.acr_id
  tags                = local.tags
}

module "monitoring" {
  source                     = "./modules/monitoring"
  count                      = var.alert_email != "" ? 1 : 0
  resource_group_name        = azurerm_resource_group.this.name
  location                   = azurerm_resource_group.this.location
  name_prefix                = local.resource_prefix
  log_analytics_workspace_id = module.container_apps.log_analytics_workspace_id
  alert_email                = var.alert_email
  tags                       = local.tags
}

# Prevent accidental deletion of Terraform state storage.
# Apply this lock to the resource group or storage account that holds tfstate.
resource "azurerm_management_lock" "tfstate_do_not_delete" {
  name       = "${local.resource_prefix}-tfstate-lock"
  scope      = azurerm_resource_group.this.id
  lock_level = "CanNotDelete"
  notes      = "Protects Terraform state and compliance evidence from accidental deletion. Remove only with management approval."
}
