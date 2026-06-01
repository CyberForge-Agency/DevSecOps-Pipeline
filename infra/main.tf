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
  retention_days       = 1825 # 5 years target; verify against legal/compliance requirements.
  tags                 = local.tags
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
