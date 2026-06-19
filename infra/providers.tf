terraform {
  required_version = ">= 1.9.0" # cross-variable validation (var.retention_minima_days in modules/storage) needs TF >= 1.9

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }

  backend "azurerm" {
    # Configured via -backend-config or environment variables
    # resource_group_name  = "cyberforge-tfstate-rg"
    # storage_account_name = "cyberforgetfstate"
    # container_name       = "tfstate"
    # key                  = "pipeline.terraform.tfstate"
    use_oidc         = true
    use_azuread_auth = true
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = false
    }
  }
}
