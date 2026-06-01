output "acr_login_server" {
  description = "Azure Container Registry login server"
  value       = module.acr.acr_login_server
}

output "app_url" {
  description = "Deployed Container App URL"
  value       = module.container_apps.app_url
}

output "keyvault_uri" {
  description = "Key Vault URI"
  value       = module.keyvault.keyvault_uri
}

output "evidence_storage_account" {
  description = "Evidence storage account name"
  value       = module.storage.storage_account_name
}

output "evidence_container" {
  description = "Evidence storage container name"
  value       = module.storage.evidence_container_name
}
