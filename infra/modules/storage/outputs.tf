output "storage_account_name" {
  description = "Storage account name"
  value       = azurerm_storage_account.this.name
}

output "storage_account_id" {
  description = "Storage account resource ID"
  value       = azurerm_storage_account.this.id
}

output "evidence_container_name" {
  description = "Evidence container name"
  value       = azurerm_storage_container.evidence.name
}
