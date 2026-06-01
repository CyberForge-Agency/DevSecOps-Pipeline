output "keyvault_id" {
  description = "Key Vault resource ID"
  value       = azurerm_key_vault.this.id
}

output "keyvault_uri" {
  description = "Key Vault URI"
  value       = azurerm_key_vault.this.vault_uri
}
