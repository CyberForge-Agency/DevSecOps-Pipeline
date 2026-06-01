output "acr_login_server" {
  description = "ACR login server URL"
  value       = azurerm_container_registry.this.login_server
}

output "acr_id" {
  description = "ACR resource ID"
  value       = azurerm_container_registry.this.id
}

output "acr_name" {
  description = "ACR name"
  value       = azurerm_container_registry.this.name
}
