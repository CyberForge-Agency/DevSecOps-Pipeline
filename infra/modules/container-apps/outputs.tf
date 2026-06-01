output "app_url" {
  description = "Container App FQDN"
  value       = "https://${azurerm_container_app.this.ingress[0].fqdn}"
}

output "app_identity_principal_id" {
  description = "Container App managed identity principal ID"
  value       = azurerm_container_app.this.identity[0].principal_id
}

output "log_analytics_workspace_id" {
  description = "Log Analytics workspace resource ID"
  value       = azurerm_log_analytics_workspace.this.id
}
