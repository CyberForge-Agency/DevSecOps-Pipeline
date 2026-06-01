output "action_group_id" {
  description = "Resource ID of the critical action group"
  value       = azurerm_monitor_action_group.critical.id
}

output "deployment_failure_alert_id" {
  description = "Resource ID of the deployment failure alert rule"
  value       = azurerm_monitor_scheduled_query_rules_alert_v2.deployment_failures.id
}

output "error_spike_alert_id" {
  description = "Resource ID of the error spike alert rule"
  value       = azurerm_monitor_scheduled_query_rules_alert_v2.error_spikes.id
}

output "image_pull_failure_alert_id" {
  description = "Resource ID of the image pull failure alert rule"
  value       = azurerm_monitor_scheduled_query_rules_alert_v2.image_pull_failures.id
}
