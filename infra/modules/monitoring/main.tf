# Monitoring module — alert rules against the Log Analytics workspace
# created by the Container Apps module.
#
# This module does NOT create a Log Analytics workspace; it receives
# the existing workspace ID as an input variable.

resource "azurerm_monitor_action_group" "critical" {
  name                = "${var.name_prefix}-critical-ag"
  resource_group_name = var.resource_group_name
  short_name          = "critical"
  tags                = var.tags

  email_receiver {
    name          = "ops-email"
    email_address = var.alert_email
  }
}

# ---------------------------------------------------------------------------
# Alert 1: Container App deployment failures
# Fires when a Container App revision fails to provision.
# ---------------------------------------------------------------------------
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "deployment_failures" {
  name                = "${var.name_prefix}-deploy-failures"
  resource_group_name = var.resource_group_name
  location            = var.location
  description         = "Fires when a Container App revision fails to provision."
  severity            = 1 # Sev1 — high
  enabled             = true
  tags                = var.tags

  scopes                = [var.log_analytics_workspace_id]
  evaluation_frequency  = "PT5M"
  window_duration       = "PT15M"
  target_resource_types = ["Microsoft.OperationalInsights/workspaces"]
  skip_query_validation = false

  criteria {
    query = <<-KQL
      ContainerAppSystemLogs_CL
      | where Reason_s in ("ProvisioningFailed", "ContainerCrashing", "ImagePullBackOff")
      | summarize FailureCount = count() by Reason_s, RevisionName_s
    KQL

    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0
    metric_measure_column   = null

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.critical.id]
  }
}

# ---------------------------------------------------------------------------
# Alert 2: Application error spikes (>10 errors in 10 minutes)
# ---------------------------------------------------------------------------
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "error_spikes" {
  name                = "${var.name_prefix}-error-spikes"
  resource_group_name = var.resource_group_name
  location            = var.location
  description         = "Fires when the application logs more than 10 errors within a 10-minute window."
  severity            = 2 # Sev2 — warning
  enabled             = true
  tags                = var.tags

  scopes                = [var.log_analytics_workspace_id]
  evaluation_frequency  = "PT5M"
  window_duration       = "PT10M"
  target_resource_types = ["Microsoft.OperationalInsights/workspaces"]
  skip_query_validation = false

  criteria {
    query = <<-KQL
      ContainerAppConsoleLogs_CL
      | where Log_s has "error" or Log_s has "Error" or Log_s has "ERROR"
        or Log_s has "exception" or Log_s has "Exception"
      | summarize ErrorCount = count() by bin(TimeGenerated, 10m), ContainerAppName_s
    KQL

    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 10
    metric_measure_column   = null

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.critical.id]
  }
}

# ---------------------------------------------------------------------------
# Alert 3: Image pull failures
# ---------------------------------------------------------------------------
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "image_pull_failures" {
  name                = "${var.name_prefix}-image-pull-failures"
  resource_group_name = var.resource_group_name
  location            = var.location
  description         = "Fires when a Container App fails to pull its container image from ACR."
  severity            = 1 # Sev1 — high
  enabled             = true
  tags                = var.tags

  scopes                = [var.log_analytics_workspace_id]
  evaluation_frequency  = "PT5M"
  window_duration       = "PT15M"
  target_resource_types = ["Microsoft.OperationalInsights/workspaces"]
  skip_query_validation = false

  criteria {
    query = <<-KQL
      ContainerAppSystemLogs_CL
      | where Reason_s == "ImagePullBackOff"
        or Log_s has "Failed to pull image"
        or Log_s has "ErrImagePull"
      | summarize FailureCount = count() by ContainerAppName_s, RevisionName_s
    KQL

    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0
    metric_measure_column   = null

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.critical.id]
  }
}
