# Monitoring Setup Runbook

**Document Owner:** DevOps Lead
**Last Updated:** 2026-04-13
**Review Cadence:** Quarterly or after infrastructure changes
**Terraform Source:** `infra/modules/monitoring/main.tf`

---

## 1. Architecture Overview

CyberForge monitoring uses **Azure Log Analytics** (already provisioned by the Container Apps Terraform module) with scheduled query alert rules. This approach provides sufficient observability for a startup without the cost overhead of Azure Sentinel.

### Components

| Component | Purpose | Terraform Resource |
|---|---|---|
| Log Analytics Workspace | Central log ingestion from Container Apps | `azurerm_log_analytics_workspace.this` (container-apps module) |
| Action Group | Email notification channel | `azurerm_monitor_action_group.critical` |
| Deployment Failure Alert | Detect failed revision provisioning | `azurerm_monitor_scheduled_query_rules_alert_v2.deployment_failures` |
| Error Spike Alert | Detect >10 application errors in 10 minutes | `azurerm_monitor_scheduled_query_rules_alert_v2.error_spikes` |
| Image Pull Failure Alert | Detect ACR pull failures | `azurerm_monitor_scheduled_query_rules_alert_v2.image_pull_failures` |

### Enabling Monitoring

Set the `alert_email` variable in your Terraform deployment:

```bash
terraform apply -var="alert_email=ops@cyberforge.pl"
```

When `alert_email` is empty (default), the monitoring module is not deployed.

---

## 2. KQL Queries for Manual Investigation

Use these queries in the Azure Portal (Log Analytics > Logs) or via `az monitor log-analytics query`.

### 2.1 Application Errors

```kql
ContainerAppConsoleLogs_CL
| where Log_s has "error" or Log_s has "Error" or Log_s has "ERROR"
    or Log_s has "exception" or Log_s has "Exception"
| project TimeGenerated, ContainerAppName_s, RevisionName_s, Log_s
| order by TimeGenerated desc
| take 100
```

### 2.2 Health Probe Failures

```kql
ContainerAppSystemLogs_CL
| where Reason_s == "Unhealthy"
    or Log_s has "Liveness probe failed"
    or Log_s has "Readiness probe failed"
| project TimeGenerated, ContainerAppName_s, RevisionName_s, Reason_s, Log_s
| order by TimeGenerated desc
| take 50
```

### 2.3 Revision Provisioning Errors

```kql
ContainerAppSystemLogs_CL
| where Reason_s in ("ProvisioningFailed", "RevisionFailed", "ContainerCrashing")
| project TimeGenerated, ContainerAppName_s, RevisionName_s, Reason_s, Log_s
| order by TimeGenerated desc
| take 50
```

### 2.4 Crash Loops

```kql
ContainerAppSystemLogs_CL
| where Reason_s == "BackOff" or Reason_s == "ContainerCrashing"
| summarize CrashCount = count() by bin(TimeGenerated, 5m), ContainerAppName_s, RevisionName_s
| where CrashCount > 3
| order by TimeGenerated desc
```

### 2.5 Image Pull Failures

```kql
ContainerAppSystemLogs_CL
| where Reason_s == "ImagePullBackOff"
    or Log_s has "Failed to pull image"
    or Log_s has "ErrImagePull"
    or Log_s has "unauthorized"
| project TimeGenerated, ContainerAppName_s, RevisionName_s, Reason_s, Log_s
| order by TimeGenerated desc
| take 50
```

### 2.6 Deployment Timeline (Last 24h)

```kql
ContainerAppSystemLogs_CL
| where TimeGenerated > ago(24h)
| where Reason_s in ("Created", "Started", "Pulling", "Pulled", "ProvisioningFailed")
| project TimeGenerated, ContainerAppName_s, RevisionName_s, Reason_s, Log_s
| order by TimeGenerated asc
```

### 2.7 All Container App Logs (Last Hour)

```kql
ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(1h)
| project TimeGenerated, ContainerAppName_s, RevisionName_s, Log_s
| order by TimeGenerated desc
| take 200
```

---

## 3. Alert Tuning

### 3.1 Adjusting Thresholds

Edit the Terraform variables or the alert rule `threshold` values in `infra/modules/monitoring/main.tf`:

| Alert | Current Threshold | Recommendation |
|---|---|---|
| Deployment Failures | > 0 in 15 min | Keep at 0 -- any failure is actionable |
| Error Spikes | > 10 in 10 min | Adjust based on baseline error rate after production deployment |
| Image Pull Failures | > 0 in 15 min | Keep at 0 -- indicates broken deployment |

### 3.2 Adding New Alert Rules

1. Add a new `azurerm_monitor_scheduled_query_rules_alert_v2` resource to `infra/modules/monitoring/main.tf`
2. Reference the existing `azurerm_monitor_action_group.critical` action group
3. Use the KQL queries from Section 2 as a starting point
4. Run `terraform plan` to verify, then `terraform apply`

### 3.3 Silencing Alerts During Maintenance

Use Azure Monitor action rules (suppression rules) via the Portal or CLI:

```bash
az monitor action-rule create \
  --resource-group <RG_NAME> \
  --name "maintenance-window" \
  --scope-type ResourceGroup \
  --scope <RG_ID> \
  --status Enabled \
  --rule-type Suppression \
  --suppression-recurrence-type Once \
  --suppression-start-date "2026-04-14" \
  --suppression-start-time "02:00:00" \
  --suppression-end-date "2026-04-14" \
  --suppression-end-time "04:00:00"
```

---

## 4. Operational Procedures

### 4.1 Responding to Deployment Failure Alerts

1. Check the alert email for the revision name and failure reason
2. Run the Revision Provisioning Errors KQL query (Section 2.3) for details
3. Common causes:
   - Image not found in ACR (check image tag and ACR push step)
   - Resource quota exceeded (check Container App CPU/memory limits)
   - Application crash on startup (check Console Logs -- Section 2.7)
4. Fix the root cause and trigger a new deployment

### 4.2 Responding to Error Spike Alerts

1. Run the Application Errors KQL query (Section 2.1) to identify the error pattern
2. Check if the spike correlates with a recent deployment (Section 2.6)
3. If caused by a bad deployment, roll back:
   ```bash
   az containerapp revision list --name <APP_NAME> --resource-group <RG_NAME> --output table
   az containerapp ingress traffic set --name <APP_NAME> --resource-group <RG_NAME> \
     --revision-weight <PREVIOUS_REVISION>=100
   ```
4. If not deployment-related, investigate application logs and escalate

### 4.3 Responding to Image Pull Failure Alerts

1. Verify ACR connectivity:
   ```bash
   az acr login --name <ACR_NAME>
   az acr repository show-tags --name <ACR_NAME> --repository <APP_NAME>
   ```
2. Verify the Container App managed identity has AcrPull role (Terraform manages this)
3. Check if the image tag exists in ACR
4. If ACR is unavailable, check Azure service health

---

## 5. Cost Considerations

| Component | Estimated Cost |
|---|---|
| Log Analytics (PerGB2018) | ~$2.76/GB ingested |
| Alert Rules (3 rules) | Free tier (first 5 rules/month) |
| Action Group (email) | Free |

Estimated monthly cost for a low-traffic startup: $5-15/month.

To reduce costs:
- Log Analytics retention is set to 90 days; reduce if not needed for compliance
- Archive older logs to the evidence storage account for long-term retention
- Use `ContainerAppConsoleLogs_CL` filtering to reduce ingestion volume
