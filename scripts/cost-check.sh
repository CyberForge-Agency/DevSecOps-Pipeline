#!/usr/bin/env bash
set -euo pipefail

# CyberForge Pipeline - Cost Check Script
# Shows current Azure resource usage and estimated spend.

RESOURCE_GROUP="${1:-cyberforge-staging-rg}"
TFSTATE_RG="${2:-cyberforge-tfstate-rg}"
BILLING_PERIOD="${3:-$(date +%Y-%m)}"

# Colors for output (disabled if not a terminal)
if [ -t 1 ]; then
  BOLD="\033[1m"
  GREEN="\033[32m"
  YELLOW="\033[33m"
  RED="\033[31m"
  RESET="\033[0m"
else
  BOLD="" GREEN="" YELLOW="" RED="" RESET=""
fi

header() {
  echo ""
  echo -e "${BOLD}=== $1 ===${RESET}"
  echo ""
}

warn() {
  echo -e "${YELLOW}[WARN]${RESET} $1"
}

info() {
  echo -e "${GREEN}[INFO]${RESET} $1"
}

# ── Pre-flight checks ──────────────────────────────────────────────

if ! command -v az &>/dev/null; then
  echo -e "${RED}[ERROR]${RESET} Azure CLI (az) is not installed. Install from https://aka.ms/install-azure-cli"
  exit 1
fi

if ! az account show &>/dev/null; then
  echo -e "${RED}[ERROR]${RESET} Not logged in to Azure CLI. Run: az login"
  exit 1
fi

SUBSCRIPTION_NAME=$(az account show --query "name" -o tsv 2>/dev/null || echo "unknown")
SUBSCRIPTION_ID=$(az account show --query "id" -o tsv 2>/dev/null || echo "unknown")

echo -e "${BOLD}CyberForge Pipeline - Cost Report${RESET}"
echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Subscription: ${SUBSCRIPTION_NAME} (${SUBSCRIPTION_ID})"
echo "Billing period: ${BILLING_PERIOD}"

# ── Section 1: Current Month Consumption ────────────────────────────

header "Current Month Consumption"

START_DATE="${BILLING_PERIOD}-01"
# Calculate end date (last day of the billing month)
END_DATE=$(date -d "${START_DATE} +1 month -1 day" +%Y-%m-%d 2>/dev/null || date -v1m -v-1d -j -f "%Y-%m-%d" "${START_DATE}" +%Y-%m-%d 2>/dev/null || echo "${BILLING_PERIOD}-28")

if az consumption usage list \
  --start-date "${START_DATE}" \
  --end-date "${END_DATE}" \
  --query "[?contains(instanceId, '${RESOURCE_GROUP}')].{Resource:instanceName, Cost:pretaxCost, Currency:currency, Meter:meterDetails.meterName}" \
  --output table 2>/dev/null; then
  info "Consumption data retrieved successfully."
else
  warn "Could not retrieve consumption data. This may be due to:"
  warn "  - Consumption API not available on this subscription type"
  warn "  - No usage data yet for the current billing period"
  warn "  - Insufficient permissions (requires Cost Management Reader role)"
  echo ""
  info "Trying Cost Management API as fallback..."

  az cost management query \
    --type ActualCost \
    --timeframe MonthToDate \
    --dataset-aggregation '{"totalCost":{"name":"Cost","function":"Sum"}}' \
    --dataset-grouping name="ResourceGroup" type="Dimension" \
    --query "properties.rows[?contains(@[1], '$(echo "${RESOURCE_GROUP}" | tr '[:upper:]' '[:lower:]')')]" \
    --output table 2>/dev/null || warn "Cost Management API also unavailable. Check permissions or subscription type."
fi

# ── Section 2: Resource Inventory ───────────────────────────────────

header "Resource Inventory - ${RESOURCE_GROUP}"

if az group show --name "${RESOURCE_GROUP}" &>/dev/null; then
  RESOURCE_COUNT=$(az resource list \
    --resource-group "${RESOURCE_GROUP}" \
    --query "length(@)" \
    -o tsv 2>/dev/null || echo "0")

  info "Total resources in ${RESOURCE_GROUP}: ${RESOURCE_COUNT}"
  echo ""

  az resource list \
    --resource-group "${RESOURCE_GROUP}" \
    --query "[].{Name:name, Type:type, Location:location}" \
    --output table 2>/dev/null || warn "Could not list resources."
else
  warn "Resource group '${RESOURCE_GROUP}' not found."
fi

# ── Section 3: Tfstate Resource Group ───────────────────────────────

header "Resource Inventory - ${TFSTATE_RG}"

if az group show --name "${TFSTATE_RG}" &>/dev/null; then
  TFSTATE_COUNT=$(az resource list \
    --resource-group "${TFSTATE_RG}" \
    --query "length(@)" \
    -o tsv 2>/dev/null || echo "0")

  info "Total resources in ${TFSTATE_RG}: ${TFSTATE_COUNT}"
  echo ""

  az resource list \
    --resource-group "${TFSTATE_RG}" \
    --query "[].{Name:name, Type:type, Location:location}" \
    --output table 2>/dev/null || warn "Could not list resources."
else
  warn "Resource group '${TFSTATE_RG}' not found (may not be deployed yet)."
fi

# ── Section 4: Key Resource Details ─────────────────────────────────

header "Key Resource Details"

# Container Apps scaling status
info "Container Apps replicas:"
az containerapp show \
  --resource-group "${RESOURCE_GROUP}" \
  --name "cyberforge-staging-app" \
  --query "{MinReplicas:properties.template.scale.minReplicas, MaxReplicas:properties.template.scale.maxReplicas, ActiveRevisions:properties.latestRevisionName}" \
  --output table 2>/dev/null || warn "Could not query Container App (may not be deployed)."

echo ""

# ACR storage usage
info "ACR storage usage:"
az acr show-usage \
  --name "cyberforgestagingacr" \
  --output table 2>/dev/null || warn "Could not query ACR usage (may not be deployed)."

echo ""

# Storage account blob count
info "Evidence storage blob summary:"
az storage blob list \
  --account-name "cyberforgestagingevidence" \
  --container-name "evidence-packs" \
  --query "length(@)" \
  --auth-mode login \
  -o tsv 2>/dev/null && info "blob count retrieved." || warn "Could not query evidence storage (may not be deployed or no access)."

# ── Section 5: Budget Status ────────────────────────────────────────

header "Budget Status"

az consumption budget list \
  --query "[?contains(name, 'cyberforge')].{Name:name, Amount:amount, CurrentSpend:currentSpend.amount, Currency:currentSpend.unit, TimeGrain:timeGrain}" \
  --output table 2>/dev/null || warn "No budgets found or insufficient permissions."

# ── Section 6: Cost Estimate Summary ────────────────────────────────

header "Static Cost Estimate (reference)"

cat <<EOF
Resource                          Idle/mo     Active/mo
────────────────────────────────  ──────────  ──────────
ACR Basic                         ~\$5.00      ~\$5.00
Container Apps (consumption)      ~\$0-3.00    ~\$12-16.00
Log Analytics (PerGB2018)         ~\$0.50-1.00 ~\$0.50-1.00
Key Vault (standard)              ~\$0.00      ~\$0.00
Storage - evidence (LRS)          ~\$0.50-1.00 ~\$0.50-1.00
Storage - tfstate (LRS)           ~\$0.10      ~\$0.10
────────────────────────────────  ──────────  ──────────
TOTAL (estimated)                 ~\$6-8       ~\$18-23

Budget limit: \$50/month
Alerts: 50% (\$25) | 80% (\$40) | 100% (\$50)
EOF

echo ""
info "Cost check complete."
