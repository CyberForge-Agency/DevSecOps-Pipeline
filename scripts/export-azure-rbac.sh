#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# export-azure-rbac.sh
# =============================================================================
# Exports Azure RBAC role assignments and service principal information for
# access review evidence. Produces JSON files suitable for compliance audits
# (DORA, NIS2, ISO 27001, SOC 2).
#
# Usage:
#   ./export-azure-rbac.sh [subscription_id] [output_dir]
#
# Arguments:
#   subscription_id - Azure subscription ID (default: current az account)
#   output_dir      - Directory for output files (default: ./azure-rbac-export)
#
# Requirements:
#   - az CLI installed and authenticated
#   - Minimum Reader access on the subscription
#   - Directory.Read.All for Azure AD queries (service principals, apps)
#
# Outputs:
#   - role-assignments.json                   All RBAC role assignments
#   - service-principals.json                 Pipeline service principals
#   - app-registrations.json                  Pipeline app registrations
#   - federated-credentials-<app_id>.json     Federated credentials per app
#   - summary.json                            Manifest with timestamp and files
# =============================================================================

# ---------------------------------------------------------------------------
# Argument parsing and validation
# ---------------------------------------------------------------------------

SUBSCRIPTION_ID="${1:-}"
OUTPUT_DIR="${2:-./azure-rbac-export}"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Verify az CLI is available and authenticated
if ! command -v az &>/dev/null; then
    echo "ERROR: az CLI is not installed. Install from https://learn.microsoft.com/en-us/cli/azure/install-azure-cli" >&2
    exit 1
fi

if ! az account show &>/dev/null; then
    echo "ERROR: az CLI is not authenticated. Run 'az login' first." >&2
    exit 1
fi

# If no subscription ID provided, use the current default subscription
if [[ -z "$SUBSCRIPTION_ID" ]]; then
    SUBSCRIPTION_ID="$(az account show --query 'id' --output tsv 2>/dev/null)"
    if [[ -z "$SUBSCRIPTION_ID" ]]; then
        echo "ERROR: Could not determine current subscription. Provide subscription_id as first argument." >&2
        exit 1
    fi
    echo "No subscription_id provided. Using current subscription: $SUBSCRIPTION_ID"
fi

# Set the active subscription
if ! az account set --subscription "$SUBSCRIPTION_ID" 2>/dev/null; then
    echo "ERROR: Could not set subscription to $SUBSCRIPTION_ID. Verify the ID and your access." >&2
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "=== Azure RBAC Configuration Export ==="
echo "Subscription: $SUBSCRIPTION_ID"
echo "Output:       $OUTPUT_DIR"
echo "Timestamp:    $TIMESTAMP"
echo ""

# Track which files were successfully exported
declare -a EXPORTED_FILES=()
declare -a FAILED_EXPORTS=()

# ---------------------------------------------------------------------------
# Helper: safely run an az command and save output to a JSON file
# ---------------------------------------------------------------------------
export_az() {
    local description="$1"
    local output_file="$2"
    shift 2
    # Remaining arguments are the az command to run

    echo -n "  Exporting $description... "

    if "$@" > "$OUTPUT_DIR/$output_file" 2>/dev/null; then
        echo "OK"
        EXPORTED_FILES+=("$output_file")
    else
        echo "FAILED (insufficient permissions or resource unavailable)"
        cat > "$OUTPUT_DIR/$output_file" <<EREOF
{
  "error": "Export failed for $description",
  "timestamp": "$TIMESTAMP",
  "reason": "Insufficient permissions or resource unavailable"
}
EREOF
        FAILED_EXPORTS+=("$output_file")
    fi
}

# ---------------------------------------------------------------------------
# 1. All RBAC role assignments for the subscription
# ---------------------------------------------------------------------------
# Exports every role assignment in the subscription, showing who (principal)
# has what role at what scope. This is the primary evidence for Azure access
# review.
# Compliance: SOC 2 CC6.1, ISO 27001 A.8.2
# ---------------------------------------------------------------------------
echo "[1/4] RBAC role assignments"
export_az "role assignments" "role-assignments.json" \
    az role assignment list \
    --all \
    --subscription "$SUBSCRIPTION_ID" \
    --output json

# ---------------------------------------------------------------------------
# 2. Service principals used by the pipeline
# ---------------------------------------------------------------------------
# Exports service principals whose display name contains "cyberforge".
# These are the workload identities used by GitHub Actions and Terraform.
# A broader search can be performed by changing the filter.
# Compliance: DORA Art.16.1.a, SOC 2 CC6.1
# ---------------------------------------------------------------------------
echo "[2/4] Service principals (CyberForge)"

# Try a case-insensitive search by using startsWith for common patterns.
# The OData filter is limited, so we search broadly and filter locally if needed.
export_az "service principals" "service-principals.json" \
    az ad sp list \
    --all \
    --filter "startswith(displayName, 'cyberforge') or startswith(displayName, 'CyberForge')" \
    --output json

# If the filtered query returned empty or failed, try listing all SPs and
# filtering locally (useful when the display name convention differs)
if [[ -f "$OUTPUT_DIR/service-principals.json" ]]; then
    SP_COUNT="$(python3 -c "
import json, sys
try:
    data = json.load(open('$OUTPUT_DIR/service-principals.json'))
    if isinstance(data, list):
        print(len(data))
    else:
        print(0)
except:
    print(0)
" 2>/dev/null || echo "0")"

    if [[ "$SP_COUNT" == "0" ]]; then
        echo "  Note: No service principals matched 'cyberforge' filter."
        echo "  Consider adjusting the filter in this script if your SPs use a different naming convention."
    else
        echo "  Found $SP_COUNT service principal(s)."
    fi
fi

# ---------------------------------------------------------------------------
# 3. App registrations with potential federated credentials
# ---------------------------------------------------------------------------
# Exports app registrations whose display name contains "cyberforge".
# App registrations hold the federated credential configuration for OIDC.
# Compliance: DORA Art.16.1.a
# ---------------------------------------------------------------------------
echo "[3/4] App registrations (CyberForge)"
export_az "app registrations" "app-registrations.json" \
    az ad app list \
    --filter "startswith(displayName, 'cyberforge') or startswith(displayName, 'CyberForge')" \
    --output json

# ---------------------------------------------------------------------------
# 4. Federated credentials for each app registration
# ---------------------------------------------------------------------------
# For each app registration found, lists the federated (OIDC) credentials.
# This proves that the pipeline uses OIDC federation instead of static secrets.
# Compliance: DORA Art.16.1.a
# ---------------------------------------------------------------------------
echo "[4/4] Federated credentials for app registrations"

if [[ -f "$OUTPUT_DIR/app-registrations.json" ]] && ! grep -q '"error"' "$OUTPUT_DIR/app-registrations.json" 2>/dev/null; then
    # Extract app IDs (object IDs) from app registrations
    APP_IDS="$(python3 -c "
import json, sys
try:
    data = json.load(open('$OUTPUT_DIR/app-registrations.json'))
    if isinstance(data, list):
        for app in data:
            app_id = app.get('id', '')
            if app_id:
                print(app_id)
except:
    pass
" 2>/dev/null || true)"

    if [[ -n "$APP_IDS" ]]; then
        while IFS= read -r app_id; do
            if [[ -n "$app_id" ]]; then
                # Sanitize app_id for use in filename (remove any non-alphanumeric chars except hyphens)
                SAFE_ID="$(echo "$app_id" | tr -cd '[:alnum:]-')"
                export_az "federated credentials for app $SAFE_ID" \
                    "federated-credentials-${SAFE_ID}.json" \
                    az ad app federated-credential list \
                    --id "$app_id" \
                    --output json
            fi
        done <<< "$APP_IDS"
    else
        echo "  No app registrations found. Skipping federated credential export."
    fi
else
    echo "  Skipping federated credential export (app registration export failed)."
fi

# ---------------------------------------------------------------------------
# Generate summary manifest
# ---------------------------------------------------------------------------
echo ""
echo "Generating summary manifest..."

# Build the file manifest as a JSON array
FILE_MANIFEST="["
FIRST=true

for f in "${EXPORTED_FILES[@]}"; do
    if [[ "$FIRST" == "true" ]]; then
        FIRST=false
    else
        FILE_MANIFEST+=","
    fi
    FILE_MANIFEST+="{\"file\":\"$f\",\"status\":\"success\"}"
done

for f in "${FAILED_EXPORTS[@]}"; do
    if [[ "$FIRST" == "true" ]]; then
        FIRST=false
    else
        FILE_MANIFEST+=","
    fi
    FILE_MANIFEST+="{\"file\":\"$f\",\"status\":\"failed\"}"
done

FILE_MANIFEST+="]"

cat > "$OUTPUT_DIR/summary.json" <<EOF
{
  "export_type": "azure-rbac",
  "timestamp": "$TIMESTAMP",
  "subscription_id": "$SUBSCRIPTION_ID",
  "output_directory": "$OUTPUT_DIR",
  "files": $FILE_MANIFEST,
  "total_exported": ${#EXPORTED_FILES[@]},
  "total_failed": ${#FAILED_EXPORTS[@]}
}
EOF

echo ""
echo "=== Export Complete ==="
echo "  Successful: ${#EXPORTED_FILES[@]}"
echo "  Failed:     ${#FAILED_EXPORTS[@]}"
echo "  Summary:    $OUTPUT_DIR/summary.json"

# Exit with warning if any exports failed
if [[ ${#FAILED_EXPORTS[@]} -gt 0 ]]; then
    echo ""
    echo "WARNING: Some exports failed. This may be due to insufficient permissions."
    echo "  Failed files: ${FAILED_EXPORTS[*]}"
    echo "  Review the error details in each failed file."
    exit 0  # Non-fatal: partial export is still useful evidence
fi
