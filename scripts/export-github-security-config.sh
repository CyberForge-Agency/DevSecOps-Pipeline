#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# export-github-security-config.sh
# =============================================================================
# Exports GitHub organization and repository security configuration for
# access review evidence. Produces JSON files suitable for compliance audits
# (DORA, NIS2, ISO 27001, SOC 2).
#
# Usage:
#   ./export-github-security-config.sh <org> <repo> [output_dir]
#
# Arguments:
#   org        - GitHub organization name
#   repo       - Repository name (without org prefix)
#   output_dir - Directory for output files (default: ./github-security-export)
#
# Requirements:
#   - gh CLI installed and authenticated
#   - Token scopes: admin:org, repo (some endpoints may require org admin)
#
# Outputs:
#   - org-members.json           Organization members and roles
#   - repo-collaborators.json    Repository collaborators and permissions
#   - teams.json                 Organization teams
#   - team-members-<slug>.json   Members of each team
#   - branch-protection.json     Branch protection rules for main branch
#   - repo-settings.json         Repository settings and security features
#   - org-settings.json          Organization settings (incl. MFA requirement)
#   - summary.json               Manifest with timestamp and file listing
# =============================================================================

# ---------------------------------------------------------------------------
# Argument parsing and validation
# ---------------------------------------------------------------------------

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <org> <repo> [output_dir]" >&2
    echo "" >&2
    echo "Arguments:" >&2
    echo "  org        GitHub organization name" >&2
    echo "  repo       Repository name (without org prefix)" >&2
    echo "  output_dir Output directory (default: ./github-security-export)" >&2
    exit 1
fi

ORG="$1"
REPO="$2"
OUTPUT_DIR="${3:-./github-security-export}"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Verify gh CLI is available and authenticated
if ! command -v gh &>/dev/null; then
    echo "ERROR: gh CLI is not installed. Install from https://cli.github.com/" >&2
    exit 1
fi

if ! gh auth status &>/dev/null; then
    echo "ERROR: gh CLI is not authenticated. Run 'gh auth login' first." >&2
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "=== GitHub Security Configuration Export ==="
echo "Organization: $ORG"
echo "Repository:   $ORG/$REPO"
echo "Output:       $OUTPUT_DIR"
echo "Timestamp:    $TIMESTAMP"
echo ""

# Track which files were successfully exported
declare -a EXPORTED_FILES=()
declare -a FAILED_EXPORTS=()

# ---------------------------------------------------------------------------
# Helper: safely export an API endpoint to a JSON file
# ---------------------------------------------------------------------------
export_endpoint() {
    local description="$1"
    local endpoint="$2"
    local output_file="$3"
    local paginate="${4:-true}"

    echo -n "  Exporting $description... "

    local gh_args=("api" "$endpoint" "--jq" ".")
    if [[ "$paginate" == "true" ]]; then
        gh_args+=("--paginate")
    fi

    if gh "${gh_args[@]}" > "$OUTPUT_DIR/$output_file" 2>/dev/null; then
        echo "OK"
        EXPORTED_FILES+=("$output_file")
    else
        echo "FAILED (insufficient permissions or endpoint unavailable)"
        # Write an error marker so downstream tools know this export failed
        cat > "$OUTPUT_DIR/$output_file" <<EREOF
{
  "error": "Export failed for $description",
  "endpoint": "$endpoint",
  "timestamp": "$TIMESTAMP",
  "reason": "Insufficient permissions or endpoint unavailable"
}
EREOF
        FAILED_EXPORTS+=("$output_file")
    fi
}

# ---------------------------------------------------------------------------
# 1. Organization members and roles
# ---------------------------------------------------------------------------
# Exports all members of the GitHub organization with their role (admin/member).
# This is the primary evidence for organizational access inventory.
# Compliance: SOC 2 CC6.1, ISO 27001 A.8.2
# ---------------------------------------------------------------------------
echo "[1/7] Organization members and roles"
export_endpoint "org members" "orgs/$ORG/members" "org-members.json"

# ---------------------------------------------------------------------------
# 2. Repository collaborators and permissions
# ---------------------------------------------------------------------------
# Exports all users who have access to the specific repository, including
# their permission level (admin, push/write, pull/read).
# Compliance: SOC 2 CC6.1, ISO 27001 A.8.4
# ---------------------------------------------------------------------------
echo "[2/7] Repository collaborators and permissions"
export_endpoint "repo collaborators" "repos/$ORG/$REPO/collaborators" "repo-collaborators.json"

# ---------------------------------------------------------------------------
# 3. Teams and team members
# ---------------------------------------------------------------------------
# Exports all teams in the organization. For each team, exports the team
# members. Team-based access is the primary authorization model.
# Compliance: ISO 27001 A.8.2
# ---------------------------------------------------------------------------
echo "[3/7] Organization teams and team members"
export_endpoint "org teams" "orgs/$ORG/teams" "teams.json"

# For each team, export its members
if [[ -f "$OUTPUT_DIR/teams.json" ]] && ! grep -q '"error"' "$OUTPUT_DIR/teams.json" 2>/dev/null; then
    # Extract team slugs from the teams export
    TEAM_SLUGS="$(gh api "orgs/$ORG/teams" --paginate --jq '.[].slug' 2>/dev/null || true)"

    if [[ -n "$TEAM_SLUGS" ]]; then
        while IFS= read -r slug; do
            if [[ -n "$slug" ]]; then
                export_endpoint "team '$slug' members" \
                    "orgs/$ORG/teams/$slug/members" \
                    "team-members-${slug}.json"
            fi
        done <<< "$TEAM_SLUGS"
    else
        echo "  No teams found or unable to list teams."
    fi
else
    echo "  Skipping team member export (teams export failed)."
fi

# ---------------------------------------------------------------------------
# 4. Branch protection rules
# ---------------------------------------------------------------------------
# Exports the branch protection configuration for the main branch.
# Verifies that required reviewers, signed commits, and force push
# restrictions are in place.
# Compliance: SOC 2 CC8.1, ISO 27001 A.8.4
# ---------------------------------------------------------------------------
echo "[4/7] Branch protection rules (main)"
export_endpoint "branch protection" "repos/$ORG/$REPO/branches/main/protection" "branch-protection.json" "false"

# ---------------------------------------------------------------------------
# 5. Repository settings
# ---------------------------------------------------------------------------
# Exports repository-level settings including visibility, security features
# (Dependabot, secret scanning, push protection), and general configuration.
# Compliance: SOC 2 CC8.1
# ---------------------------------------------------------------------------
echo "[5/7] Repository settings"
export_endpoint "repo settings" "repos/$ORG/$REPO" "repo-settings.json" "false"

# ---------------------------------------------------------------------------
# 6. Organization security settings
# ---------------------------------------------------------------------------
# Exports organization-level settings. The key field is
# two_factor_requirement_enabled which proves MFA is enforced for all members.
# Compliance: NIS2 Art.21.2.j, SOC 2 CC6.1
# ---------------------------------------------------------------------------
echo "[6/7] Organization security settings"
export_endpoint "org settings" "orgs/$ORG" "org-settings.json" "false"

# ---------------------------------------------------------------------------
# 7. Generate summary manifest
# ---------------------------------------------------------------------------
# Creates a summary JSON file with timestamp, organization, repository,
# and a manifest of all exported files with their status.
# ---------------------------------------------------------------------------
echo "[7/7] Generating summary manifest"

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
  "export_type": "github-security-config",
  "timestamp": "$TIMESTAMP",
  "organization": "$ORG",
  "repository": "$ORG/$REPO",
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

# Exit with warning code if any exports failed
if [[ ${#FAILED_EXPORTS[@]} -gt 0 ]]; then
    echo ""
    echo "WARNING: Some exports failed. This may be due to insufficient permissions."
    echo "  Failed files: ${FAILED_EXPORTS[*]}"
    echo "  Review the error details in each failed file."
    exit 0  # Non-fatal: partial export is still useful evidence
fi
