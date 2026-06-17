#!/usr/bin/env bash
set -euo pipefail

# Generates pipeline-run.json with full metadata.
#
# T-32: tool versions are MEASURED (not hardcoded). The "tools" block reflects
# the versions captured at runtime by generate-tool-versions.sh into
# evidence/tool-versions.json (spec X.3; blueprint/04 §7; FULLY-OPERATIONAL
# item 7). We embed the measured map verbatim when the file is present; if it is
# absent we emit a {"_note": ...} pointer instead of fabricating versions.

# Resolve the measured tool-versions artifact relative to common evidence roots.
TOOL_VERSIONS_FILE=""
for candidate in \
  "${TOOL_VERSIONS_JSON:-}" \
  "evidence/tool-versions.json" \
  "tool-versions.json"; do
  if [ -n "$candidate" ] && [ -f "$candidate" ]; then
    TOOL_VERSIONS_FILE="$candidate"
    break
  fi
done

# Build the JSON value for the "tools" key: either the measured map (preferred)
# or a structured note. No hardcoded version literals are ever emitted here.
if [ -n "$TOOL_VERSIONS_FILE" ] && command -v jq >/dev/null 2>&1; then
  # Surface only the measured {tool: version} pairs into pipeline-run.json,
  # keeping the full raw inventory in tool-versions.json itself.
  TOOLS_JSON="$(jq -c '{measured_versions: (.tools | map_values(.version)), source: .source, measured_at: .measured_at}' "$TOOL_VERSIONS_FILE" 2>/dev/null || true)"
fi
if [ -z "${TOOLS_JSON:-}" ]; then
  TOOLS_JSON='{"_note": "tool versions measured at runtime into evidence/tool-versions.json (T-32); run scripts/generate-tool-versions.sh"}'
fi

# Generates pipeline-run.json with full metadata
cat <<EOF
{
  "pipeline": {
    "name": "${GITHUB_WORKFLOW:-unknown}",
    "run_id": "${GITHUB_RUN_ID:-unknown}",
    "run_number": "${GITHUB_RUN_NUMBER:-unknown}",
    "run_attempt": "${GITHUB_RUN_ATTEMPT:-1}"
  },
  "trigger": {
    "event": "${GITHUB_EVENT_NAME:-unknown}",
    "actor": "${GITHUB_ACTOR:-unknown}",
    "ref": "${GITHUB_REF:-unknown}",
    "sha": "${GITHUB_SHA:-unknown}",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  },
  "repository": {
    "full_name": "${GITHUB_REPOSITORY:-unknown}",
    "url": "${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-unknown}"
  },
  "environment": "${DEPLOY_ENVIRONMENT:-staging}",
  "image": {
    "uri": "${IMAGE_URI:-unknown}",
    "digest": "${IMAGE_DIGEST:-unknown}"
  },
  "gates": {
    "security_gate": "${GATE_SECURITY:-unknown}",
    "build_scan": "${GATE_BUILD:-unknown}",
    "sign_attest": "${GATE_SIGN:-unknown}",
    "deploy": "${GATE_DEPLOY:-unknown}",
    "dast": "${GATE_DAST:-unknown}"
  },
  "tools": ${TOOLS_JSON}
}
EOF
