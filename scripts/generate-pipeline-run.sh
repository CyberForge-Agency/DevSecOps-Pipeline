#!/usr/bin/env bash
set -euo pipefail

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
  "tools": {
    "trufflehog": "v3.82+",
    "checkov": "v3+",
    "trivy": "v0.58+",
    "codeql": "v3+",
    "cosign": "v2.4+",
    "syft": "v1.18+",
    "zap": "v2.15+",
    "terraform": "v1.7+"
  }
}
EOF
