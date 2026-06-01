#!/usr/bin/env bash
set -euo pipefail

cat <<EOF
{
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "description": "Data flow diagram for CyberForge DevSecOps Pipeline",
  "stages": [
    {
      "name": "Source Code",
      "location": "GitHub Repository",
      "pii_present": true,
      "pii_types": ["developer_emails_in_commits", "developer_names_in_commits"],
      "pii_justification": "Git metadata required for audit trail (ISO 27001 A.8.4)",
      "data_flows_to": ["Security Gate", "Build & Scan"]
    },
    {
      "name": "Security Gate",
      "location": "GitHub Actions Runner (ephemeral)",
      "pii_present": false,
      "pii_types": [],
      "data_flows_to": ["Build & Scan"]
    },
    {
      "name": "Build & Scan",
      "location": "GitHub Actions Runner (ephemeral)",
      "pii_present": false,
      "pii_types": [],
      "data_flows_to": ["Azure Container Registry"]
    },
    {
      "name": "Azure Container Registry",
      "location": "Azure (Poland Central)",
      "pii_present": false,
      "pii_types": [],
      "data_flows_to": ["Azure Container Apps"]
    },
    {
      "name": "Azure Container Apps",
      "location": "Azure (Poland Central)",
      "pii_present": false,
      "pii_types": [],
      "pii_justification": "Demo app does not process personal data"
    },
    {
      "name": "Evidence Pack Archive",
      "location": "Azure Blob Storage WORM (Poland Central)",
      "pii_present": true,
      "pii_types": ["developer_names_in_pipeline_logs"],
      "pii_justification": "Required for audit trail. Sanitized to minimum. Retention: 5 years (DORA). Access: compliance-team + auditor roles only.",
      "retention_days": 1825
    }
  ]
}
EOF
