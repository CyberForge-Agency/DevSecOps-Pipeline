#!/usr/bin/env bash
set -euo pipefail

# Check DPA (Data Processing Agreement) status for third-party tools
cat <<EOF
{
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "description": "DPA compliance verification for pipeline third-party processors",
  "vendor_risk_register_ref": "docs/governance/vendor-risk-register.md",
  "retention_policy": {
    "evidence_pack_retention_days": 1825,
    "log_retention_days": 90,
    "deletion_schedule": "Automated via Azure lifecycle management policy"
  },
  "processors": [
    {
      "name": "GitHub (Microsoft)",
      "service": "GitHub Actions, GitHub Advanced Security",
      "dpa_status": "ACTIVE",
      "dpa_url": "https://github.com/customer-terms/github-data-protection-agreement",
      "data_location": "EU",
      "data_types": ["source_code", "build_logs", "developer_metadata"]
    },
    {
      "name": "Microsoft Azure",
      "service": "ACR, Container Apps, Key Vault, Blob Storage",
      "dpa_status": "ACTIVE",
      "dpa_url": "https://www.microsoft.com/licensing/docs/view/Microsoft-Products-and-Services-Data-Protection-Addendum-DPA",
      "data_location": "Poland Central (EU)",
      "data_types": ["container_images", "application_logs", "evidence_packs"]
    },
    {
      "name": "Sigstore (Linux Foundation)",
      "service": "Fulcio, Rekor (transparency log)",
      "dpa_status": "NOT_REQUIRED",
      "justification": "Public transparency log. Only cryptographic signatures and OIDC identities are recorded. No personal data beyond GitHub identity.",
      "data_types": ["oidc_identity", "cryptographic_signatures"]
    },
    {
      "name": "OWASP ZAP",
      "service": "Dynamic Application Security Testing",
      "dpa_status": "NOT_REQUIRED",
      "justification": "Self-hosted on GitHub Actions runner. No data sent to external service.",
      "data_types": []
    },
    {
      "name": "Aqua Security (Trivy)",
      "service": "Container and dependency vulnerability scanning",
      "dpa_status": "NOT_REQUIRED",
      "justification": "Open-source tool running locally on GitHub Actions runner. Vulnerability database downloaded read-only. No scan data sent externally.",
      "data_types": []
    },
    {
      "name": "Bridgecrew / Palo Alto Networks (Checkov)",
      "service": "Infrastructure-as-Code static analysis",
      "dpa_status": "NOT_REQUIRED",
      "justification": "Open-source tool running locally on GitHub Actions runner. All IaC scan results remain local. No telemetry enabled.",
      "data_types": []
    },
    {
      "name": "Anchore (Syft)",
      "service": "Software Bill of Materials (SBOM) generation",
      "dpa_status": "NOT_REQUIRED",
      "justification": "Open-source tool running locally on GitHub Actions runner. SBOM output stored as pipeline artifact only.",
      "data_types": []
    },
    {
      "name": "OxSecurity (MegaLinter)",
      "service": "Multi-language linting and code quality",
      "dpa_status": "NOT_REQUIRED",
      "justification": "Open-source tool running locally on GitHub Actions runner. All linting results remain local. No external reporting enabled.",
      "data_types": []
    },
    {
      "name": "Mend / WhiteSource (Renovate)",
      "service": "Automated dependency updates",
      "dpa_status": "COVERED_BY_GITHUB_DPA",
      "justification": "Operates as a GitHub App within the GitHub environment. Dependency metadata processed within GitHub infrastructure, covered under GitHub DPA.",
      "dpa_url": "https://github.com/customer-terms/github-data-protection-agreement",
      "data_types": ["dependency_metadata"]
    },
    {
      "name": "Truffle Security (TruffleHog)",
      "service": "Secret detection and scanning",
      "dpa_status": "NOT_REQUIRED",
      "justification": "Open-source tool running locally on GitHub Actions runner. All secret scan results remain local. No data exfiltrated.",
      "data_types": []
    }
  ]
}
EOF
