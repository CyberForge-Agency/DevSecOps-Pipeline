#!/usr/bin/env bash
set -euo pipefail

EVIDENCE_DIR="${1:-.}"

# Check which evidence files exist
check_file() {
  if [ -f "${EVIDENCE_DIR}/$1" ]; then echo "PASS"; else echo "MISSING"; fi
}

check_all() {
  for file in "$@"; do
    if [ ! -f "${EVIDENCE_DIR}/${file}" ]; then
      echo "MISSING"
      return
    fi
  done
  echo "PASS"
}

cat <<EOF
{
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "frameworks": {
    "DORA": [
      {"article": "Art.16.1.a", "requirement": "ICT risk management", "evidence": "security-report.json", "status": "$(check_file security-report.json)"},
      {"article": "Art.16.1.c", "requirement": "Updated systems", "evidence": "dependency-review.json", "status": "$(check_file dependency-review.json)"},
      {"article": "Art.16.1.d", "requirement": "Anomaly detection", "evidence": "pipeline-run.json", "status": "$(check_file pipeline-run.json)"},
      {"article": "Art.28", "requirement": "Supply chain risk", "evidence": "sbom.cyclonedx.json + provenance.intoto.jsonl", "status": "$(check_all sbom.cyclonedx.json provenance.intoto.jsonl)"}
    ],
    "NIS2": [
      {"article": "Art.21.2.b", "requirement": "Incident handling", "evidence": "zap-report.json", "status": "$(check_file zap-report.json)"},
      {"article": "Art.21.2.d", "requirement": "Supply chain security", "evidence": "sbom.cyclonedx.json + provenance.intoto.jsonl", "status": "$(check_all sbom.cyclonedx.json provenance.intoto.jsonl)"},
      {"article": "Art.21.2.e", "requirement": "Secure development", "evidence": "pipeline-run.json", "status": "$(check_file pipeline-run.json)"},
      {"article": "Art.21.2.h", "requirement": "Cryptography", "evidence": "cosign-verification.log", "status": "$(check_file cosign-verification.log)"}
    ],
    "ISO27001": [
      {"article": "A.8.4", "requirement": "Access to source code", "evidence": "pipeline-run.json", "status": "$(check_file pipeline-run.json)"},
      {"article": "A.8.9", "requirement": "Configuration management", "evidence": "pipeline-run.json", "status": "$(check_file pipeline-run.json)"},
      {"article": "A.8.25", "requirement": "Secure SDLC", "evidence": "pipeline-run.json", "status": "$(check_file pipeline-run.json)"},
      {"article": "A.8.28", "requirement": "Secure coding", "evidence": "security-report.json", "status": "$(check_file security-report.json)"}
    ],
    "SOC2": [
      {"article": "CC6.1", "requirement": "Logical access", "evidence": "pipeline-run.json", "status": "$(check_file pipeline-run.json)"},
      {"article": "CC7.1", "requirement": "System operations", "evidence": "cosign-verification.log", "status": "$(check_file cosign-verification.log)"},
      {"article": "CC8.1", "requirement": "Change management", "evidence": "pipeline-run.json", "status": "$(check_file pipeline-run.json)"},
      {"article": "PI1.1", "requirement": "Processing integrity", "evidence": "security-report.json", "status": "$(check_file security-report.json)"}
    ],
    "RODO": [
      {"article": "Art.5.1.c", "requirement": "Data minimization", "evidence": "dpa-compliance-check.json", "status": "$(check_file dpa-compliance-check.json)"},
      {"article": "Art.5.1.e", "requirement": "Storage limitation", "evidence": "dpa-compliance-check.json", "status": "$(check_file dpa-compliance-check.json)"},
      {"article": "Art.25", "requirement": "Data protection by design", "evidence": "data-flow-diagram.json", "status": "$(check_file data-flow-diagram.json)"},
      {"article": "Art.28", "requirement": "Processor agreements", "evidence": "dpa-compliance-check.json", "status": "$(check_file dpa-compliance-check.json)"},
      {"article": "Art.30", "requirement": "Records of processing", "evidence": "pipeline-run.json", "status": "$(check_file pipeline-run.json)"}
    ]
  }
}
EOF
