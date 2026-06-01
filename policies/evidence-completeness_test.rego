package compliance.evidence_test

import rego.v1

import data.compliance.evidence

test_complete_evidence if {
  evidence.complete with input as {"files": [
    "security-report.json",
    "sbom.cyclonedx.json",
    "provenance.intoto.jsonl",
    "cosign-verification.log",
    "pipeline-run.json",
    "dependency-review.json",
    "zap-report.json",
    "dpa-compliance-check.json",
    "data-flow-diagram.json",
    "compliance-matrix.json",
    "manifest.sha256",
  ]}
}

test_missing_sbom if {
  not evidence.complete with input as {"files": [
    "security-report.json",
    "pipeline-run.json",
  ]}
}

test_deny_messages if {
  msgs := evidence.deny with input as {"files": ["pipeline-run.json"]}
  count(msgs) > 0
}
