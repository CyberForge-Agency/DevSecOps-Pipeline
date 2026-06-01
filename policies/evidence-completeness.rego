package compliance.evidence

import rego.v1

required_files := {
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
}

present_files := {f | some f in input.files}

missing := required_files - present_files

complete if count(missing) == 0

deny contains msg if {
  some f in missing
  msg := sprintf("Missing required evidence file: %s", [f])
}
