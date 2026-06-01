package compliance.deployment

import rego.v1

allow if {
  input.image_signed == true
  input.sbom_attached == true
  input.critical_cves == 0
  input.tests_passed == true
  input.coverage_pct >= 80
}

deny contains msg if {
  input.image_signed != true
  msg := "Image must be signed with Cosign before deployment"
}

deny contains msg if {
  input.sbom_attached != true
  msg := "SBOM must be attached as attestation before deployment"
}

deny contains msg if {
  input.critical_cves > 0
  msg := sprintf("Cannot deploy with %d critical CVEs", [input.critical_cves])
}

deny contains msg if {
  input.coverage_pct < 80
  msg := sprintf("Test coverage %d%% is below 80%% threshold", [input.coverage_pct])
}
