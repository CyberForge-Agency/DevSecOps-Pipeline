package compliance.deployment_test

import rego.v1

import data.compliance.deployment

test_allow_clean_deploy if {
  deployment.allow with input as {
    "image_signed": true,
    "sbom_attached": true,
    "critical_cves": 0,
    "tests_passed": true,
    "coverage_pct": 85,
  }
}

test_deny_unsigned_image if {
  not deployment.allow with input as {
    "image_signed": false,
    "sbom_attached": true,
    "critical_cves": 0,
    "tests_passed": true,
    "coverage_pct": 85,
  }
}

test_deny_critical_cves if {
  not deployment.allow with input as {
    "image_signed": true,
    "sbom_attached": true,
    "critical_cves": 2,
    "tests_passed": true,
    "coverage_pct": 85,
  }
}

test_deny_low_coverage if {
  not deployment.allow with input as {
    "image_signed": true,
    "sbom_attached": true,
    "critical_cves": 0,
    "tests_passed": true,
    "coverage_pct": 60,
  }
}
