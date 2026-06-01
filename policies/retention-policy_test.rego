package compliance.retention_test

import rego.v1

import data.compliance.retention

test_compliant_config if {
  retention.compliant with input as {
    "retention_days": 1825,
    "deletion_schedule": "Automated via Azure lifecycle policy",
    "worm_enabled": true,
  }
}

test_insufficient_retention if {
  not retention.compliant with input as {
    "retention_days": 365,
    "deletion_schedule": "Manual",
    "worm_enabled": true,
  }
}

test_worm_disabled if {
  not retention.compliant with input as {
    "retention_days": 1825,
    "deletion_schedule": "Automated",
    "worm_enabled": false,
  }
}
