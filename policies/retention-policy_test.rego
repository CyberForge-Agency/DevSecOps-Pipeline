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

# worm_locked distinguishes true (irreversible) WORM from retention-by-policy.
test_worm_locked_true if {
  retention.worm_locked with input as {
    "retention_days": 1825,
    "deletion_schedule": "Automated",
    "worm_enabled": true,
    "worm_locked": true,
  }
}

test_worm_locked_false_when_unlocked if {
  not retention.worm_locked with input as {
    "retention_days": 1825,
    "deletion_schedule": "Automated",
    "worm_enabled": true,
    "worm_locked": false,
  }
}

# An unlocked-but-enabled WORM is compliant (retention configured) but emits the
# non-blocking warn — it is NOT denied (the lock is a deliberate owner decision).
test_unlocked_worm_warns_not_denied if {
  retention.compliant with input as {
    "retention_days": 1825,
    "deletion_schedule": "Automated",
    "worm_enabled": true,
    "worm_locked": false,
  }

  count(retention.warn) == 1 with input as {
    "retention_days": 1825,
    "deletion_schedule": "Automated",
    "worm_enabled": true,
    "worm_locked": false,
  }

  count(retention.deny) == 0 with input as {
    "retention_days": 1825,
    "deletion_schedule": "Automated",
    "worm_enabled": true,
    "worm_locked": false,
  }
}

# A locked WORM produces no warn.
test_locked_worm_no_warn if {
  count(retention.warn) == 0 with input as {
    "retention_days": 1825,
    "deletion_schedule": "Automated",
    "worm_enabled": true,
    "worm_locked": true,
  }
}
