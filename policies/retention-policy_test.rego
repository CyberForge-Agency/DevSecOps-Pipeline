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

# T-10/T-62 recommended posture: 1825 immutability + WORM on, lifecycle delete
# intentionally OFF (no delete_after_days / empty schedule). Deletion is governed
# by the WORM/legal-hold window, so this is COMPLIANT and NOT denied.
test_recommended_no_lifecycle_delete_compliant if {
	retention.compliant with input as {
		"retention_days": 1825,
		"deletion_schedule": "",
		"worm_enabled": true,
		"worm_locked": true,
	}

	count(retention.deny) == 0 with input as {
		"retention_days": 1825,
		"deletion_schedule": "",
		"worm_enabled": true,
		"worm_locked": true,
	}
}

# Footgun: a lifecycle delete SHORTER than the immutability period is denied
# (evidence would be purged before WORM expiry).
test_short_lifecycle_delete_denied if {
	not retention.compliant with input as {
		"retention_days": 1825,
		"deletion_schedule": "delete after 30 days",
		"worm_enabled": true,
		"delete_after_days": 30,
	}

	count(retention.deny) == 1 with input as {
		"retention_days": 1825,
		"deletion_schedule": "delete after 30 days",
		"worm_enabled": true,
		"delete_after_days": 30,
	}
}

# A lifecycle delete >= the immutability period is fine (not a footgun).
test_long_lifecycle_delete_compliant if {
	retention.compliant with input as {
		"retention_days": 1825,
		"deletion_schedule": "delete after 1825 days",
		"worm_enabled": true,
		"worm_locked": true,
		"delete_after_days": 1825,
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
