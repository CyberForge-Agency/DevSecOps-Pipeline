package compliance.retention

import rego.v1

minimum_retention_days := 1825 # 5 years (DORA)

compliant if {
  input.retention_days >= minimum_retention_days
  input.deletion_schedule != ""
  input.worm_enabled == true
}

# True WORM: the retention is not only configured (worm_enabled) but the
# time-based immutability policy has been irreversibly LOCKED (one-way). Until
# the lock is applied the data is still mutable/deletable by an account owner,
# so locked vs unlocked is a materially different posture for tamper-evidence.
# A missing/false worm_locked is honest as retention-by-policy, not true WORM.
worm_locked if {
  input.worm_enabled == true
  input.worm_locked == true
}

deny contains msg if {
  input.retention_days < minimum_retention_days
  msg := sprintf("Retention %d days is below DORA minimum of %d days", [input.retention_days, minimum_retention_days])
}

deny contains msg if {
  input.worm_enabled != true
  msg := "WORM storage must be enabled for evidence packs"
}

deny contains msg if {
  input.deletion_schedule == ""
  msg := "Deletion schedule must be defined (RODO Art.5.1.e)"
}

# Non-blocking warning: WORM is enabled but NOT locked, so the immutability is
# reversible. This is recorded honestly (retention-by-policy, not enforced WORM)
# rather than denied — the one-way lock is a deliberate owner decision (T-46).
warn contains msg if {
  input.worm_enabled == true
  input.worm_locked != true
  msg := "WORM immutability is enabled but NOT locked (reversible): retention-by-policy, not tamper-proof WORM. Lock is a one-way owner decision (T-46)."
}
