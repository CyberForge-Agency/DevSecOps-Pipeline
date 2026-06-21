package compliance.retention

import rego.v1

# 5 years — the longest in-scope statutory minimum (PL AML art.49 / tax Ord.pod.
# art.70,86 / accounting art.74). DORA & NIS2 impose NO numeric retention period;
# they expect a proportionate, audit-defensible window (5y+), so this floor is the
# organisation's configured threshold grounded in PL statute, not a DORA mandate.
minimum_retention_days := 1825

# Compliant when no deny fires: retention meets the configured floor, WORM is enabled,
# and no lifecycle delete would purge evidence before the immutability period
# expires. An ABSENT lifecycle delete is fine — deletion is then governed solely
# by the WORM / legal-hold window (the recommended posture; the storage module
# leaves lifecycle delete off by default, T-105/T-52).
compliant if {
	count(deny) == 0
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
	msg := sprintf("Retention %d days is below the configured 5-year evidence floor of %d days (PL statutory basis; DORA/NIS2 = 5y+ audit-defensibility, no numeric mandate)", [input.retention_days, minimum_retention_days])
}

deny contains msg if {
	input.worm_enabled != true
	msg := "WORM storage must be enabled for evidence packs"
}

# Footgun guard (T-10/T-62, T-105/T-52): a lifecycle delete that fires BEFORE the
# immutability period expires would purge evidence early. Denies ONLY when a
# positive delete threshold is actually configured AND it is shorter than the
# retention period. An absent/null delete_after_days (the recommended posture)
# does NOT deny — deletion is governed by the WORM / legal-hold window, which
# satisfies RODO Art.5.1.e via a defined retention period, not an auto-delete rule.
deny contains msg if {
	is_number(input.delete_after_days)
	input.delete_after_days > 0
	input.delete_after_days < input.retention_days
	msg := sprintf("Lifecycle delete after %d days is shorter than the %d-day immutability period — evidence would be purged before WORM expiry", [input.delete_after_days, input.retention_days])
}

# Non-blocking warning: WORM is enabled but NOT locked, so the immutability is
# reversible. This is recorded honestly (retention-by-policy, not enforced WORM)
# rather than denied — the one-way lock is a deliberate owner decision (T-46).
warn contains msg if {
	input.worm_enabled == true
	input.worm_locked != true
	msg := "WORM immutability is enabled but NOT locked (reversible): retention-by-policy, not tamper-proof WORM. Lock is a one-way owner decision (T-46)."
}
