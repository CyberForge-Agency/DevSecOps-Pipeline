package compliance.retention

import rego.v1

minimum_retention_days := 1825 # 5 years (DORA)

compliant if {
  input.retention_days >= minimum_retention_days
  input.deletion_schedule != ""
  input.worm_enabled == true
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
