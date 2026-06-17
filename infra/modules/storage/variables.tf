variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
}

variable "location" {
  description = "Azure region"
  type        = string
}

variable "storage_account_name" {
  description = "Storage account name (3-24 chars, lowercase alphanumeric)"
  type        = string
}

# Per-data-class statutory retention minima (Poland), in days. These are the
# legally-grounded floors that the evidence-WORM period must meet; they are the
# infra-side encoding of the retention table in docs/poland-appendix.md §6.4
# (spec 6.4 / 7.5). Each entry pairs a data class with its Polish statutory basis:
#
#   aml_cft_records        = 1825 (5y) — art. 49 ustawy o przeciwdziałaniu praniu
#                            pieniędzy oraz finansowaniu terroryzmu (Dz.U. 2018
#                            poz. 723 ze zm.); extendable on KGIIF request by up
#                            to a further 5y. ⚠️ confirm extension triggers.
#   tax_books              = 1825 (5y) — przedawnienie per art. 70 § 1 Ordynacji
#                            podatkowej; storage obligation art. 86 § 1 Ordynacji
#                            podatkowej. ⚠️ confirm loss-year extension applies.
#   accounting_books       = 1825 (5y) — art. 74 ust. 2 pkt 1 ustawy o
#                            rachunkowości.
#   dora_ict_risk_records  = 1825 (5y+) — DORA (EU 2022/2554) Art. 11–12 + RTS;
#                            PL op. act Dz.U. 2025 poz. 1069. ⚠️ confirm exact
#                            period per record type.
#   nis2_ksc_records       = 1825 (5y+) — KSC (Dz.U. 2026 poz. 252). ⚠️ confirm
#                            exact period.
#
# OUT OF THIS STORE'S SCOPE (do NOT silently rely on the WORM floor for them):
#   - approved annual financial statements: trwałe przechowywanie / permanent,
#     art. 74 ust. 1 ustawy o rachunkowości.
#   - payroll / ZUS records: 10y (50y for pre-2019 employment).
#   These long/permanent classes are NOT satisfied by the 1825-day floor; the
#   evidence store is asserted to exclude them. ⚠️ confirm scope with legal, or
#   extend retention for the affected artifacts (see docs/poland-appendix.md §6.4).
variable "retention_minima_days" {
  description = "Per-data-class statutory retention minima in days (Poland). The WORM immutability period must meet the maximum in-scope value. See docs/poland-appendix.md §6.4 for citations. ⚠️ confirm exact periods per data class with legal/compliance."
  type        = map(number)
  default = {
    aml_cft_records       = 1825 # art. 49 ust. AML (Dz.U. 2018 poz. 723)
    tax_books             = 1825 # art. 70 § 1 / art. 86 § 1 Ordynacji podatkowej
    accounting_books      = 1825 # art. 74 ust. 2 pkt 1 ust. o rachunkowości
    dora_ict_risk_records = 1825 # DORA (EU 2022/2554) Art. 11–12; Dz.U. 2025 poz. 1069
    nis2_ksc_records      = 1825 # KSC (Dz.U. 2026 poz. 252)
  }

  validation {
    condition     = alltrue([for v in values(var.retention_minima_days) : v > 0])
    error_message = "Every retention_minima_days entry must be a positive number of days (a statutory minimum cannot be zero or negative)."
  }
}

# Single source of truth for evidence retention. The WORM immutability period
# governs how long evidence is protected from modification/deletion. By default
# the lifecycle policy does NOT delete evidence — WORM (and legal hold) own the
# end-of-retention decision (blueprint/06 §6.5-A remediation 9). Lifecycle only
# performs cost tiering. A delete action can be opted into via
# enable_lifecycle_delete, in which case it fires strictly after the WORM period
# and is guarded by a precondition forbidding it when WORM is disabled.
#
# The default 1825 days (5 years) is justified against the LONGEST in-scope
# statutory class in var.retention_minima_days (AML 5y, tax 5y, accounting 5y,
# DORA/NIS2 5y+) per docs/poland-appendix.md §6.4 (spec 6.4 / 7.5). The
# validation below fails the plan if the configured period falls below the
# maximum in-scope statutory minimum, so a future edit cannot silently breach a
# Polish retention floor. ⚠️ confirm exact periods per data class with legal.
variable "immutability_period_days" {
  description = "Evidence retention / WORM immutability period in days for compliance. Default 1825 = 5 years, justified against the longest in-scope Polish statutory minimum (AML/tax/accounting 5y; DORA/NIS2 5y+ — docs/poland-appendix.md §6.4). 0 = WORM disabled. ⚠️ confirm against legal/compliance."
  type        = number
  default     = 1825

  validation {
    # When WORM is enabled (>0), the period must meet the longest in-scope
    # statutory retention minimum. 0 (WORM disabled) is allowed and handled by
    # the lifecycle-delete precondition in main.tf.
    condition     = var.immutability_period_days == 0 || var.immutability_period_days >= max(values(var.retention_minima_days)...)
    error_message = "immutability_period_days must be >= the longest in-scope Polish statutory retention minimum in var.retention_minima_days (default 1825 days = 5 years, covering AML/tax/accounting/DORA/NIS2 per docs/poland-appendix.md §6.4). Set 0 only to disable WORM entirely."
  }
}

variable "enable_lifecycle_delete" {
  description = "If true, the lifecycle policy deletes evidence blobs after the WORM period elapses (immutability_period_days + delete_grace_days). Disabled by default so WORM/legal hold govern deletion."
  type        = bool
  default     = false
}

variable "delete_grace_days" {
  description = "Grace period (days) added to immutability_period_days before lifecycle delete fires, ensuring delete is strictly after the WORM period."
  type        = number
  default     = 30

  validation {
    condition     = var.delete_grace_days > 0
    error_message = "delete_grace_days must be greater than 0 so the lifecycle delete fires strictly after the WORM immutability period."
  }
}

variable "lock_worm" {
  type        = bool
  default     = false
  description = "Irreversibly lock the time-based immutability policy (true WORM). One-way; cannot be undone. Default false (retention-only) — owner decision."
}

variable "network_hardened" {
  type        = bool
  default     = false
  description = "Disable public network access and require private endpoints / explicit IP rules for regulated clients."
}

variable "replication_type" {
  description = "Storage account replication type (LRS, GRS, ZRS, etc.)"
  type        = string
  default     = "LRS"
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}
