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

variable "retention_days" {
  description = "Evidence retention period in days (5 years = 1825)"
  type        = number
  default     = 1825
}

variable "immutability_period_days" {
  description = "Blob immutability period in days for WORM compliance (0 = disabled)"
  type        = number
  default     = 1825
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
