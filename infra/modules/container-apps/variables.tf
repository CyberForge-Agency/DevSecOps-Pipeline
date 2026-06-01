variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
}

variable "location" {
  description = "Azure region"
  type        = string
}

variable "environment_name" {
  description = "Container Apps Environment name"
  type        = string
}

variable "app_name" {
  description = "Container App name"
  type        = string
}

variable "image" {
  description = "Container image URI"
  type        = string
}

variable "acr_login_server" {
  description = "ACR login server for managed identity pull"
  type        = string
}

variable "acr_id" {
  description = "ACR resource ID for role assignment"
  type        = string
}

variable "tags" {
  description = "Tags to apply"
  type        = map(string)
  default     = {}
}
