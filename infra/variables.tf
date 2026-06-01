variable "project_name" {
  description = "Project name prefix for all resources"
  type        = string
  default     = "cyberforge"
}

variable "environment" {
  description = "Environment name (staging, production)"
  type        = string
  default     = "staging"
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "polandcentral"
}

variable "container_image" {
  description = "Container image URI to deploy"
  type        = string
  default     = "mcr.microsoft.com/azuredocs/containerapps-helloworld:latest"
}

variable "alert_email" {
  description = "Email address for critical monitoring alert notifications"
  type        = string
  default     = ""
}
