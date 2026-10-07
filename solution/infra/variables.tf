variable "prefix" {
  type        = string
  description = "Unique deployment prefix for this attempt"
  default     = "frostpass"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,24}$", var.prefix))
    error_message = "prefix must be 3-25 lowercase letters, digits or hyphens"
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "aws_endpoint_url" {
  type    = string
  default = "http://aws:4566"
}

variable "archive_account_id" {
  type    = string
  default = "111111111111"
}

variable "access_account_id" {
  type    = string
  default = "222222222222"
}

variable "archive_admin_access_key" {
  type      = string
  sensitive = true
}

variable "archive_admin_secret_key" {
  type      = string
  sensitive = true
}

variable "access_admin_access_key" {
  type      = string
  sensitive = true
}

variable "access_admin_secret_key" {
  type      = string
  sensitive = true
}

variable "intake_image" {
  type    = string
  default = "111111111111.dkr.ecr.us-east-1.amazonaws.com/frostpass-intake:1"
}

variable "grants_image" {
  type    = string
  default = "222222222222.dkr.ecr.us-east-1.amazonaws.com/frostpass-grants:1"
}

variable "broker_image" {
  type    = string
  default = "222222222222.dkr.ecr.us-east-1.amazonaws.com/frostpass-broker:1"
}

variable "witness_image" {
  type    = string
  default = "222222222222.dkr.ecr.us-east-1.amazonaws.com/frostpass-witness:1"
}
