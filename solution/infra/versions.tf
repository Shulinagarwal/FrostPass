terraform {
  required_version = ">= 1.8.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.51.0"
    }
  }
}

provider "aws" {
  alias      = "archive"
  access_key = var.archive_admin_access_key
  secret_key = var.archive_admin_secret_key
  region     = var.region

  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  skip_region_validation      = true
  s3_use_path_style           = true

  endpoints {
    dynamodb  = var.aws_endpoint_url
    iam       = var.aws_endpoint_url
    kms       = var.aws_endpoint_url
    lambda    = var.aws_endpoint_url
    logs      = var.aws_endpoint_url
    s3        = var.aws_endpoint_url
    scheduler = var.aws_endpoint_url
    sts       = var.aws_endpoint_url
  }
}

provider "aws" {
  alias      = "access"
  access_key = var.access_admin_access_key
  secret_key = var.access_admin_secret_key
  region     = var.region

  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  skip_region_validation      = true
  s3_use_path_style           = true

  endpoints {
    dynamodb  = var.aws_endpoint_url
    iam       = var.aws_endpoint_url
    kms       = var.aws_endpoint_url
    lambda    = var.aws_endpoint_url
    logs      = var.aws_endpoint_url
    s3        = var.aws_endpoint_url
    scheduler = var.aws_endpoint_url
    sts       = var.aws_endpoint_url
  }
}
