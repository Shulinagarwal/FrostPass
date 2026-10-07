locals {
  lambda_trust = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role" "intake" {
  provider           = aws.archive
  name               = "${var.prefix}-intake"
  assume_role_policy = local.lambda_trust
}

resource "aws_iam_role" "grants" {
  provider           = aws.access
  name               = "${var.prefix}-grants"
  assume_role_policy = local.lambda_trust
}

resource "aws_iam_role" "broker" {
  provider           = aws.access
  name               = "${var.prefix}-broker"
  assume_role_policy = local.lambda_trust
}

resource "aws_iam_role" "archive_reader" {
  provider = aws.archive
  name     = "${var.prefix}-archive-reader"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { AWS = [
        aws_iam_role.broker.arn,
        "arn:aws:sts::${var.access_account_id}:assumed-role/${aws_iam_role.broker.name}/floci-session",
      ] }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role" "witness" {
  provider           = aws.access
  name               = "${var.prefix}-witness"
  assume_role_policy = local.lambda_trust
}

resource "aws_iam_role_policy" "intake" {
  provider = aws.archive
  name     = "${var.prefix}-intake-policy"
  role     = aws_iam_role.intake.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.evidence.arn}/reports/*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey"]
        Resource = "arn:aws:kms:${var.region}:${var.archive_account_id}:key/*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "grants" {
  provider = aws.access
  name     = "${var.prefix}-grants-policy"
  role     = aws_iam_role.grants.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # New grants may carry only the attributes Grant Manager writes.
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = aws_dynamodb_table.grants.arn
        Condition = {
          "ForAllValues:StringEquals" = {
            "dynamodb:Attributes" = ["grant_id", "shipment_id", "sensor_id", "version_id", "expires_at", "state", "expected_sha256"]
          }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:UpdateItem"]
        Resource = aws_dynamodb_table.grants.arn
      }
    ]
  })
}

resource "aws_iam_role_policy" "broker" {
  provider = aws.access
  name     = "${var.prefix}-broker-policy"
  role     = aws_iam_role.broker.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem"]
        Resource = [aws_dynamodb_table.grants.arn, aws_dynamodb_table.audit.arn]
      },
      {
        # Audit items may carry only the attributes the Broker writes.
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = aws_dynamodb_table.audit.arn
        Condition = {
          "ForAllValues:StringEquals" = {
            "dynamodb:Attributes" = ["audit_id", "grant_id", "outcome", "reason", "at", "request_hash", "response_json"]
          }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["sts:AssumeRole"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "archive_reader" {
  provider = aws.archive
  name     = "${var.prefix}-archive-reader-policy"
  role     = aws_iam_role.archive_reader.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:GetObjectVersion"]
        Resource = "${aws_s3_bucket.evidence.arn}/reports/*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = "arn:aws:kms:${var.region}:${var.archive_account_id}:key/*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "witness" {
  provider = aws.access
  name     = "${var.prefix}-witness-policy"
  role     = aws_iam_role.witness.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["dynamodb:DescribeStream", "dynamodb:GetRecords", "dynamodb:GetShardIterator", "dynamodb:ListStreams"]
        Resource = "${aws_dynamodb_table.audit.arn}/stream/*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.audit_mirror.arn}/decisions/*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.audit_mirror.arn}/decisions/*"
      },
      {
        # Lets HeadObject report a missing copy as 404 rather than 403.
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = aws_s3_bucket.audit_mirror.arn
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:Scan"]
        Resource = aws_dynamodb_table.audit.arn
      }
    ]
  })
}

resource "aws_iam_role" "audit_scheduler" {
  provider = aws.access
  name     = "${var.prefix}-audit-scheduler"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "scheduler.amazonaws.com" }
      # Confused-deputy protection: only schedules in this deployment's group.
      # Scheduler sets aws:SourceArn to the schedule group's ARN.
      Condition = {
        StringEquals = { "aws:SourceAccount" = var.access_account_id }
        ArnEquals = {
          "aws:SourceArn" = "arn:aws:scheduler:${var.region}:${var.access_account_id}:schedule-group/${var.prefix}-audit"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "audit_scheduler" {
  provider = aws.access
  name     = "${var.prefix}-audit-scheduler-invoke"
  role     = aws_iam_role.audit_scheduler.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["lambda:InvokeFunction"]
      Resource = aws_lambda_function.witness.arn
    }]
  })
}

resource "aws_iam_user" "custodian" {
  provider = aws.archive
  name     = "${var.prefix}-custodian"
}

resource "aws_iam_user" "approver" {
  provider = aws.access
  name     = "${var.prefix}-approver"
}

resource "aws_iam_user" "reviewer" {
  provider = aws.access
  name     = "${var.prefix}-reviewer"
}

resource "aws_iam_user" "outsider" {
  provider = aws.access
  name     = "${var.prefix}-outsider"
}

resource "aws_iam_user_policy" "custodian" {
  provider = aws.archive
  name     = "${var.prefix}-custodian-invoke"
  user     = aws_iam_user.custodian.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["lambda:InvokeFunction"]
      Resource = aws_lambda_function.intake.arn
    }]
  })
}

resource "aws_iam_user_policy" "approver" {
  provider = aws.access
  name     = "${var.prefix}-approver-invoke"
  user     = aws_iam_user.approver.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["lambda:InvokeFunction"]
      Resource = aws_lambda_function.grants.arn
    }]
  })
}

resource "aws_iam_user_policy" "reviewer" {
  provider = aws.access
  name     = "${var.prefix}-reviewer-invoke"
  user     = aws_iam_user.reviewer.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["lambda:InvokeFunction"]
      Resource = aws_lambda_function.broker.arn
    }]
  })
}

resource "aws_iam_access_key" "custodian" {
  provider = aws.archive
  user     = aws_iam_user.custodian.name
}

resource "aws_iam_access_key" "approver" {
  provider = aws.access
  user     = aws_iam_user.approver.name
}

resource "aws_iam_access_key" "reviewer" {
  provider = aws.access
  user     = aws_iam_user.reviewer.name
}

resource "aws_iam_access_key" "outsider" {
  provider = aws.access
  user     = aws_iam_user.outsider.name
}
