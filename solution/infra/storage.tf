resource "aws_s3_bucket" "evidence" {
  provider      = aws.archive
  bucket        = "${var.prefix}-evidence"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "evidence" {
  provider = aws.archive
  bucket   = aws_s3_bucket.evidence.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  provider                = aws.archive
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_dynamodb_table" "grants" {
  provider     = aws.access
  name         = "${var.prefix}-grants"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "grant_id"

  attribute {
    name = "grant_id"
    type = "S"
  }
}

resource "aws_dynamodb_table" "audit" {
  provider         = aws.access
  name             = "${var.prefix}-audit"
  billing_mode     = "PAY_PER_REQUEST"
  hash_key         = "audit_id"
  stream_enabled   = true
  stream_view_type = "NEW_IMAGE"

  attribute {
    name = "audit_id"
    type = "S"
  }
}

resource "aws_s3_bucket" "audit_mirror" {
  provider      = aws.archive
  bucket        = "${var.prefix}-audit-mirror"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "audit_mirror" {
  provider = aws.archive
  bucket   = aws_s3_bucket.audit_mirror.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "audit_mirror" {
  provider                = aws.archive
  bucket                  = aws_s3_bucket.audit_mirror.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

locals {
  # Key administration only: no cryptographic action is delegated to IAM.
  kms_admin_actions = [
    "kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*",
    "kms:Update*", "kms:Revoke*", "kms:Disable*", "kms:Get*", "kms:Delete*",
    "kms:TagResource", "kms:UntagResource", "kms:ScheduleKeyDeletion",
    "kms:CancelKeyDeletion",
  ]
  # The encryption context must be exactly {case, file}. ForAllValues alone
  # would also accept an empty context, hence the Null checks.
  evidence_context = {
    "ForAllValues:StringEquals" = { "kms:EncryptionContextKeys" = ["shipment", "sensor"] }
    "Null" = {
      "kms:EncryptionContext:shipment" = "false"
      "kms:EncryptionContext:sensor" = "false"
    }
  }
}

resource "aws_kms_key" "evidence" {
  provider                = aws.archive
  description             = "FrostPass evidence key ${var.prefix}"
  deletion_window_in_days = 7
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "ArchiveAccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.archive_account_id}:root" }
        Action    = local.kms_admin_actions
        Resource  = "*"
      },
      {
        Sid       = "IntakeGeneratesDataKeys"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.intake.arn }
        Action    = ["kms:GenerateDataKey"]
        Resource  = "*"
        Condition = local.evidence_context
      },
      {
        Sid       = "ArchiveReaderDecrypts"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.archive_reader.arn }
        Action    = ["kms:Decrypt"]
        Resource  = "*"
        Condition = local.evidence_context
      }
    ]
  })
}

# A stable name for the key, so a deployment can find it again after losing state.
resource "aws_kms_alias" "evidence" {
  provider      = aws.archive
  name          = "alias/${var.prefix}-evidence"
  target_key_id = aws_kms_key.evidence.key_id
}

resource "aws_s3_bucket_policy" "audit_mirror" {
  provider = aws.archive
  bucket   = aws_s3_bucket.audit_mirror.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "WitnessWritesDecisions"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.witness.arn }
        Action    = ["s3:PutObject", "s3:GetObject"]
        Resource  = "${aws_s3_bucket.audit_mirror.arn}/decisions/*"
      },
      {
        Sid       = "WitnessChecksDecisions"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.witness.arn }
        Action    = ["s3:ListBucket"]
        Resource  = aws_s3_bucket.audit_mirror.arn
      },
      {
        Sid          = "DecisionCopiesAreImmutable"
        Effect       = "Deny"
        NotPrincipal = { AWS = local.archive_deployers }
        Action       = local.immutable_actions
        Resource     = [aws_s3_bucket.audit_mirror.arn, "${aws_s3_bucket.audit_mirror.arn}/*"]
      }
    ]
  })
}

resource "aws_s3_bucket_policy" "broker_read" {
  provider = aws.archive
  bucket   = aws_s3_bucket.evidence.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "OnlyArchiveReaderMayReadEvidence"
        Effect = "Deny"
        NotPrincipal = { AWS = [
          aws_iam_role.archive_reader.arn,
          "arn:aws:sts::${var.archive_account_id}:assumed-role/${aws_iam_role.archive_reader.name}/floci-session",
        ] }
        Action   = ["s3:GetObject", "s3:GetObjectVersion"]
        Resource = "${aws_s3_bucket.evidence.arn}/reports/*"
      },
      {
        Sid    = "CallersCannotReadEvidenceDirectly"
        Effect = "Deny"
        Principal = { AWS = [
          aws_iam_user.custodian.arn,
          aws_iam_user.approver.arn,
          aws_iam_user.reviewer.arn,
          aws_iam_user.outsider.arn,
        ] }
        Action   = ["s3:GetObject", "s3:GetObjectVersion"]
        Resource = "${aws_s3_bucket.evidence.arn}/reports/*"
      },
      {
        Sid       = "ArchiveReaderReadsApprovedVersions"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.archive_reader.arn }
        Action    = ["s3:GetObject", "s3:GetObjectVersion"]
        Resource  = "${aws_s3_bucket.evidence.arn}/reports/*"
      },
      {
        Sid          = "EvidenceIsImmutable"
        Effect       = "Deny"
        NotPrincipal = { AWS = local.archive_deployers }
        Action       = local.immutable_actions
        Resource     = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]
      }
    ]
  })
}

# Only the deployment identity may delete versions or change versioning, so
# destroy.sh can still empty the buckets while every other principal cannot.
data "aws_caller_identity" "archive" {
  provider = aws.archive
}

locals {
  archive_deployers = [
    data.aws_caller_identity.archive.arn,
    "arn:aws:iam::${var.archive_account_id}:root",
  ]
  immutable_actions = [
    "s3:DeleteObject",
    "s3:DeleteObjectVersion",
    "s3:PutBucketVersioning",
    "s3:PutLifecycleConfiguration",
  ]
}
