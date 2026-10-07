resource "aws_lambda_function" "intake" {
  provider      = aws.archive
  function_name = "${var.prefix}-intake"
  package_type  = "Image"
  image_uri     = var.intake_image
  role          = aws_iam_role.intake.arn
  timeout       = 15
  memory_size   = 256

  environment {
    variables = {
      EVIDENCE_BUCKET = aws_s3_bucket.evidence.bucket
      EVIDENCE_KEY_ID = aws_kms_key.evidence.arn
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.evidence,
    aws_iam_role_policy.intake,
    aws_kms_key.evidence,
  ]

  lifecycle {
    ignore_changes = [image_config]
  }
}

resource "aws_lambda_function" "grants" {
  provider      = aws.access
  function_name = "${var.prefix}-grants"
  package_type  = "Image"
  image_uri     = var.grants_image
  role          = aws_iam_role.grants.arn
  timeout       = 15
  memory_size   = 256

  environment {
    variables = {
      GRANTS_TABLE = aws_dynamodb_table.grants.name
    }
  }

  depends_on = [aws_iam_role_policy.grants]

  lifecycle {
    ignore_changes = [image_config]
  }
}

resource "aws_lambda_function" "broker" {
  provider      = aws.access
  function_name = "${var.prefix}-broker"
  package_type  = "Image"
  image_uri     = var.broker_image
  role          = aws_iam_role.broker.arn
  timeout       = 15
  memory_size   = 256

  environment {
    variables = {
      EVIDENCE_BUCKET     = aws_s3_bucket.evidence.bucket
      GRANTS_TABLE        = aws_dynamodb_table.grants.name
      AUDIT_TABLE         = aws_dynamodb_table.audit.name
      ARCHIVE_READER_ROLE = aws_iam_role.archive_reader.arn
    }
  }

  depends_on = [
    aws_iam_role_policy.broker,
    aws_s3_bucket_policy.broker_read,
    aws_iam_role_policy.archive_reader,
  ]

  lifecycle {
    ignore_changes = [image_config]
  }
}

resource "aws_lambda_function" "witness" {
  provider      = aws.access
  function_name = "${var.prefix}-witness"
  package_type  = "Image"
  image_uri     = var.witness_image
  role          = aws_iam_role.witness.arn
  timeout       = 60
  memory_size   = 256
  environment {
    variables = {
      AUDIT_BUCKET = aws_s3_bucket.audit_mirror.bucket
      AUDIT_TABLE  = aws_dynamodb_table.audit.name
    }
  }
  depends_on = [aws_iam_role_policy.witness, aws_s3_bucket_policy.audit_mirror]
  lifecycle {
    ignore_changes = [image_config]
  }
}

resource "aws_lambda_event_source_mapping" "audit_witness" {
  provider          = aws.access
  event_source_arn  = aws_dynamodb_table.audit.stream_arn
  function_name     = aws_lambda_function.witness.arn
  starting_position = "TRIM_HORIZON"
  batch_size        = 10
  depends_on        = [aws_iam_role_policy.witness]
}
