output "manifest" {
  sensitive = true
  value = {
    region   = var.region
    endpoint = var.aws_endpoint_url
    accounts = {
      archive = var.archive_account_id
      access  = var.access_account_id
    }
    functions = {
      intake  = aws_lambda_function.intake.function_name
      grants  = aws_lambda_function.grants.function_name
      broker  = aws_lambda_function.broker.function_name
      witness = aws_lambda_function.witness.function_name
    }
    bucket              = aws_s3_bucket.evidence.bucket
    audit_bucket        = aws_s3_bucket.audit_mirror.bucket
    evidence_key        = aws_kms_key.evidence.arn
    archive_reader_role = aws_iam_role.archive_reader.arn
    reconciliation_schedule = {
      group = aws_scheduler_schedule_group.audit.name
      name  = aws_scheduler_schedule.audit_reconcile.name
    }
    tables = {
      grants = aws_dynamodb_table.grants.name
      audit  = aws_dynamodb_table.audit.name
    }
    callers = {
      custodian = {
        access_key_id     = aws_iam_access_key.custodian.id
        secret_access_key = aws_iam_access_key.custodian.secret
      }
      approver = {
        access_key_id     = aws_iam_access_key.approver.id
        secret_access_key = aws_iam_access_key.approver.secret
      }
      reviewer = {
        access_key_id     = aws_iam_access_key.reviewer.id
        secret_access_key = aws_iam_access_key.reviewer.secret
      }
      outsider = {
        access_key_id     = aws_iam_access_key.outsider.id
        secret_access_key = aws_iam_access_key.outsider.secret
      }
    }
  }
}
