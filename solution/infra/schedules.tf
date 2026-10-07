resource "aws_scheduler_schedule_group" "audit" {
  provider = aws.access
  name     = "${var.prefix}-audit"
}

resource "aws_scheduler_schedule" "audit_reconcile" {
  provider   = aws.access
  name       = "${var.prefix}-audit-reconcile"
  group_name = aws_scheduler_schedule_group.audit.name
  state      = "ENABLED"

  schedule_expression = "rate(1 minute)"

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_lambda_function.witness.arn
    role_arn = aws_iam_role.audit_scheduler.arn
    input    = jsonencode({ source = "frostpass", operation = "reconcile" })
  }

  depends_on = [aws_iam_role_policy.audit_scheduler]
}
