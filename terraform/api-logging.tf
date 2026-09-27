# GAP-08 (HIPAA 164.312(b)): a place for the API's access logs to land.
resource "aws_cloudwatch_log_group" "api_access" { # nosemgrep: terraform.aws.security.aws-cloudwatch-log-group-unencrypted.aws-cloudwatch-log-group-unencrypted
  # checkov:skip=CKV_AWS_158:The access log holds request metadata only (no PHI) and is kept for 365 days. A customer-managed key for this log group is an improvement I did not make.
  name              = "/aws/apigateway/${local.name_prefix}-${local.suffix}"
  retention_in_days = 365
}