# GAP-08 (HIPAA 164.312(b)): a place for the API's access logs to land.
resource "aws_cloudwatch_log_group" "api_access" {
  name              = "/aws/apigateway/${local.name_prefix}-${local.suffix}"
  retention_in_days = 365
}