# GAP-02 (HIPAA 164.312(a)(2)(iv), 164.312(a)(1)): customer-managed key for the
# DynamoDB submissions table, with rotation.
resource "aws_kms_key" "dynamodb" {
  description             = "CMK for the ${local.name_prefix} submissions table"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "dynamodb" {
  name          = "alias/${local.name_prefix}-submissions-${local.suffix}"
  target_key_id = aws_kms_key.dynamodb.key_id
}