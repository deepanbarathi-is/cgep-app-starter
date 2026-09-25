# Hardens one existing S3 bucket. The module never creates the bucket itself.

# HIPAA 164.312(a)(1), 164.312(a)(2)(iv): customer-managed key with rotation,
# so key access is under my control and every use shows up in CloudTrail.
resource "aws_kms_key" "this" {
  description             = "CMK for S3 bucket ${var.bucket_id}"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.key_alias}"
  target_key_id = aws_kms_key.this.key_id
}

# HIPAA 164.312(a)(2)(iv): default encryption at rest with the CMK above.
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = var.bucket_id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.this.arn
    }
    bucket_key_enabled = true
  }
}

# HIPAA 164.308(a)(7): overwritten or deleted PHI objects stay recoverable.
resource "aws_s3_bucket_versioning" "this" {
  bucket = var.bucket_id

  versioning_configuration {
    status = "Enabled"
  }
}

# HIPAA 164.312(a)(1): explicit deny on every public access path.
resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = var.bucket_id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}