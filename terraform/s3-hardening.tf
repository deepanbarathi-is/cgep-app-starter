# GAP-01 (HIPAA 164.312(a)(2)(iv), 164.312(a)(1)) and GAP-04 (HIPAA 164.308(a)(7)):
# customer-managed key, default SSE-KMS, versioning, and an explicit public
# access block on the starter's uploads bucket.
module "uploads_storage" {
  source    = "./modules/compliant-storage"
  bucket_id = aws_s3_bucket.uploads.id
  key_alias = "${local.name_prefix}-uploads-${local.suffix}"
}

# GAP-03 (HIPAA 164.312(e)(1)): deny any request to the uploads bucket that
# does not use TLS.
data "aws_iam_policy_document" "uploads_tls_only" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.uploads.arn, "${aws_s3_bucket.uploads.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "uploads_tls_only" {
  bucket = aws_s3_bucket.uploads.id
  policy = data.aws_iam_policy_document.uploads_tls_only.json

  # The module also changes this bucket's settings. Waiting for it avoids a
  # conflict when two bucket-level changes run at the same time.
  depends_on = [module.uploads_storage]
}