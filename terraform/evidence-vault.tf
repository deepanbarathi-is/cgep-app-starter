# Layer 1 evidence vault (HIPAA 164.312(b), audit controls): tamper-evident storage
# for the signed evidence bundles the pipeline produces.
#
# Object Lock can only be switched on when a bucket is created, so the bucket is
# defined here and the module hardens it afterwards.
resource "aws_s3_bucket" "evidence" {
  bucket              = "${local.name_prefix}-evidence-${local.suffix}"
  object_lock_enabled = true
}

module "evidence_storage" {
  source    = "./modules/compliant-storage"
  bucket_id = aws_s3_bucket.evidence.id
  key_alias = "${local.name_prefix}-evidence-${local.suffix}"
}

# GOVERNANCE mode with 30 days of default retention, as decided in DESIGN.md.
resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 30
    }
  }

  # Object Lock needs versioning on first, and the module turns it on.
  depends_on = [module.evidence_storage]
}

data "aws_iam_policy_document" "evidence_tls_only" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]

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

resource "aws_s3_bucket_policy" "evidence_tls_only" {
  bucket = aws_s3_bucket.evidence.id
  policy = data.aws_iam_policy_document.evidence_tls_only.json

  depends_on = [module.evidence_storage]
}

output "evidence_bucket" {
  value       = aws_s3_bucket.evidence.id
  description = "Name of the evidence vault bucket. The pipeline uploads signed bundles here."
}

output "evidence_kms_key_arn" {
  value       = module.evidence_storage.kms_key_arn
  description = "ARN of the key that encrypts the evidence vault. The pipeline role needs access to it."
}
