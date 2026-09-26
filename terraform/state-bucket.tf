# Remote Terraform state (HIPAA 164.312(a)(1), 164.312(b)): the pipeline runs on a runner
# that is thrown away after every run, so state has to live somewhere that lasts. State can
# hold sensitive values, so the bucket gets the same protection as the other buckets:
# a customer-managed key, versioning, no public access, and TLS only.
#
# The bucket is created here first, by an apply that still uses local state. Only after it
# exists does the backend block in main.tf point at it.
resource "aws_s3_bucket" "tfstate" {
  bucket = "${local.name_prefix}-tfstate-${local.suffix}"
}

module "state_storage" {
  source    = "./modules/compliant-storage"
  bucket_id = aws_s3_bucket.tfstate.id
  key_alias = "${local.name_prefix}-tfstate-${local.suffix}"
}

data "aws_iam_policy_document" "tfstate_tls_only" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.tfstate.arn, "${aws_s3_bucket.tfstate.arn}/*"]

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

resource "aws_s3_bucket_policy" "tfstate_tls_only" {
  bucket = aws_s3_bucket.tfstate.id
  policy = data.aws_iam_policy_document.tfstate_tls_only.json

  depends_on = [module.state_storage]
}

output "tfstate_bucket" {
  value       = aws_s3_bucket.tfstate.id
  description = "Name of the bucket that holds the Terraform state."
}

output "tfstate_kms_key_arn" {
  value       = module.state_storage.kms_key_arn
  description = "ARN of the key that encrypts the state bucket. The pipeline role needs access to it."
}
