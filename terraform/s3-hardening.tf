# GAP-01 (HIPAA 164.312(a)(2)(iv), 164.312(a)(1)) and GAP-04 (HIPAA 164.308(a)(7)):
# customer-managed key, default SSE-KMS, versioning, and an explicit public
# access block on the starter's uploads bucket.
module "uploads_storage" {
  source    = "./modules/compliant-storage"
  bucket_id = aws_s3_bucket.uploads.id
  key_alias = "${local.name_prefix}-uploads-${local.suffix}"
}