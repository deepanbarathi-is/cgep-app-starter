# DEMONSTRATION ONLY. This pull request is opened to show the policy gate blocking a change,
# and it is never merged. The bucket below is built with the compliant-storage module, so it
# has a customer-managed key, versioning and a public access block, but it is missing the
# bucket policy that denies requests not using TLS (GAP-03, HIPAA 164.312(e)(1)).
resource "aws_s3_bucket" "red_demo" {
  bucket = "${local.name_prefix}-red-demo-${local.suffix}"
}

module "red_demo_storage" {
  source    = "./modules/compliant-storage"
  bucket_id = aws_s3_bucket.red_demo.id
  key_alias = "${local.name_prefix}-red-demo-${local.suffix}"
}
