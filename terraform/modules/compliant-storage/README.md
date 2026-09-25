# compliant-storage

Hardens one existing S3 bucket. It does not create the bucket. It adds a customer-managed KMS key with rotation, default SSE-KMS encryption, versioning, and an explicit public access block.

## Inputs

- `bucket_id`: the bucket to harden.
- `key_alias`: a short alias name for the key. The module adds the `alias/` prefix.

## Outputs

- `kms_key_arn` and `kms_key_id`, so callers can grant principals access to the key.

## Controls

The module covers HIPAA 164.312(a)(1) and 164.312(a)(2)(iv) (key custody, encryption at rest, and public access blocked in code) and 164.308(a)(7) (versioning, so overwritten PHI can be recovered). Used on the starter's uploads bucket, it closes GAP-01 and GAP-04. It does not add the TLS-deny bucket policy (GAP-03).

## Example

```hcl
module "uploads" {
  source    = "./modules/compliant-storage"
  bucket_id = aws_s3_bucket.uploads.id
  key_alias = "acme-health-uploads"
}
```
