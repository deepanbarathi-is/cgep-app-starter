variable "bucket_id" {
  type        = string
  description = "ID of the existing S3 bucket to harden with KMS encryption, versioning, and a public access block."
}

variable "key_alias" {
  type        = string
  description = "Alias name for the KMS key this module creates. Must be unique per account and region."
}