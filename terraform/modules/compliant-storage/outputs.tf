output "kms_key_arn" {
  value       = aws_kms_key.this.arn
  description = "ARN of the CMK created for this bucket. Use it to grant principals access to the key."
}

output "kms_key_id" {
  value       = aws_kms_key.this.key_id
  description = "Key ID of the CMK created for this bucket."
}