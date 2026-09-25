variable "aws_region" {
  type        = string
  description = "AWS region for the starter."
  default     = "us-east-1"
}

variable "alert_email" {
  type        = string
  default     = ""
  description = "Address that receives Config non-compliance alerts. Leave empty to create the alert routing without an email subscription."
}
