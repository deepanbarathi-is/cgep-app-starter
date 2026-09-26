# Layer 1 continuous monitoring (HIPAA 164.312(b)): AWS Config records how the
# resources are configured and checks them against managed rules.

resource "aws_s3_bucket" "config" {
  bucket = "${local.name_prefix}-config-${local.suffix}"
}

module "config_storage" {
  source    = "./modules/compliant-storage"
  bucket_id = aws_s3_bucket.config.id
  key_alias = "${local.name_prefix}-config-${local.suffix}"
}

data "aws_iam_policy_document" "config_tls_only" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.config.arn, "${aws_s3_bucket.config.arn}/*"]

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

resource "aws_s3_bucket_policy" "config_tls_only" {
  bucket = aws_s3_bucket.config.id
  policy = data.aws_iam_policy_document.config_tls_only.json

  depends_on = [module.config_storage]
}

# The role AWS Config assumes to read resource settings and deliver its records.
resource "aws_iam_role" "config" {
  name = "${local.name_prefix}-config-${local.suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# Writing to the bucket and using its key are not in the managed policy above.
data "aws_iam_policy_document" "config_delivery" {
  statement {
    sid       = "ReadBucketAcl"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.config.arn]
  }

  statement {
    sid       = "WriteConfigRecords"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid       = "UseBucketKey"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [module.config_storage.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "config_delivery" {
  name   = "config-delivery"
  role   = aws_iam_role.config.id
  policy = data.aws_iam_policy_document.config_delivery.json
}

# The recorder is the part that watches. It only records the four resource types the
# rules below look at, which keeps Config's per-item charge small.
resource "aws_config_configuration_recorder" "main" {
  name     = "${local.name_prefix}-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported = false
    resource_types = [
      "AWS::S3::Bucket",
      "AWS::DynamoDB::Table",
      "AWS::Lambda::Function",
      "AWS::ApiGatewayV2::Stage",
    ]
  }
}

# The delivery channel says where the records go. Creating it makes Config test-write
# to the bucket, so a permission mistake in step 1 shows up here.
resource "aws_config_delivery_channel" "main" {
  name           = "${local.name_prefix}-delivery"
  s3_bucket_name = aws_s3_bucket.config.id

  depends_on = [
    aws_config_configuration_recorder.main,
    aws_iam_role_policy.config_delivery,
    aws_iam_role_policy_attachment.config,
    aws_s3_bucket_policy.config_tls_only,
    module.config_storage,
  ]
}

# A recorder does nothing until it is switched on.
resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}

# One AWS-managed rule per gap that Config can see. Config detects, it does not
# prevent: the Rego policies in Layer 2 are the preventive side.
locals {
  config_rules = {
    "s3-default-encryption-kms"    = "S3_DEFAULT_ENCRYPTION_KMS"    # GAP-01, 164.312(a)(2)(iv)
    "dynamodb-table-encrypted-kms" = "DYNAMODB_TABLE_ENCRYPTED_KMS" # GAP-02, 164.312(a)(2)(iv)
    "s3-bucket-ssl-requests-only"  = "S3_BUCKET_SSL_REQUESTS_ONLY"  # GAP-03, 164.312(e)(1)
    "s3-bucket-versioning-enabled" = "S3_BUCKET_VERSIONING_ENABLED" # GAP-04, 164.308(a)(7)
    "lambda-inside-vpc"            = "LAMBDA_INSIDE_VPC"            # GAP-05, 164.312(e)(1)
    "api-gwv2-access-logs-enabled" = "API_GWV2_ACCESS_LOGS_ENABLED" # GAP-08, 164.312(b)
  }
}

resource "aws_config_config_rule" "managed" {
  for_each = local.config_rules

  name = "${local.name_prefix}-${each.key}"

  source {
    owner             = "AWS"
    source_identifier = each.value
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# When a Config rule turns NON_COMPLIANT, EventBridge sees the event and publishes it
# to an SNS topic (HIPAA 164.312(b)). The topic uses its own key because the AWS-managed
# SNS key does not let EventBridge publish.
data "aws_iam_policy_document" "alerts_key" {
  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid       = "EventBridgePublishToEncryptedTopic"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "alerts" {
  description             = "CMK for the ${local.name_prefix} compliance alert topic"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.alerts_key.json
}

resource "aws_kms_alias" "alerts" {
  name          = "alias/${local.name_prefix}-alerts-${local.suffix}"
  target_key_id = aws_kms_key.alerts.key_id
}

resource "aws_sns_topic" "compliance_alerts" {
  name              = "${local.name_prefix}-compliance-alerts-${local.suffix}"
  kms_master_key_id = aws_kms_key.alerts.arn
}

# Created only when an address is given, so the code plans and applies with no input.
resource "aws_sns_topic_subscription" "email" {
  count = var.alert_email == "" ? 0 : 1

  topic_arn = aws_sns_topic.compliance_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "noncompliant" {
  name        = "${local.name_prefix}-config-noncompliant-${local.suffix}"
  description = "A Config rule evaluated a resource as NON_COMPLIANT"

  event_pattern = jsonencode({
    source        = ["aws.config"]
    "detail-type" = ["Config Rules Compliance Change"]
    detail = {
      newEvaluationResult = { complianceType = ["NON_COMPLIANT"] }
    }
  })
}

resource "aws_cloudwatch_event_target" "alerts" {
  rule = aws_cloudwatch_event_rule.noncompliant.name
  arn  = aws_sns_topic.compliance_alerts.arn
}

# EventBridge may publish to the topic only if the topic says so.
data "aws_iam_policy_document" "alerts_topic" {
  statement {
    sid       = "AllowEventBridgePublish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.compliance_alerts.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.noncompliant.arn]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.compliance_alerts.arn
  policy = data.aws_iam_policy_document.alerts_topic.json
}
