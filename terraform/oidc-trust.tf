# Layer 3 pipeline login (HIPAA 164.312(a)(1)): GitHub Actions gets temporary AWS keys by
# presenting a signed token, so no long-lived keys are stored in GitHub. Two roles, split
# by what the run is allowed to do:
#
#   plan role   pull requests only, read-only, so a PR can be checked but cannot change AWS
#   apply role  merges to main only, can change what this project manages
#
# The trust conditions use the token's exact "sub" claim, not a wildcard. GitHub documents
# the formats as repo:OWNER/REPO:pull_request and repo:OWNER/REPO:ref:refs/heads/BRANCH.
locals {
  github_repo = "deepanbarathi-is/cgep-app-starter"
  github_sub  = "token.actions.githubusercontent.com:sub"
  github_aud  = "token.actions.githubusercontent.com:aud"
}

# AWS checks GitHub's certificate against its own list of trusted authorities, so no
# thumbprint is set here.
resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_policy_document" "pipeline_plan_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = local.github_aud
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = local.github_sub
      values   = ["repo:${local.github_repo}:pull_request"]
    }
  }
}

data "aws_iam_policy_document" "pipeline_apply_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = local.github_aud
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = local.github_sub
      values   = ["repo:${local.github_repo}:ref:refs/heads/main"]
    }
  }
}

resource "aws_iam_role" "pipeline_plan" {
  name               = "acme-health-pipeline-plan"
  assume_role_policy = data.aws_iam_policy_document.pipeline_plan_trust.json
}

resource "aws_iam_role" "pipeline_apply" {
  name               = "acme-health-pipeline-apply"
  assume_role_policy = data.aws_iam_policy_document.pipeline_apply_trust.json
}

# Plan role: read everything so terraform can refresh, plus the state file and its key.
# Pull request plans run with -lock=false, so this role never needs to write.
resource "aws_iam_role_policy_attachment" "pipeline_plan_readonly" {
  role       = aws_iam_role.pipeline_plan.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

data "aws_iam_policy_document" "pipeline_plan_state" {
  statement {
    sid       = "ListStateBucket"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.tfstate.arn]
  }

  statement {
    sid       = "ReadStateFile"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.tfstate.arn}/capstone/terraform.tfstate"]
  }

  statement {
    sid       = "DecryptStateFile"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = [module.state_storage.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "pipeline_plan_state" {
  name   = "read-terraform-state"
  role   = aws_iam_role.pipeline_plan.id
  policy = data.aws_iam_policy_document.pipeline_plan_state.json
}

# Apply role: PowerUserAccess covers the services this project uses, including the state
# bucket, the evidence vault and their keys. It excludes IAM, so IAM is added by hand
# below and limited to this project's workload roles. The pipeline roles are named
# acme-health-pipeline-*, which does not match, so the apply role cannot change its own
# permissions or its own trust. A change to the pipeline's login has to be applied by me.
resource "aws_iam_role_policy_attachment" "pipeline_apply_poweruser" {
  role       = aws_iam_role.pipeline_apply.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

data "aws_iam_policy_document" "pipeline_apply_iam" {
  statement {
    sid = "ManageWorkloadRoles"
    actions = [
      "iam:CreateRole",
      "iam:DeleteRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:PutRolePolicy",
      "iam:DeleteRolePolicy",
      "iam:AttachRolePolicy",
      "iam:DetachRolePolicy",
      "iam:TagRole",
      "iam:UntagRole",
    ]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.name_prefix}-*"]
  }

  statement {
    sid       = "PassWorkloadRoles"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.name_prefix}-*"]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["lambda.amazonaws.com", "config.amazonaws.com"]
    }
  }

  # Terraform reads every IAM object it manages, including the pipeline's own, on each run.
  statement {
    sid = "ReadIam"
    actions = [
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:ListRolePolicies",
      "iam:ListAttachedRolePolicies",
      "iam:ListRoleTags",
      "iam:ListInstanceProfilesForRole",
      "iam:GetOpenIDConnectProvider",
      "iam:ListOpenIDConnectProviderTags",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "pipeline_apply_iam" {
  name   = "manage-workload-iam"
  role   = aws_iam_role.pipeline_apply.id
  policy = data.aws_iam_policy_document.pipeline_apply_iam.json
}

output "pipeline_plan_role_arn" {
  value       = aws_iam_role.pipeline_plan.arn
  description = "Role that pull request workflow runs assume to plan."
}

output "pipeline_apply_role_arn" {
  value       = aws_iam_role.pipeline_apply.arn
  description = "Role that the merge-to-main workflow run assumes to apply and upload evidence."
}
