# Policies

These are the Rego policies that check my Terraform plan before anything is applied. Each policy reads the plan JSON and adds a message to its `deny` set for every violation it finds. An empty set means the plan passes. Conftest runs them as the gate in the pipeline, and a single message makes the run exit with a non-zero code.

HIPAA Security Rule is my primary framework, so every policy cites a HIPAA control ID in its `# METADATA` block and in its deny message. A developer who reads a failed run sees the control, the gap, the resource address, and what to change.

## The five policies

| File | Gap | HIPAA control | What it denies | Tests |
|---|---|---|---|---|
| `hipaa_312e1_lambda_vpc.rego` | GAP-05 | 164.312(e)(1) | A Lambda function with no `vpc_config` | 5 |
| `hipaa_312a2iv_dynamodb_cmk.rego` | GAP-02 | 164.312(a)(2)(iv) | A DynamoDB table not encrypted with a customer-managed key | 8 |
| `hipaa_312a2iv_s3_kms.rego` | GAP-01 | 164.312(a)(2)(iv) | An S3 bucket whose default encryption is not SSE-KMS with a customer-managed key, or that has none | 10 |
| `hipaa_312a1_iam_least_privilege.rego` | GAP-07 | 164.312(a)(1) | An identity policy that allows `*` or a service-wide wildcard like `s3:*` | 12 |
| `hipaa_312e1_s3_tls_only.rego` | GAP-03 | 164.312(e)(1) | A bucket with no policy that denies requests not using TLS | 18 |

The tests live in `tests/`, one file per policy, with passing and failing cases for each. There are 53 in total.

## How the policies read the plan

They read `resource_changes`, the flat list Terraform gives for every resource in the plan, including the ones inside modules. My S3 hardening lives in the `compliant-storage` module, so a policy that only looked at root-module resources would find no encryption next to the bucket and report a violation on a bucket that is fine.

Resources that the plan is deleting are ignored, since they are on their way out.

## What "fail closed" means here

A policy denies when the evidence it needs is missing, not only when it finds something bad. A Lambda with no `vpc_config` block is denied because the block is not there to check. A bucket with no encryption configuration is denied because no configuration matches it.

Some values are not known until apply, for example the ARN of a key created in the same plan. Each policy decides what to do about that, and I chose per policy:

- The GAP-01 and GAP-02 policies accept an unknown key ARN, because the block exists and the key will be real at apply. They still deny a block that names no key at all.
- The GAP-03 policy reads the bucket policy text when it can. When the bucket or its text is not known yet, it follows the code instead: bucket, then policy, then the policy document that holds the Deny statement. It never lets that fallback approve a policy it could read and found wrong.
- The GAP-07 policy denies an identity policy whose text is not known, because it cannot check what it cannot read.

## Running them

From the repo root:

```
opa fmt --list policies
opa check policies --strict
opa test policies -v
```

To check a real plan:

```
cd terraform
terraform plan -out=tfplan
terraform show -json tfplan > ../plan.json
cd ..
conftest test plan.json --policy policies --all-namespaces
```

`--all-namespaces` runs every policy at once, which is how the pipeline calls them. To run one, use `--namespace compliance.hipaa.s3_kms`, for example.

## Break tests

The unit tests in `tests/` feed each policy hand-built input. `test/policy-breaks.sh` tests the whole gate against a plan shaped like a real one. It takes a saved plan that passes, breaks it in one specific way per case with `jq`, and checks that Conftest rejects each broken plan and names the right gap and resource. It also checks that the untouched plan still passes, so a gate that rejected everything could not get through.

```
test/policy-breaks.sh
```

There are seven cases: a Lambda outside the VPC, a DynamoDB table on the default key, an S3 bucket on SSE-S3, an S3 bucket with no encryption configuration, a wildcard IAM action, a TLS condition turned off, and a TLS-deny policy removed from the code. The plan it uses is `test/fixtures/plan-baseline.json`. It comes from my real baseline plan, trimmed to the six resource types the policies read, with my AWS account ID replaced by `111122223333`, so it runs anywhere with `opa` and `conftest` and needs no AWS credentials.

## What they do not cover

- They only see what goes through Terraform. A bucket someone creates by hand in the console never appears in a plan, so these policies cannot stop it. The AWS Config rules in `terraform/monitoring.tf` are the detective control for that case.
- The GAP-01 policy cannot match a bucket that is being created to its encryption configuration by name, because the name does not exist yet. It checks that each new bucket has its own new encryption configuration in the same plan, which proves the counts line up but not which one belongs to which.
- The GAP-07 policy checks action wildcards only. It does not judge whether a resource scope is too wide, and it skips AWS-managed policies such as `AWSLambdaBasicExecutionRole`. On a plan built from an empty state it denies the role policies, because their text is not known yet. That only matters for a first-ever apply, and the pipeline runs against existing state.
- The GAP-03 fallback that follows the code looks at policies in the root module. A bucket policy inside a module is still checked when its text is known.
- GAP-04, GAP-06, and GAP-08 have no Rego policy. GAP-04 is covered by Terraform and a Config rule, and GAP-06 and GAP-08 are closed only in part, which `DESIGN.md` explains.
