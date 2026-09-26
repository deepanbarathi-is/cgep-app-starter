#!/usr/bin/env bash
# Integration test for the policy gate. It takes a saved Terraform plan that passes,
# breaks it in one specific way per case with jq, and checks that Conftest rejects
# each broken plan with the expected gap and resource. It also checks that the
# untouched plan still passes, so a gate that rejects everything cannot pass this test.
#
# Usage: test/policy-breaks.sh [plan.json]   (default: test/fixtures/plan-baseline.json)
set -uo pipefail

cd "$(dirname "$0")/.."
PLAN="${1:-test/fixtures/plan-baseline.json}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

failures=0

run_gate() {
  conftest test "$1" --policy policies --all-namespaces --no-color 2>&1
}

# Case 0: the untouched plan must pass.
if out="$(run_gate "$PLAN")"; then
  echo "PASS  baseline plan is accepted"
else
  echo "FAIL  baseline plan was rejected, so the break tests below prove nothing"
  echo "$out"
  exit 1
fi

# expect_block NAME GAP ADDRESS JQ_FILTER
# Applies JQ_FILTER to the baseline, then requires a non-zero exit and a message that
# names both the gap and the resource address.
expect_block() {
  local name="$1" gap="$2" address="$3" filter="$4"
  local broken="$WORK/broken.json"
  if ! jq "$filter" "$PLAN" > "$broken"; then
    echo "FAIL  $name: the jq filter did not apply"
    failures=$((failures + 1))
    return
  fi
  local out
  if out="$(run_gate "$broken")"; then
    echo "FAIL  $name: the broken plan was accepted"
    failures=$((failures + 1))
  elif grep -q "$gap" <<<"$out" && grep -q "$address" <<<"$out"; then
    echo "PASS  $name is blocked ($gap, $address)"
  else
    echo "FAIL  $name: rejected, but not for $gap on $address"
    echo "$out"
    failures=$((failures + 1))
  fi
}

expect_block "Lambda outside the VPC" "GAP-05" "aws_lambda_function.intake" \
  '(.resource_changes[] | select(.type=="aws_lambda_function") | .change.after.vpc_config) = []'

expect_block "DynamoDB on the default key" "GAP-02" "aws_dynamodb_table.intake" \
  '(.resource_changes[] | select(.type=="aws_dynamodb_table") | .change.after.server_side_encryption) = []'

expect_block "S3 bucket on SSE-S3" "GAP-01" "module.uploads_storage.aws_s3_bucket_server_side_encryption_configuration.this" \
  '(.resource_changes[] | select(.address=="module.uploads_storage.aws_s3_bucket_server_side_encryption_configuration.this") | .change.after.rule[0].apply_server_side_encryption_by_default[0]) = {"sse_algorithm":"AES256","kms_master_key_id":null}'

expect_block "S3 bucket with no encryption configuration" "GAP-01" "aws_s3_bucket.evidence" \
  'del(.resource_changes[] | select(.address=="module.evidence_storage.aws_s3_bucket_server_side_encryption_configuration.this"))'

expect_block "Wildcard IAM action" "GAP-07" "aws_iam_role_policy.lambda_inline" \
  '(.resource_changes[] | select(.address=="aws_iam_role_policy.lambda_inline") | .change.after.policy) |= sub("s3:PutObject";"s3:*")'

expect_block "TLS condition turned off" "GAP-03" "aws_s3_bucket.uploads" \
  '(.resource_changes[] | select(.address=="aws_s3_bucket_policy.uploads_tls_only") | .change.after.policy) |= sub("\"false\"";"\"true\"")'

expect_block "TLS-deny policy removed from the code" "GAP-03" "aws_s3_bucket.config" \
  '(.resource_changes[] | select(.address=="aws_s3_bucket_policy.config_tls_only") | .change) |= (.actions=["delete"] | .after=null) | del(.configuration.root_module.resources[] | select(.address=="aws_s3_bucket_policy.config_tls_only"))'

echo
if [ "$failures" -eq 0 ]; then
  echo "All break tests passed."
else
  echo "$failures break test(s) failed."
  exit 1
fi
