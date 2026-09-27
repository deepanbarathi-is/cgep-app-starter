#!/usr/bin/env bash
# Proves the detection chain fires on a real change, not just in the pipeline: break a
# control by hand through the AWS CLI (no Terraform involved), watch AWS Config notice
# and go NON_COMPLIANT, confirm the alert reaches the SNS topic, then put it back and
# confirm Config clears.
#
# The gap: S3 versioning on the uploads bucket (GAP-04, HIPAA 164.308(a)(7)), the exact
# example named in DESIGN.md's testing strategy. Versioning is suspended, not deleted, so
# it reverses cleanly with one more API call, and nothing about the running app depends on
# it mid-request.
#
# This script pauses for you to read each step and check your email; it does not run
# unattended. Run it from the repo root.
set -euo pipefail

BUCKET="acme-health-intake-uploads-5c657426"
RULE="acme-health-intake-s3-bucket-versioning-enabled"
REGION="us-east-1"
TIMEOUT_SECONDS=300
POLL_SECONDS=15

pause() {
  echo
  read -r -p "$1 Press Enter to continue. " _
}

compliance() {
  aws configservice describe-compliance-by-config-rule \
    --config-rule-names "$RULE" --region "$REGION" \
    --query 'ComplianceByConfigRules[0].Compliance.ComplianceType' --output text
}

wait_for() {
  local want="$1" elapsed=0
  echo "Waiting for Config to report $want on $RULE (checking every ${POLL_SECONDS}s, up to ${TIMEOUT_SECONDS}s)..."
  while true; do
    aws configservice start-config-rules-evaluation --config-rule-names "$RULE" --region "$REGION" >/dev/null 2>&1 || true
    local now
    now="$(compliance)"
    echo "  $(date -u +%H:%M:%S)  $RULE is $now"
    if [ "$now" = "$want" ]; then
      return 0
    fi
    elapsed=$((elapsed + POLL_SECONDS))
    if [ "$elapsed" -ge "$TIMEOUT_SECONDS" ]; then
      echo "Gave up after ${TIMEOUT_SECONDS}s still waiting for $want." >&2
      return 1
    fi
    sleep "$POLL_SECONDS"
  done
}

echo "Bucket:        $BUCKET"
echo "Config rule:   $RULE"
echo "Starting versioning status: $(aws s3api get-bucket-versioning --bucket "$BUCKET" --query Status --output text)"
echo "Starting compliance:        $(compliance)"

pause "About to suspend versioning on $BUCKET. This is reversible with one command."

aws s3api put-bucket-versioning --bucket "$BUCKET" --versioning-configuration Status=Suspended
echo "Versioning suspended at $(date -u +%Y-%m-%dT%H:%M:%SZ)"

wait_for "NON_COMPLIANT"
echo
echo "Config caught it. Check your email now for the compliance alert (it may take a minute to arrive), then come back here."
pause "Confirmed you saw it, or given it a fair wait?"

aws s3api put-bucket-versioning --bucket "$BUCKET" --versioning-configuration Status=Enabled
echo "Versioning re-enabled at $(date -u +%Y-%m-%dT%H:%M:%SZ)"

wait_for "COMPLIANT"
echo
echo "Detection chain verified: the break was caught, and the fix was confirmed, both by AWS Config, not by assumption."
