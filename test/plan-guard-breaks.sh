#!/usr/bin/env bash
# Integration test for the "not a real plan" guard in the pipeline. That guard is one line:
#
#   jq -e '(.resource_changes | type == "array") and (.resource_changes | length > 0)' plan.json
#
# This proves that exact line rejects an empty or malformed plan, and still accepts a real
# one, so the policy gate can never pass just because it had nothing to look at.
#
# Usage: test/plan-guard-breaks.sh [PLAN_JSON]
set -uo pipefail

cd "$(dirname "$0")/.."
plan="${1:-test/fixtures/plan-baseline.json}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

failures=0
guard() { jq -e '(.resource_changes | type == "array") and (.resource_changes | length > 0)' "$1" >/dev/null 2>&1; }

if guard "$plan"; then
  echo "PASS  the real plan is accepted"
else
  echo "FAIL  the real plan was rejected, so the cases below prove nothing"
  exit 1
fi

# expect_rejected NAME JSON_TEXT
expect_rejected() {
  local name="$1" json="$2" f="$work/case.json"
  printf '%s' "$json" > "$f"
  if guard "$f"; then
    echo "FAIL  $name: the guard accepted it"
    failures=$((failures + 1))
  else
    echo "PASS  $name is rejected"
  fi
}

expect_rejected "an empty resource_changes list" '{"resource_changes": []}'
expect_rejected "no resource_changes key at all" '{}'
expect_rejected "resource_changes is an object, not a list" '{"resource_changes": {}}'
expect_rejected "resource_changes is null" '{"resource_changes": null}'
expect_rejected "a file that is not JSON" 'not a plan'

echo
if [ "$failures" -eq 0 ]; then
  echo "All plan-guard break tests passed."
else
  echo "$failures plan-guard break test(s) failed."
  exit 1
fi
