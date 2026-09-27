#!/usr/bin/env bash
# Builds the evidence bundle for one pipeline run: the redacted plan, the policy verdict on
# that plan, a note of which policy files judged it, the apply log, and metadata that ties
# all of it to a commit and a workflow run. The bundle is a single tar.gz with a SHA-256
# file next to it. The pipeline then signs the bundle and uploads it to the evidence vault.
#
# Usage: scripts/build-evidence.sh PLAN_JSON OUT_DIR [APPLY_LOG]
#   PLAN_JSON  the plan with the alert email already removed
#   OUT_DIR    where the bundle and its .sha256 file are written
#   APPLY_LOG  optional, the output of terraform apply (already redacted)
set -euo pipefail

plan="${1:?usage: scripts/build-evidence.sh PLAN_JSON OUT_DIR [APPLY_LOG]}"
out="${2:?usage: scripts/build-evidence.sh PLAN_JSON OUT_DIR [APPLY_LOG]}"
apply_log="${3:-}"

cd "$(dirname "$0")/.."

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

# In the pipeline these come from GitHub. On a laptop they fall back to local values.
run_id="${GITHUB_RUN_ID:-local}"
commit="${GITHUB_SHA:-$(git rev-parse HEAD)}"
ref="${GITHUB_REF:-$(git symbolic-ref -q HEAD || echo detached)}"
repository="${GITHUB_REPOSITORY:-local}"
event="${GITHUB_EVENT_NAME:-local}"
workflow="${GITHUB_WORKFLOW:-local}"
run_url="local"
if [ -n "${GITHUB_RUN_ID:-}" ]; then
  run_url="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
bundle="$work/evidence"
mkdir -p "$bundle" "$out"

cp "$plan" "$bundle/plan.json"

# The verdict. The gate has already passed by the time the pipeline builds a bundle, but
# the exit code is recorded so the bundle states what it found and does not only assume it.
set +e
conftest test "$bundle/plan.json" --policy policies --all-namespaces --no-color --output json \
  > "$bundle/policy-results.json"
gate_exit=$?
set -e

# Which policy files judged the plan, so a reader can tell whether the rules changed later.
sha256 $(find policies -name '*.rego' | sort) > "$bundle/policies.sha256"

if [ -n "$apply_log" ] && [ -f "$apply_log" ]; then
  cp "$apply_log" "$bundle/apply.log"
fi

jq -n \
  --arg run_id "$run_id" \
  --arg run_url "$run_url" \
  --arg commit "$commit" \
  --arg ref "$ref" \
  --arg repository "$repository" \
  --arg event "$event" \
  --arg workflow "$workflow" \
  --arg built_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg terraform "$(terraform version 2>/dev/null | head -1 || true)" \
  --arg conftest "$(conftest --version 2>/dev/null | head -1 || true)" \
  --arg plan_sha256 "$(sha256 "$bundle/plan.json" | cut -d' ' -f1)" \
  --argjson gate_exit "$gate_exit" \
  --argjson resources "$(jq '.resource_changes | length' "$bundle/plan.json")" \
  '{
    schema: "acme-health-evidence/v1",
    framework: "hipaa",
    run_id: $run_id,
    run_url: $run_url,
    commit: $commit,
    ref: $ref,
    repository: $repository,
    event: $event,
    workflow: $workflow,
    built_at: $built_at,
    tools: {terraform: $terraform, conftest: $conftest},
    plan: {sha256: $plan_sha256, resources: $resources},
    policy_gate_exit_code: $gate_exit
  }' > "$bundle/metadata.json"

name="evidence-${run_id}-${commit:0:12}"
tar -C "$work" -czf "$out/$name.tar.gz" evidence
(cd "$out" && sha256 "$name.tar.gz" > "$name.tar.gz.sha256")

echo "Built $out/$name.tar.gz"
cat "$out/$name.tar.gz.sha256"
