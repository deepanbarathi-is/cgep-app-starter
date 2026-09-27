#!/usr/bin/env bash
# Verifies a signed evidence bundle: integrity, authenticity and timestamp, and preservation.
#
# Usage:
#   scripts/verify-evidence.sh --dir DIR             a folder holding the bundle, its .sha256,
#                                                    its .sig.bundle and receipt.json
#   scripts/verify-evidence.sh --run RUN_ID [--vault BUCKET]
#                                                    download that run from the evidence vault
#                                                    first (needs AWS access to the vault)
#
# Options:
#   --identity URL   the workflow identity the signature must come from
#                    (default: this repository's grc-gate workflow on main)
#   --live           also ask the vault for the Object Lock retention (needs AWS access;
#                    always on with --run)
#
# Without AWS access the first two checks are fully verified and the retention is reported
# from the receipt, not verified. cosign needs the internet to fetch Sigstore's trust root.
set -euo pipefail

identity="https://github.com/deepanbarathi-is/cgep-app-starter/.github/workflows/grc-gate.yml@refs/heads/main"
issuer="https://token.actions.githubusercontent.com"
vault="${EVIDENCE_VAULT:-acme-health-intake-evidence-5c657426}"
dir=""
run_id=""
live=0

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) dir="$2"; shift 2 ;;
    --run) run_id="$2"; live=1; shift 2 ;;
    --vault) vault="$2"; shift 2 ;;
    --identity) identity="$2"; shift 2 ;;
    --live) live=1; shift ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

for tool in cosign jq tar; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Need $tool" >&2; exit 2; }
done
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

work=""
if [ -n "$run_id" ]; then
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  aws s3 cp "s3://$vault/runs/$run_id/" "$work/" --recursive --quiet
  dir="$work"
fi
[ -n "$dir" ] || { echo "Give --dir DIR or --run RUN_ID" >&2; exit 2; }

bundle="$(ls "$dir"/evidence-*.tar.gz | head -1)"
receipt="$dir/receipt.json"
for f in "$bundle" "$bundle.sha256" "$bundle.sig.bundle" "$receipt"; do
  [ -f "$f" ] || { echo "Missing $f" >&2; exit 2; }
done

failed=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; failed=1; }

# 1. Integrity: the bundle must hash to what its .sha256 file and the receipt both say.
actual="$(sha256 "$bundle" | cut -d' ' -f1)"
expected_file="$(cut -d' ' -f1 "$bundle.sha256")"
expected_receipt="$(jq -r '.sha256' "$receipt")"
if [ "$actual" = "$expected_file" ] && [ "$actual" = "$expected_receipt" ]; then
  pass "integrity: SHA-256 $actual matches the .sha256 file and the receipt"
else
  fail "integrity: SHA-256 mismatch (actual $actual, file $expected_file, receipt $expected_receipt)"
fi

# 2. Authenticity and timestamp: the signature must come from the expected workflow, and
# the bundle carries Rekor's public timestamp, which cosign checks as part of this.
if cosign verify-blob --bundle "$bundle.sig.bundle" \
     --certificate-identity "$identity" \
     --certificate-oidc-issuer "$issuer" "$bundle" >/dev/null 2>&1; then
  pass "authenticity: signed by $identity (Sigstore, with Rekor timestamp)"
else
  fail "authenticity: signature does not verify for identity $identity"
fi

# The receipt and the bundle must describe the same commit and run.
meta="$(tar -xzOf "$bundle" evidence/metadata.json)"
if [ "$(jq -r '.commit' <<<"$meta")" = "$(jq -r '.commit' "$receipt")" ] \
   && [ "$(jq -r '.run_id' <<<"$meta")" = "$(jq -r '.run_id' "$receipt")" ]; then
  pass "consistency: bundle metadata and receipt name the same commit and run"
else
  fail "consistency: bundle metadata and receipt disagree on commit or run"
fi

# 3. Preservation: Object Lock must still be holding the object.
now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
recorded_until="$(jq -r '.object_lock.retain_until' "$receipt")"
recorded_mode="$(jq -r '.object_lock.mode' "$receipt")"
if [ "$live" -eq 1 ]; then
  live_json="$(aws s3api get-object-retention \
    --bucket "$(jq -r '.vault' "$receipt")" \
    --key "$(jq -r '.bundle_key' "$receipt")" \
    --version-id "$(jq -r '.version_id' "$receipt")" --output json)"
  live_until="$(jq -r '.Retention.RetainUntilDate' <<<"$live_json")"
  live_mode="$(jq -r '.Retention.Mode' <<<"$live_json")"
  if [[ "$live_until" > "$now" ]]; then
    pass "preservation: the vault holds it in $live_mode mode until $live_until (checked live)"
  else
    fail "preservation: retention ended at $live_until"
  fi
else
  if [[ "$recorded_until" > "$now" ]]; then
    echo "NOTE  preservation: the receipt records $recorded_mode until $recorded_until (not checked live; add --live with AWS access)"
  else
    echo "NOTE  preservation: the receipt records $recorded_mode until $recorded_until, which has passed (not checked live)"
  fi
fi

echo
if [ "$failed" -eq 0 ]; then
  echo "CHAIN INTACT for run $(jq -r '.run_id' "$receipt")"
else
  echo "CHAIN BROKEN"
  exit 1
fi
