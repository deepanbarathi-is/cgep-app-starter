#!/usr/bin/env bash
# Integration test for the evidence verifier. It takes the signed sample bundle kept in this
# repository, checks that the untouched copy verifies, then damages a copy in specific ways
# and checks that the verifier catches each one. A verifier that says "intact" to everything
# would pass a plain success test, so the failures are what this file proves.
#
# Usage: test/verify-evidence-breaks.sh [SAMPLE_DIR]
set -uo pipefail

cd "$(dirname "$0")/.."
sample="${1:-$(ls -d evidence-samples/run-* | head -1)}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

failures=0

fresh_copy() {
  rm -rf "$work/case"
  cp -R "$sample" "$work/case"
  bundle="$(ls "$work"/case/evidence-*.tar.gz | head -1)"
}

# expect_broken NAME EXPECTED_TEXT [extra verifier args]
expect_broken() {
  local name="$1" text="$2"
  shift 2
  local out
  if out="$(scripts/verify-evidence.sh --dir "$work/case" "$@" 2>&1)"; then
    echo "FAIL  $name: the verifier said intact"
    failures=$((failures + 1))
  elif grep -q "$text" <<<"$out"; then
    echo "PASS  $name is caught ($text)"
  else
    echo "FAIL  $name: rejected, but not with '$text'"
    echo "$out"
    failures=$((failures + 1))
  fi
}

fresh_copy
if scripts/verify-evidence.sh --dir "$work/case" >/dev/null 2>&1; then
  echo "PASS  the untouched sample verifies"
else
  echo "FAIL  the untouched sample does not verify, so the cases below prove nothing"
  exit 1
fi

fresh_copy
printf 'x' >> "$bundle"
expect_broken "A bundle changed by one byte" "integrity: SHA-256 mismatch"

fresh_copy
echo "0000000000000000000000000000000000000000000000000000000000000000  x" > "$bundle.sha256"
expect_broken "A .sha256 file that does not match" "integrity: SHA-256 mismatch"

fresh_copy
expect_broken "A signature from a different workflow identity" "authenticity: signature does not verify" \
  --identity "https://github.com/someone-else/repo/.github/workflows/grc-gate.yml@refs/heads/main"

fresh_copy
jq '.commit = "0000000000000000000000000000000000000000"' "$work/case/receipt.json" > "$work/r.json"
mv "$work/r.json" "$work/case/receipt.json"
expect_broken "A receipt for a different commit" "consistency: bundle metadata and receipt disagree"

fresh_copy
rm "$bundle.sig.bundle"
expect_broken "A missing signature file" "Missing"

echo
if [ "$failures" -eq 0 ]; then
  echo "All verifier break tests passed."
else
  echo "$failures verifier break test(s) failed."
  exit 1
fi
