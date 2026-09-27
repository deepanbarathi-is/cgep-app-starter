#!/usr/bin/env bash
# Uploads a signed evidence bundle to the evidence vault and writes a receipt.
#
# The receipt records what the vault said back: the object version, S3's own SHA-256 of the
# upload, and the Object Lock mode and retain-until date that are in force. A reviewer who
# cannot reach the vault can still read the receipt and check the signature and the SHA
# against the copy kept in this repository.
#
# Usage: scripts/upload-evidence.sh BUNDLE VAULT_BUCKET RECEIPT_OUT
#   BUNDLE       the .tar.gz; BUNDLE.sha256 and BUNDLE.sig.bundle must sit next to it
#   VAULT_BUCKET name of the evidence vault bucket
#   RECEIPT_OUT  where to write receipt.json locally (it is uploaded as well)
set -euo pipefail

bundle="${1:?usage: scripts/upload-evidence.sh BUNDLE VAULT_BUCKET RECEIPT_OUT}"
vault="${2:?usage: scripts/upload-evidence.sh BUNDLE VAULT_BUCKET RECEIPT_OUT}"
receipt_out="${3:?usage: scripts/upload-evidence.sh BUNDLE VAULT_BUCKET RECEIPT_OUT}"

for f in "$bundle" "$bundle.sha256" "$bundle.sig.bundle"; do
  [ -f "$f" ] || { echo "Missing $f" >&2; exit 1; }
done

run_id="${GITHUB_RUN_ID:-local}"
commit="${GITHUB_SHA:-$(git rev-parse HEAD)}"
run_url="local"
if [ -n "${GITHUB_RUN_ID:-}" ]; then
  run_url="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
fi

name="$(basename "$bundle")"
prefix="runs/${run_id}"

# put_object FILE KEY prints the JSON that S3 returns. The SHA-256 checksum makes S3 verify
# the upload itself, so a corrupted transfer is refused instead of stored.
put_object() {
  aws s3api put-object --bucket "$vault" --key "$2" --body "$1" \
    --checksum-algorithm SHA256 --output json
}

bundle_result="$(put_object "$bundle" "$prefix/$name")"
put_object "$bundle.sha256" "$prefix/$name.sha256" > /dev/null
put_object "$bundle.sig.bundle" "$prefix/$name.sig.bundle" > /dev/null

version_id="$(jq -r '.VersionId' <<<"$bundle_result")"
s3_checksum="$(jq -r '.ChecksumSHA256' <<<"$bundle_result")"

# What is actually protecting the object, read back from the vault and not assumed.
retention="$(aws s3api get-object-retention --bucket "$vault" --key "$prefix/$name" \
  --version-id "$version_id" --output json)"

jq -n \
  --arg run_id "$run_id" \
  --arg run_url "$run_url" \
  --arg commit "$commit" \
  --arg vault "$vault" \
  --arg bundle_key "$prefix/$name" \
  --arg signature_key "$prefix/$name.sig.bundle" \
  --arg version_id "$version_id" \
  --arg sha256_hex "$(cut -d' ' -f1 "$bundle.sha256")" \
  --arg s3_checksum_sha256_b64 "$s3_checksum" \
  --arg uploaded_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson retention "$retention" \
  '{
    schema: "acme-health-receipt/v1",
    run_id: $run_id,
    run_url: $run_url,
    commit: $commit,
    vault: $vault,
    bundle_key: $bundle_key,
    signature_key: $signature_key,
    version_id: $version_id,
    sha256: $sha256_hex,
    s3_checksum_sha256_base64: $s3_checksum_sha256_b64,
    object_lock: {mode: $retention.Retention.Mode, retain_until: $retention.Retention.RetainUntilDate},
    uploaded_at: $uploaded_at
  }' > "$receipt_out"

put_object "$receipt_out" "$prefix/receipt.json" > /dev/null

echo "Uploaded s3://$vault/$prefix/$name (version $version_id)"
jq -c '{object_lock, sha256}' "$receipt_out"
