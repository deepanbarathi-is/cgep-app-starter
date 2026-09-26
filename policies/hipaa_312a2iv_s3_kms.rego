# METADATA
# title: HIPAA 164.312(a)(2)(iv) - Encryption at rest (S3 customer-managed key)
# description: Every aws_s3_bucket must have a default encryption configuration that uses SSE-KMS with a customer-managed key, so the key is under our custody and its use is auditable.
# custom:
#   control_id: 164.312(a)(2)(iv)
#   framework: hipaa
#   severity: high
#   gap: GAP-01
#   remediation: Add an aws_s3_bucket_server_side_encryption_configuration for the bucket with sse_algorithm = "aws:kms" and a kms_master_key_id for a customer-managed key (the compliant-storage module does this).
package compliance.hipaa.s3_kms

import rego.v1

# An encryption configuration that is present but not SSE-KMS with our own key.
deny contains msg if {
	some rc in config_changes
	not kms_with_cmk(rc)
	msg := sprintf(
		"[HIPAA 164.312(a)(2)(iv)] %s: bucket encryption is not SSE-KMS with a customer-managed key (GAP-01). Set sse_algorithm = \"aws:kms\" and a kms_master_key_id.",
		[rc.address],
	)
}

# An existing bucket with no encryption configuration, which leaves the AWS default SSE-S3.
deny contains msg if {
	some rc in known_buckets
	not has_config(rc.change.after.id)
	msg := sprintf(
		"[HIPAA 164.312(a)(2)(iv)] %s: bucket has no encryption configuration, so it uses the AWS default SSE-S3 (GAP-01). Add SSE-KMS with a customer-managed key.",
		[rc.address],
	)
}

# New buckets have no id yet, so they cannot be matched by name. Each one needs its own
# encryption configuration created in the same plan, so the counts must line up.
deny contains msg if {
	count(new_buckets) > count(new_bucket_configs)
	msg := sprintf(
		"[HIPAA 164.312(a)(2)(iv)] %d new bucket(s) (%s) but only %d new encryption configuration(s) (GAP-01). Each new bucket needs SSE-KMS with a customer-managed key.",
		[count(new_buckets), concat(", ", sort([rc.address | some rc in new_buckets])), count(new_bucket_configs)],
	)
}

bucket_changes contains rc if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	not deleting(rc)
}

config_changes contains rc if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_server_side_encryption_configuration"
	not deleting(rc)
}

deleting(rc) if rc.change.actions == ["delete"]

known_buckets contains rc if {
	some rc in bucket_changes
	has_id(rc)
}

# Anything without a known id counts as new, so a bucket with an odd shape is checked
# instead of skipped.
new_buckets contains rc if {
	some rc in bucket_changes
	not has_id(rc)
}

has_id(rc) if is_string(rc.change.after.id)

new_bucket_configs contains rc if {
	some rc in config_changes
	rc.change.after_unknown.bucket == true
}

has_config(bucket_id) if {
	some rc in config_changes
	rc.change.after.bucket == bucket_id
}

kms_with_cmk(rc) if {
	some rule in rc.change.after.rule
	some d in rule.apply_server_side_encryption_by_default
	d.sse_algorithm in {"aws:kms", "aws:kms:dsse"}
	key_is_set(rc, d)
}

key_is_set(_, d) if {
	is_string(d.kms_master_key_id)
	d.kms_master_key_id != ""
}

# A key created in the same plan has no ARN yet. Terraform marks it unknown, and it will
# be a real key by apply time, so that counts as set.
key_is_set(rc, _) if rc.change.after_unknown.rule[0].apply_server_side_encryption_by_default[0].kms_master_key_id == true
