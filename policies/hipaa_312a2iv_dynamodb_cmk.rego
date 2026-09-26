# METADATA
# title: HIPAA 164.312(a)(2)(iv) - Encryption at rest (DynamoDB customer-managed key)
# description: Every aws_dynamodb_table must turn on server_side_encryption with a customer-managed KMS key, so the key is under our custody and its use is auditable.
# custom:
#   control_id: 164.312(a)(2)(iv)
#   framework: hipaa
#   severity: high
#   gap: GAP-02
#   remediation: Add a server_side_encryption block with enabled = true and kms_key_arn pointing at a customer-managed key.
package compliance.hipaa.dynamodb_cmk

import rego.v1

deny contains msg if {
	some rc in table_changes
	not encrypted_with_cmk(rc)
	msg := sprintf(
		"[HIPAA 164.312(a)(2)(iv)] %s: DynamoDB table is not encrypted with a customer-managed KMS key (GAP-02). Add server_side_encryption with enabled = true and a kms_key_arn.",
		[rc.address],
	)
}

# Every DynamoDB table in the plan that is not being deleted.
table_changes contains rc if {
	some rc in input.resource_changes
	rc.type == "aws_dynamodb_table"
	not deleting(rc)
}

deleting(rc) if rc.change.actions == ["delete"]

# Encryption must be on and name a key. An empty block list, or enabled = true with no
# key (which means the AWS-managed key), leaves this undefined and the table is denied.
encrypted_with_cmk(rc) if {
	some sse in rc.change.after.server_side_encryption
	sse.enabled == true
	key_is_set(rc, sse)
}

key_is_set(_, sse) if {
	is_string(sse.kms_key_arn)
	sse.kms_key_arn != ""
}

# A key created in the same plan has no ARN yet. Terraform marks it unknown, and it
# will be a real key by apply time, so that counts as set.
key_is_set(rc, _) if rc.change.after_unknown.server_side_encryption[0].kms_key_arn == true
