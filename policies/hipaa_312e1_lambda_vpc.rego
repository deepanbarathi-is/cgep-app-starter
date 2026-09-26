# METADATA
# title: HIPAA 164.312(e)(1) - Transmission security (Lambda inside the VPC)
# description: Every aws_lambda_function must be attached to the VPC through a vpc_config block, so PHI traffic stays on private paths.
# custom:
#   control_id: 164.312(e)(1)
#   framework: hipaa
#   severity: high
#   gap: GAP-05
#   remediation: Add a vpc_config block with private subnet_ids and a security_group_ids list to the function.
package compliance.hipaa.lambda_vpc

import rego.v1

deny contains msg if {
	some rc in lambda_changes
	not in_vpc(rc)
	msg := sprintf(
		"[HIPAA 164.312(e)(1)] %s: Lambda function has no vpc_config, so it runs outside the VPC (GAP-05). Add a vpc_config block with private subnets and a security group.",
		[rc.address],
	)
}

# Every Lambda function in the plan that is not being deleted.
lambda_changes contains rc if {
	some rc in input.resource_changes
	rc.type == "aws_lambda_function"
	not deleting(rc)
}

deleting(rc) if rc.change.actions == ["delete"]

# A missing or empty vpc_config leaves this undefined, so the function is denied.
in_vpc(rc) if count(rc.change.after.vpc_config) > 0
