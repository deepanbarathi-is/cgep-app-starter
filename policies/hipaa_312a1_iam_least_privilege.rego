# METADATA
# title: HIPAA 164.312(a)(1) - Access control (least-privilege IAM policies)
# description: No IAM identity policy may allow a service-wide wildcard action such as s3:* or dynamodb:*, or every action with *. Grant only the specific actions the workload calls.
# custom:
#   control_id: 164.312(a)(1)
#   framework: hipaa
#   severity: high
#   gap: GAP-07
#   remediation: Replace the wildcard with the exact actions the workload needs, and scope the resource to the specific ARNs it touches.
package compliance.hipaa.iam_least_privilege

import rego.v1

identity_policy_types := {
	"aws_iam_role_policy",
	"aws_iam_policy",
	"aws_iam_user_policy",
	"aws_iam_group_policy",
}

# A wildcard action in an Allow statement.
deny contains msg if {
	some rc in policy_changes
	has_policy_text(rc)
	some stmt in statements(json.unmarshal(rc.change.after.policy))
	stmt.Effect == "Allow"
	some action in as_list(stmt.Action)
	is_wildcard(action)
	msg := sprintf(
		"[HIPAA 164.312(a)(1)] %s: statement %s allows the wildcard action %q (GAP-07). List the specific actions the workload calls instead.",
		[rc.address, sid(stmt), action],
	)
}

# Allow with NotAction grants everything except a short list, which is just as broad.
deny contains msg if {
	some rc in policy_changes
	has_policy_text(rc)
	some stmt in statements(json.unmarshal(rc.change.after.policy))
	stmt.Effect == "Allow"
	stmt.NotAction
	msg := sprintf(
		"[HIPAA 164.312(a)(1)] %s: statement %s uses Allow with NotAction, which grants almost every action (GAP-07). List the specific actions instead.",
		[rc.address, sid(stmt)],
	)
}

# If the policy text is not known until apply, it cannot be inspected, so it is denied
# rather than assumed safe. Build the policy from values that already exist, or apply in two steps.
deny contains msg if {
	some rc in policy_changes
	not has_policy_text(rc)
	msg := sprintf(
		"[HIPAA 164.312(a)(1)] %s: the policy text is not known at plan time, so it cannot be checked for wildcard actions (GAP-07).",
		[rc.address],
	)
}

policy_changes contains rc if {
	some rc in input.resource_changes
	rc.type in identity_policy_types
	not deleting(rc)
}

deleting(rc) if rc.change.actions == ["delete"]

has_policy_text(rc) if is_string(rc.change.after.policy)

# Statement can be one object or a list of them.
statements(doc) := doc.Statement if is_array(doc.Statement)

statements(doc) := [doc.Statement] if is_object(doc.Statement)

as_list(x) := x if is_array(x)

as_list(x) := [x] if is_string(x)

# "*" is every action. "service:*" is every action of one service.
is_wildcard("*")

is_wildcard(action) if endswith(action, ":*")

sid(stmt) := stmt.Sid

sid(stmt) := "(no Sid)" if not stmt.Sid
