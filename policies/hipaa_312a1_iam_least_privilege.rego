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

# If the policy text is not known until apply, Terraform still shows the statements of the
# policy document it is built from. Follow the code from the policy to that document and
# check its statements instead. The document is the same one that produces the text.
deny contains msg if {
	some rc in policy_changes
	not has_policy_text(rc)
	some stmt in linked_statements(rc)
	stmt.effect != "Deny"
	some action in stmt.actions
	is_wildcard(action)
	msg := sprintf(
		"[HIPAA 164.312(a)(1)] %s: statement %s allows the wildcard action %q (GAP-07). List the specific actions the workload calls instead.",
		[rc.address, doc_sid(stmt), action],
	)
}

deny contains msg if {
	some rc in policy_changes
	not has_policy_text(rc)
	some stmt in linked_statements(rc)
	stmt.effect != "Deny"
	count(stmt.not_actions) > 0
	msg := sprintf(
		"[HIPAA 164.312(a)(1)] %s: statement %s uses Allow with not_actions, which grants almost every action (GAP-07). List the specific actions instead.",
		[rc.address, doc_sid(stmt)],
	)
}

# With no readable text and no document to follow, the policy cannot be checked, so it is
# denied rather than assumed safe.
deny contains msg if {
	some rc in policy_changes
	not has_policy_text(rc)
	not has_linked_statements(rc)
	msg := sprintf(
		"[HIPAA 164.312(a)(1)] %s: the policy text is not known at plan time and no policy document could be found to check instead, so it cannot be checked for wildcard actions (GAP-07).",
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

# The statements of the policy document that an unreadable policy is built from, found
# through the reference in the code (a policy = data.aws_iam_policy_document.NAME.json line).
linked_statements(rc) := array.concat(from_changes, from_state) if {
	some res in input.configuration.root_module.resources
	res.address == rc.address
	some ref in res.expressions.policy.references
	startswith(ref, "data.aws_iam_policy_document.")
	endswith(ref, ".json")
	doc := trim_suffix(ref, ".json")
	from_changes := [d |
		some c in input.resource_changes
		c.address == doc
		some d in c.change.after.statement
	]
	from_state := [d |
		some r in input.prior_state.values.root_module.resources
		r.address == doc
		some d in r.values.statement
	]
}

doc_sid(stmt) := stmt.sid if stmt.sid

doc_sid(stmt) := "(no sid)" if not stmt.sid

has_linked_statements(rc) if count(linked_statements(rc)) > 0
