# METADATA
# title: HIPAA 164.312(e)(1) - Transmission security (S3 refuses non-TLS requests)
# description: Every aws_s3_bucket must have a bucket policy with a Deny statement for requests where aws:SecureTransport is false, covering the bucket and its objects, so PHI is never sent over an unencrypted connection.
# custom:
#   control_id: 164.312(e)(1)
#   framework: hipaa
#   severity: high
#   gap: GAP-03
#   remediation: Add an aws_s3_bucket_policy with a Deny statement, Principal "*", Action "s3:*", covering the bucket ARN and its /* objects, with the condition Bool aws:SecureTransport = "false".
package compliance.hipaa.s3_tls_only

import rego.v1

deny contains msg if {
	some rc in bucket_changes
	not protected(rc)
	msg := sprintf(
		"[HIPAA 164.312(e)(1)] %s: bucket has no policy that denies requests not using TLS (GAP-03). Add a Deny statement on aws:SecureTransport = false covering the bucket and its objects.",
		[rc.address],
	)
}

bucket_changes contains rc if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	not deleting(rc)
}

deleting(rc) if rc.change.actions == ["delete"]

# A bucket is protected if its policy text shows a TLS deny. Only when that text is not
# available yet does the check fall back to following the code.
protected(rc) if protected_by_value(rc)

protected(rc) if {
	not has_readable_policy(rc)
	protected_by_reference(rc)
}

# True when a policy for this existing bucket is in the plan with its text known. If it
# is there and does not deny non-TLS requests, the code cannot rescue it.
has_readable_policy(rc) if {
	some pol in input.resource_changes
	pol.type == "aws_s3_bucket_policy"
	not deleting(pol)
	pol.change.after.bucket == rc.change.after.id
	is_string(pol.change.after.policy)
}

# Check 1: the bucket already exists, so its id is known and a policy naming that id can
# be read as text.
protected_by_value(rc) if {
	some pol in input.resource_changes
	pol.type == "aws_s3_bucket_policy"
	not deleting(pol)
	pol.change.after.bucket == rc.change.after.id
	is_string(pol.change.after.policy)
	some stmt in statements(json.unmarshal(pol.change.after.policy))
	tls_deny_json(stmt, rc.change.after.id)
}

# Check 2: the bucket or its policy text is not known until apply. Follow the code
# instead: a policy resource that points at this bucket and is built from a policy
# document data source, whose statements Terraform does show in the plan.
protected_by_reference(rc) if {
	some res in input.configuration.root_module.resources
	res.type == "aws_s3_bucket_policy"
	rc.address in res.expressions.bucket.references
	some ref in res.expressions.policy.references
	startswith(ref, "data.aws_iam_policy_document.")
	endswith(ref, ".json")
	some stmt in doc_statements(trim_suffix(ref, ".json"))
	tls_deny_doc(stmt)
}

# Statement can be one object or a list of them.
statements(doc) := doc.Statement if is_array(doc.Statement)

statements(doc) := [doc.Statement] if is_object(doc.Statement)

as_list(x) := x if is_array(x)

as_list(x) := [x] if is_string(x)

tls_deny_json(stmt, id) if {
	stmt.Effect == "Deny"
	everyone(stmt.Principal)
	some action in as_list(stmt.Action)
	action in {"s3:*", "*"}
	stmt.Condition.Bool["aws:SecureTransport"] in {"false", false}
	some resource in as_list(stmt.Resource)
	resource == sprintf("arn:aws:s3:::%s/*", [id])
}

everyone("*")

everyone(principal) if principal.AWS == "*"

# Statements of a policy document data source, from the plan's changes (documents read
# during apply) or from its prior state (documents already read).
doc_statements(address) := array.concat(from_changes, from_state) if {
	from_changes := [s |
		some rc in input.resource_changes
		rc.address == address
		some s in rc.change.after.statement
	]
	from_state := [s |
		some r in input.prior_state.values.root_module.resources
		r.address == address
		some s in r.values.statement
	]
}

tls_deny_doc(stmt) if {
	stmt.effect == "Deny"
	some principal in stmt.principals
	"*" in principal.identifiers
	some action in stmt.actions
	action in {"s3:*", "*"}
	some cond in stmt.condition
	cond.test == "Bool"
	cond.variable == "aws:SecureTransport"
	"false" in cond.values
	covers_objects(stmt)
}

# A resource that is null is not known until apply, so it is accepted here.
covers_objects(stmt) if {
	some resource in stmt.resources
	resource == null
}

covers_objects(stmt) if {
	some resource in stmt.resources
	is_string(resource)
	endswith(resource, "/*")
}
