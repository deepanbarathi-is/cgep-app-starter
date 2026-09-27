package compliance.hipaa.iam_least_privilege_test

import data.compliance.hipaa.iam_least_privilege
import rego.v1

# Builds a plan with one inline role policy from a list of statements.
plan_with(statements) := {"resource_changes": [{
	"address": "aws_iam_role_policy.p",
	"type": "aws_iam_role_policy",
	"change": {"actions": ["no-op"], "after": {"policy": json.marshal({"Version": "2012-10-17", "Statement": statements})}},
}]}

test_specific_actions_pass if {
	plan := plan_with([{"Sid": "Write", "Effect": "Allow", "Action": ["dynamodb:PutItem", "s3:PutObject"], "Resource": "arn:aws:s3:::b/*"}])
	count(iam_least_privilege.deny) == 0 with input as plan
}

test_service_wildcard_string_fails if {
	plan := plan_with([{"Sid": "Wide", "Effect": "Allow", "Action": "s3:*", "Resource": "*"}])
	some msg in iam_least_privilege.deny with input as plan
	contains(msg, "164.312(a)(1)")
	contains(msg, "s3:*")
	contains(msg, "aws_iam_role_policy.p")
}

test_service_wildcard_in_list_fails if {
	plan := plan_with([{"Sid": "Mixed", "Effect": "Allow", "Action": ["dynamodb:PutItem", "dynamodb:*"], "Resource": "*"}])
	some msg in iam_least_privilege.deny with input as plan
	contains(msg, "dynamodb:*")
}

test_full_wildcard_fails if {
	plan := plan_with([{"Sid": "Admin", "Effect": "Allow", "Action": "*", "Resource": "*"}])
	some msg in iam_least_privilege.deny with input as plan
	contains(msg, "Admin")
}

test_partial_wildcard_is_allowed if {
	plan := plan_with([{"Sid": "Read", "Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}])
	count(iam_least_privilege.deny) == 0 with input as plan
}

test_deny_statement_with_wildcard_is_allowed if {
	plan := plan_with([{"Sid": "Block", "Effect": "Deny", "Action": "s3:*", "Resource": "*"}])
	count(iam_least_privilege.deny) == 0 with input as plan
}

test_statement_as_single_object_is_checked if {
	plan := {"resource_changes": [{
		"address": "aws_iam_role_policy.single",
		"type": "aws_iam_role_policy",
		"change": {"actions": ["create"], "after": {"policy": json.marshal({"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}})}},
	}]}
	some msg in iam_least_privilege.deny with input as plan
	contains(msg, "aws_iam_role_policy.single")
	contains(msg, "no Sid")
}

test_allow_with_notaction_fails if {
	plan := plan_with([{"Sid": "AllButOne", "Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}])
	some msg in iam_least_privilege.deny with input as plan
	contains(msg, "NotAction")
}

test_unknown_policy_text_fails if {
	plan := {"resource_changes": [{
		"address": "aws_iam_role_policy.later",
		"type": "aws_iam_role_policy",
		"change": {"actions": ["create"], "after": {"name": "x"}, "after_unknown": {"policy": true}},
	}]}
	some msg in iam_least_privilege.deny with input as plan
	contains(msg, "aws_iam_role_policy.later")
	contains(msg, "not known at plan time")
}

# An unreadable policy whose text comes from a policy document that Terraform still shows.
unreadable_policy_with_document(actions_list, effect) := {
	"resource_changes": [
		{
			"address": "aws_iam_role_policy.later",
			"type": "aws_iam_role_policy",
			"change": {"actions": ["update"], "after": {"name": "x"}, "after_unknown": {"policy": true}},
		},
		{
			"address": "data.aws_iam_policy_document.doc",
			"mode": "data",
			"type": "aws_iam_policy_document",
			"change": {"actions": ["read"], "after": {"statement": [{"sid": "Doc", "effect": effect, "actions": actions_list, "not_actions": []}]}},
		},
	],
	"configuration": {"root_module": {"resources": [{
		"address": "aws_iam_role_policy.later",
		"type": "aws_iam_role_policy",
		"expressions": {"policy": {"references": ["data.aws_iam_policy_document.doc.json", "data.aws_iam_policy_document.doc"]}},
	}]}},
}

test_unreadable_policy_with_safe_document_passes if {
	plan := unreadable_policy_with_document(["s3:PutObject"], null)
	count(iam_least_privilege.deny) == 0 with input as plan
}

test_unreadable_policy_with_wildcard_document_fails if {
	plan := unreadable_policy_with_document(["s3:*"], null)
	some msg in iam_least_privilege.deny with input as plan
	contains(msg, "aws_iam_role_policy.later")
	contains(msg, "s3:*")
}

test_unreadable_policy_with_deny_wildcard_document_passes if {
	plan := unreadable_policy_with_document(["s3:*"], "Deny")
	count(iam_least_privilege.deny) == 0 with input as plan
}

test_unreadable_policy_with_document_from_prior_state_is_checked if {
	plan := {
		"resource_changes": [{
			"address": "aws_iam_role_policy.later",
			"type": "aws_iam_role_policy",
			"change": {"actions": ["update"], "after": {"name": "x"}, "after_unknown": {"policy": true}},
		}],
		"prior_state": {"values": {"root_module": {"resources": [{"address": "data.aws_iam_policy_document.doc", "values": {"statement": [{"sid": "Old", "effect": "Allow", "actions": ["*"], "not_actions": []}]}}]}}},
		"configuration": {"root_module": {"resources": [{
			"address": "aws_iam_role_policy.later",
			"type": "aws_iam_role_policy",
			"expressions": {"policy": {"references": ["data.aws_iam_policy_document.doc.json"]}},
		}]}},
	}
	some msg in iam_least_privilege.deny with input as plan
	contains(msg, "wildcard action")
}

test_deleted_policy_is_ignored if {
	plan := {"resource_changes": [{
		"address": "aws_iam_role_policy.old",
		"type": "aws_iam_role_policy",
		"change": {"actions": ["delete"], "after": null},
	}]}
	count(iam_least_privilege.deny) == 0 with input as plan
}

test_bucket_policy_deny_all_is_not_an_identity_policy if {
	plan := {"resource_changes": [{
		"address": "aws_s3_bucket_policy.tls",
		"type": "aws_s3_bucket_policy",
		"change": {"actions": ["no-op"], "after": {"policy": json.marshal({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:*", "Resource": "*"}]})}},
	}]}
	count(iam_least_privilege.deny) == 0 with input as plan
}

test_managed_policy_attachment_is_ignored if {
	plan := {"resource_changes": [{
		"address": "aws_iam_role_policy_attachment.a",
		"type": "aws_iam_role_policy_attachment",
		"change": {"actions": ["no-op"], "after": {"policy_arn": "arn:aws:iam::aws:policy/service-role/X"}},
	}]}
	count(iam_least_privilege.deny) == 0 with input as plan
}
