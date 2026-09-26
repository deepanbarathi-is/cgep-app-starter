package compliance.hipaa.s3_tls_only_test

import data.compliance.hipaa.s3_tls_only
import rego.v1

existing_bucket := {
	"address": "aws_s3_bucket.a",
	"type": "aws_s3_bucket",
	"change": {"actions": ["no-op"], "after": {"id": "bkt-a", "bucket": "bkt-a"}},
}

new_bucket := {
	"address": "aws_s3_bucket.n",
	"type": "aws_s3_bucket",
	"change": {"actions": ["create"], "after": {"id": null, "bucket": null}, "after_unknown": {"id": true, "bucket": true}},
}

tls_deny_statement(id) := {
	"Sid": "DenyInsecureTransport",
	"Effect": "Deny",
	"Principal": "*",
	"Action": "s3:*",
	"Resource": [sprintf("arn:aws:s3:::%s", [id]), sprintf("arn:aws:s3:::%s/*", [id])],
	"Condition": {"Bool": {"aws:SecureTransport": "false"}},
}

policy_for(bucket_id, statements) := {
	"address": "aws_s3_bucket_policy.a",
	"type": "aws_s3_bucket_policy",
	"change": {
		"actions": ["no-op"],
		"after": {"bucket": bucket_id, "policy": json.marshal({"Version": "2012-10-17", "Statement": statements})},
	},
}

# Configuration and data document for the "bucket not known yet" check.
config_linking(bucket_address, doc_name) := {"root_module": {"resources": [{
	"address": "aws_s3_bucket_policy.n",
	"type": "aws_s3_bucket_policy",
	"expressions": {
		"bucket": {"references": [sprintf("%s.id", [bucket_address]), bucket_address]},
		"policy": {"references": [sprintf("data.aws_iam_policy_document.%s.json", [doc_name]), sprintf("data.aws_iam_policy_document.%s", [doc_name])]},
	},
}]}}

doc_change(doc_name, statement) := {
	"address": sprintf("data.aws_iam_policy_document.%s", [doc_name]),
	"mode": "data",
	"type": "aws_iam_policy_document",
	"change": {"actions": ["read"], "after": {"statement": [statement]}},
}

tls_doc_statement := {
	"effect": "Deny",
	"principals": [{"type": "*", "identifiers": ["*"]}],
	"actions": ["s3:*"],
	"condition": [{"test": "Bool", "variable": "aws:SecureTransport", "values": ["false"]}],
	"resources": [null, null],
}

test_existing_bucket_with_tls_deny_passes if {
	plan := {"resource_changes": [existing_bucket, policy_for("bkt-a", [tls_deny_statement("bkt-a")])]}
	count(s3_tls_only.deny) == 0 with input as plan
}

test_tls_deny_next_to_other_statements_passes if {
	other := {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}, "Action": "s3:PutObject", "Resource": "arn:aws:s3:::bkt-a/*"}
	plan := {"resource_changes": [existing_bucket, policy_for("bkt-a", [other, tls_deny_statement("bkt-a")])]}
	count(s3_tls_only.deny) == 0 with input as plan
}

test_bucket_without_policy_fails if {
	plan := {"resource_changes": [existing_bucket]}
	some msg in s3_tls_only.deny with input as plan
	contains(msg, "164.312(e)(1)")
	contains(msg, "aws_s3_bucket.a")
}

test_policy_without_tls_condition_fails if {
	stmt := {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bkt-a/*"}
	plan := {"resource_changes": [existing_bucket, policy_for("bkt-a", [stmt])]}
	some msg in s3_tls_only.deny with input as plan
	contains(msg, "aws_s3_bucket.a")
}

test_allow_instead_of_deny_fails if {
	stmt := object.union(tls_deny_statement("bkt-a"), {"Effect": "Allow"})
	plan := {"resource_changes": [existing_bucket, policy_for("bkt-a", [stmt])]}
	some msg in s3_tls_only.deny with input as plan
	contains(msg, "aws_s3_bucket.a")
}

test_condition_value_true_fails if {
	stmt := object.union(tls_deny_statement("bkt-a"), {"Condition": {"Bool": {"aws:SecureTransport": "true"}}})
	plan := {"resource_changes": [existing_bucket, policy_for("bkt-a", [stmt])]}
	some msg in s3_tls_only.deny with input as plan
	contains(msg, "aws_s3_bucket.a")
}

test_deny_covering_only_the_bucket_not_objects_fails if {
	stmt := object.union(tls_deny_statement("bkt-a"), {"Resource": "arn:aws:s3:::bkt-a"})
	plan := {"resource_changes": [existing_bucket, policy_for("bkt-a", [stmt])]}
	some msg in s3_tls_only.deny with input as plan
	contains(msg, "aws_s3_bucket.a")
}

test_policy_for_a_different_bucket_does_not_count if {
	plan := {"resource_changes": [existing_bucket, policy_for("bkt-b", [tls_deny_statement("bkt-b")])]}
	some msg in s3_tls_only.deny with input as plan
	contains(msg, "aws_s3_bucket.a")
}

test_policy_text_unknown_and_unlinked_fails if {
	unknown_policy := {
		"address": "aws_s3_bucket_policy.a",
		"type": "aws_s3_bucket_policy",
		"change": {"actions": ["update"], "after": {"bucket": "bkt-a"}, "after_unknown": {"policy": true}},
	}
	plan := {"resource_changes": [existing_bucket, unknown_policy]}
	some msg in s3_tls_only.deny with input as plan
	contains(msg, "aws_s3_bucket.a")
}

test_new_bucket_linked_to_tls_document_passes if {
	plan := {
		"resource_changes": [new_bucket, doc_change("tls", tls_doc_statement)],
		"configuration": config_linking("aws_s3_bucket.n", "tls"),
	}
	count(s3_tls_only.deny) == 0 with input as plan
}

test_new_bucket_linked_to_document_from_prior_state_passes if {
	plan := {
		"resource_changes": [new_bucket],
		"prior_state": {"values": {"root_module": {"resources": [{"address": "data.aws_iam_policy_document.tls", "values": {"statement": [object.union(tls_doc_statement, {"resources": ["arn:aws:s3:::x", "arn:aws:s3:::x/*"]})]}}]}}},
		"configuration": config_linking("aws_s3_bucket.n", "tls"),
	}
	count(s3_tls_only.deny) == 0 with input as plan
}

test_new_bucket_linked_to_document_without_tls_deny_fails if {
	weak := object.union(tls_doc_statement, {"effect": "Allow"})
	plan := {
		"resource_changes": [new_bucket, doc_change("weak", weak)],
		"configuration": config_linking("aws_s3_bucket.n", "weak"),
	}
	some msg in s3_tls_only.deny with input as plan
	contains(msg, "aws_s3_bucket.n")
}

test_new_bucket_with_no_policy_fails if {
	plan := {"resource_changes": [new_bucket], "configuration": {"root_module": {"resources": []}}}
	some msg in s3_tls_only.deny with input as plan
	contains(msg, "aws_s3_bucket.n")
}

test_policy_that_points_at_another_bucket_does_not_protect_new_bucket if {
	plan := {
		"resource_changes": [new_bucket, doc_change("tls", tls_doc_statement)],
		"configuration": config_linking("aws_s3_bucket.other", "tls"),
	}
	some msg in s3_tls_only.deny with input as plan
	contains(msg, "aws_s3_bucket.n")
}

test_readable_but_wrong_policy_is_not_rescued_by_the_code_link if {
	weak := object.union(tls_deny_statement("bkt-a"), {"Effect": "Allow"})
	plan := {
		"resource_changes": [existing_bucket, policy_for("bkt-a", [weak]), doc_change("tls", tls_doc_statement)],
		"configuration": config_linking("aws_s3_bucket.a", "tls"),
	}
	some msg in s3_tls_only.deny with input as plan
	contains(msg, "aws_s3_bucket.a")
}

test_existing_bucket_with_unreadable_policy_passes_when_code_links_a_tls_document if {
	unknown_policy := {
		"address": "aws_s3_bucket_policy.n",
		"type": "aws_s3_bucket_policy",
		"change": {"actions": ["update"], "after": {"bucket": "bkt-a"}, "after_unknown": {"policy": true}},
	}
	plan := {
		"resource_changes": [existing_bucket, unknown_policy, doc_change("tls", tls_doc_statement)],
		"configuration": config_linking("aws_s3_bucket.a", "tls"),
	}
	count(s3_tls_only.deny) == 0 with input as plan
}

test_deleted_bucket_is_ignored if {
	plan := {"resource_changes": [{
		"address": "aws_s3_bucket.old",
		"type": "aws_s3_bucket",
		"change": {"actions": ["delete"], "after": null},
	}]}
	count(s3_tls_only.deny) == 0 with input as plan
}

test_unrelated_resources_are_ignored if {
	plan := {"resource_changes": [{
		"address": "aws_sns_topic.t",
		"type": "aws_sns_topic",
		"change": {"actions": ["create"], "after": {}},
	}]}
	count(s3_tls_only.deny) == 0 with input as plan
}
