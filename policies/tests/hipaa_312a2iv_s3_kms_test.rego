package compliance.hipaa.s3_kms_test

import data.compliance.hipaa.s3_kms
import rego.v1

bucket(address, id) := {
	"address": address,
	"type": "aws_s3_bucket",
	"change": {"actions": ["no-op"], "after": {"id": id, "bucket": id}, "after_unknown": {}},
}

new_bucket(address) := {
	"address": address,
	"type": "aws_s3_bucket",
	"change": {"actions": ["create"], "after": {"bucket": "x"}, "after_unknown": {"id": true}},
}

kms_config(address, bucket_id) := {
	"address": address,
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"change": {
		"actions": ["no-op"],
		"after": {
			"bucket": bucket_id,
			"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms", "kms_master_key_id": "arn:aws:kms:us-east-1:111122223333:key/abc"}]}],
		},
		"after_unknown": {},
	},
}

new_kms_config(address) := {
	"address": address,
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"change": {
		"actions": ["create"],
		"after": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]},
		"after_unknown": {
			"bucket": true,
			"rule": [{"apply_server_side_encryption_by_default": [{"kms_master_key_id": true}]}],
		},
	},
}

aes_config(address, bucket_id) := {
	"address": address,
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"change": {
		"actions": ["update"],
		"after": {
			"bucket": bucket_id,
			"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256", "kms_master_key_id": null}]}],
		},
		"after_unknown": {},
	},
}

kms_without_key(address, bucket_id) := {
	"address": address,
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"change": {
		"actions": ["update"],
		"after": {
			"bucket": bucket_id,
			"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms", "kms_master_key_id": null}]}],
		},
		"after_unknown": {},
	},
}

test_bucket_with_kms_passes if {
	plan := {"resource_changes": [bucket("aws_s3_bucket.a", "bkt-a"), kms_config("module.a.aws_s3_bucket_server_side_encryption_configuration.this", "bkt-a")]}
	count(s3_kms.deny) == 0 with input as plan
}

test_bucket_without_config_fails if {
	plan := {"resource_changes": [bucket("aws_s3_bucket.a", "bkt-a")]}
	some msg in s3_kms.deny with input as plan
	contains(msg, "aws_s3_bucket.a")
	contains(msg, "no encryption configuration")
}

test_config_for_a_different_bucket_does_not_count if {
	plan := {"resource_changes": [bucket("aws_s3_bucket.a", "bkt-a"), kms_config("aws_s3_bucket_server_side_encryption_configuration.b", "bkt-b")]}
	some msg in s3_kms.deny with input as plan
	contains(msg, "aws_s3_bucket.a")
}

test_aes256_fails if {
	plan := {"resource_changes": [bucket("aws_s3_bucket.a", "bkt-a"), aes_config("aws_s3_bucket_server_side_encryption_configuration.a", "bkt-a")]}
	some msg in s3_kms.deny with input as plan
	contains(msg, "164.312(a)(2)(iv)")
	contains(msg, "aws_s3_bucket_server_side_encryption_configuration.a")
}

test_kms_without_customer_key_fails if {
	plan := {"resource_changes": [bucket("aws_s3_bucket.a", "bkt-a"), kms_without_key("aws_s3_bucket_server_side_encryption_configuration.a", "bkt-a")]}
	some msg in s3_kms.deny with input as plan
	contains(msg, "aws_s3_bucket_server_side_encryption_configuration.a")
}

test_new_bucket_with_new_config_passes if {
	plan := {"resource_changes": [new_bucket("aws_s3_bucket.n"), new_kms_config("module.n.aws_s3_bucket_server_side_encryption_configuration.this")]}
	count(s3_kms.deny) == 0 with input as plan
}

test_new_bucket_without_config_fails if {
	plan := {"resource_changes": [new_bucket("aws_s3_bucket.n")]}
	some msg in s3_kms.deny with input as plan
	contains(msg, "aws_s3_bucket.n")
	contains(msg, "new bucket")
}

test_two_new_buckets_one_config_fails if {
	plan := {"resource_changes": [new_bucket("aws_s3_bucket.n1"), new_bucket("aws_s3_bucket.n2"), new_kms_config("module.n1.aws_s3_bucket_server_side_encryption_configuration.this")]}
	some msg in s3_kms.deny with input as plan
	contains(msg, "aws_s3_bucket.n1")
	contains(msg, "aws_s3_bucket.n2")
}

test_deleted_bucket_is_ignored if {
	plan := {"resource_changes": [{
		"address": "aws_s3_bucket.old",
		"type": "aws_s3_bucket",
		"change": {"actions": ["delete"], "after": null, "after_unknown": {}},
	}]}
	count(s3_kms.deny) == 0 with input as plan
}

test_unrelated_resources_are_ignored if {
	plan := {"resource_changes": [{
		"address": "aws_sns_topic.t",
		"type": "aws_sns_topic",
		"change": {"actions": ["create"], "after": {}},
	}]}
	count(s3_kms.deny) == 0 with input as plan
}
