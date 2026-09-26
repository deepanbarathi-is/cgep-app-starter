package compliance.hipaa.dynamodb_cmk_test

import data.compliance.hipaa.dynamodb_cmk
import rego.v1

table_with_cmk := {"resource_changes": [{
	"address": "aws_dynamodb_table.good",
	"type": "aws_dynamodb_table",
	"change": {
		"actions": ["no-op"],
		"after": {"server_side_encryption": [{"enabled": true, "kms_key_arn": "arn:aws:kms:us-east-1:111122223333:key/abc"}]},
	},
}]}

table_default_encryption := {"resource_changes": [{
	"address": "aws_dynamodb_table.default",
	"type": "aws_dynamodb_table",
	"change": {"actions": ["create"], "after": {"server_side_encryption": []}},
}]}

table_aws_managed_key := {"resource_changes": [{
	"address": "aws_dynamodb_table.awskey",
	"type": "aws_dynamodb_table",
	"change": {"actions": ["create"], "after": {"server_side_encryption": [{"enabled": true, "kms_key_arn": null}]}},
}]}

table_encryption_off := {"resource_changes": [{
	"address": "aws_dynamodb_table.off",
	"type": "aws_dynamodb_table",
	"change": {"actions": ["create"], "after": {"server_side_encryption": [{"enabled": false, "kms_key_arn": "arn:aws:kms:us-east-1:111122223333:key/abc"}]}},
}]}

table_without_block := {"resource_changes": [{
	"address": "aws_dynamodb_table.noblock",
	"type": "aws_dynamodb_table",
	"change": {"actions": ["create"], "after": {"name": "x"}},
}]}

table_key_unknown_until_apply := {"resource_changes": [{
	"address": "aws_dynamodb_table.newkey",
	"type": "aws_dynamodb_table",
	"change": {
		"actions": ["create"],
		"after": {"server_side_encryption": [{"enabled": true}]},
		"after_unknown": {"server_side_encryption": [{"kms_key_arn": true}]},
	},
}]}

table_being_deleted := {"resource_changes": [{
	"address": "aws_dynamodb_table.old",
	"type": "aws_dynamodb_table",
	"change": {"actions": ["delete"], "after": null},
}]}

unrelated_resource := {"resource_changes": [{
	"address": "aws_sns_topic.t",
	"type": "aws_sns_topic",
	"change": {"actions": ["create"], "after": {}},
}]}

test_table_with_cmk_passes if {
	count(dynamodb_cmk.deny) == 0 with input as table_with_cmk
}

test_default_encryption_fails if {
	some msg in dynamodb_cmk.deny with input as table_default_encryption
	contains(msg, "164.312(a)(2)(iv)")
	contains(msg, "aws_dynamodb_table.default")
}

test_aws_managed_key_fails if {
	some msg in dynamodb_cmk.deny with input as table_aws_managed_key
	contains(msg, "aws_dynamodb_table.awskey")
}

test_encryption_off_fails if {
	some msg in dynamodb_cmk.deny with input as table_encryption_off
	contains(msg, "aws_dynamodb_table.off")
}

test_missing_block_fails if {
	some msg in dynamodb_cmk.deny with input as table_without_block
	contains(msg, "aws_dynamodb_table.noblock")
}

test_key_unknown_until_apply_passes if {
	count(dynamodb_cmk.deny) == 0 with input as table_key_unknown_until_apply
}

test_deleted_table_is_ignored if {
	count(dynamodb_cmk.deny) == 0 with input as table_being_deleted
}

test_unrelated_resources_are_ignored if {
	count(dynamodb_cmk.deny) == 0 with input as unrelated_resource
}
