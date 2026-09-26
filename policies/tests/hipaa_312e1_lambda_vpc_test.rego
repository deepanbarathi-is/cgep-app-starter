package compliance.hipaa.lambda_vpc_test

import data.compliance.hipaa.lambda_vpc
import rego.v1

lambda_in_vpc := {"resource_changes": [{
	"address": "aws_lambda_function.good",
	"type": "aws_lambda_function",
	"change": {
		"actions": ["no-op"],
		"after": {"vpc_config": [{"subnet_ids": ["subnet-1"], "security_group_ids": ["sg-1"]}]},
	},
}]}

lambda_empty_vpc_config := {"resource_changes": [{
	"address": "aws_lambda_function.bad",
	"type": "aws_lambda_function",
	"change": {"actions": ["create"], "after": {"vpc_config": []}},
}]}

lambda_without_vpc_config := {"resource_changes": [{
	"address": "aws_lambda_function.worse",
	"type": "aws_lambda_function",
	"change": {"actions": ["create"], "after": {"function_name": "x"}},
}]}

lambda_being_deleted := {"resource_changes": [{
	"address": "aws_lambda_function.old",
	"type": "aws_lambda_function",
	"change": {"actions": ["delete"], "after": null},
}]}

unrelated_resource := {"resource_changes": [{
	"address": "aws_sns_topic.t",
	"type": "aws_sns_topic",
	"change": {"actions": ["create"], "after": {}},
}]}

test_lambda_in_vpc_passes if {
	count(lambda_vpc.deny) == 0 with input as lambda_in_vpc
}

test_empty_vpc_config_fails if {
	some msg in lambda_vpc.deny with input as lambda_empty_vpc_config
	contains(msg, "164.312(e)(1)")
	contains(msg, "aws_lambda_function.bad")
}

test_missing_vpc_config_fails if {
	some msg in lambda_vpc.deny with input as lambda_without_vpc_config
	contains(msg, "aws_lambda_function.worse")
}

test_deleted_lambda_is_ignored if {
	count(lambda_vpc.deny) == 0 with input as lambda_being_deleted
}

test_unrelated_resources_are_ignored if {
	count(lambda_vpc.deny) == 0 with input as unrelated_resource
}
