# METADATA
# title: Performance Insights encryption should use Customer Managed Keys
# description: |
#   Amazon RDS uses the AWS managed key for your new DB instance. For complete control over KMS keys, including establishing and maintaining their key policies, IAM policies, and grants, enabling and disabling them, and rotating their cryptographic material, use a customer managed keys.
#   The encryption key specified in `performance_insights_kms_key_id` references a KMS ARN
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PerfInsights.access-control.html#USER_PerfInsights.access-control.cmk-policy
#   - https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-mgmt
# custom:
#   id: AWS-0078
#   aliases:
#     - AVD-AWS-0078
#     - performance-insights-encryption-customer-key
#   long_id: aws-rds-performance-insights-encryption-customer-key
#   provider: aws
#   service: rds
#   severity: LOW
#   recommended_action: Use Customer Managed Keys to encrypt Performance Insights data
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: rds
#             provider: aws
#   examples: checks/cloud/aws/rds/performance_insights_encryption_customer_key.yaml
package builtin.aws.rds.aws0078

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some cluster in input.aws.rds.clusters
	some instance in cluster.instances
	kms_key_not_used(instance.instance)
	res := result.new(
		"Cluster instance Performance Insights enctyption does not use a customer-managed KMS key.",
		instance.instance,
	)
}

deny contains res if {
	some instance in input.aws.rds.instances
	kms_key_not_used(instance)
	res := result.new(
		"Instance Performance Insights enctyption does not use a customer-managed KMS key.",
		instance,
	)
}

kms_key_not_used(instance) if {
	isManaged(instance)
	instance.performanceinsights.enabled.value
	perfomance_insights_kms_key_id_missed(instance)
}

perfomance_insights_kms_key_id_missed(instance) if value.is_empty(instance.performanceinsights.kmskeyid)

perfomance_insights_kms_key_id_missed(instance) if not instance.performanceinsights.kmskeyid
