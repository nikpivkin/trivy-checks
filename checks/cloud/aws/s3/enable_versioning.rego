# METADATA
# title: S3 Data should be versioned
# description: |
#   Versioning in Amazon S3 is a means of keeping multiple variants of an object in the same bucket.
#
#   You can use the S3 Versioning feature to preserve, retrieve, and restore every version of every object stored in your buckets.
#
#   With versioning you can recover more easily from both unintended user actions and application failures.
#
#   When you enable versioning, also keep in mind the potential costs of storing noncurrent versions of objects. To help manage those costs, consider setting up an S3 Lifecycle configuration.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html
#   - https://aws.amazon.com/blogs/storage/reduce-storage-costs-with-fewer-noncurrent-versions-using-amazon-s3-lifecycle/
# custom:
#   aliases:
#     - aws-s3-enable-versioning
#   avd_id: AVD-AWS-0090
#   provider: aws
#   service: s3
#   severity: MEDIUM
#   short_code: enable-versioning
#   recommended_action: Enable versioning to protect against accidental/malicious removal or modification
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: s3
#             provider: aws
#   examples: checks/cloud/aws/s3/enable_versioning.yaml
package builtin.aws.s3.aws0090

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some bucket in input.aws.s3.buckets
	not bucket.versioning.enabled.value
	res := result.new(
		"Bucket does not have versioning enabled",
		metadata.obj_by_path(bucket, ["versioning", "enabled"]),
	)
}
