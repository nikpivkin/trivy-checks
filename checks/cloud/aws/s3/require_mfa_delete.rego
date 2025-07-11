# METADATA
# title: Buckets should have MFA deletion protection enabled.
# description: |
#   Adding MFA delete to an S3 bucket, requires additional authentication when you change the version state of your bucket or you delete an object version, adding another layer of security in the event your security credentials are compromised or unauthorized access is obtained.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiFactorAuthenticationDelete.html
# custom:
#   id: AWS-0170
#   aliases:
#     - AVD-AWS-0170
#     - require-mfa-delete
#   long_id: aws-s3-require-mfa-delete
#   provider: aws
#   service: s3
#   severity: LOW
#   recommended_action: Enable MFA deletion protection on the bucket
#   frameworks:
#     cis-aws-1.4:
#       - "2.1.3"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: s3
#             provider: aws
#   examples: checks/cloud/aws/s3/require_mfa_delete.yaml
package builtin.aws.s3.aws0170

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some bucket in input.aws.s3.buckets
	isManaged(bucket.versioning.mfadelete)
	not bucket.versioning.mfadelete.value
	res := result.new(
		"Bucket does not have MFA deletion protection enabled",
		metadata.obj_by_path(bucket, ["versioning", "mfadelete"]),
	)
}
