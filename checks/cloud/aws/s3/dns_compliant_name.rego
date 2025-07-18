# METADATA
# title: "S3 DNS Compliant Bucket Names"
# description: "Ensures that S3 buckets have DNS complaint bucket names."
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonS3/latest/dev/transfer-acceleration.html
# custom:
#   id: AWS-0320
#   aliases:
#     - AVD-AWS-0320
#     - dns-compliant-name
#   long_id: aws-s3-dns-compliant-name
#   provider: aws
#   service: s3
#   severity: MEDIUM
#   recommended_action: "Recreate S3 bucket to use - instead of . in S3 bucket names"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: s3
#             provider: aws
package builtin.aws.s3.aws0320

import rego.v1

deny contains res if {
	bucket := input.aws.s3.buckets[_]
	indexof(bucket.name.value, ".") != -1
	res := result.new("S3 bucket name is not compliant with DNS naming requirements", bucket.name)
}
