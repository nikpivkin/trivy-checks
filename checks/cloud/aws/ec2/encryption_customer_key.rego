# METADATA
# title: EBS volume encryption should use Customer Managed Keys
# description: |
#   Encryption using AWS keys provides protection for your EBS volume. To increase control of the encryption and manage factors like rotation use customer managed keys.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html
# custom:
#   avd_id: AVD-AWS-0027
#   aliases:
#     - aws-ebs-encryption-customer-key
#     - aws-ec2-volume-encryption-customer-key
#   provider: aws
#   service: ec2
#   severity: LOW
#   short_code: volume-encryption-customer-key
#   recommended_action: Enable encryption using customer managed keys
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ec2
#             provider: aws
#   examples: checks/cloud/aws/ec2/encryption_customer_key.yaml
package builtin.aws.ec2.aws0027

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some volume in input.aws.ec2.volumes
	isManaged(volume)
	without_cmk(volume)
	res := result.new(
		"EBS volume does not use a customer-managed KMS key.",
		metadata.obj_by_path(volume, ["encryption", "kmskeyid"]),
	)
}

without_cmk(volume) if value.is_empty(volume.encryption.kmskeyid)

without_cmk(volume) if not volume.encryption.kmskeyid
