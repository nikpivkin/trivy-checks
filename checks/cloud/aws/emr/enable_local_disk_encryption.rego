# METADATA
# title: Enable local-disk encryption for EMR clusters.
# description: |
#   Data stored within an EMR instances should be encrypted to ensure sensitive data is kept private.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-nist_800-171.html
# custom:
#   aliases:
#     - aws-emr-enable-local-disk-encryption
#   avd_id: AVD-AWS-0139
#   provider: aws
#   service: emr
#   severity: HIGH
#   short_code: enable-local-disk-encryption
#   recommended_action: Enable local-disk encryption for EMR cluster
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: emr
#             provider: aws
#   examples: checks/cloud/aws/emr/enable_local_disk_encryption.yaml
package builtin.aws.emr.aws0139

import rego.v1

deny contains res if {
	some sec_conf in input.aws.emr.securityconfiguration
	vars := json.unmarshal(sec_conf.configuration.value)
	vars.EncryptionConfiguration.AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration.EncryptionKeyProviderType == ""
	res := result.new("EMR cluster does not have local-disk encryption enabled.", sec_conf.configuration)
}
