# METADATA
# title: Secrets Manager should use customer managed keys
# description: |
#   Secrets Manager encrypts secrets by default using a default key created by AWS. To ensure control and granularity of secret encryption, CMK's should be used explicitly.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/kms/latest/developerguide/services-secrets-manager.html#asm-encrypt
# custom:
#   id: AWS-0098
#   aliases:
#     - AVD-AWS-0098
#     - secret-use-customer-key
#   long_id: aws-ssm-secret-use-customer-key
#   provider: aws
#   service: ssm
#   severity: LOW
#   recommended_action: Use customer managed keys
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: ssm
#             provider: aws
#   examples: checks/cloud/aws/ssm/secret_use_customer_key.yaml
package builtin.aws.ssm.aws0098

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some secret in input.aws.ssm.secrets
	without_cmk(secret)
	res := result.new("Secret is not encrypted with a customer managed key.", secret.kmskeyid)
}

deny contains res if {
	some secret in input.aws.ssm.secrets
	secret.kmskeyid.value == "alias/aws/secretsmanager"
	res := result.new("Secret explicitly uses the default key.", secret.kmskeyid)
}

without_cmk(secret) if value.is_empty(secret.kmskeyid)

without_cmk(secret) if not secret.kmskeyid
