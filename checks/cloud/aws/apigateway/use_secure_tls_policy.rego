# METADATA
# title: API Gateway domain name uses outdated SSL/TLS protocols.
# description: |
#   You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-custom-domain-tls-version.html
# custom:
#   id: AWS-0005
#   aliases:
#     - AVD-AWS-0005
#     - use-secure-tls-policy
#   long_id: aws-apigateway-use-secure-tls-policy
#   provider: aws
#   service: apigateway
#   severity: HIGH
#   recommended_action: Use the most modern TLS/SSL policies available
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: apigateway
#             provider: aws
#   examples: checks/cloud/aws/apigateway/use_secure_tls_policy.yaml
package builtin.aws.apigateway.aws0005

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some domain in input.aws.apigateway.v1.domainnames
	not is_tls_1_2(domain)
	res := result.new(
		"Domain name is configured with an outdated TLS policy.",
		metadata.obj_by_path(domain, "securitypolicy"),
	)
}

deny contains res if {
	some domain in input.aws.apigateway.v2.domainnames
	not is_tls_1_2(domain)
	res := result.new(
		"Domain name is configured with an outdated TLS policy.",
		metadata.obj_by_path(domain, "securitypolicy"),
	)
}

is_tls_1_2(domain) := domain.securitypolicy.value == "TLS_1_2"
