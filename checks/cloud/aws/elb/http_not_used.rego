# METADATA
# title: Use of plain HTTP.
# description: |
#   Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.
#   You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://www.cloudflare.com/en-gb/learning/ssl/why-is-http-not-secure/
# custom:
#   id: AWS-0054
#   aliases:
#     - AVD-AWS-0054
#     - http-not-used
#   long_id: aws-elb-http-not-used
#   provider: aws
#   service: elb
#   severity: CRITICAL
#   recommended_action: Switch to HTTPS to benefit from TLS security features
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: elb
#             provider: aws
#   examples: checks/cloud/aws/elb/http_not_used.yaml
package builtin.aws.elb.aws0054

import rego.v1

deny contains res if {
	some lb in input.aws.elb.loadbalancers
	isManaged(lb)
	lb.type.value == "application"

	some listener in lb.listeners
	use_http(listener)
	res := result.new("Listener for application load balancer does not use HTTPS.", listener)
}

use_http(listener) if {
	listener.protocol.value == "HTTP"
	not has_redirect(listener)
}

has_redirect(listener) if {
	some action in listener.defaultactions
	action.type.value == "redirect"
}
