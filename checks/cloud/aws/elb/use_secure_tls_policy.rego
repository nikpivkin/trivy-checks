# METADATA
# title: An outdated SSL policy is in use by a load balancer.
# description: |
#   You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AWS-0047
#   aliases:
#     - AVD-AWS-0047
#     - use-secure-tls-policy
#   long_id: aws-elb-use-secure-tls-policy
#   provider: aws
#   service: elb
#   severity: CRITICAL
#   recommended_action: Use a more recent TLS/SSL policy for the load balancer
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: elb
#             provider: aws
#   examples: checks/cloud/aws/elb/use_secure_tls_policy.yaml
package builtin.aws.elb.aws0047

import rego.v1

outdated_ssl_policies := {
	"ELBSecurityPolicy-2015-05",
	"ELBSecurityPolicy-2016-08",
	"ELBSecurityPolicy-FS-2018-06",
	"ELBSecurityPolicy-FS-1-1-2019-08",
	"ELBSecurityPolicy-TLS-1-0-2015-04",
	"ELBSecurityPolicy-TLS-1-1-2017-01",
	"ELBSecurityPolicy-TLS13-1-0-2021-06",
	"ELBSecurityPolicy-TLS13-1-1-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06",
}

deny contains res if {
	some lb in input.aws.elb.loadbalancers
	isManaged(lb)
	some listener in lb.listeners
	has_outdated_policy(listener)
	res := result.new("Listener uses an outdated TLS policy.", listener.tlspolicy)
}

has_outdated_policy(listener) if {
	listener.tlspolicy.value in outdated_ssl_policies
}
