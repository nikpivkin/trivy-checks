# METADATA
# title: A security group rule allows egress traffic to multiple public addresses
# description: |
#   Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: OPNSTK-0004
#   aliases:
#     - AVD-OPNSTK-0004
#     - no-public-egress
#   long_id: openstack-networking-no-public-egress
#   provider: openstack
#   service: networking
#   severity: MEDIUM
#   recommended_action: Employ more restrictive security group rules
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: networking
#             provider: openstack
#   examples: checks/cloud/openstack/networking/no_public_egress.yaml
package builtin.openstack.networking.openstack0004

import rego.v1

deny contains res if {
	some sg in input.openstack.networking.securitygroups
	some rule in sg.rules
	not is_ingress(rule)
	cidr.is_public(rule.cidr.value)
	cidr.count_addresses(rule.cidr.value) > 1
	res := result.new("Security group rule allows egress to multiple public addresses.", rule.cidr)
}

is_ingress(rule) := rule.isingress.value == true
