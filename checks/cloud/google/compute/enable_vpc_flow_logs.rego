# METADATA
# title: VPC flow logs should be enabled for all subnetworks
# description: |
#   VPC flow logs record information about all traffic, which is a vital tool in reviewing anomalous traffic.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: GCP-0029
#   aliases:
#     - AVD-GCP-0029
#     - enable-vpc-flow-logs
#   long_id: google-compute-enable-vpc-flow-logs
#   provider: google
#   service: compute
#   severity: LOW
#   recommended_action: Enable VPC flow logs
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: google
#   examples: checks/cloud/google/compute/enable_vpc_flow_logs.yaml
package builtin.google.compute.google0029

import rego.v1

deny contains res if {
	some subnetwork in input.google.compute.networks[_].subnetworks
	not is_proxy_only_network(subnetwork)
	is_flow_logs_disabled(subnetwork)
	res := result.new(
		"Subnetwork does not have VPC flow logs enabled.",
		object.get(subnetwork, "enableflowlogs", subnetwork),
	)
}

is_proxy_only_network(network) if network.purpose.value in {"REGIONAL_MANAGED_PROXY", "GLOBAL_MANAGED_PROXY"}

is_flow_logs_disabled(network) if not network.enableflowlogs.value
