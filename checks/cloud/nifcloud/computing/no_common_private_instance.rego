# METADATA
# title: The instance has common private network
# description: |
#   When handling sensitive data between servers, please consider using a private LAN to isolate the private side network from the shared network.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pfs.nifcloud.com/service/plan.htm
# custom:
#   avd_id: AVD-NIF-0005
#   aliases:
#     - nifcloud-computing-no-common-private-instance
#   provider: nifcloud
#   service: computing
#   severity: LOW
#   short_code: no-common-private-instance
#   recommended_action: Use private LAN
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: computing
#             provider: nifcloud
#   examples: checks/cloud/nifcloud/computing/no_common_private_instance.yaml
package builtin.nifcloud.computing.nifcloud0005

import rego.v1

deny contains res if {
	some instance in input.nifcloud.computing.instances
	some ni in instance.networkinterfaces
	ni.networkid.value == "net-COMMON_PRIVATE"
	res := result.new("The instance has common private network", ni.networkid)
}
