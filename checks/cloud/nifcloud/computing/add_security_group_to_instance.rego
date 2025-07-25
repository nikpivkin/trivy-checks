# METADATA
# title: Missing security group for instance.
# description: |
#   Need to add a security group to your instance.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pfs.nifcloud.com/help/server/change_fw.htm
# custom:
#   id: NIF-0004
#   aliases:
#     - AVD-NIF-0004
#     - nifcloud-computing-add-security-group-to-instance
#     - add-security-group-to-instance
#   long_id: nifcloud-computing-add-security-group-to-instance
#   provider: nifcloud
#   service: computing
#   severity: CRITICAL
#   recommended_action: Add security group for all instances
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: computing
#             provider: nifcloud
#   examples: checks/cloud/nifcloud/computing/add_security_group_to_instance.yaml
package builtin.nifcloud.computing.nifcloud0004

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some instance in input.nifcloud.computing.instances
	without_sg(instance)
	res := result.new("Instance does not have a security group.", instance.securitygroup)
}

without_sg(instance) if value.is_empty(instance.securitygroup)

without_sg(instance) if not instance.securitygroup
