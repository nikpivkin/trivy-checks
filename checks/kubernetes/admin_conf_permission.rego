# METADATA
# title: "Ensure that the admin config file permissions are set to 600 or more restrictive"
# description: "Ensure that the admin config file has permissions of 600 or more restrictive."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   avd_id: AVD-KCV-0060
#   severity: CRITICAL
#   short_code: ensure-admin-config-file-permissions-set-600-or-more-restrictive
#   recommended_action: "Change the admin config file /etc/kubernetes/admin.conf permissions of 600 or more restrictive "
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: nodeinfo
package builtin.kubernetes.KCV0060

import rego.v1

validate_conf_permission(sp) := {"adminConfFilePermissions": violation} if {
	sp.kind == "NodeInfo"
	sp.type == "master"
	violation := {permission | permission = sp.info.adminConfFilePermissions.values[_]; permission > 600}
	count(violation) > 0
}

deny contains res if {
	output := validate_conf_permission(input)
	msg := "Ensure that the admin config file permissions is set to 600 or more restrictive"
	res := result.new(msg, output)
}
