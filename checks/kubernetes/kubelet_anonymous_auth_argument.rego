# METADATA
# title: "Ensure that the --anonymous-auth argument is set to false"
# description: "Disable anonymous requests to the Kubelet server."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   avd_id: AVD-KCV-0079
#   severity: CRITICAL
#   short_code: disable-anonymous-requests-kubelet-server.
#   recommended_action: "Disable anonymous requests to the Kubelet server"
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: nodeinfo
package builtin.kubernetes.KCV0079

import rego.v1

types := ["master", "worker"]

validate_kubelet_anonymous_auth_set(sp) := {"kubeletAnonymousAuthArgumentSet": violation} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	violation := {anonymous_auth | anonymous_auth = sp.info.kubeletAnonymousAuthArgumentSet.values[_]; anonymous_auth == "true"}
	count(violation) > 0
}

deny contains res if {
	output := validate_kubelet_anonymous_auth_set(input)
	msg := "Ensure that the --anonymous-auth argument is set to false"
	res := result.new(msg, output)
}
