# METADATA
# title: "Ensure that the --kubeconfig kubelet.conf file ownership is set to root:root"
# description: "Ensure that the kubelet.conf file ownership is set to root:root."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0074
#   aliases:
#     - AVD-KCV-0074
#     - KCV0074
#     - ensure-kubeconfig-kubelet.conf-ownership-set-root:root
#   long_id: kubernetes-ensure-kubeconfig-kubelet.conf-ownership-set-root:root
#   severity: HIGH
#   recommended_action: "Change the --kubeconfig kubelet.conf file ownership to root:root"
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: nodeinfo
package builtin.kubernetes.KCV0074

import rego.v1

types := ["master", "worker"]

validate_kubelet_file_ownership(sp) := {"kubeletConfFileOwnership": violation} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	violation := {ownership | ownership = sp.info.kubeletConfFileOwnership.values[_]; not ownership == "root:root"}
	count(violation) > 0
}

deny contains res if {
	output := validate_kubelet_file_ownership(input)
	msg := "Ensure that the kubelet.conf file ownership is set to root:root."
	res := result.new(msg, output)
}
