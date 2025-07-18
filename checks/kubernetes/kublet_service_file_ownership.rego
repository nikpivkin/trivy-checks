# METADATA
# title: "Ensure that the kubelet service file ownership is set to root:root"
# description: "Ensure that the kubelet service file ownership is set to root:root."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0070
#   aliases:
#     - AVD-KCV-0070
#     - KCV0070
#     - ensure-kubelet-service-file-ownership-set-root:root.
#   long_id: kubernetes-ensure-kubelet-service-file-ownership-set-root:root.
#   severity: CRITICAL
#   recommended_action: "Change the kubelet service file /etc/systemd/system/kubelet.service.d/10-kubeadm.conf ownership to root:root"
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: nodeinfo
package builtin.kubernetes.KCV0070

import rego.v1

types := ["master", "worker"]

validate_service_file_ownership(sp) := {"kubeletServiceFileOwnership": violation} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	violation := {ownership | ownership = sp.info.kubeletServiceFileOwnership.values[_]; ownership != "root:root"}
	count(violation) > 0
}

deny contains res if {
	output := validate_service_file_ownership(input)
	msg := "Ensure that the kubelet service file ownership is set to root:root"
	res := result.new(msg, output)
}
