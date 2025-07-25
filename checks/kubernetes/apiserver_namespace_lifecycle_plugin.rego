# METADATA
# title: "Ensure that the admission control plugin NamespaceLifecycle is set"
# description: "Reject creating objects in a namespace that is undergoing termination."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0015
#   aliases:
#     - AVD-KCV-0015
#     - KCV0015
#     - ensure-admission-control-plugin-namespace-lifecycle-is-set
#   long_id: kubernetes-ensure-admission-control-plugin-namespace-lifecycle-is-set
#   severity: LOW
#   recommended_action: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --disable-admission-plugins parameter to ensure it does not include NamespaceLifecycle."
#   input:
#     selector:
#       - type: kubernetes
package builtin.kubernetes.KCV0015

import rego.v1

import data.lib.kubernetes

check_flag(container) if {
	some i
	output := regex.find_all_string_submatch_n(`--disable-admission-plugins=([^\s]+)`, container.command[i], -1)
	regex.match("NamespaceLifecycle", output[0][1])
}

check_flag(container) if {
	some i
	output := regex.find_all_string_submatch_n(`--disable-admission-plugins=([^\s]+)`, container.args[i], -1)
	regex.match("NamespaceLifecycle", output[0][1])
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	check_flag(container)
	msg := "Ensure that the admission control plugin NamespaceLifecycle is set"
	res := result.new(msg, container)
}
