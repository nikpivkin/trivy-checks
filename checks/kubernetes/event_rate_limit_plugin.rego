# METADATA
# title: "Ensure that the admission control plugin EventRateLimit is set"
# description: "Limit the rate at which the API server accepts requests."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0010
#   aliases:
#     - AVD-KCV-0010
#     - KCV0010
#     - ensure-admission-control-plugin-event-rate-limit-is-set
#   long_id: kubernetes-ensure-admission-control-plugin-event-rate-limit-is-set
#   severity: LOW
#   recommended_action: "Follow the Kubernetes documentation and set the desired limits in a configuration file. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml and set the below parameters."
#   input:
#     selector:
#       - type: kubernetes
package builtin.kubernetes.KCV0010

import rego.v1

import data.lib.kubernetes

check_flag(container) if {
	kubernetes.command_has_flag(container.command, "--enable-admission-plugins")
	some i
	output := regex.find_all_string_submatch_n(`--enable-admission-plugins=([^\s]+)`, container.command[i], -1)
	regex.match("EventRateLimit", output[0][1])
}

check_flag(container) if {
	kubernetes.command_has_flag(container.args, "--enable-admission-plugins")
	some i
	output := regex.find_all_string_submatch_n(`--enable-admission-plugins=([^\s]+)`, container.args[i], -1)
	regex.match("EventRateLimit", output[0][1])
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not check_flag(container)
	msg := "Ensure that the admission control plugin EventRateLimit is set"
	res := result.new(msg, container)
}
