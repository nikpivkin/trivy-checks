# METADATA
# title: "Ensure that the admission control plugin ServiceAccount is set"
# description: "Automate service accounts management."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0014
#   aliases:
#     - AVD-KCV-0014
#     - KCV0014
#     - ensure-admission-control-plugin-service-account-is-set
#   long_id: kubernetes-ensure-admission-control-plugin-service-account-is-set
#   severity: LOW
#   recommended_action: "Follow the documentation and create ServiceAccount objects as per your environment. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and ensure that the --disable-admission-plugins parameter is set to a value that does not include ServiceAccount."
#   input:
#     selector:
#       - type: kubernetes
package builtin.kubernetes.KCV0014

import rego.v1

import data.lib.kubernetes

check_flag(container) if {
	some i
	output := regex.find_all_string_submatch_n(`--disable-admission-plugins=([^\s]+)`, container.command[i], -1)
	regex.match("ServiceAccount", output[0][1])
}

check_flag(container) if {
	some i
	output := regex.find_all_string_submatch_n(`--disable-admission-plugins=([^\s]+)`, container.args[i], -1)
	regex.match("ServiceAccount", output[0][1])
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	check_flag(container)
	msg := "Ensure that the admission control plugin ServiceAccount is set"
	res := result.new(msg, container)
}
