# METADATA
# title: "Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate"
# description: "Rotate log files on reaching 100 MB or as appropriate."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0022
#   aliases:
#     - AVD-KCV-0022
#     - KCV0022
#     - ensure-audit-log-maxsize-argument-is-set-to-100-or-as-appropriate
#   long_id: kubernetes-ensure-audit-log-maxsize-argument-is-set-to-100-or-as-appropriate
#   severity: LOW
#   recommended_action: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --audit-log-maxsize parameter to an appropriate size in MB"
#   input:
#     selector:
#       - type: kubernetes
package builtin.kubernetes.KCV0022

import rego.v1

import data.lib.kubernetes

check_flag(container) if {
	kubernetes.command_has_flag(container.command, "--audit-log-maxsize")
}

check_flag(container) if {
	kubernetes.command_has_flag(container.args, "--audit-log-maxsize")
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not check_flag(container)
	msg := "Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate"
	res := result.new(msg, container)
}
