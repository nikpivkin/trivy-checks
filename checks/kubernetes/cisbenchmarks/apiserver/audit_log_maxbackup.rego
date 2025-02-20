# METADATA
# entrypoint: true
# title: "Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate"
# description: "Retain 10 or an appropriate number of old log files."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0021
#   avd_id: AVD-KCV-0021
#   severity: LOW
#   short_code: ensure-audit-log-maxbackup-argument-is-set-to-10-or-as-appropriate
#   recommended_action: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --audit-log-maxbackup parameter to 10 or to an appropriate value."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0021

import rego.v1

import data.lib.kubernetes

check_flag(container) if {
	kubernetes.command_has_flag(container.command, "--audit-log-maxbackup")
}

check_flag(container) if {
	kubernetes.command_has_flag(container.args, "--audit-log-maxbackup")
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not check_flag(container)
	msg := "Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate"
	res := result.new(msg, container)
}
