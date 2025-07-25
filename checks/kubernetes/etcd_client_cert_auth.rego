# METADATA
# title: "Ensure that the --client-cert-auth argument is set to true"
# description: "Enable client authentication on etcd service."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0043
#   aliases:
#     - AVD-KCV-0043
#     - KCV0043
#     - ensure-client-cert-auth-argument-is-set-to-true
#   long_id: kubernetes-ensure-client-cert-auth-argument-is-set-to-true
#   severity: LOW
#   recommended_action: "Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameter."
#   input:
#     selector:
#       - type: kubernetes
package builtin.kubernetes.KCV0043

import rego.v1

import data.lib.kubernetes

checkFlag(container) if {
	kubernetes.command_has_flag(container.command, "--client-cert-auth=true")
}

checkFlag(container) if {
	kubernetes.command_has_flag(container.args, "--client-cert-auth=true")
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_etcd(container)
	not checkFlag(container)
	msg := "Ensure that the --client-cert-auth argument is set to true"
	res := result.new(msg, container)
}
