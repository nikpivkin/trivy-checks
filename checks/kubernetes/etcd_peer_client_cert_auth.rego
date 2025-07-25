# METADATA
# title: "Ensure that the --peer-client-cert-auth argument is set to true"
# description: "etcd should be configured for peer authentication."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0046
#   aliases:
#     - AVD-KCV-0046
#     - KCV0046
#     - ensure-peer-client-cert-auth-argument-is-set-to-true
#   long_id: kubernetes-ensure-peer-client-cert-auth-argument-is-set-to-true
#   severity: LOW
#   recommended_action: "Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameter."
#   input:
#     selector:
#       - type: kubernetes
package builtin.kubernetes.KCV0046

import rego.v1

import data.lib.kubernetes

checkFlag(container) if {
	kubernetes.command_has_flag(container.command, "--peer-client-cert-auth=true")
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_etcd(container)
	not checkFlag(container)
	msg := "Ensure that the --peer-client-cert-auth argument is set to true"
	res := result.new(msg, container)
}
