# METADATA
# title: "Ensure that the --auto-tls argument is not set to true"
# description: "Do not use self-signed certificates for TLS."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0044
#   aliases:
#     - AVD-KCV-0044
#     - KCV0044
#     - ensure-auto-tls-argument-is-not-set-to-true
#   long_id: kubernetes-ensure-auto-tls-argument-is-not-set-to-true
#   severity: LOW
#   recommended_action: "Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and either remove the --auto-tls parameter or set it to false."
#   input:
#     selector:
#       - type: kubernetes
package builtin.kubernetes.KCV0044

import rego.v1

import data.lib.kubernetes

checkFlag(container) if {
	kubernetes.command_has_flag(container.command, "--auto-tls=true")
}

checkFlag(container) if {
	kubernetes.command_has_flag(container.args, "--auto-tls=true")
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_etcd(container)
	checkFlag(container)
	msg := "Ensure that the --auto-tls argument is not set to true"
	res := result.new(msg, container)
}
