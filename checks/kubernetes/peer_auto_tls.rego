# METADATA
# title: "Ensure that the --peer-auto-tls argument is not set to true"
# description: "Do not use self-signed certificates for TLS."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   avd_id: AVD-KCV-0047
#   severity: LOW
#   short_code: ensure-peer-auto-tls-argument-is-not-set-to-true
#   recommended_action: "Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and either remove the --peer-auto-tls parameter or set it to false."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0047

import rego.v1

import data.lib.kubernetes

checkFlag(container) if {
	kubernetes.command_has_flag(container.command, "--peer-auto-tls=true")
}

checkFlag(container) if {
	kubernetes.command_has_flag(container.args, "--peer-auto-tls=true")
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_etcd(container)
	checkFlag(container)
	msg := "Ensure that the --peer-auto-tls argument is not set to true"
	res := result.new(msg, container)
}
