# METADATA
# title: "Access to host network"
# description: "Sharing the host’s network namespace permits processes in the pod to communicate with processes bound to the host’s loopback adapter."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline
# custom:
#   id: KSV-0009
#   aliases:
#     - AVD-KSV-0009
#     - KSV009
#     - no-host-network
#   long_id: kubernetes-no-host-network
#   severity: HIGH
#   recommended_action: "Do not set 'spec.template.spec.hostNetwork' to true."
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: pod
#           - kind: replicaset
#           - kind: replicationcontroller
#           - kind: deployment
#           - kind: deploymentconfig
#           - kind: statefulset
#           - kind: daemonset
#           - kind: cronjob
#           - kind: job
#   examples: checks/kubernetes/host_network.yaml
package builtin.kubernetes.KSV009

import rego.v1

import data.lib.kubernetes

default failHostNetwork := false

# failHostNetwork is true if spec.hostNetwork is set to true (on all controllers)
failHostNetwork if {
	kubernetes.host_networks[_] == true
}

deny contains res if {
	failHostNetwork
	msg := kubernetes.format(sprintf("%s '%s' should not set 'spec.template.spec.hostNetwork' to true", [kubernetes.kind, kubernetes.name]))
	res := result.new(msg, input.spec)
}
