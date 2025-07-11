# METADATA
# title: "Memory requests not specified"
# description: "When containers have memory requests specified, the scheduler can make better decisions about which nodes to place pods on, and how to deal with resource contention."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubesec.io/basics/containers-resources-limits-memory/
# custom:
#   id: KSV-0016
#   aliases:
#     - AVD-KSV-0016
#     - KSV016
#     - no-unspecified-memory-requests
#   long_id: kubernetes-no-unspecified-memory-requests
#   severity: LOW
#   recommended_action: "Set 'containers[].resources.requests.memory'."
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
package builtin.kubernetes.KSV016

import rego.v1

import data.lib.kubernetes
import data.lib.utils

default failRequestsMemory := false

# getRequestsMemoryContainers returns all containers which have set resources.requests.memory
getRequestsMemoryContainers contains container if {
	container := kubernetes.containers[_]
	utils.has_key(container.resources.requests, "memory")
}

# getNoRequestsMemoryContainers returns all containers which have not set
# resources.requests.memory
getNoRequestsMemoryContainers contains container if {
	container := kubernetes.containers[_]
	not getRequestsMemoryContainers[container]
}

deny contains res if {
	output := getNoRequestsMemoryContainers[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'resources.requests.memory'", [output.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}
