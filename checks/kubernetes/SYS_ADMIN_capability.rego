# METADATA
# title: "SYS_ADMIN capability added"
# description: "SYS_ADMIN gives the processes running inside the container privileges that are equivalent to root."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubesec.io/basics/containers-securitycontext-capabilities-add-index-sys-admin/
# custom:
#   id: KSV-0005
#   aliases:
#     - AVD-KSV-0005
#     - KSV005
#     - no-sysadmin-capability
#   long_id: kubernetes-no-sysadmin-capability
#   severity: HIGH
#   recommended_action: "Remove the SYS_ADMIN capability from 'containers[].securityContext.capabilities.add'."
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
package builtin.kubernetes.KSV005

import rego.v1

import data.lib.kubernetes

default failCapsSysAdmin := false

# getCapsSysAdmin returns the names of all containers which include
# 'SYS_ADMIN' in securityContext.capabilities.add.
getCapsSysAdmin contains container if {
	container := kubernetes.containers[_]
	container.securityContext.capabilities.add[_] == "SYS_ADMIN"
}

deny contains res if {
	output := getCapsSysAdmin[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should not include 'SYS_ADMIN' in 'securityContext.capabilities.add'", [output.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}
