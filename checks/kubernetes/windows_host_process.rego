# METADATA
# title: "Access to host process"
# description: "Windows pods offer the ability to run HostProcess containers which enable privileged access to the Windows node."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline
# custom:
#   id: KSV-0103
#   aliases:
#     - AVD-KSV-0103
#     - KSV103
#     - no-hostprocess-containers
#   long_id: kubernetes-no-hostprocess-containers
#   severity: MEDIUM
#   recommended_action: "Do not enable 'hostProcess' on any securityContext"
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
package builtin.kubernetes.KSV103

import rego.v1

import data.lib.kubernetes

failHostProcess contains spec if {
	spec := input.spec
	spec.securityContext.windowsOptions.hostProcess == true
}

failHostProcess contains options if {
	container := kubernetes.containers[_]
	options := container.securityContext.windowsOptions
	options.hostProcess == true
}

deny contains res if {
	cause := failHostProcess[_]
	msg := "You should not enable hostProcess."
	res := result.new(msg, cause)
}
