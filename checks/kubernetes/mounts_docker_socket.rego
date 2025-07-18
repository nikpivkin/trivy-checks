# METADATA
# title: "hostPath volume mounted with docker.sock"
# description: "Mounting docker.sock from the host can give the container full root access to the host."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubesec.io/basics/spec-volumes-hostpath-path-var-run-docker-sock/
# custom:
#   id: KSV-0006
#   aliases:
#     - AVD-KSV-0006
#     - KSV006
#     - no-docker-sock-mount
#   long_id: kubernetes-no-docker-sock-mount
#   severity: HIGH
#   recommended_action: "Do not specify /var/run/docker.socket in 'spec.template.volumes.hostPath.path'."
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
package builtin.kubernetes.KSV006

import rego.v1

import data.lib.kubernetes

name := input.metadata.name

default checkDockerSocket := false

# checkDockerSocket is true if volumes.hostPath.path is set to /var/run/docker.sock
# and is false if volumes.hostPath is set to some other path or not set.
checkDockerSocket if {
	volumes := kubernetes.volumes
	volumes[_].hostPath.path == "/var/run/docker.sock"
}

deny contains res if {
	checkDockerSocket
	msg := kubernetes.format(sprintf("%s '%s' should not specify '/var/run/docker.socker' in 'spec.template.volumes.hostPath.path'", [kubernetes.kind, kubernetes.name]))
	res := result.new(msg, input.spec)
}
