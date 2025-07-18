# METADATA
# title: "Kubernetes resource with disallowed volumes mounted"
# description: "HostPath present many security risks and as a security practice it is better to avoid critical host paths mounts."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted
# custom:
#   id: KSV-0121
#   aliases:
#     - AVD-KSV-0121
#     - KSV121
#     - no-k8s-with-disallowed-volumes
#   long_id: kubernetes-no-k8s-with-disallowed-volumes
#   severity: HIGH
#   recommended_action: "Do not Set 'spec.volumes[*].hostPath.path' to any of the disallowed volumes."
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
package builtin.kubernetes.KSV121

import rego.v1

import data.lib.kubernetes

# Add disallowed volume type
disallowedVolumes := [
	"/",
	"/boot",
	"/dev",
	"/etc",
	"/lib",
	"/proc",
	"/sys",
	"/usr",
	"/var/lib/docker",
]

# getDisallowedVolumes returns a list of volumes
# which are set to any of the disallowed hostPath volumes
getDisallowedVolumes contains path if {
	hostpath := kubernetes.volumes[_].hostPath.path
	volume := disallowedVolumes[_]
	volume == hostpath
	path := hostpath
}

# failVolumes is true if any of volume has a disallowed volumes
failVolumes if {
	count(getDisallowedVolumes) > 0
}

deny contains res if {
	failVolumes
	msg := kubernetes.format(sprintf("%s %s in %s namespace shouldn't have volumes set to %s", [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace, getDisallowedVolumes]))
	res := result.new(msg, input.spec)
}
