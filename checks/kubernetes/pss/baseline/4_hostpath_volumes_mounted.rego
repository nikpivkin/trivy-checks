# METADATA
# entrypoint: true
# title: "hostPath volumes mounted"
# description: "According to pod security standard 'HostPath Volumes', HostPath volumes must be forbidden."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline
# custom:
#   id: KSV023
#   avd_id: AVD-KSV-0023
#   severity: MEDIUM
#   short_code: no-mounted-hostpath
#   recommended_action: "Do not set 'spec.volumes[*].hostPath'."
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: pod
#         - kind: replicaset
#         - kind: replicationcontroller
#         - kind: deployment
#         - kind: deploymentconfig
#         - kind: statefulset
#         - kind: daemonset
#         - kind: cronjob
#         - kind: job
#   examples: checks/kubernetes/pss/baseline/4_hostpath_volumes_mounted.yaml
package builtin.kubernetes.KSV023

import rego.v1

import data.lib.kubernetes
import data.lib.utils

default failHostPathVolume := false

failHostPathVolume if {
	volumes := kubernetes.volumes
	utils.has_key(volumes[_], "hostPath")
}

deny contains res if {
	failHostPathVolume
	msg := kubernetes.format(sprintf("%s '%s' should not set 'spec.template.volumes.hostPath'", [kubernetes.kind, kubernetes.name]))
	res := result.new(msg, input.spec)
}
