# METADATA
# title: "Manage Kubernetes workloads and pods"
# description: "Depending on the policies enforced by the admission controller, this permission ranges from the ability to steal compute (crypto) by running workloads or allowing for creating workloads that escape to the node as root and escalation to cluster-admin."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV-0048
#   aliases:
#     - AVD-KSV-0048
#     - KSV048
#     - deny-create-update-malicious-pod
#   long_id: kubernetes-deny-create-update-malicious-pod
#   severity: MEDIUM
#   recommended_action: "Kubernetes workloads resources are only allowed for verbs 'list', 'watch', 'get'"
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: clusterrole
#           - kind: role
package builtin.kubernetes.KSV048

import rego.v1

import data.lib.kubernetes

workloads := ["pods", "deployments", "jobs", "cronjobs", "statefulsets", "daemonsets", "replicasets", "replicationcontrollers"]

changeVerbs := ["create", "update", "patch", "delete", "deletecollection", "impersonate", "*"]

readKinds := ["Role", "ClusterRole"]

update_malicious_pod contains input.rules[ru] if {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == workloads[_]
	input.rules[ru].verbs[v] == changeVerbs[_]
}

deny contains res if {
	badRule := update_malicious_pod[_]
	msg := kubernetes.format(sprintf("%s '%s' should not have access to resources %s for verbs %s", [kubernetes.kind, kubernetes.name, workloads, changeVerbs]))
	res := result.new(msg, badRule)
}
