# METADATA
# title: "Delete pod logs"
# description: "Used to cover attacker’s tracks, but most clusters ship logs quickly off-cluster."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV-0042
#   aliases:
#     - AVD-KSV-0042
#     - KSV042
#     - no-delete-pod-logs
#   long_id: kubernetes-no-delete-pod-logs
#   severity: MEDIUM
#   recommended_action: "Remove verbs 'delete' and 'deletecollection' for resource 'pods/log' for Role and ClusterRole"
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: clusterrole
#           - kind: role
package builtin.kubernetes.KSV042

import rego.v1

import data.lib.kubernetes

readVerbs := ["delete", "deletecollection", "*"]

readKinds := ["Role", "ClusterRole"]

deletePodsLogRestricted contains input.rules[ru] if {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == "pods/log"
	input.rules[ru].verbs[v] == readVerbs[_]
}

deny contains res if {
	badRule := deletePodsLogRestricted[_]
	msg := kubernetes.format(sprintf("%s '%s' should not have access to resource 'pods/log' for verbs %s", [kubernetes.kind, kubernetes.name, readVerbs]))
	res := result.new(msg, badRule)
}
