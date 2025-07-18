# METADATA
# title: "Do not allow role binding creation and association with privileged role/clusterrole"
# description: "Check whether role permits creating role bindings and associating to privileged role/clusterrole"
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV-0051
#   aliases:
#     - AVD-KSV-0051
#     - KSV051
#     - do-not-allow-role-binding-associate-privileged-role
#   long_id: kubernetes-do-not-allow-role-binding-associate-privileged-role
#   severity: HIGH
#   recommended_action: "Create a role which does not permit creation of role bindings and associating with privileged cluster role"
#   input:
#     selector:
#       - type: kubernetes
package builtin.kubernetes.KSV051

import rego.v1

readKinds := ["Role", "ClusterRole"]

readroles := ["clusterroles", "roles"]

allowing_create_role_binding_and_associate_cluster_role contains ruleA if {
	input.kind == readKinds[_]
	some i, j
	ruleA := input.rules[i]
	ruleB := input.rules[j]
	i < j
	ruleA.apiGroups[_] == "rbac.authorization.k8s.io"
	ruleA.resources[_] == "rolebindings"
	ruleA.verbs[_] == "create"

	ruleB.apiGroups[_] == "rbac.authorization.k8s.io"
	ruleB.resources[_] == ["clusterroles", "roles"][_]
	ruleB.verbs[_] == "bind"
	ruleB.resourceNames[_] == "*"
}

deny contains res if {
	badRule := allowing_create_role_binding_and_associate_cluster_role[_]
	msg := "Role permits creation of role binding and association with privileged role"
	res := result.new(msg, badRule)
}
