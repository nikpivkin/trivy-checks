# METADATA
# title: "Do not allow attaching to shell on pods"
# description: "Check whether role permits attaching to shell on pods"
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV-0054
#   aliases:
#     - AVD-KSV-0054
#     - KSV054
#     - no-attaching-shell-pods
#   long_id: kubernetes-no-attaching-shell-pods
#   severity: HIGH
#   recommended_action: "Create a role which does not permit attaching to shell on pods"
#   input:
#     selector:
#       - type: kubernetes
package builtin.kubernetes.KSV054

import rego.v1

readKinds := ["Role", "ClusterRole"]

attach_shell_on_pod contains ruleA if {
	input.kind == readKinds[_]
	some i, j
	ruleA := input.rules[i]
	ruleB := input.rules[j]
	i < j
	ruleA.apiGroups[_] == "*"
	ruleA.resources[_] == "pods/attach"
	ruleA.verbs[_] == "create"
	ruleB.apiGroups[_] == "*"
	ruleB.resources[_] == "pods"
	ruleB.verbs[_] == "get"
}

deny contains res if {
	badRule := attach_shell_on_pod[_]
	msg := "Role permits attaching to shell on pods"
	res := result.new(msg, badRule)
}
