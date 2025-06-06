# METADATA
# title: "No wildcard verb and resource roles"
# description: "Check whether role permits wildcard verb on wildcard resource"
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   avd_id: AVD-KSV-0044
#   severity: CRITICAL
#   short_code: no-wildcard-verb-resource-role
#   recommended_action: "Create a role which does not permit wildcard verb on wildcard resource"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV044

import rego.v1

readKinds := ["Role", "ClusterRole"]

anyAnyResource contains input.rules[ru] if {
	some ru
	input.kind == readKinds[_]
	input.rules[ru].apiGroups[_] == "*"
	input.rules[ru].resources[_] == "*"
	input.rules[ru].verbs[_] == "*"
}

deny contains res if {
	badRule := anyAnyResource[_]
	msg := "Role permits wildcard verb on wildcard resource"
	res := result.new(msg, badRule)
}
