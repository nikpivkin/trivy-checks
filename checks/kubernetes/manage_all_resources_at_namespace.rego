# METADATA
# title: "Manage all resources at the namespace"
# description: "Full control of the resources within a namespace.  In some cluster configurations, this is excessive. In others, this is normal (a gitops deployment operator like flux)"
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV-0112
#   aliases:
#     - AVD-KSV-0112
#     - KSV112
#     - no-wildcard-resource-role
#   long_id: kubernetes-no-wildcard-resource-role
#   severity: CRITICAL
#   recommended_actions: "Remove '*' from 'rules.resources'. Provide specific list of resources to be managed by role in namespace"
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: role
package builtin.kubernetes.KSV112

import rego.v1

import data.lib.kubernetes

readVerbs := ["create", "update", "delete", "deletecollection", "impersonate", "*", "list", "get"]

readKinds := ["Role"]

managingAllResourcesAtNamespace contains input.rules[ru] if {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == "*"
	input.rules[ru].verbs[v] == readVerbs[_]
}

deny contains res if {
	badRule := managingAllResourcesAtNamespace[_]
	msg := kubernetes.format(sprintf("%s '%s' shouldn't manage all resources at the namespace '%s'", [kubernetes.kind, kubernetes.name, kubernetes.namespace]))
	res := result.new(msg, badRule)
}
