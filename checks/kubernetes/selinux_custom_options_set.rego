# METADATA
# title: "SELinux custom options set"
# description: "According to pod security standard 'SElinux', setting custom SELinux options should be disallowed."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline
# custom:
#   id: KSV-0025
#   aliases:
#     - AVD-KSV-0025
#     - KSV025
#     - no-custom-selinux-options
#   long_id: kubernetes-no-custom-selinux-options
#   severity: MEDIUM
#   recommended_action: "Do not set 'spec.securityContext.seLinuxOptions', spec.containers[*].securityContext.seLinuxOptions and spec.initContainers[*].securityContext.seLinuxOptions."
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
#   examples: checks/kubernetes/selinux_custom_options_set.yaml
package builtin.kubernetes.KSV025

import rego.v1

import data.lib.kubernetes
import data.lib.utils

default failSELinux := false

allowed_selinux_types := ["container_t", "container_init_t", "container_kvm_t"]

getAllSecurityContexts contains context if {
	context := kubernetes.containers[_].securityContext
}

getAllSecurityContexts contains context if {
	context := kubernetes.pods[_].spec.securityContext
}

failSELinuxType contains type if {
	context := getAllSecurityContexts[_]

	trace(context.seLinuxOptions.type)
	context.seLinuxOptions != null
	context.seLinuxOptions.type != null

	not hasAllowedType(context.seLinuxOptions)

	type := context.seLinuxOptions.type
}

failForbiddenSELinuxProperties contains key if {
	context := getAllSecurityContexts[_]

	context.seLinuxOptions != null

	forbiddenProps := getForbiddenSELinuxProperties(context)
	key := forbiddenProps[_]
}

getForbiddenSELinuxProperties(context) := keys if {
	forbiddenProperties = ["role", "user"]
	keys := {msg |
		key := forbiddenProperties[_]
		utils.has_key(context.seLinuxOptions, key)
		msg := sprintf("'%s'", [key])
	}
}

hasAllowedType(options) if {
	allowed_selinux_types[_] == options.type
}

deny contains res if {
	type := failSELinuxType[_]
	msg := kubernetes.format(sprintf("%s '%s' uses invalid seLinux type '%s'", [kubernetes.kind, kubernetes.name, type]))
	res := result.new(msg, input.spec)
}

deny contains res if {
	keys := failForbiddenSELinuxProperties
	count(keys) > 0
	msg := kubernetes.format(sprintf("%s '%s' uses restricted properties in seLinuxOptions: (%s)", [kubernetes.kind, kubernetes.name, concat(", ", keys)]))
	res := result.new(msg, input.spec)
}
