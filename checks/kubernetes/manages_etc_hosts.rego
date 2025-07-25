# METADATA
# title: "Manages /etc/hosts"
# description: "Managing /etc/hosts aliases can prevent the container engine from modifying the file after a pod’s containers have already been started."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# custom:
#   id: KSV-0007
#   aliases:
#     - AVD-KSV-0007
#     - KSV007
#     - no-hostaliases
#   long_id: kubernetes-no-hostaliases
#   severity: LOW
#   recommended_action: "Do not set 'spec.template.spec.hostAliases'."
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
package builtin.kubernetes.KSV007

import rego.v1

import data.lib.kubernetes
import data.lib.utils

# failHostAliases is true if spec.hostAliases is set (on all controllers)
failHostAliases contains spec if {
	spec := kubernetes.host_aliases[_]
	utils.has_key(spec, "hostAliases")
}

deny contains res if {
	spec := failHostAliases[_]
	msg := kubernetes.format(sprintf("'%s' '%s' in '%s' namespace should not set spec.template.spec.hostAliases", [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))
	res := result.new(msg, spec)
}
