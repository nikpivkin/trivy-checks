# METADATA
# title: "Ensure that the Kubernetes PKI key file permission is set to 600"
# description: "Ensure that the Kubernetes PKI key file permission is set to 600."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0067
#   aliases:
#     - AVD-KCV-0067
#     - KCV0067
#     - ensure-kubernetes-pki-key-file-permission-set-600.
#   long_id: kubernetes-ensure-kubernetes-pki-key-file-permission-set-600.
#   severity: CRITICAL
#   recommended_action: "Change the Kubernetes PKI key file /etc/kubernetes/pki/*.key permission to 600"
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: nodeinfo
package builtin.kubernetes.KCV0067

import rego.v1

validate_pki_key_permission(sp) := {"kubePKIKeyFilePermissions": violation} if {
	sp.kind == "NodeInfo"
	sp.type == "master"
	violation := {permission | permission = sp.info.kubePKIKeyFilePermissions.values[_]; permission > 600}
	count(violation) > 0
}

deny contains res if {
	output := validate_pki_key_permission(input)
	msg := "Ensure that the Kubernetes PKI key file permission is set to 600"
	res := result.new(msg, output)
}
