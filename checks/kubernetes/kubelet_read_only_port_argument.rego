# METADATA
# title: "Verify that the --read-only-port argument is set to 0"
# description: "Disable the read-only port."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   avd_id: AVD-KCV-0082
#   severity: HIGH
#   short_code: verify-read-only-port-argument-set-0
#   recommended_action: "Disable the read-only port"
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: nodeinfo
package builtin.kubernetes.KCV0082

import rego.v1

types := ["master", "worker"]

validate_kubelet_read_only_set(sp) := {"kubeletReadOnlyPortArgumentSet": violation} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	violation := {read_only | read_only = sp.info.kubeletReadOnlyPortArgumentSet.values[_]; not read_only == 0}
	count(violation) > 0
}

deny contains res if {
	output := validate_kubelet_read_only_set(input)
	msg := "Verify that the --read-only-port argument is set to 0"
	res := result.new(msg, output)
}
