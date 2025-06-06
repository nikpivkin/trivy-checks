# METADATA
# title: "Ensure that the --streaming-connection-idle-timeout argument is not set to 0"
# description: "Do not disable timeouts on streaming connections."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   avd_id: AVD-KCV-0085
#   severity: HIGH
#   short_code: disable-timeouts-streaming-connections.
#   recommended_action: "Edit the kubelet service file /etc/kubernetes/kubelet.conf and set --streaming-connection-idle-timeout=5m "
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: nodeinfo
package builtin.kubernetes.KCV0085

import rego.v1

types := ["master", "worker"]

validate_kubelet_streaming_connection_idle_timeout_set(sp) := {"kubeletStreamingConnectionIdleTimeoutArgumentSet": violation} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	violation := {streaming_connection_idle_timeout | streaming_connection_idle_timeout = sp.info.kubeletStreamingConnectionIdleTimeoutArgumentSet.values[_]; streaming_connection_idle_timeout == 0}
	count(violation) > 0
}

deny contains res if {
	output := validate_kubelet_streaming_connection_idle_timeout_set(input)
	msg := "Ensure that the --streaming-connection-idle-timeout argument is not set to 0"
	res := result.new(msg, output)
}
