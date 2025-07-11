# METADATA
# title: "Ensure that the --event-qps argument is set to 0 or a level which ensures appropriate event capture"
# description: "Security relevant information should be captured. The --event-qps flag on the Kubelet can be used to limit the rate at which events are gathered"
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0087
#   aliases:
#     - AVD-KCV-0087
#     - KCV0087
#     - ensure-event-qps argument-set-0-or-level-forappropriate-event-capture
#   long_id: kubernetes-ensure-event-qps argument-set-0-or-level-forappropriate-event-capture
#   severity: HIGH
#   recommended_action: "If using a Kubelet config file, edit the file to set eventRecordQPS: to an appropriate level. If using command line arguments, edit the kubelet service file"
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: nodeinfo
package builtin.kubernetes.KCV0087

import rego.v1

types := ["master", "worker"]

validate_kubelet_event_qps_set(sp) := {"kubeletEventQpsArgumentSet": violation} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	violation := {event_qps | event_qps = sp.info.kubeletEventQpsArgumentSet.values[_]; event_qps < 0}
	count(violation) > 0
}

deny contains res if {
	output := validate_kubelet_event_qps_set(input)
	msg := "Ensure that the --event-qps argument is set to 0 or a level which ensures appropriate event capture"
	res := result.new(msg, output)
}
