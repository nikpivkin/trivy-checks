# METADATA
# title: "Service with External IP"
# description: "Services with external IP addresses allows direct access from the internet and might expose risk for CVE-2020-8554"
# scope: package
# schemas:
# - input: schema["kubernetes"]
# custom:
#   avd_id: AVD-KSV-0108
#   severity: HIGH
#   short_code: no_svc_with_extip
#   recommended_action: "Do not set spec.externalIPs"
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: service
package builtin.kubernetes.KSV0108

import rego.v1

import data.lib.kubernetes

allowedIPs := set()

allowedNames := set()

# failExtIpsOrName is true if service has external IPs
failExtIpsOrName if {
	kubernetes.kind == "Service"
	externalIPs := {ip | ip := kubernetes.object.spec.externalIPs[_]}
	forbiddenIPs := externalIPs - allowedIPs
	count(forbiddenIPs) > 0
}

# failExtIpsOrName is true if service has external Name
failExtIpsOrName if {
	kubernetes.kind == "Service"
	not allowedNames[kubernetes.object.spec.externalName]
}

deny contains res if {
	failExtIpsOrName
	msg := kubernetes.format(sprintf("%s '%s' in '%s' namespace should not set external IPs or external Name", [kubernetes.kind, kubernetes.name, kubernetes.namespace]))
	res := result.new(msg, kubernetes.kind)
}
