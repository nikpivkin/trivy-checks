# METADATA
# title: Cloud DNS should use DNSSEC
# description: |
#   DNSSEC authenticates DNS responses, preventing MITM attacks and impersonation.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   aliases:
#     - google-dns-enable-dnssec
#   avd_id: AVD-GCP-0013
#   provider: google
#   service: dns
#   severity: MEDIUM
#   short_code: enable-dnssec
#   recommended_action: Enable DNSSEC
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: dns
#             provider: google
#   examples: checks/cloud/google/dns/enable_dnssec.yaml
package builtin.google.dns.google0013

import rego.v1

deny contains res if {
	some zone in input.google.dns.managedzones
	zone.visibility.value != "private"
	zone.dnssec.enabled.value == false
	res := result.new("Managed zone does not have DNSSEC enabled.", zone.dnssec.enabled)
}
