# METADATA
# title: Instances should not have public IP addresses
# description: |
#   Instances should not be publicly exposed to the internet
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://cloud.google.com/compute/docs/ip-addresses#externaladdresses
# custom:
#   aliases:
#     - google-compute-no-public-ip
#   avd_id: AVD-GCP-0031
#   provider: google
#   service: compute
#   severity: HIGH
#   short_code: no-public-ip
#   recommended_action: Remove public IP
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: google
#   examples: checks/cloud/google/compute/no_public_ip.yaml
package builtin.google.compute.google0031

import rego.v1

deny contains res if {
	some instance in input.google.compute.instances
	some ni in instance.networkinterfaces
	ni.haspublicip.value == true
	res := result.new("Instance has a public IP allocated.", ni.haspublicip)
}
