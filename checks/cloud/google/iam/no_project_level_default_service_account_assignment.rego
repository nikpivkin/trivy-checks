# METADATA
# title: Roles should not be assigned to default service accounts
# description: |
#   Default service accounts should not be used - consider creating specialised service accounts for individual purposes.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
# custom:
#   id: GCP-0006
#   aliases:
#     - AVD-GCP-0006
#     - no-project-level-default-service-account-assignment
#   long_id: google-iam-no-project-level-default-service-account-assignment
#   provider: google
#   service: iam
#   severity: MEDIUM
#   recommended_action: Use specialised service accounts for specific purposes.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: google
#   examples: checks/cloud/google/iam/no_project_level_default_service_account_assignment.yaml
package builtin.google.iam.google0006

import rego.v1

import data.lib.google.iam

deny contains res if {
	some member in iam.members("projects")
	member.defaultserviceaccount.value
	res := result.new("Role is assigned to a default service account at project level.", member.defaultserviceaccount)
}

deny contains res if {
	some member in iam.members("projects")
	iam.is_member_default_service_account(member.member.value)
	res := result.new("Role is assigned to a default service account at project level.", member.member)
}

deny contains res if {
	some binding in iam.bindings("projects")
	binding.includesdefaultserviceaccount.value == true
	res := result.new("Role is assigned to a default service account at project level.", binding.includesdefaultserviceaccount)
}

deny contains res if {
	some binding in iam.bindings("projects")
	some member in binding.members
	iam.is_member_default_service_account(member.value)
	res := result.new("Role is assigned to a default service account at project level.", member)
}
