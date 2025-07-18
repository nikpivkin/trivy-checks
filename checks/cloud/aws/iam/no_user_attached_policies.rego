# METADATA
# title: IAM policies should not be granted directly to users.
# description: |
#   CIS recommends that you apply IAM policies directly to groups and roles but not users. Assigning privileges at the group or role level reduces the complexity of access management as the number of users grow. Reducing access management complexity might in turn reduce opportunity for a principal to inadvertently receive or retain excessive privileges.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://console.aws.amazon.com/iam/
# custom:
#   id: AWS-0143
#   aliases:
#     - AVD-AWS-0143
#     - no-user-attached-policies
#   long_id: aws-iam-no-user-attached-policies
#   provider: aws
#   service: iam
#   severity: LOW
#   recommended_action: Grant policies at the group level instead.
#   frameworks:
#     default:
#       - null
#     cis-aws-1.4:
#       - "1.15"
#     cis-aws-1.2:
#       - "1.16"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
#   examples: checks/cloud/aws/iam/no_user_attached_policies.yaml
package builtin.aws.iam.aws0143

import rego.v1

deny contains res if {
	some user in input.aws.iam.users
	count(user.policies) > 0

	res := result.new("One or more policies are attached directly to a user", user)
}
