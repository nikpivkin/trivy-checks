# METADATA
# title: At least one email address is set for threat alerts
# description: |
#   SQL Server sends alerts for threat detection via email, if there are no email addresses set then mitigation will be delayed.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AZU-0018
#   aliases:
#     - AVD-AZU-0018
#     - threat-alert-email-set
#   long_id: azure-database-threat-alert-email-set
#   provider: azure
#   service: database
#   severity: MEDIUM
#   recommended_action: Provide at least one email address for threat alerts
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: database
#             provider: azure
#   examples: checks/cloud/azure/database/threat_alert_email_set.yaml
package builtin.azure.database.azure0018

import rego.v1

deny contains res if {
	some server in input.azure.database.mssqlservers
	some policy in server.securityalertpolicies
	not has_emails(policy)
	res := result.new(
		"Security alert policy does not include any email addresses for notification.",
		policy,
	)
}

has_emails(policy) := count(policy.emailaddresses) > 0
