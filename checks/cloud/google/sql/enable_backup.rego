# METADATA
# title: Enable automated backups to recover from data-loss
# description: |
#   Automated backups are not enabled by default. Backups are an easy way to restore data in a corruption or data-loss scenario.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://cloud.google.com/sql/docs/mysql/backup-recovery/backups
# custom:
#   aliases:
#     - google-sql-enable-backup
#   avd_id: AVD-GCP-0024
#   provider: google
#   service: sql
#   severity: MEDIUM
#   short_code: enable-backup
#   recommended_action: Enable automated backups
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sql
#             provider: google
#   examples: checks/cloud/google/sql/enable_backup.yaml
package builtin.google.sql.google0024

import rego.v1

deny contains res if {
	some instance in input.google.sql.instances
	instance.isreplica.value == false
	instance.settings.backups.enabled.value == false
	res := result.new("Database instance does not have backups enabled.", instance.settings.backups.enabled)
}
