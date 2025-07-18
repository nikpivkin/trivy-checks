# METADATA
# title: RDS Cluster and RDS instance should have backup retention longer than default 1 day
# description: |
#   RDS backup retention for clusters defaults to 1 day, this may not be enough to identify and respond to an issue. Backup retention periods should be set to a period that is a balance on cost and limiting risk.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html#USER_WorkingWithAutomatedBackups.BackupRetention
# custom:
#   id: AWS-0077
#   aliases:
#     - AVD-AWS-0077
#     - specify-backup-retention
#   long_id: aws-rds-specify-backup-retention
#   provider: aws
#   service: rds
#   severity: MEDIUM
#   recommended_action: Explicitly set the retention period to greater than the default
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: rds
#             provider: aws
#   examples: checks/cloud/aws/rds/specify_backup_retention.yaml
package builtin.aws.rds.aws0077

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some cluster in input.aws.rds.clusters
	has_low_backup_retention_period(cluster)
	res := result.new(
		"Cluster instance has very low backup retention period.",
		cluster.backupretentionperioddays,
	)
}

deny contains res if {
	some instance in input.aws.rds.instances
	has_low_backup_retention_period(instance)
	res := result.new(
		"Instance has very low backup retention period.",
		instance.backupretentionperioddays,
	)
}

has_low_backup_retention_period(instance) if {
	isManaged(instance)
	without_replication_source(instance)
	value.less_than(instance.backupretentionperioddays, 2)
}

without_replication_source(instance) if value.is_empty(instance.replicationsourcearn)

without_replication_source(instance) if not instance.replicationsourcearn
