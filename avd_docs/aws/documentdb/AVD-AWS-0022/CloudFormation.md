
Enable encryption using customer managed keys

```yaml
Resources:
  GoodExample:
    Type: AWS::DocDB::DBCluster
    Properties:
      BackupRetentionPeriod: 8
      DBClusterIdentifier: sample-cluster
      DBClusterParameterGroupName: default.docdb3.6
      EnableCloudwatchLogsExports:
        - audit
        - profiler
      KmsKeyId: your-kms-key-id

  InstanceInstanceExample:
    Type: AWS::DocDB::DBInstance
    Properties:
      AutoMinorVersionUpgrade: true
      AvailabilityZone: us-east-1c
      DBClusterIdentifier: sample-cluster
      DBInstanceClass: db.r5.large
      DBInstanceIdentifier: sample-cluster-instance-0
      PreferredMaintenanceWindow: sat:06:54-sat:07:24
```


