
Use Customer Managed Keys to encrypt Performance Insights data

```hcl
resource "aws_rds_cluster_instance" "good_example" {
  name                            = "bar"
  performance_insights_enabled    = true
  performance_insights_kms_key_id = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
}
```
```hcl
resource "aws_rds_cluster_instance" "good_example" {
  name                         = "bar"
  performance_insights_enabled = false
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster_instance#performance_insights_kms_key_id

 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance#performance_insights_kms_key_id

