
Enable encryption using customer managed keys

```hcl
resource "aws_kms_key" "ebs_encryption" {
  enable_key_rotation = true
}

resource "aws_ebs_volume" "example" {
  kms_key_id = aws_kms_key.ebs_encryption.arn
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ebs_volume#kms_key_id

