
Enable HTTP token requirement for IMDS

```hcl
resource "aws_launch_template" "good_example" {
  image_id      = "ami-005e54dee72cc1d00"
  instance_type = "t2.micro"
  metadata_options {
    http_tokens = "required"
  }
}
```
```hcl
resource "aws_launch_configuration" "good_example" {
  image_id      = "ami-005e54dee72cc1d00"
  instance_type = "t2.micro"
  metadata_options {
    http_tokens = "required"
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#metadata-options

