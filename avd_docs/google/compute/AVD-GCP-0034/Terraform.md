
Use managed keys to encrypt disks.

```hcl
resource "google_compute_disk" "good_example" {
  name                      = "test-disk"
  type                      = "pd-ssd"
  zone                      = "us-central1-a"
  image                     = "debian-9-stretch-v20200805"
  physical_block_size_bytes = 4096
  disk_encryption_key {
    kms_key_self_link = "something"
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_disk#kms_key_self_link

