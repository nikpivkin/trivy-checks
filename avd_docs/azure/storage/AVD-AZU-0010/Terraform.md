
Allow Trusted Microsoft Services to bypass

```hcl
resource "azurerm_storage_account" "good_example" {
  name                = "storageaccountname"
  resource_group_name = azurerm_resource_group.example.name

  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  network_rules {
    default_action = "Deny"
    ip_rules       = ["100.0.0.1"]
    bypass         = ["Metrics", "AzureServices"]
  }
}
```
```hcl
resource "azurerm_storage_account" "good_example" {
  name                = "storageaccountname"
  resource_group_name = azurerm_resource_group.example.name
}

resource "azurerm_storage_account_network_rules" "test" {
  resource_group_name  = azurerm_resource_group.test.name
  storage_account_name = azurerm_storage_account.good_example.name

  default_action = "Allow"
  ip_rules       = ["127.0.0.1"]
  bypass         = ["Metrics", "AzureServices"]
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#bypass

 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account_network_rules#bypass

