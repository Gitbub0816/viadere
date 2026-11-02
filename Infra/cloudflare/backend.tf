# Remote state: the Azure state storage account of Infra/azure (Entra authentication, no storage key), container `tfstate`, its own
# key. A FRESH state (ADR-0029): the old GCS-backed state of Infra/terraform is not migrated; existing Cloudflare resources are
# imported (README). Values come from `tofu init -backend-config=backend.<env>.hcl` (template: backend.example.hcl).
terraform {
  backend "azurerm" {}
}
