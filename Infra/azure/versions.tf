# Azure landing zone (WP-B1, docs/IMPLEMENTATION-PLAN-v3.md section 5; ADR-0010..0014). Applied once per environment (staging and production
# live in separate subscriptions and separate state files). Owner guide: docs/ops/AZURE-SETUP.md.
#
# Versions checked 2026-10-29 (CLAUDE.md "Current versions"):
#   OpenTofu 1.13.2           https://get.opentofu.org/tofu/api.json
#   hashicorp/azurerm 5.12.0  https://registry.opentofu.org/v1/providers/hashicorp/azurerm/versions (also latest on registry.terraform.io)
#   azure/azapi 2.13.0        https://registry.opentofu.org/v1/providers/azure/azapi/versions
# azapi is used only where azurerm has no resource or property: the Container Apps environment (peer-to-peer encryption, Azure Monitor log
# destination, public network access) and Key Vault keys/secret placeholders created through the ARM control plane (so no data-plane network
# path or data-plane role is needed by OpenTofu, and secret values never enter the state).
terraform {
  required_version = ">= 1.13.2"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "5.12.0"
    }
    azapi = {
      source  = "azure/azapi"
      version = "2.13.0"
    }
  }

  # Remote state: Azure Storage with Entra ID authentication (no storage account key), blob versioning, soft delete and a CanNotDelete lock
  # on the state resource group. Values come from `tofu init -backend-config=backend.<env>.hcl` (template: backend.example.hcl; bootstrap:
  # docs/ops/AZURE-SETUP.md section 3). Nothing environment-specific is committed.
  backend "azurerm" {}
}

provider "azurerm" {
  subscription_id = var.subscription_id
  tenant_id       = var.tenant_id
  # Data-plane calls to Storage (containers) use Entra ID, never shared keys (shared keys are disabled on every account).
  storage_use_azuread = true
  # Resource providers are registered once in the bootstrap (AZURE-SETUP.md section 2) so the apply identity needs no subscription-wide
  # register permission.
  resource_provider_registrations = "none"

  features {
    key_vault {
      # Never purge: purge protection is on, and a destroyed vault must stay recoverable for its retention period.
      purge_soft_delete_on_destroy          = false
      purge_soft_deleted_keys_on_destroy    = false
      purge_soft_deleted_secrets_on_destroy = false
      recover_soft_deleted_key_vaults       = false
    }
    resource_group {
      prevent_deletion_if_contains_resources = true
    }
    log_analytics_workspace {
      permanently_delete_on_destroy = false
    }
  }
}

provider "azapi" {
  subscription_id = var.subscription_id
  tenant_id       = var.tenant_id
}
