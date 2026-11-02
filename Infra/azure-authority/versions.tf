# Private authority tier (ADR-0019, ADR-0028, ADR-0034; docs/architecture/TRUST_BOUNDARIES.md section 9). Its own OpenTofu root, its own state
# key and its own apply identity (id-gh-infra-auth-apply-<env>), so that applying the ordinary tier (Infra/azure) can never touch it and the
# other way round (ADR-0028 section 7). DISABLED BY DEFAULT: with `authority_enabled = false` the plan is empty and nothing bills.
# Owner steps to enable it: docs/ops/AUTHORITY-OWNER-CHECKLIST.md.
#
# Versions are the ones of Infra/azure (checked 2026-10-29, re-checked 2026-11-02 in CLAUDE.md "Current versions"):
#   OpenTofu 1.13.2, hashicorp/azurerm 5.12.0, azure/azapi 2.13.0.
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

  # Own state key (viadere/azure-authority/<env>.tfstate) in the same Entra-only state account (backend.example.hcl).
  backend "azurerm" {}
}

provider "azurerm" {
  subscription_id                 = var.subscription_id
  tenant_id                       = var.tenant_id
  storage_use_azuread             = true
  resource_provider_registrations = "none"

  features {
    key_vault {
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
