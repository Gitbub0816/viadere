# Plan-time checks with mocked providers (no Azure credentials): `tofu test` in Infra/azure-authority.
mock_provider "azurerm" {
  mock_data "azurerm_virtual_network" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-net/providers/Microsoft.Network/virtualNetworks/vnet-viadere-stg"
    }
  }
  mock_data "azurerm_postgresql_flexible_server" {
    defaults = {
      id   = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-data/providers/Microsoft.DBforPostgreSQL/flexibleServers/psql-viadere-stgabc1l"
      fqdn = "psql-viadere-stgabc1l.postgres.database.azure.com"
    }
  }
  mock_data "azurerm_subnet" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-net/providers/Microsoft.Network/virtualNetworks/vnet-viadere-stg/subnets/snet-pe"
    }
  }
  mock_data "azurerm_private_dns_zone" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-net/providers/Microsoft.Network/privateDnsZones/privatelink.vaultcore.azure.net"
    }
  }
  mock_resource "azurerm_resource_group" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-auth"
    }
  }
  mock_resource "azurerm_key_vault" {
    defaults = {
      id        = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-auth/providers/Microsoft.KeyVault/vaults/kv-vdr-auth-stgabc1l"
      vault_uri = "https://kv-vdr-auth-stgabc1l.vault.azure.net/"
    }
  }
  mock_resource "azurerm_user_assigned_identity" {
    defaults = {
      id           = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-auth/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-mock"
      client_id    = "11111111-1111-1111-1111-111111111111"
      principal_id = "22222222-2222-2222-2222-222222222222"
    }
  }
  mock_resource "azurerm_subnet" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-net/providers/Microsoft.Network/virtualNetworks/vnet-viadere-stg/subnets/snet-auth"
    }
  }
  mock_resource "azurerm_container_registry" {
    defaults = {
      id           = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-auth/providers/Microsoft.ContainerRegistry/registries/crmock"
      login_server = "crmock.azurecr.io"
    }
  }
  mock_resource "azurerm_log_analytics_workspace" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-auth/providers/Microsoft.OperationalInsights/workspaces/log-mock"
    }
  }
  mock_resource "azurerm_application_insights" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-auth/providers/Microsoft.Insights/components/appi-mock"
    }
  }
  mock_resource "azurerm_private_dns_zone" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-auth/providers/Microsoft.Network/privateDnsZones/mock.centralus.azurecontainerapps.io"
    }
  }
  mock_resource "azurerm_network_security_group" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-mock"
    }
  }
  mock_resource "azurerm_role_definition" {
    defaults = {
      id                 = "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/roleDefinitions/11111111-1111-1111-1111-111111111111"
      role_definition_id = "11111111-1111-1111-1111-111111111111"
    }
  }
  mock_resource "azurerm_monitor_action_group" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-auth/providers/Microsoft.Insights/actionGroups/ag-mock"
    }
  }
  mock_resource "azurerm_container_app_job" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-auth/providers/Microsoft.App/jobs/job-mock"
    }
  }
}

mock_provider "azapi" {
  mock_resource "azapi_resource" {
    defaults = {
      id     = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-auth/providers/Microsoft.App/managedEnvironments/cae-mock"
      output = { properties = { defaultDomain = "mock.centralus.azurecontainerapps.io", staticIp = "10.40.4.5" } }
    }
  }
}

variables {
  environment       = "staging"
  subscription_id   = "00000000-0000-0000-0000-000000000000"
  tenant_id         = "00000000-0000-0000-0000-000000000000"
  name_suffix       = "abc1"
  github_repository = "viadere/viadere"
}

run "disabled_by_default_creates_nothing" {
  command = plan

  assert {
    condition     = length(azurerm_resource_group.auth) == 0 && length(azurerm_container_app.authority) == 0 && length(azurerm_key_vault.auth) == 0
    error_message = "with authority_enabled = false nothing may be created"
  }
}

run "enabled_lean_has_no_standby_role_and_no_public_ingress" {
  command = plan

  variables {
    authority_enabled        = true
    image                    = "crmock.azurecr.io/viadere-authority@sha256:0000000000000000000000000000000000000000000000000000000000000000"
    authority_entra_audience = "api://viadere-authority-staging"
  }

  assert {
    condition     = length(azurerm_role_assignment.rollover) == 0
    error_message = "a standby key must have no role without a recorded rollover"
  }
  assert {
    condition     = azurerm_container_app.authority[0].ingress[0].external_enabled == false && azurerm_container_app.authority[0].ingress[0].allow_insecure_connections == false
    error_message = "the authority ingress must be internal and HTTPS only"
  }
  assert {
    condition     = length(azapi_resource.kv_key) == 7 && length(azurerm_role_assignment.authority_key) == 5
    error_message = "lean HPKE construction: 4 signing + kek (active) + 2 standby keys = 7 (one signing standby, one kek standby), roles on the 5 active keys only"
  }
}

run "standard_uses_the_rsa_seal_and_no_kek" {
  command = plan

  variables {
    profile                  = "standard"
    authority_enabled        = true
    image                    = "crmock.azurecr.io/viadere-authority@sha256:0000000000000000000000000000000000000000000000000000000000000000"
    authority_entra_audience = "api://viadere-authority-staging"
  }

  assert {
    condition     = !contains(keys(azapi_resource.kv_key), "recovery-seal-kek") && contains(keys(azapi_resource.kv_key), "recovery-seal-rsa")
    error_message = "standard must use the RSA decrypt construction (C-16)"
  }
}

run "standby_grant_needs_a_change_file" {
  command = plan

  variables {
    authority_enabled        = true
    image                    = "crmock.azurecr.io/viadere-authority@sha256:0000000000000000000000000000000000000000000000000000000000000000"
    authority_entra_audience = "api://viadere-authority-staging"
    rollover_standby_grants  = ["device-statement-signing-standby"]
  }

  expect_failures = [azurerm_resource_group.auth]
}
