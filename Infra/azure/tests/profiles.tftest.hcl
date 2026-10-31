# Plan-time checks of both profiles with mocked providers (no Azure credentials): `tofu test` in Infra/azure.
# They complement policy_check.py (which reads a real plan): here the module's own profile logic is exercised offline in CI.

mock_provider "azurerm" {
  mock_resource "azurerm_servicebus_namespace" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-app/providers/Microsoft.ServiceBus/namespaces/sb-mock"
    }
  }
  mock_resource "azurerm_application_insights" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-ops/providers/Microsoft.Insights/components/appi-mock"
    }
  }
  mock_resource "azurerm_log_analytics_workspace" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-ops/providers/Microsoft.OperationalInsights/workspaces/log-mock"
    }
  }
  mock_resource "azurerm_postgresql_flexible_server" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-data/providers/Microsoft.DBforPostgreSQL/flexibleServers/psql-mock"
    }
  }
  mock_resource "azurerm_private_dns_zone" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-net/providers/Microsoft.Network/privateDnsZones/mock.private.postgres.database.azure.com"
    }
  }
  mock_resource "azurerm_virtual_network" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-net/providers/Microsoft.Network/virtualNetworks/vnet-mock"
    }
  }
  mock_resource "azurerm_network_security_group" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-mock"
    }
  }
  mock_resource "azurerm_storage_account" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-data/providers/Microsoft.Storage/storageAccounts/stmock"
    }
  }
  mock_resource "azurerm_storage_container" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-data/providers/Microsoft.Storage/storageAccounts/stmock/blobServices/default/containers/audit-heads"
    }
  }
  mock_resource "azurerm_nat_gateway" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-net/providers/Microsoft.Network/natGateways/ng-mock"
    }
  }
  mock_resource "azurerm_public_ip" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-net/providers/Microsoft.Network/publicIPAddresses/pip-mock"
    }
  }
  mock_resource "azurerm_key_vault" {
    defaults = {
      vault_uri = "https://kv-vdr-stgabc1l.vault.azure.net/"
      id        = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-sec/providers/Microsoft.KeyVault/vaults/kv-vdr-stgabc1l"
    }
  }
  mock_resource "azurerm_user_assigned_identity" {
    defaults = {
      id           = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-sec/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-mock"
      client_id    = "11111111-1111-1111-1111-111111111111"
      principal_id = "22222222-2222-2222-2222-222222222222"
    }
  }
  mock_resource "azurerm_subnet" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-net/providers/Microsoft.Network/virtualNetworks/vnet-viadere-stg/subnets/snet-mock"
    }
  }
  mock_resource "azurerm_resource_group" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-mock"
    }
  }
  mock_resource "azurerm_container_registry" {
    defaults = {
      id           = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-app/providers/Microsoft.ContainerRegistry/registries/crmock"
      login_server = "crmock.azurecr.io"
    }
  }
}

mock_provider "azapi" {
  mock_resource "azapi_resource" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-viadere-stg-app/providers/Microsoft.App/managedEnvironments/cae-mock"
    }
  }
}

variables {
  environment              = "staging"
  subscription_id          = "00000000-0000-0000-0000-000000000000"
  tenant_id                = "00000000-0000-0000-0000-000000000001"
  name_suffix              = "abc1"
  github_repository        = "example/viadere"
  db_admin_group_object_id = "33333333-3333-3333-3333-333333333333"
  image                    = "ghcr.io/example/viadere/viadere-server@sha256:0000000000000000000000000000000000000000000000000000000000000000"
}

run "lean_is_the_default_and_has_no_fixed_fee_extras" {
  command = plan

  assert {
    condition     = var.profile == "lean"
    error_message = "lean must be the default profile"
  }
  assert {
    condition     = length(azurerm_private_endpoint.key_vault) + length(azurerm_private_endpoint.service_bus) + length(azurerm_private_endpoint.acr) + length(azurerm_private_endpoint.audit_blob) == 0
    error_message = "lean must not create private endpoints"
  }
  assert {
    condition     = length(azurerm_nat_gateway.this) == 0 && length(azurerm_public_ip.nat) == 0 && length(azurerm_container_registry.this) == 0
    error_message = "lean must not create a NAT gateway, public IP or registry"
  }
  assert {
    condition     = azurerm_servicebus_namespace.this.sku == "Basic" && azurerm_servicebus_namespace.this.local_auth_enabled == false
    error_message = "lean Service Bus must be Basic with local auth disabled"
  }
  assert {
    condition     = azurerm_key_vault.this.sku_name == "standard" && azurerm_key_vault.this.purge_protection_enabled && azurerm_key_vault.this.rbac_authorization_enabled
    error_message = "lean Key Vault must be Standard, RBAC, purge protection"
  }
  assert {
    condition     = azurerm_storage_account.brand.shared_access_key_enabled == false && azurerm_storage_account.brand.allow_nested_items_to_be_public == false && azurerm_storage_account.brand.network_rules[0].default_action == "Deny" && length(azurerm_storage_account.brand.network_rules[0].ip_rules) == 0 && azurerm_storage_container.brand_assets.container_access_type == "private" && length(azurerm_private_endpoint.brand_blob) == 0
    error_message = "lean brand storage: Entra only, private container, subnet-only firewall, no private endpoint"
  }
  assert {
    condition     = azapi_resource.kv_key["brand-manifest"].body.properties.curveName == "P-256" && azapi_resource.kv_key["brand-manifest"].body.properties.kty == "EC"
    error_message = "the brand-manifest key is EC P-256"
  }
  assert {
    condition     = azurerm_postgresql_flexible_server.this.sku_name == "B_Standard_B1ms" && azurerm_postgresql_flexible_server.this.version == "18" && azurerm_postgresql_flexible_server.this.storage_mb == 32768 && azurerm_postgresql_flexible_server.this.backup_retention_days == 7
    error_message = "lean PostgreSQL must be 18 on B1ms, 32 GiB, 7-day PITR"
  }
  assert {
    condition     = azurerm_postgresql_flexible_server.this.public_network_access_enabled == false && length(azurerm_postgresql_flexible_server.this.high_availability) == 0
    error_message = "PostgreSQL must be private; lean has no HA"
  }
  assert {
    condition     = azapi_resource.cae.body.properties.vnetConfiguration.internal == true && length(azapi_resource.cae.body.properties.workloadProfiles) == 1 && azapi_resource.cae.body.properties.workloadProfiles[0].workloadProfileType == "Consumption"
    error_message = "environment must be internal with only the Consumption profile"
  }
  assert {
    condition     = azurerm_container_app.api.ingress[0].external_enabled == false
    error_message = "api ingress must be internal"
  }
  assert {
    condition     = azapi_resource.kv_key["kek-data"].body.properties.kty == "RSA" && azapi_resource.kv_key["audit-head-signing"].body.properties.kty == "EC"
    error_message = "lean keys are software-protected"
  }
  assert {
    condition     = azurerm_log_analytics_workspace.this.daily_quota_gb == 0.15
    error_message = "lean log cap must stay inside the free allowance"
  }
  assert {
    condition     = length(azurerm_container_app.worker) == 0 && length(azurerm_container_app_job.scheduled) == 0
    error_message = "worker and scheduled jobs are placeholders, off by default"
  }
  assert {
    condition     = !contains([for s in azurerm_container_app.api.secret : s.name], "database-migration-url")
    error_message = "the api must never reference the migration URL"
  }
  assert {
    condition     = length(azurerm_container_app_job.migrate.secret) == 0 && !contains([for s in azurerm_container_app.api.secret : s.name], "database-url")
    error_message = "Entra-only by default (WP-B2): no database password is referenced anywhere"
  }
  assert {
    condition     = one([for e in azurerm_container_app.api.template[0].container[0].env : e.value if e.name == "DATABASE_AUTH"]) == "entra"
    error_message = "the api connects with its managed identity's Entra token"
  }
  assert {
    condition     = alltrue([for k, ra in azurerm_role_assignment.secret_user : can(regex("^workload:", ra.description))])
    error_message = "every workload assignment is classified"
  }
}

run "standard_profile" {
  command = plan

  variables {
    profile     = "standard"
    environment = "production"
  }

  assert {
    condition     = length(azurerm_private_endpoint.key_vault) == 1 && length(azurerm_private_endpoint.service_bus) == 1 && length(azurerm_private_endpoint.acr) == 1 && length(azurerm_private_endpoint.audit_blob) == 1
    error_message = "standard needs private endpoints for Key Vault, Service Bus, ACR and the audit blob"
  }
  assert {
    condition     = azurerm_key_vault.this.sku_name == "premium" && azurerm_key_vault.this.public_network_access_enabled == false
    error_message = "standard Key Vault must be Premium and private"
  }
  assert {
    condition     = azapi_resource.kv_key["kek-data"].body.properties.kty == "RSA-HSM" && azapi_resource.kv_key["kek-data"].body.properties.keySize == 3072 && azapi_resource.kv_key["kd-log-signing"].body.properties.kty == "EC-HSM" && azapi_resource.kv_key["kd-log-signing"].body.properties.curveName == "P-256"
    error_message = "standard keys: RSA-HSM 3072 wrap, EC-HSM P-256 sign"
  }
  assert {
    condition     = azurerm_servicebus_namespace.this.sku == "Premium" && azurerm_servicebus_namespace.this.public_network_access_enabled == false && azurerm_servicebus_namespace.this.local_auth_enabled == false
    error_message = "standard Service Bus: Premium, private, Entra only"
  }
  assert {
    condition     = azurerm_postgresql_flexible_server.this.high_availability[0].mode == "ZoneRedundant" && azurerm_postgresql_flexible_server.this.backup_retention_days == 35 && azurerm_postgresql_flexible_server.this.geo_redundant_backup_enabled
    error_message = "standard PostgreSQL: zone-redundant HA, 35-day PITR, geo-redundant backup"
  }
  assert {
    condition     = azurerm_storage_account.audit[0].shared_access_key_enabled == false && azurerm_storage_account.audit[0].public_network_access == "Disabled"
    error_message = "audit storage: Entra only, private"
  }
  assert {
    condition     = azurerm_storage_account.brand.public_network_access == "Disabled" && azurerm_storage_account.brand.shared_access_key_enabled == false && length(azurerm_private_endpoint.brand_blob) == 1 && azapi_resource.kv_key["brand-manifest"].body.properties.kty == "EC-HSM"
    error_message = "standard brand storage: private endpoint, public access disabled, Entra only; brand-manifest key EC-HSM"
  }
  assert {
    condition     = azurerm_container_registry.this[0].admin_enabled == false && azurerm_container_registry.this[0].public_network_access_enabled == false
    error_message = "registry: no admin user, private"
  }
  assert {
    condition     = azurerm_container_app.api.template[0].min_replicas == 2 && azapi_resource.cae.body.properties.zoneRedundant == true
    error_message = "standard api: 2 replicas in a zone-redundant environment"
  }
  assert {
    condition     = azurerm_federated_identity_credential.gh_deploy.subject == "repo:example/viadere:environment:production"
    error_message = "deploy identity is bound to the GitHub environment"
  }
}

run "worker_and_jobs_when_enabled" {
  command = plan

  variables {
    enable_worker         = true
    enable_scheduled_jobs = true
  }

  assert {
    condition     = length(azurerm_container_app.worker) == 1 && length(azurerm_container_app_job.scheduled) == 3
    error_message = "worker and three scheduled jobs"
  }
  assert {
    condition     = one([for e in azurerm_container_app.api.template[0].container[0].env : e.value if e.name == "RUN_BACKGROUND_JOBS"]) == "false"
    error_message = "with a worker, the api stops the in-process job loop"
  }
  assert {
    condition     = one([for e in azurerm_container_app.worker[0].template[0].container[0].env : e.value if e.name == "RUN_BACKGROUND_JOBS"]) == "false"
    error_message = "with the scheduled jobs, the worker leaves the sweeps to them"
  }
  assert {
    condition     = one([for e in azurerm_container_app.worker[0].template[0].container[0].env : e.value if e.name == "QUEUE_TRANSPORT"]) == "servicebus"
    error_message = "with a worker, messages travel over Service Bus"
  }
  assert {
    condition     = alltrue([for job in azurerm_container_app_job.scheduled : job.template[0].container[0].args[0] == "maintenance"])
    error_message = "scheduled jobs run `ViadereServer maintenance <task>`"
  }
}

# WP-B2: `migrate` runs with a database-only configuration (ROLE=migrate): with password authentication its job references the migration URL and
# nothing else; Entra-only, it references no secret at all, and no process gets a database password.
run "migrate_job_holds_no_service_secret" {
  command = plan
  variables {
    postgres_password_auth_enabled = true
  }

  assert {
    condition     = toset([for s in azurerm_container_app_job.migrate.secret : s.name]) == toset(["database-migration-url"])
    error_message = "the migrate job references only database-migration-url while password auth is on"
  }
  assert {
    condition     = one([for e in azurerm_container_app_job.migrate.template[0].container[0].env : e.value if e.name == "ROLE"]) == "migrate"
    error_message = "the migrate job runs with ROLE=migrate"
  }
}

# The default since WP-B2.
run "entra_only_postgres_has_no_database_password_anywhere" {
  command = plan
  variables {
    enable_worker = true
  }

  assert {
    condition     = length(azurerm_container_app_job.migrate.secret) == 0
    error_message = "Entra-only: the migrate job references no secret"
  }
  assert {
    condition     = !contains([for e in azurerm_container_app.api.template[0].container[0].env : e.name], "DATABASE_URL") && !contains([for e in azurerm_container_app.worker[0].template[0].container[0].env : e.name], "DATABASE_URL")
    error_message = "Entra-only: no process gets DATABASE_URL"
  }
  assert {
    condition     = one([for e in azurerm_container_app.api.template[0].container[0].env : e.value if e.name == "DATABASE_AUTH"]) == "entra"
    error_message = "Entra-only: DATABASE_AUTH=entra"
  }
  assert {
    condition     = !contains(keys(azapi_resource.kv_secret), "database-url") && !contains(keys(azapi_resource.kv_secret), "database-migration-url")
    error_message = "Entra-only: the database secrets are not created"
  }
}

run "rejects_unpinned_image" {
  command = plan
  variables {
    image = "ghcr.io/example/viadere/viadere-server:latest"
  }
  expect_failures = [var.image]
}

run "rejects_migration_url_on_the_api" {
  command = plan
  variables {
    app_secret_env = { DATABASE_MIGRATION_URL = "database-migration-url" }
  }
  expect_failures = [var.app_secret_env]
}

run "first_apply_sets_the_admin_password_write_only" {
  command = plan
  variables {
    postgres_password_auth_enabled = true # the opt-in password fallback (needs the CLAUDE.md exception row)
    postgres_set_admin_password    = true
    postgres_admin_password        = "only-in-this-test-not-a-secret"
  }
  assert {
    condition     = azurerm_postgresql_flexible_server.this.administrator_password_wo_version == 1
    error_message = "the write-only password is sent with its version on the first apply"
  }
}

run "lean_private_ghcr_package" {
  command = plan
  variables {
    ghcr_pull_username = "viadere-bot"
  }
  assert {
    condition     = azurerm_container_app.api.registry[0].server == "ghcr.io" && azurerm_container_app.api.registry[0].password_secret_name == "ghcr-pull-token" && contains([for s in azurerm_container_app.api.secret : s.name], "ghcr-pull-token")
    error_message = "a private GHCR package is pulled with the read:packages token from Key Vault"
  }
  assert {
    condition     = contains(keys(azapi_resource.kv_secret), "ghcr-pull-token") && contains(keys(azurerm_role_assignment.secret_user), "api/ghcr-pull-token")
    error_message = "the pull token is a Key Vault secret readable by the api identity only through its own assignment"
  }
}
