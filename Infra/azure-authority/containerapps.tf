# The authority's Container Apps environment and workloads (ADR-0019 sections 2-5, TRUST_BOUNDARIES section 9).
#  * cae-viadere-<env>-auth: its OWN workload-profiles environment (Consumption profile only, no fixed fee), INTERNAL, public network access
#    disabled, in snet-auth, peer-to-peer encryption on. A separate environment, not a separate app in the ordinary one: network isolation,
#    NSG and diagnostics differ, and nothing of the ordinary tier shares its control plane scope (AUTH-IDENTITY-SEPARATE).
#  * ca-viadere-authority: ingress internal only (external_enabled = false) and HTTPS only (allow_insecure_connections = false). There is no
#    tunnel route, no Cloudflare hostname, no public IP.
#  * job-viadere-authority-admin (reviewer-gated `ViadereAuthority admin <command> --change-file`), job-viadere-authority-migrate.
# INTERFACE ASSUMPTION (reconcile with ViadereAuthorityKit's configuration when it lands): the AUTHORITY_* and DATABASE_* variable names and the
# executable path /app/ViadereAuthority. Infra/azure/check_env_coverage.py covers the ordinary server only.

resource "azapi_resource" "cae" {
  count     = local.on
  type      = "Microsoft.App/managedEnvironments@2026-01-01"
  name      = local.cae_name
  parent_id = azurerm_resource_group.auth[0].id
  location  = var.location
  tags      = local.tags

  body = {
    properties = {
      workloadProfiles = [{
        name                = "Consumption"
        workloadProfileType = "Consumption"
      }]
      vnetConfiguration = {
        infrastructureSubnetId = azurerm_subnet.auth[0].id
        internal               = true
      }
      infrastructureResourceGroup = "rg-viadere-${local.env}-auth-cae-infra"
      zoneRedundant               = local.standard
      publicNetworkAccess         = "Disabled"
      peerTrafficConfiguration = {
        encryption = { enabled = true }
      }
      appLogsConfiguration = {
        destination = "azure-monitor"
      }
    }
  }

  replace_triggers_external_values = [local.standard, azurerm_subnet.auth[0].id]
  response_export_values           = ["properties.defaultDomain", "properties.staticIp"]

  depends_on = [azurerm_subnet_network_security_group_association.auth]
}

locals {
  authority_base_env = local.on == 0 ? {} : merge(var.authority_env, {
    ENVIRONMENT                  = var.environment
    PORT                         = "8080"
    BIND_HOST                    = "0.0.0.0"
    AZURE_TENANT_ID              = var.tenant_id
    AZURE_KEY_VAULT_URL          = azurerm_key_vault.auth[0].vault_uri
    DATABASE_HOST                = data.azurerm_postgresql_flexible_server.ordinary[0].fqdn
    DATABASE_NAME                = local.authority_db
    DATABASE_AUTH                = "entra"
    AUTHORITY_ENTRA_AUDIENCE     = var.authority_entra_audience
    AUTHORITY_CALLER_OIDS        = join(",", [for k, v in var.authority_caller_object_ids : "${k}:${v}"])
    AUTHORITY_OUTBOUND_ALLOWLIST = local.outbound_allowlist
  })

  # Explicit key NAMES (versions are pinned by the admin job, never "latest": ADR-0028 section 2).
  authority_key_env = {
    AUTHORITY_KEY_GRANT_SIGNING    = "grant-signing"
    AUTHORITY_KEY_OIDC_RS256       = "oidc-signing-rs256"
    AUTHORITY_KEY_OIDC_ES256       = "oidc-signing-es256"
    AUTHORITY_KEY_DEVICE_STATEMENT = "device-statement-signing"
    AUTHORITY_KEY_SEAL_KEK         = local.p.jwe_rsa_seal ? "" : "recovery-seal-kek"
    AUTHORITY_KEY_SEAL_RSA         = local.p.jwe_rsa_seal ? "recovery-seal-rsa" : ""
  }

  authority_probe_headers = { "X-Forwarded-Proto" = "https" }
}

resource "azurerm_container_app" "authority" {
  count                        = local.on
  name                         = local.app_name
  container_app_environment_id = azapi_resource.cae[0].id
  resource_group_name          = azurerm_resource_group.auth[0].name
  workload_profile_name        = "Consumption"
  revision_mode                = "Single"
  max_inactive_revisions       = 10
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.authority[0].id]
  }

  dynamic "secret" {
    for_each = toset(values(local.authority_secrets))
    content {
      name                = secret.value
      key_vault_secret_id = "${azurerm_key_vault.auth[0].vault_uri}secrets/${secret.value}"
      identity            = azurerm_user_assigned_identity.authority[0].id
    }
  }

  registry {
    server   = azurerm_container_registry.auth[0].login_server
    identity = azurerm_user_assigned_identity.authority[0].id
  }

  ingress {
    external_enabled           = false # environment-internal: reachable from snet-cae only (NSG), never from the Internet (AUTH-NO-PUBLIC-INGRESS)
    target_port                = 8080
    transport                  = "http"
    allow_insecure_connections = false # HTTPS to the internal FQDN (ADR-0019 section 4.1)
    client_certificate_mode    = "ignore"
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    min_replicas                     = local.min_replicas
    max_replicas                     = var.authority_max_replicas
    termination_grace_period_seconds = 30

    http_scale_rule {
      name                = "http-concurrency"
      concurrent_requests = "50"
    }

    container {
      name   = "authority"
      image  = var.image
      cpu    = local.p.app_cpu
      memory = local.p.app_memory

      dynamic "env" {
        for_each = merge(local.authority_base_env, local.authority_key_env, {
          AZURE_CLIENT_ID   = azurerm_user_assigned_identity.authority[0].client_id
          DATABASE_USER     = local.db_roles.runtime
          AUTHORITY_ENABLED = tostring(var.authority_flag_enabled)
        })
        content {
          name  = env.key
          value = env.value
        }
      }
      dynamic "env" {
        for_each = local.authority_secrets
        content {
          name        = env.key
          secret_name = env.value
        }
      }

      startup_probe {
        transport               = "HTTP"
        port                    = 8080
        path                    = "/healthz"
        interval_seconds        = 5
        timeout                 = 3
        failure_count_threshold = 24
        dynamic "header" {
          for_each = local.authority_probe_headers
          content {
            name  = header.key
            value = header.value
          }
        }
      }
      liveness_probe {
        transport               = "HTTP"
        port                    = 8080
        path                    = "/healthz"
        interval_seconds        = 15
        timeout                 = 3
        failure_count_threshold = 3
        dynamic "header" {
          for_each = local.authority_probe_headers
          content {
            name  = header.key
            value = header.value
          }
        }
      }
      readiness_probe {
        transport               = "HTTP"
        port                    = 8080
        path                    = "/readyz"
        interval_seconds        = 15
        timeout                 = 5
        failure_count_threshold = 3
        success_count_threshold = 1
        dynamic "header" {
          for_each = local.authority_probe_headers
          content {
            name  = header.key
            value = header.value
          }
        }
      }
    }
  }

  lifecycle {
    # authority-deploy.yml owns the image (update by digest after the authority migrate job succeeded) and the revision.
    ignore_changes = [template[0].container[0].image, template[0].revision_suffix]
  }

  depends_on = [azurerm_role_assignment.authority_secret, azurerm_role_assignment.acr_pull, azurerm_role_assignment.authority_key]
}

# ---- Admin job: reviewer-gated commands that INCREASE authority (ADR-0019 section 5). DB role viadere_authority_admin, NO Key Vault role
# (AUTH-ADMIN-NO-KV): seal keys are wrapped under attested KEK public halves (ADR-0034 section 5.1). -----------------------------------------
resource "azurerm_container_app_job" "admin" {
  count                        = local.on
  name                         = local.admin_job
  location                     = var.location
  resource_group_name          = azurerm_resource_group.auth[0].name
  container_app_environment_id = azapi_resource.cae[0].id
  workload_profile_name        = "Consumption"
  replica_timeout_in_seconds   = 900
  replica_retry_limit          = 0
  tags                         = local.tags

  manual_trigger_config {
    parallelism              = 1
    replica_completion_count = 1
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.authority_admin[0].id]
  }

  registry {
    server   = azurerm_container_registry.auth[0].login_server
    identity = azurerm_user_assigned_identity.authority_admin[0].id
  }

  template {
    container {
      name    = "admin"
      image   = var.image
      cpu     = local.p.app_cpu
      memory  = local.p.app_memory
      command = ["/app/ViadereAuthority"]
      args    = ["admin", "--help"] # authority-admin.yml overrides the arguments per run (command + --change-file)

      dynamic "env" {
        for_each = merge(local.authority_base_env, {
          AZURE_CLIENT_ID = azurerm_user_assigned_identity.authority_admin[0].client_id
          DATABASE_USER   = local.db_roles.admin
        })
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [template[0].container[0].image, template[0].container[0].args]
  }

  depends_on = [azurerm_role_assignment.acr_pull]
}

resource "azurerm_container_app_job" "migrate" {
  count                        = local.on
  name                         = local.migr_job
  location                     = var.location
  resource_group_name          = azurerm_resource_group.auth[0].name
  container_app_environment_id = azapi_resource.cae[0].id
  workload_profile_name        = "Consumption"
  replica_timeout_in_seconds   = 600
  replica_retry_limit          = 0
  tags                         = local.tags

  manual_trigger_config {
    parallelism              = 1
    replica_completion_count = 1
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.authority_migrator[0].id]
  }

  registry {
    server   = azurerm_container_registry.auth[0].login_server
    identity = azurerm_user_assigned_identity.authority_migrator[0].id
  }

  template {
    container {
      name    = "migrate"
      image   = var.image
      cpu     = local.p.app_cpu
      memory  = local.p.app_memory
      command = ["/app/ViadereAuthority"]
      args    = ["migrate", "--yes"]

      dynamic "env" {
        for_each = merge(local.authority_base_env, {
          AZURE_CLIENT_ID = azurerm_user_assigned_identity.authority_migrator[0].client_id
          DATABASE_USER   = local.db_roles.migrator
        })
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [template[0].container[0].image]
  }

  depends_on = [azurerm_role_assignment.acr_pull]
}

# ---- Reconciliation job (ADR-0023 section 6, ADR-0028 section 2, ADR-0034 section 5.2; condition C-11): hourly, independent of the worker. Every
# Key Vault sign and unwrap in the AuditEvent rows must match a sign record the authority wrote before the call; any unmatched operation fails
# the execution (alert in monitoring.tf). No Key Vault role, no AUTHORITY_ENABLED. -----------------------------------------------------------
resource "azurerm_container_app_job" "reconcile" {
  count                        = local.reconcile
  name                         = local.recon_job
  location                     = var.location
  resource_group_name          = azurerm_resource_group.auth[0].name
  container_app_environment_id = azapi_resource.cae[0].id
  workload_profile_name        = "Consumption"
  replica_timeout_in_seconds   = 600
  replica_retry_limit          = 0
  tags                         = local.tags

  schedule_trigger_config {
    cron_expression          = "17 * * * *"
    parallelism              = 1
    replica_completion_count = 1
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.authority_reconcile[0].id]
  }

  registry {
    server   = azurerm_container_registry.auth[0].login_server
    identity = azurerm_user_assigned_identity.authority_reconcile[0].id
  }

  template {
    container {
      name    = "reconcile"
      image   = var.image
      cpu     = local.p.app_cpu
      memory  = local.p.app_memory
      command = ["/app/ViadereAuthority"]
      args    = ["reconcile"]

      dynamic "env" {
        for_each = merge(local.authority_base_env, {
          AZURE_CLIENT_ID              = azurerm_user_assigned_identity.authority_reconcile[0].client_id
          DATABASE_USER                = local.db_roles.reconcile
          AUTHORITY_AUDIT_WORKSPACE_ID = azurerm_log_analytics_workspace.auth[0].workspace_id
        })
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [template[0].container[0].image]
  }

  depends_on = [azurerm_role_assignment.reconcile_acr_pull, azurerm_role_assignment.reconcile_logs]
}
