# Container Apps (ADR-0010, plan sections 5.1, 5.4, 5.5, 5.9).
#
# Environment: workload-profiles type with ONLY the built-in Consumption profile (Microsoft's recommended consumption setup; the older
# "Consumption-only" type is legacy). No dedicated profile, no environment private endpoint and no planned-maintenance window, so the
# Dedicated Plan Management / Environment Management charges never apply (Container Apps billing page, 2025-12-09; Retail Prices API
# meters "Environment Private Endpoint", "Environment Management Hour", "Environment Planned Maintenance Hour", 2026-10-29). Internal load
# balancer only, public network access disabled, peer-to-peer encryption on, logs to Azure Monitor (no workspace shared key).
#
# Origin: Cloudflare Tunnel. cloudflared runs as its OWN small container app (ca-cloudflared), not as a sidecar of the api, because
#  1. a sidecar connector forwards to localhost, i.e. to its own replica, bypassing the environment ingress, revision traffic split and
#     readiness gating, so a starting or failing api revision would receive edge traffic;
#  2. the tunnel token stays with a dedicated identity (Secrets User on that one secret); the api identity never sees it;
#  3. api rollouts, restarts and scale-outs do not drop or multiply tunnel connectors.
# The cost is the same as a sidecar (one more 0.25 vCPU / 0.5 GiB allocation either way). The api ingress is reachable only inside the
# environment (external_enabled = false); EDGE_TOKEN stays enforced by the server as a second layer (section 5.4).

resource "azapi_resource" "cae" {
  type      = "Microsoft.App/managedEnvironments@2026-01-01"
  name      = "cae-viadere-${local.env}"
  parent_id = azurerm_resource_group.this["app"].id
  location  = var.location
  tags      = local.tags

  body = {
    properties = {
      workloadProfiles = [{
        name                = "Consumption"
        workloadProfileType = "Consumption"
      }]
      vnetConfiguration = {
        infrastructureSubnetId = azurerm_subnet.cae.id
        internal               = true
      }
      infrastructureResourceGroup = "rg-viadere-${local.env}-cae-infra"
      zoneRedundant               = local.p.zone_redundant
      publicNetworkAccess         = "Disabled"
      peerTrafficConfiguration = {
        encryption = { enabled = true }
      }
      appLogsConfiguration = {
        destination = "azure-monitor"
      }
    }
  }

  # Zone redundancy, the subnet and the infrastructure resource group cannot change in place.
  replace_triggers_external_values = [local.p.zone_redundant, azurerm_subnet.cae.id]
  response_export_values           = ["properties.defaultDomain", "properties.staticIp"]

  depends_on = [azurerm_subnet_network_security_group_association.cae, azurerm_subnet_nat_gateway_association.cae]
}

locals {
  kv_secret_uri = { for s in local.all_secret_names : s => "${azurerm_key_vault.this.vault_uri}secrets/${s}" } # versionless: latest version

  # Settings every server process gets (docs/ops/AZURE-SETUP.md section 11 lists every variable; Infra/azure/check_env_coverage.py checks them
  # against Server/.env.example).
  base_env = {
    ENVIRONMENT           = var.environment # (now) strict mode: every secret mandatory
    PORT                  = "8080"          # (now)
    BIND_HOST             = "0.0.0.0"       # (now)
    AUTO_MIGRATE          = "false"         # (now) migrations only from job-viadere-migrate
    RATE_LIMIT_STORE      = "database"      # (now)
    DATABASE_APP_ROLE     = local.db_roles.api
    AZURE_TENANT_ID       = var.tenant_id
    AZURE_KEY_VAULT_URL   = azurerm_key_vault.this.vault_uri
    AZURE_SERVICEBUS_FQDN = "${azurerm_servicebus_namespace.this.name}.servicebus.windows.net"
    DATABASE_HOST         = azurerm_postgresql_flexible_server.this.fqdn
    DATABASE_NAME         = local.database_name
    DATABASE_AUTH         = var.postgres_password_auth_enabled ? "password" : "entra"
    QUEUE_TRANSPORT       = var.enable_worker ? "servicebus" : "database"
    HEALTH_PEER_NETWORKS  = local.subnets.cae
  }

  process_env = {
    api = merge(var.app_env, local.base_env, {
      ROLE                                = "api"
      AZURE_CLIENT_ID                     = azurerm_user_assigned_identity.workload["api"].client_id
      DATABASE_USER                       = local.db_roles.api
      RUN_BACKGROUND_JOBS                 = var.enable_worker ? "false" : "true" # (now) the in-process loop runs until WP-B3's worker exists
      AZURE_KEY_VAULT_KEK_KEY             = "kek-data"
      AZURE_KEY_VAULT_KD_LOG_KEY          = "kd-log-signing"
      AZURE_KEY_VAULT_LINK_DESCRIPTOR_KEY = "link-descriptor"
    })
    worker = merge(var.app_env, local.base_env, {
      ROLE            = "worker"
      AZURE_CLIENT_ID = azurerm_user_assigned_identity.workload["worker"].client_id
      DATABASE_USER   = local.db_roles.worker
      # The worker consumes the queues continuously; the periodic sweeps run in the scheduled jobs when they exist, else in the worker.
      RUN_BACKGROUND_JOBS            = var.enable_scheduled_jobs ? "false" : "true"
      AZURE_KEY_VAULT_KEK_KEY        = "kek-data"
      AZURE_KEY_VAULT_AUDIT_HEAD_KEY = "audit-head-signing"
      AZURE_AUDIT_BLOB_ENDPOINT      = local.p.audit_storage ? azurerm_storage_account.audit[0].primary_blob_endpoint : ""
      AZURE_AUDIT_BLOB_CONTAINER     = local.p.audit_storage ? "audit-heads" : ""
    })
    migrator = merge(var.app_env, local.base_env, {
      ROLE                 = "migrate"
      AZURE_CLIENT_ID      = azurerm_user_assigned_identity.workload["migrator"].client_id
      DATABASE_USER        = local.db_roles.migrator
      DATABASE_WORKER_ROLE = local.db_roles.worker # `migrate` grants the worker role the same data-only privileges as the api role
      RUN_BACKGROUND_JOBS  = "false"
    })
  }

  # Image pull: managed identity against ACR (standard), or a read:packages token from Key Vault against GHCR (lean, private package), or
  # anonymous (lean, public package).
  registry = local.p.registry ? {
    server   = azurerm_container_registry.this[0].login_server
    identity = azurerm_user_assigned_identity.acrpull[0].id
    username = null
    secret   = null
    } : local.ghcr_auth ? {
    server   = "ghcr.io"
    identity = null
    username = var.ghcr_pull_username
    secret   = local.ghcr_pull_secret
  } : null

  pull_secret = local.ghcr_auth ? { GHCR_PULL = local.ghcr_pull_secret } : {}
  acrpull_ids = local.p.registry ? [azurerm_user_assigned_identity.acrpull[0].id] : []

  probe_headers = { "X-Forwarded-Proto" = "https" }
}

# ---- API ---------------------------------------------------------------------------------------------------------------
resource "azurerm_container_app" "api" {
  name                         = "ca-viadere-api"
  container_app_environment_id = azapi_resource.cae.id
  resource_group_name          = azurerm_resource_group.this["app"].name
  workload_profile_name        = "Consumption"
  # Single revision mode: a new revision takes traffic only once its readiness probe passes, then the old one is deactivated (kept as an
  # inactive revision for rollback). Multiple mode would keep the old revision's replicas running and billing.
  revision_mode          = "Single"
  max_inactive_revisions = 10
  tags                   = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = concat([azurerm_user_assigned_identity.workload["api"].id], local.acrpull_ids)
  }

  dynamic "secret" {
    for_each = toset(concat(values(local.api_secrets), values(local.pull_secret)))
    content {
      name                = secret.value
      key_vault_secret_id = local.kv_secret_uri[secret.value]
      identity            = azurerm_user_assigned_identity.workload["api"].id
    }
  }

  dynamic "registry" {
    for_each = local.registry == null ? [] : [local.registry]
    content {
      server               = registry.value.server
      identity             = registry.value.identity
      username             = registry.value.username
      password_secret_name = registry.value.secret
    }
  }

  ingress {
    external_enabled = false # environment-internal only: reachable from ca-cloudflared, never from the Internet or the VNet edge
    target_port      = 8080
    transport        = "http"
    # cloudflared reaches http://ca-viadere-api inside the environment; the hop is covered by the environment's peer-to-peer encryption.
    allow_insecure_connections = true
    client_certificate_mode    = "ignore" # Tier E mTLS is verified at Cloudflare API Shield (SECURITY.md §2.74)
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    min_replicas                     = local.api_min_replicas
    max_replicas                     = local.api_max_replicas
    termination_grace_period_seconds = 30

    http_scale_rule {
      name                = "http-concurrency"
      concurrent_requests = "50"
    }

    container {
      name   = "api"
      image  = var.image
      cpu    = local.p.api_cpu
      memory = local.p.api_memory

      dynamic "env" {
        for_each = local.process_env.api
        content {
          name  = env.key
          value = env.value
        }
      }
      dynamic "env" {
        for_each = local.api_secrets
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
          for_each = local.probe_headers
          content {
            name  = header.key
            value = header.value
          }
        }
      }
      # Liveness: the process answers HTTP (no dependency state). Probes come from the platform inside snet-cae without proxy headers, which
      # the server's origin lock exempts for /healthz and /readyz only (healthPeerNetworks; HEALTH_PEER_NETWORKS in WP-B2).
      liveness_probe {
        transport               = "HTTP"
        port                    = 8080
        path                    = "/healthz"
        interval_seconds        = 15
        timeout                 = 3
        failure_count_threshold = 3
        dynamic "header" {
          for_each = local.probe_headers
          content {
            name  = header.key
            value = header.value
          }
        }
      }
      # Readiness: the database answers (503 otherwise): a revision gets no traffic until it passes.
      readiness_probe {
        transport               = "HTTP"
        port                    = 8080
        path                    = "/readyz"
        interval_seconds        = 15
        timeout                 = 5
        failure_count_threshold = 3
        success_count_threshold = 1
        dynamic "header" {
          for_each = local.probe_headers
          content {
            name  = header.key
            value = header.value
          }
        }
      }
    }
  }

  lifecycle {
    # The release workflow owns the image (update by digest after the migrate job succeeded).
    ignore_changes = [template[0].container[0].image, template[0].revision_suffix]
  }

  depends_on = [azurerm_role_assignment.secret_user]
}

# ---- Cloudflare Tunnel connector -----------------------------------------------------------------------------------------
resource "azurerm_container_app" "cloudflared" {
  name                         = "ca-cloudflared"
  container_app_environment_id = azapi_resource.cae.id
  resource_group_name          = azurerm_resource_group.this["app"].name
  workload_profile_name        = "Consumption"
  revision_mode                = "Single"
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.workload["cloudflared"].id]
  }

  secret {
    name                = local.tunnel_secret
    key_vault_secret_id = local.kv_secret_uri[local.tunnel_secret]
    identity            = azurerm_user_assigned_identity.workload["cloudflared"].id
  }

  template {
    min_replicas = local.p.cloudflared_min
    max_replicas = local.p.cloudflared_min

    container {
      name    = "cloudflared"
      image   = var.cloudflared_image
      cpu     = 0.25
      memory  = "0.5Gi"
      command = ["cloudflared"]
      args    = ["tunnel", "--no-autoupdate", "--metrics", "0.0.0.0:2000", "run"]

      env {
        name        = "TUNNEL_TOKEN"
        secret_name = local.tunnel_secret
      }

      liveness_probe {
        transport               = "HTTP"
        port                    = 2000
        path                    = "/ready"
        initial_delay           = 10
        interval_seconds        = 30
        timeout                 = 5
        failure_count_threshold = 5
      }
    }
  }

  depends_on = [azurerm_role_assignment.secret_user]
}

# ---- Migrations (section 5.9): manual job, one execution at a time, migrator identity ----------------------------------------
resource "azurerm_container_app_job" "migrate" {
  name                         = "job-viadere-migrate"
  location                     = var.location
  resource_group_name          = azurerm_resource_group.this["app"].name
  container_app_environment_id = azapi_resource.cae.id
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
    identity_ids = concat([azurerm_user_assigned_identity.workload["migrator"].id], local.acrpull_ids)
  }

  dynamic "secret" {
    for_each = toset(concat(values(local.migrate_secrets), values(local.pull_secret)))
    content {
      name                = secret.value
      key_vault_secret_id = local.kv_secret_uri[secret.value]
      identity            = azurerm_user_assigned_identity.workload["migrator"].id
    }
  }

  dynamic "registry" {
    for_each = local.registry == null ? [] : [local.registry]
    content {
      server               = registry.value.server
      identity             = registry.value.identity
      username             = registry.value.username
      password_secret_name = registry.value.secret
    }
  }

  template {
    container {
      name    = "migrate"
      image   = var.image
      cpu     = local.p.api_cpu
      memory  = local.p.api_memory
      command = ["/app/ViadereServer"]
      args    = ["migrate", "--yes", "--env", "production"]

      dynamic "env" {
        for_each = local.process_env.migrator
        content {
          name  = env.key
          value = env.value
        }
      }
      dynamic "env" {
        for_each = local.migrate_secrets
        content {
          name        = env.key
          secret_name = env.value
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [template[0].container[0].image]
  }

  depends_on = [azurerm_role_assignment.secret_user]
}

# ---- Worker (WP-B3 queue consumers) and scheduled maintenance jobs (`ViadereServer maintenance <task>`, WP-B2) ---------------------
resource "azurerm_container_app" "worker" {
  count                        = var.enable_worker ? 1 : 0
  name                         = "ca-viadere-worker"
  container_app_environment_id = azapi_resource.cae.id
  resource_group_name          = azurerm_resource_group.this["app"].name
  workload_profile_name        = "Consumption"
  revision_mode                = "Single"
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = concat([azurerm_user_assigned_identity.workload["worker"].id], local.acrpull_ids)
  }

  dynamic "secret" {
    for_each = toset(concat(values(local.worker_secrets), values(local.pull_secret)))
    content {
      name                = secret.value
      key_vault_secret_id = local.kv_secret_uri[secret.value]
      identity            = azurerm_user_assigned_identity.workload["worker"].id
    }
  }

  dynamic "registry" {
    for_each = local.registry == null ? [] : [local.registry]
    content {
      server               = registry.value.server
      identity             = registry.value.identity
      username             = registry.value.username
      password_secret_name = registry.value.secret
    }
  }

  template {
    min_replicas = local.p.worker_min
    max_replicas = local.p.worker_min + 2

    container {
      name   = "worker"
      image  = var.image
      cpu    = local.p.worker_cpu
      memory = local.p.worker_memory

      dynamic "env" {
        for_each = local.process_env.worker
        content {
          name  = env.key
          value = env.value
        }
      }
      dynamic "env" {
        for_each = local.worker_secrets
        content {
          name        = env.key
          secret_name = env.value
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [template[0].container[0].image, template[0].revision_suffix]
  }

  depends_on = [azurerm_role_assignment.secret_user]
}

locals {
  scheduled_jobs = var.enable_scheduled_jobs ? {
    maintenance    = "*/5 * * * *"  # sweeps, purges, retention (section 5.7)
    hourly         = "23 * * * *"   # verify maintenance, API-key lifecycle, onboarding assurance
    "audit-export" = "41 */6 * * *" # AUDIT_HEAD_EXPORT_INTERVAL_HOURS = 6
  } : {}
}

resource "azurerm_container_app_job" "scheduled" {
  for_each                     = local.scheduled_jobs
  name                         = "job-viadere-${each.key}"
  location                     = var.location
  resource_group_name          = azurerm_resource_group.this["app"].name
  container_app_environment_id = azapi_resource.cae.id
  workload_profile_name        = "Consumption"
  replica_timeout_in_seconds   = 1800
  replica_retry_limit          = 1
  tags                         = local.tags

  schedule_trigger_config {
    cron_expression          = each.value
    parallelism              = 1
    replica_completion_count = 1
  }

  identity {
    type         = "UserAssigned"
    identity_ids = concat([azurerm_user_assigned_identity.workload["worker"].id], local.acrpull_ids)
  }

  dynamic "secret" {
    for_each = toset(concat(values(local.worker_secrets), values(local.pull_secret)))
    content {
      name                = secret.value
      key_vault_secret_id = local.kv_secret_uri[secret.value]
      identity            = azurerm_user_assigned_identity.workload["worker"].id
    }
  }

  dynamic "registry" {
    for_each = local.registry == null ? [] : [local.registry]
    content {
      server               = registry.value.server
      identity             = registry.value.identity
      username             = registry.value.username
      password_secret_name = registry.value.secret
    }
  }

  template {
    container {
      name    = each.key
      image   = var.image
      cpu     = local.p.worker_cpu
      memory  = local.p.worker_memory
      command = ["/app/ViadereServer"]
      args    = ["maintenance", each.key, "--env", "production"]

      dynamic "env" {
        for_each = local.process_env.worker
        content {
          name  = env.key
          value = env.value
        }
      }
      dynamic "env" {
        for_each = local.worker_secrets
        content {
          name        = env.key
          secret_name = env.value
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [template[0].container[0].image]
  }

  depends_on = [azurerm_role_assignment.secret_user]
}
