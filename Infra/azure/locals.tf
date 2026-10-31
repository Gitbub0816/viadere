locals {
  standard = var.profile == "standard"
  env      = var.environment == "production" ? "prd" : "stg"
  # Globally unique names carry the profile letter, so moving an environment from lean to standard creates new resources next to the old
  # ones instead of colliding with soft-deleted names (Key Vault purge protection keeps a deleted vault's name for 90 days).
  plet = local.standard ? "s" : "l"
  uniq = "${local.env}${var.name_suffix}${local.plet}"

  # Every SKU and network difference between the profiles lives here; the server code is identical in both (plan section 5.8a).
  profiles = {
    lean = {
      kv_sku              = "standard" # software-protected keys (CLAUDE.md exception, lean)
      ec_kty              = "EC"
      rsa_kty             = "RSA"
      sb_sku              = "Basic" # queues, DLQ, scheduled messages; no duplicate detection (consumers are idempotent, ADR-0014)
      sb_capacity         = 0
      sb_partitions       = 0
      private_endpoints   = false # Service Bus Basic and Key Vault Standard on Entra-only public endpoints (CLAUDE.md exception, lean)
      pg_sku              = "B_Standard_B1ms"
      pg_storage_mb       = 32768
      pg_ha               = false
      pg_backup_days      = 7
      pg_geo_backup       = false
      zone_redundant      = false
      registry            = false # images pulled from GHCR
      nat_gateway         = false
      audit_storage       = false # audit-head export stays off in lean (AUDIT_HEAD_EXPORT empty, as on Fly staging today)
      api_cpu             = 0.25
      api_memory          = "0.5Gi"
      api_min             = 1
      api_max             = 2
      worker_cpu          = 0.25
      worker_memory       = "0.5Gi"
      worker_min          = 1
      cloudflared_min     = 1
      la_cap_gb           = 0.15
      la_retention_days   = 30
      locks               = false
      duplicate_detection = false
    }
    standard = {
      kv_sku              = "premium" # HSM-backed keys (ADR-0012); Managed HSM is not used
      ec_kty              = "EC-HSM"
      rsa_kty             = "RSA-HSM"
      sb_sku              = "Premium"
      sb_capacity         = 1
      sb_partitions       = 1
      private_endpoints   = true
      pg_sku              = "GP_Standard_D2ds_v5"
      pg_storage_mb       = 131072
      pg_ha               = true
      pg_backup_days      = 35
      pg_geo_backup       = true
      zone_redundant      = true
      registry            = true
      nat_gateway         = true
      audit_storage       = true
      api_cpu             = 0.5
      api_memory          = "1Gi"
      api_min             = 2
      api_max             = 10
      worker_cpu          = 0.25
      worker_memory       = "0.5Gi"
      worker_min          = 2
      cloudflared_min     = 2
      la_cap_gb           = -1 # no cap
      la_retention_days   = 90
      locks               = true
      duplicate_detection = true
    }
  }
  p = local.profiles[var.profile]

  api_min_replicas = coalesce(var.api_min_replicas, local.p.api_min)
  api_max_replicas = coalesce(var.api_max_replicas, local.p.api_max)
  la_daily_cap_gb  = coalesce(var.log_daily_cap_gb, local.p.la_cap_gb)
  resource_locks   = coalesce(var.resource_locks, local.p.locks)

  github_deploy_environment = coalesce(var.github_deploy_environment, var.environment)

  # Address plan (section 5.2). The Container Apps subnet is delegated to Microsoft.App/environments (workload-profiles environment).
  vnet_cidr = var.environment == "production" ? "10.50.0.0/16" : "10.40.0.0/16"
  subnets = {
    cae = cidrsubnet(local.vnet_cidr, 7, 0)   # x.x.0.0/23
    pg  = cidrsubnet(local.vnet_cidr, 12, 32) # x.x.2.0/28
    pe  = cidrsubnet(local.vnet_cidr, 11, 24) # x.x.3.0/27
    # x.x.4.0/27 is reserved for snet-ops (jump host or Bastion), not created.
  }

  tags = merge({
    project     = "viadere"
    environment = var.environment
    profile     = var.profile
    managed-by  = "opentofu"
    source      = "Infra/azure"
  }, var.tags)

  rg = {
    net  = "rg-viadere-${local.env}-net"
    app  = "rg-viadere-${local.env}-app"
    data = "rg-viadere-${local.env}-data"
    sec  = "rg-viadere-${local.env}-sec"
    ops  = "rg-viadere-${local.env}-ops"
  }

  database_name = "viadere"
  # Database roles (created by the bootstrap runbook, AZURE-SETUP.md section 8; GrantRuntimeRolePrivileges grants DML to the runtime role).
  db_roles = {
    api      = "viadere_app"
    worker   = "viadere_worker"
    migrator = "viadere_migrator"
  }

  # Key Vault keys (plan section 5.6). Created through the ARM control plane; rotation is a crypto-officer task (docs/ops/KEY-ROTATION.md).
  kv_keys = {
    "audit-head-signing" = { kty = local.p.ec_kty, curve = "P-256", size = null, ops = ["sign", "verify"] }
    "kd-log-signing"     = { kty = local.p.ec_kty, curve = "P-256", size = null, ops = ["sign", "verify"] }
    "link-descriptor"    = { kty = local.p.ec_kty, curve = "P-256", size = null, ops = ["sign", "verify"] }
    "brand-manifest"     = { kty = local.p.ec_kty, curve = "P-256", size = null, ops = ["sign", "verify"] }
    "kek-data"           = { kty = local.p.rsa_kty, curve = null, size = 3072, ops = ["wrapKey", "unwrapKey"] }
  }
  # Which identity may use which key (Key Vault Crypto User at KEY scope, section 5.3).
  key_grants = {
    api    = ["kek-data", "kd-log-signing", "link-descriptor", "brand-manifest"]
    worker = ["kek-data", "audit-head-signing"]
  }

  # Secrets (WP-B2). `ViadereServer migrate` runs with ROLE=migrate, a database-only configuration: the migrate job references nothing but its
  # database credential, and nothing at all once PostgreSQL is Entra-only (postgres_password_auth_enabled = false: every process then connects
  # with its own managed identity's token, and database-url / database-migration-url are not created). The api and the worker get the service
  # secrets; DATABASE_URL only while password authentication is on.
  db_password_secret = var.postgres_password_auth_enabled ? { DATABASE_URL = "database-url" } : {}
  service_secrets    = { for name, secret in var.app_secret_env : name => secret if name != "DATABASE_URL" }
  api_secrets        = merge(local.service_secrets, local.db_password_secret)
  worker_secrets     = merge(local.service_secrets, local.db_password_secret)
  migrate_secrets    = var.postgres_password_auth_enabled ? { DATABASE_MIGRATION_URL = "database-migration-url" } : {}
  ghcr_pull_secret   = "ghcr-pull-token"
  tunnel_secret      = "cloudflared-tunnel-token"
  ghcr_auth          = !local.p.registry && var.ghcr_pull_username != ""

  all_secret_names = toset(concat(
    values(local.api_secrets),
    values(local.worker_secrets),
    values(local.migrate_secrets),
    [local.tunnel_secret],
    local.ghcr_auth ? [local.ghcr_pull_secret] : [],
  ))

  # (identity, secret) pairs for Key Vault Secrets User at SECRET scope.
  secret_grants = merge(
    { for env_name, s in local.api_secrets : "api/${s}" => { identity = "api", secret = s } },
    { for env_name, s in local.migrate_secrets : "migrator/${s}" => { identity = "migrator", secret = s } },
    { for env_name, s in local.worker_secrets : "worker/${s}" => { identity = "worker", secret = s } },
    { "cloudflared/${local.tunnel_secret}" = { identity = "cloudflared", secret = local.tunnel_secret } },
    local.ghcr_auth ? { for id in ["api", "migrator", "worker"] : "${id}/${local.ghcr_pull_secret}" => { identity = id, secret = local.ghcr_pull_secret } } : {},
  )

  # Service Bus queues (plan section 5.7, ADR-0014). lock 60 s, DLQ on expiry, per-queue max deliveries.
  queues = {
    "push"             = { max_delivery = 5, ttl = "PT1H" }
    "sms-outbound"     = { max_delivery = 8, ttl = "P1D" }
    "channel-outbound" = { max_delivery = 8, ttl = "P1D" }
    "webhook-delivery" = { max_delivery = 8, ttl = "P3D" }
    "wallet-push"      = { max_delivery = 8, ttl = "P1D" }
    "operator-notices" = { max_delivery = 8, ttl = "P3D" }
    "consumer-export"  = { max_delivery = 3, ttl = "P3D" }
    "expiry"           = { max_delivery = 10, ttl = "P14D" } # scheduled interaction.expire / approve.expire / identity holds
  }

  workload_identities = ["api", "worker", "migrator", "cloudflared"]
}
