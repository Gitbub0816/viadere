locals {
  on       = var.authority_enabled ? 1 : 0
  standard = var.profile == "standard"
  env      = var.environment == "production" ? "prd" : "stg"
  plet     = local.standard ? "s" : "l"
  uniq     = "${local.env}${var.name_suffix}${local.plet}" # same derivation as Infra/azure/locals.tf

  # ---- The ordinary tier's shared resources, found by their derived names (Infra/azure) ------------------------------------------
  ordinary = {
    rg_net      = "rg-viadere-${local.env}-net"
    rg_data     = "rg-viadere-${local.env}-data"
    vnet        = "vnet-viadere-${local.env}"
    pg_server   = "psql-viadere-${local.uniq}"
    cae_subnet  = "snet-cae"
    pe_subnet   = "snet-pe"
    vault_zone  = "privatelink.vaultcore.azure.net"
    pg_database = "viadere"
  }

  # Address plan (TRUST_BOUNDARIES section 9): snet-auth = cidrsubnet(vnet, 11, 32) = x.x.4.0/27, next to snet-cae /23, snet-pg /28, snet-pe /27.
  vnet_cidr = var.environment == "production" ? "10.50.0.0/16" : "10.40.0.0/16"
  subnets = {
    auth = cidrsubnet(local.vnet_cidr, 11, 32)
    cae  = cidrsubnet(local.vnet_cidr, 7, 0)
    pg   = cidrsubnet(local.vnet_cidr, 12, 32)
  }

  rg_auth      = "rg-viadere-${local.env}-auth"
  authority_db = "viadere_authority"
  db_roles = {
    runtime  = "viadere_authority"
    admin    = "viadere_authority_admin"
    migrator = "viadere_authority_migrator"
  }

  p = {
    kv_sku        = local.standard ? "premium" : "standard"
    ec_kty        = local.standard ? "EC-HSM" : "EC"
    rsa_kty       = local.standard ? "RSA-HSM" : "RSA"
    private_ep    = local.standard
    la_cap_gb     = local.standard ? -1 : 0.1
    la_retention  = local.standard ? 90 : 30
    locks         = local.standard
    app_cpu       = 0.25
    app_memory    = "0.5Gi"
    acr_sku       = local.standard ? "Premium" : "Basic"
    jwe_rsa_seal  = local.standard || var.seal_construction == "jwe-rsa"
    replica_floor = local.standard ? 2 : 1
  }

  la_daily_cap_gb = coalesce(var.log_daily_cap_gb, local.p.la_cap_gb)
  resource_locks  = coalesce(var.resource_locks, local.p.locks)
  min_replicas    = var.authority_min_replicas

  tags = merge({
    project     = "viadere"
    environment = var.environment
    profile     = var.profile
    tier        = "authority"
    managed-by  = "opentofu"
    source      = "Infra/azure-authority"
  }, var.tags)

  # ---- Key Vault keys (ADR-0028 section 1, ADR-0034). Created through the ARM control plane by id-gh-infra-auth-apply-<env> only. ----
  # `active` keys can be used by id-viadere-authority through a custom role; `standby` keys are created DISABLED and carry no role until a
  # recorded rollover (AUTH-STANDBY-ROLE). Nothing here is ever granted to an ordinary identity (AUTH-KEY-SCOPE, API-NO-NEW-KEYS).
  signing_keys = {
    "grant-signing"            = { kty = local.p.ec_kty, curve = "P-256", size = null, ops = ["sign", "verify"] }
    "oidc-signing-es256"       = { kty = local.p.ec_kty, curve = "P-256", size = null, ops = ["sign", "verify"] }
    "oidc-signing-rs256"       = { kty = local.p.rsa_kty, curve = null, size = 3072, ops = ["sign", "verify"] }
    "device-statement-signing" = { kty = local.p.ec_kty, curve = "P-256", size = null, ops = ["sign", "verify"] }
  }
  standby_signing_keys = {
    "device-statement-signing-standby" = { kty = local.p.ec_kty, curve = "P-256", size = null, ops = ["sign", "verify"] }
  }
  seal_keys_kek = local.p.jwe_rsa_seal ? {} : {
    "recovery-seal-kek" = { kty = local.p.rsa_kty, curve = null, size = 3072, ops = ["wrapKey", "unwrapKey"] }
  }
  seal_standby_kek = local.p.jwe_rsa_seal ? {} : {
    "recovery-seal-kek-standby" = { kty = local.p.rsa_kty, curve = null, size = 3072, ops = ["wrapKey", "unwrapKey"] }
  }
  seal_keys_rsa = local.p.jwe_rsa_seal ? {
    "recovery-seal-rsa" = { kty = local.p.rsa_kty, curve = null, size = 3072, ops = ["decrypt"] }
  } : {}
  seal_standby_rsa = local.p.jwe_rsa_seal ? {
    "recovery-seal-rsa-standby" = { kty = local.p.rsa_kty, curve = null, size = 3072, ops = ["decrypt"] }
  } : {}

  active_keys  = merge(local.signing_keys, local.seal_keys_kek, local.seal_keys_rsa)
  standby_keys = merge(local.standby_signing_keys, local.seal_standby_kek, local.seal_standby_rsa)
  all_keys     = merge(local.active_keys, local.standby_keys)

  # Which custom role fits which key (names are checked by policy_check.py: AUTH-SIGNER-ROLE).
  key_role = merge(
    { for k in keys(local.signing_keys) : k => "signer" },
    { for k in keys(local.seal_keys_kek) : k => "unwrapper" },
    { for k in keys(local.seal_keys_rsa) : k => "decrypter" },
    { for k in keys(local.standby_signing_keys) : k => "signer" },
    { for k in keys(local.seal_standby_kek) : k => "unwrapper" },
    { for k in keys(local.seal_standby_rsa) : k => "decrypter" },
  )

  # Secrets of the authority (TRUST_BOUNDARIES 4.1). Placeholders; values are set by the officers, never by OpenTofu. Env name -> secret name.
  authority_secrets = {
    OIDC_PAIRWISE_KEY     = "oidc-pairwise-key"
    ACCOUNT_REF_KEY       = "account-ref-key"
    RECOVERY_VERIFIER_KEY = "recovery-verifier-key"
    SUBJECT_REF_KEY       = "subject-ref-key"
  }

  # Hosts the authority may call, for BOTH the app-level OutboundDestinationGuard (allow-list mode) and the documentation of the NSG.
  outbound_allowlist = join(",", [
    "login.microsoftonline.com",
    "${local.kv_name}.vault.azure.net",
    "${local.pg_fqdn}",
  ])

  kv_name   = "kv-vdr-auth-${local.uniq}"
  pg_fqdn   = "${local.ordinary.pg_server}.postgres.database.azure.com"
  cr_name   = "crviadereauth${local.uniq}"
  cae_name  = "cae-viadere-${local.env}-auth"
  app_name  = "ca-viadere-authority"
  admin_job = "job-viadere-authority-admin"
  migr_job  = "job-viadere-authority-migrate"

  deploy_subject = var.oidc_subject_workflow_ref ? "repo:${var.github_repository}:environment:${var.deploy_environment}:job_workflow_ref:${var.github_repository}/.github/workflows/authority-deploy.yml@refs/heads/main" : "repo:${var.github_repository}:environment:${var.deploy_environment}"
  admin_subject  = var.oidc_subject_workflow_ref ? "repo:${var.github_repository}:environment:${var.admin_environment}:job_workflow_ref:${var.github_repository}/.github/workflows/authority-admin.yml@refs/heads/main" : "repo:${var.github_repository}:environment:${var.admin_environment}"
}
