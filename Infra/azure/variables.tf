# Every identifier is a variable; nothing environment-specific or secret is committed. Values come from terraform.tfvars (gitignored) or
# TF_VAR_* (CI maps GitHub environment variables to them). Example: terraform.tfvars.example.

# ---- Profile and placement -------------------------------------------------------------------------------------
variable "profile" {
  description = <<-EOT
    lean (default; testing, about USD 27-31/month, plan section 5.8a) or standard (production-grade, plan sections 5.1-5.8).
    Lean: PostgreSQL Burstable B1ms without HA, Service Bus Basic and Key Vault Standard on Entra-only public endpoints, images from GHCR,
    no private endpoints, no NAT gateway, no audit storage account. Standard: zone-redundant HA PostgreSQL with 35-day PITR and geo-redundant
    backup, Service Bus Premium and Key Vault Premium (HSM keys) behind private endpoints, ACR Premium, NAT gateway, WORM audit storage.
    Switching an existing environment from lean to standard REPLACES the environment, Key Vault, Service Bus namespace and PostgreSQL server
    (names carry the profile): see docs/ops/AZURE-SETUP.md section 12.
  EOT
  type        = string
  default     = "lean"
  validation {
    condition     = contains(["lean", "standard"], var.profile)
    error_message = "profile must be lean or standard."
  }
}

variable "environment" {
  description = "staging | production. Each lives in its own subscription and state file."
  type        = string
  validation {
    condition     = contains(["staging", "production"], var.environment)
    error_message = "environment must be staging or production."
  }
}

variable "subscription_id" {
  description = "Subscription of this environment (viadere-staging or viadere-production)."
  type        = string
  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.subscription_id))
    error_message = "subscription_id must be a GUID."
  }
}

variable "tenant_id" {
  description = "Microsoft Entra tenant."
  type        = string
  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.tenant_id))
    error_message = "tenant_id must be a GUID."
  }
}

variable "location" {
  description = "Azure region. centralus: on 2026-10-30 this subscription was refused PostgreSQL Flexible Server in eastus (no versions offered) and eastus2 (SkuNotAvailable for B1ms at create time, although list-skus showed it); a test create succeeded in centralus."
  type        = string
  default     = "centralus"
}

variable "name_suffix" {
  description = "3-6 lowercase letters/digits appended to globally unique names (Key Vault, Service Bus, PostgreSQL, storage, registry). Pick once; changing it replaces those resources."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9]{3,6}$", var.name_suffix))
    error_message = "name_suffix must be 3-6 lowercase letters or digits."
  }
}

variable "tags" {
  description = "Extra tags for every resource."
  type        = map(string)
  default     = {}
}

# ---- GitHub OIDC ------------------------------------------------------------------------------------------------
variable "github_repository" {
  description = "owner/repo whose Actions may deploy (federated credential subject repo:<owner>/<repo>:environment:<github_deploy_environment>)."
  type        = string
  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must be owner/repo."
  }
}

variable "github_deploy_environment" {
  description = "GitHub environment whose jobs may use the deploy identity. Defaults to the environment name (staging | production); the production environment must have required reviewers."
  type        = string
  default     = null
}

# ---- People (Entra groups created by the owner, AZURE-SETUP.md section 2) ------------------------------------------
variable "db_admin_group_object_id" {
  description = "Object id of grp-viadere-db-admins: the PostgreSQL Entra administrator. No workload uses it."
  type        = string
}

variable "db_admin_group_display_name" {
  description = "Display name of that group (PostgreSQL maps the Entra admin by name)."
  type        = string
  default     = "grp-viadere-db-admins"
}

variable "key_vault_crypto_officers_group_object_id" {
  description = "Object id of grp-viadere-kv-crypto-officers (Key Vault Crypto Officer: create and rotate keys). Empty = no assignment."
  type        = string
  default     = ""
}

variable "key_vault_secrets_officers_group_object_id" {
  description = "Object id of the group that may set secret values on the data plane (Key Vault Secrets Officer). Empty = no assignment (secrets are then set through the ARM control plane by a subscription Owner/Contributor, AZURE-SETUP.md section 7)."
  type        = string
  default     = ""
}

variable "key_vault_allowed_ip_ranges" {
  description = "Lean only: public IPv4 addresses/CIDRs of administrators allowed through the Key Vault firewall for data-plane work (e.g. `az keyvault secret set`). Empty = only the Container Apps subnet; secrets can still be set through the ARM control plane (AZURE-SETUP.md section 7)."
  type        = list(string)
  default     = []
}

# ---- Images -----------------------------------------------------------------------------------------------------
variable "image" {
  description = "Server image by digest for the FIRST apply (ghcr.io/<owner>/<repo>/viadere-server@sha256:...). Afterwards the deploy workflow owns the image (lifecycle ignore_changes)."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$", var.image))
    error_message = "image must be pinned by digest: registry/repository@sha256:<64 hex>."
  }
}

variable "cloudflared_image" {
  description = "Cloudflare Tunnel connector image, pinned by digest (Go binary; checked 2026-10-29: 2026.10.6). Mirror it to your registry if Docker Hub anonymous pull limits bite."
  type        = string
  default     = "docker.io/cloudflare/cloudflared:2026.10.6@sha256:004d843fa5fdc3103983fd580ee19fab4a8fa98add31f87249c1659e848c98e0"
  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.cloudflared_image))
    error_message = "cloudflared_image must be pinned by digest."
  }
}

variable "ghcr_pull_username" {
  description = "Lean profile: GitHub user that owns the read:packages token stored in Key Vault secret ghcr-pull-token. Empty = the GHCR package is public and no registry credential is configured."
  type        = string
  default     = ""
}

# ---- Workloads ----------------------------------------------------------------------------------------------------
variable "api_min_replicas" {
  description = "Minimum api replicas. Default: 1 (lean), 2 (standard). 0 lets a lean api scale to zero (saves about USD 6/month, but cold starts and the in-process job loop stops while idle). Use 0 for the very first apply (AZURE-SETUP.md section 6)."
  type        = number
  default     = null
}

variable "api_max_replicas" {
  type    = number
  default = null
}

variable "enable_worker" {
  description = "Create ca-viadere-worker (WP-B3 queue consumers, ROLE=worker) and switch QUEUE_TRANSPORT to servicebus. False keeps the lean single-app setup: the api runs the in-process job loop on the database queue (RUN_BACKGROUND_JOBS=true)."
  type        = bool
  default     = false
}

variable "enable_scheduled_jobs" {
  description = "Create the maintenance/hourly/audit-export Container Apps Jobs (`ViadereServer maintenance <task>`). With them the worker stops running the sweeps itself."
  type        = bool
  default     = false
}

variable "app_env" {
  description = "Non-secret server configuration (the [env] block of Infra/fly/fly.<env>.toml minus the keys this module sets itself). Example values: terraform.tfvars.example."
  type        = map(string)
  default     = {}
  validation {
    condition = length(setintersection(keys(var.app_env), [
      "ENVIRONMENT", "PORT", "BIND_HOST", "AUTO_MIGRATE", "RATE_LIMIT_STORE", "RUN_BACKGROUND_JOBS", "DATABASE_URL", "DATABASE_MIGRATION_URL",
      "DATABASE_APP_ROLE", "ROLE", "AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_KEY_VAULT_URL", "DATABASE_HOST", "DATABASE_NAME", "DATABASE_USER",
      "DATABASE_AUTH", "QUEUE_TRANSPORT", "AZURE_SERVICEBUS_FQDN", "HEALTH_PEER_NETWORKS", "EDGE_TOKEN", "EDGE_TOKEN_PREVIOUS",
    ])) == 0
    error_message = "app_env must not set keys this module owns (ENVIRONMENT, PORT, AUTO_MIGRATE, DATABASE_*, AZURE_*, ROLE, EDGE_TOKEN, ...) or secrets."
  }
}

variable "app_secret_env" {
  description = "Server secrets: environment variable name -> Key Vault secret name. The module creates an empty placeholder secret for each, grants the api and the worker Key Vault Secrets User on that secret only, and references it from the container app (the migrate job gets none of them: ROLE=migrate is database-only). DATABASE_URL is used only while postgres_password_auth_enabled. A wrapped value is stored under the `<NAME>_WRAPPED` variable name (kms1:<kek>/<version>:<base64url>, AZURE-SETUP.md section 7). Values are set by the owner, never by OpenTofu."
  type        = map(string)
  default = {
    DATABASE_URL                  = "database-url" # only while postgres_password_auth_enabled (CLAUDE.md exception)
    EDGE_TOKEN                    = "edge-token"
    CONNECT_LINK_SIGNING_KEY      = "connect-link-key"
    SERVER_PEPPER                 = "server-pepper"
    DATA_ENCRYPTION_KEY           = "data-encryption-key"
    AUDIT_CHAIN_KEY               = "audit-chain-key"
    SUBJECT_REF_KEY               = "subject-ref-key"
    EMAIL_API_KEY                 = "mailersend-api-token"
    APNS_KEY_P8                   = "apns-p8"
    MAILERSEND_SMS_API_TOKEN      = "mailersend-sms-api-token"
    MAILERSEND_SMS_INBOUND_SECRET = "mailersend-sms-inbound-secret"
    MAILERSEND_SMS_WEBHOOK_SECRET = "mailersend-sms-webhook-secret"
    BRAND_SELECTION_KEY           = "brand-selection-key" # Brand Kits daily rotation seed key; empty = no rotation
  }
  validation {
    condition     = alltrue([for k, v in var.app_secret_env : can(regex("^[A-Z][A-Z0-9_]+$", k)) && can(regex("^[a-z0-9][a-z0-9-]{0,62}$", v))])
    error_message = "app_secret_env keys must be ENV_NAMES and values Key Vault secret names (lowercase letters, digits, hyphens)."
  }
  validation {
    condition     = !contains(keys(var.app_secret_env), "DATABASE_MIGRATION_URL")
    error_message = "DATABASE_MIGRATION_URL is given to the migrate job only (secret database-migration-url); never to a serving app."
  }
}

# ---- PostgreSQL -----------------------------------------------------------------------------------------------------
variable "postgres_password_auth_enabled" {
  description = "Password authentication next to Entra (the CLAUDE.md exception). The server's Entra token connection source shipped with WP-B2 (DATABASE_AUTH=entra): after creating the Entra principal roles (AZURE-SETUP.md section 8) set this false: Entra-only, no database password exists, and database-url / database-migration-url are no longer referenced."
  type        = bool
  default     = false
}

variable "postgres_admin_password" {
  description = "Local administrator password, used only with postgres_set_admin_password = true on the first apply (write-only and ephemeral: never stored in state or plan). Generate it, use it once to create the password roles, then discard it (AZURE-SETUP.md section 8)."
  type        = string
  default     = null
  sensitive   = true
  ephemeral   = true
}

variable "postgres_set_admin_password" {
  description = "true only on the apply that creates the server (or deliberately resets the local admin password); then pass postgres_admin_password."
  type        = bool
  default     = false
}

variable "postgres_admin_password_version" {
  description = "Version tag stored with the write-only password (ignored after creation; rotate with the az CLI)."
  type        = number
  default     = 1
}

# ---- Monitoring -----------------------------------------------------------------------------------------------------
variable "log_daily_cap_gb" {
  description = "Log Analytics daily ingestion cap in GB. Default: 0.15 (lean, stays inside the 5 GB/month free allowance), none (standard)."
  type        = number
  default     = null
}

variable "audit_immutability_locked" {
  description = "Standard profile: lock the audit-head account's version-level immutability policy. IRREVERSIBLE: set only after the WP-B2 export is verified."
  type        = bool
  default     = false
}

variable "resource_locks" {
  description = "CanNotDelete locks on the data and security resource groups. Default: on in standard, off in lean."
  type        = bool
  default     = null
}
