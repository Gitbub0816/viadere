# Every identifier is a variable; nothing environment-specific or secret is committed (values: terraform.tfvars or TF_VAR_*).

variable "authority_enabled" {
  description = "Master switch. false (default): the plan is empty and nothing bills. true: creates the whole authority tier. Set only after the owner's checklist (docs/ops/AUTHORITY-OWNER-CHECKLIST.md): GitHub environments with reviewers, branch protection, CODEOWNERS, distinct agent identity (condition C-5)."
  type        = bool
  default     = false
}

variable "profile" {
  description = "lean | standard; must equal the profile of Infra/azure for this environment (names carry the profile letter). Standard uses Key Vault Premium (HSM keys), a private endpoint and the RSA-HSM seal construction of ADR-0034 section 9."
  type        = string
  default     = "lean"
  validation {
    condition     = contains(["lean", "standard"], var.profile)
    error_message = "profile must be lean or standard."
  }
}

variable "environment" {
  description = "staging | production. Production additionally needs ADR-0034 section 9 (C-16) or an owner exception, and a second human reviewer (R-21)."
  type        = string
  validation {
    condition     = contains(["staging", "production"], var.environment)
    error_message = "environment must be staging or production."
  }
}

variable "subscription_id" {
  description = "Subscription of this environment. Lean: the SAME subscription as the ordinary tier (recorded exception, CLAUDE.md); standard: a separate subscription or management group (spec section 9.2)."
  type        = string
  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.subscription_id))
    error_message = "subscription_id must be a GUID."
  }
}

variable "tenant_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.tenant_id))
    error_message = "tenant_id must be a GUID."
  }
}

variable "location" {
  description = "Azure region; must be a US region (decision 13, policy rule RESIDENCY-US) and the region of the ordinary tier."
  type        = string
  default     = "centralus"
}

variable "name_suffix" {
  description = "The SAME 3-6 character suffix as Infra/azure: the shared resources (PostgreSQL server, virtual network) are found by their derived names."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9]{3,6}$", var.name_suffix))
    error_message = "name_suffix must be 3-6 lowercase letters or digits."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}

# ---- GitHub OIDC ------------------------------------------------------------------------------------------------
variable "github_repository" {
  description = "owner/repo whose workflows may use the authority identities."
  type        = string
  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must be owner/repo."
  }
}

variable "oidc_subject_workflow_ref" {
  description = "true: every federated credential pins job_workflow_ref (repo:<r>:environment:<e>:job_workflow_ref:<r>/.github/workflows/<file>@refs/heads/main), so only that workflow on main obtains the token (ADR-0028 section 6.1). Needs the repository's OIDC subject template to include job_workflow_ref FIRST (checklist step); false is a recorded exception (policy rule AUTH-OIDC-SUBJECT)."
  type        = bool
  default     = false
}

variable "deploy_environment" {
  description = "GitHub environment of authority-deploy.yml (required reviewers, deployment branch main only)."
  type        = string
  default     = "authority-staging"
}

variable "admin_environment" {
  description = "GitHub environment of authority-admin.yml."
  type        = string
  default     = "authority-admin-staging"
}

# ---- People (Entra groups, owner creates them: checklist) --------------------------------------------------------------
variable "authority_crypto_officers_group_object_id" {
  description = "Object id of grp-viadere-<env>-auth-crypto-officers (Key Vault Crypto Officer on kv-vdr-auth, PIM time-bound; the ONLY principal with backup rights). Must not overlap the ordinary crypto-officer group. Empty = no assignment."
  type        = string
  default     = ""
}

variable "authority_secrets_officers_group_object_id" {
  description = "Group that sets secret values on kv-vdr-auth (Key Vault Secrets Officer). Empty = no assignment (secrets are then set through the ARM control plane)."
  type        = string
  default     = ""
}

variable "key_vault_allowed_ip_ranges" {
  description = "Lean only: administrator IPv4 addresses/CIDRs admitted through the kv-vdr-auth firewall for officer data-plane work (public key reads)."
  type        = list(string)
  default     = []
}

variable "db_admin_group_object_id" {
  description = "Not used for creation here; documented for the database bootstrap (docs/ops/AUTHORITY-OWNER-CHECKLIST.md): the Entra administrator of the shared server creates the authority roles."
  type        = string
  default     = ""
}

# ---- Workload ---------------------------------------------------------------------------------------------------
variable "image" {
  description = "Authority image BY DIGEST in the authority registry (<crname>.azurecr.io/viadere-authority@sha256:...) or a bootstrap digest for the first apply; afterwards authority-deploy.yml owns it (lifecycle ignore_changes). Required when authority_enabled."
  type        = string
  default     = ""
  validation {
    condition     = var.image == "" || can(regex("^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$", var.image))
    error_message = "image must be pinned by digest: registry/repository@sha256:<64 hex>."
  }
}

variable "authority_min_replicas" {
  description = "Minimum replicas of ca-viadere-authority. 1 (default, ADR-0019): no cold start. 0 saves about USD 6/month but the authority then unwraps its seal key on every cold start (ADR-0034 section 5 reconciliation expects exactly one unwrap per start)."
  type        = number
  default     = 1
}

variable "authority_max_replicas" {
  type    = number
  default = 2
}

variable "authority_entra_audience" {
  description = "Audience of the Entra application the api and worker present tokens for (api://viadere-authority-<env>); created by bootstrap/create-entra-app.sh, never by this module (no Graph write rights for CI)."
  type        = string
  default     = ""
}

variable "authority_caller_object_ids" {
  description = "Object ids (oid) allowed to call the authority: the api identity (Authority.Evidence.Submit) and the worker identity (Authority.Revocations). The authority checks the role per route AND this allow-list (ADR-0019 section 4.4)."
  type        = map(string)
  default     = {}
}

variable "authority_env" {
  description = "Extra non-secret authority configuration (the keys this module sets itself are refused)."
  type        = map(string)
  default     = {}
  validation {
    condition = length(setintersection(keys(var.authority_env), [
      "ENVIRONMENT", "PORT", "BIND_HOST", "AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_KEY_VAULT_URL", "DATABASE_HOST", "DATABASE_NAME",
      "DATABASE_USER", "DATABASE_AUTH", "AUTHORITY_ENABLED", "AUTHORITY_ENTRA_AUDIENCE", "AUTHORITY_CALLER_OIDS", "AUTHORITY_OUTBOUND_ALLOWLIST",
    ])) == 0
    error_message = "authority_env must not set keys this module owns."
  }
}

variable "authority_flag_enabled" {
  description = "Value of AUTHORITY_ENABLED on the app. false (default): the process runs but refuses every grant route; the api then fails closed for link service and OIDC (ADR-0019 section 6). Flip only after the conditions C-1, C-11, C-15."
  type        = bool
  default     = false
}

# ---- Key custody ----------------------------------------------------------------------------------------------------
variable "seal_construction" {
  description = "hpke-kek (lean pilot, ADR-0034 sections 5, 8, 10: wrapped HPKE seal key held in authority memory, R-23) or jwe-rsa (ADR-0034 section 9: RSA decrypt inside Key Vault, no wrapped blob, no unwrap role). Standard ALWAYS uses jwe-rsa. Staging may move to jwe-rsa too (recommended: one code path); that needs an A3 delta check."
  type        = string
  default     = "hpke-kek"
  validation {
    condition     = contains(["hpke-kek", "jwe-rsa"], var.seal_construction)
    error_message = "seal_construction must be hpke-kek or jwe-rsa."
  }
}

variable "rollover_standby_grants" {
  description = "Standby key objects whose role is granted NOW (a recorded rollover, ADR-0033 section 3.2): any of device-statement-signing-standby, recovery-seal-kek-standby, recovery-seal-rsa-standby. Needs rollover_change_file. Reviewer-gated apply only."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for k in var.rollover_standby_grants : contains(["device-statement-signing-standby", "recovery-seal-kek-standby", "recovery-seal-rsa-standby"], k)])
    error_message = "rollover_standby_grants may only name the standby key objects."
  }
}

variable "rollover_change_file" {
  description = "Path of the reviewed change-file commit on protected main that records the rollover (policy rule AUTH-STANDBY-ROLE). Must be non-empty when rollover_standby_grants is not."
  type        = string
  default     = ""
}

# ---- Monitoring -----------------------------------------------------------------------------------------------------
variable "log_daily_cap_gb" {
  description = "Daily ingestion cap of the authority's OWN Log Analytics workspace (the sign/unwrap reconciliation reads it; ADR-0028 section 2). Default 0.1 (lean), none (standard). An alert fires when the cap is reached, because a capped workspace is blind."
  type        = number
  default     = null
}

variable "alert_email" {
  description = "E-mail receiver of the authority action group. Empty = no action group (alerts still exist in the portal)."
  type        = string
  default     = ""
}

variable "resource_locks" {
  description = "CanNotDelete lock on rg-viadere-<env>-auth. Default: on in standard, off in lean."
  type        = bool
  default     = null
}
