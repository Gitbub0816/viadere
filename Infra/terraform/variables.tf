# Every identifier is a variable; nothing environment-specific or secret is committed. Values come from terraform.tfvars
# (gitignored) or TF_VAR_* in CI. See terraform.tfvars.example.

variable "environment" {
  description = "production | staging. Selects names, branch layout and protection."
  type        = string
  validation {
    condition     = contains(["production", "staging"], var.environment)
    error_message = "environment must be production or staging."
  }
}

# ---- Cloudflare ----------------------------------------------------------------------------------------------
variable "cloudflare_account_id" {
  type = string
}

variable "cloudflare_zone_id" {
  description = "Zone id of the apex domain (the zone itself is created out of band so the registrar delegation is a manual step)."
  type        = string
}

variable "apex_domain" {
  description = "Apex domain, e.g. viadere.com."
  type        = string
}

variable "api_hostname_label" {
  description = "Label of the API origin hostname under the apex (api, or api-staging)."
  type        = string
  default     = "api"
}

variable "fly_origin_hostname" {
  description = "The Fly app hostname the proxied api record points to, e.g. viadere-server.fly.dev."
  type        = string
}

variable "fly_acme_challenge_cname" {
  description = "Target of the _acme-challenge CNAME printed by `fly certs show` (leave empty before the certificate is added)."
  type        = string
  default     = ""
}

variable "site_worker_name" {
  description = "Name of the Workers Static Assets script the Site deploy uploads (Site/deploy/upload.py owns its contents)."
  type        = string
  default     = "viadere-site"
}

variable "manage_site_custom_domain" {
  description = "Bind apex and www to the site Worker. Enable only after Site/deploy/upload.py has created the script once."
  type        = bool
  default     = false
}

variable "status_page_target" {
  description = "CNAME target of the hosted status page (e.g. a statuspage provider). Empty = no status record."
  type        = string
  default     = ""
}

variable "min_tls_version" {
  description = "Minimum TLS version Cloudflare accepts from clients. 1.2 is the reviewed compatibility policy (docs/ops/TLS-COMPATIBILITY-POLICY.md, SEC-TR-001); set 1.3 once the telemetry gate in that document is met."
  type        = string
  default     = "1.2"
  validation {
    condition     = contains(["1.2", "1.3"], var.min_tls_version)
    error_message = "min_tls_version must be 1.2 or 1.3."
  }
}

variable "tls12_cipher_suites" {
  description = "Cipher suites allowed for TLS 1.2 (TLS 1.3 suites are fixed and all AEAD). ECDHE + AEAD only: no CBC, no RSA key exchange, no 3DES/RC4."
  type        = list(string)
  default = [
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
  ]
}

variable "hsts_max_age_seconds" {
  description = "HSTS max-age. Start at 300 on first rollout, raise to 31536000 after a clean week; preload only after the review in the TLS policy."
  type        = number
  default     = 31536000
}

variable "hsts_preload" {
  type    = bool
  default = false
}

variable "edge_token" {
  description = "Random value of the X-Viadere-Edge-Token request header Cloudflare adds to every origin request (shared with Fly secret EDGE_TOKEN). Sensitive; rotate with an overlap window."
  type        = string
  sensitive   = true
}

variable "enable_origin_edge_token" {
  type    = bool
  default = true
}

variable "enable_mtls" {
  description = "Create the Tier E enterprise hostname with API Shield mTLS (SEC-TR-005). Off until the first enterprise tenant is onboarded. The client-certificate headers are overwritten at the edge whether this is on or not."
  type        = bool
  default     = false
}

variable "mtls_hostname_label" {
  description = "Label of the enterprise mTLS hostname under the apex (api-mtls, or api-mtls.staging)."
  type        = string
  default     = "api-mtls"
}

variable "managed_ruleset_ids" {
  description = "Cloudflare managed ruleset ids to execute (plan dependent). Defaults: Cloudflare Managed Ruleset and OWASP Core Ruleset."
  type        = map(string)
  default = {
    cloudflare_managed = "efb7b8c949ac4650a09736fc376e9aee"
    owasp_core         = "4814384a9e5d4991b9815dcfc25d2f1f"
  }
}

variable "rate_limit_scale" {
  description = "Multiplier for the edge rate-limit thresholds (staging may use a larger value so load tests are not blocked)."
  type        = number
  default     = 1
}

variable "aop_client_certificate" {
  description = "PEM client certificate for per-zone Authenticated Origin Pulls (optional; empty = Cloudflare's shared certificate)."
  type        = string
  default     = ""
}

variable "aop_client_private_key" {
  type      = string
  default   = ""
  sensitive = true
}

# ---- Google Cloud KMS ---------------------------------------------------------------------------------------
variable "gcp_project_id" {
  description = "Dedicated project that holds only the Viadere key ring and its audit sink."
  type        = string
}

variable "kms_location" {
  description = "KMS location. Use a multi-region such as `us` or a region next to the Fly primary region; HSM keys are available in both."
  type        = string
  default     = "us-east1"
}

variable "kms_signing_principals" {
  description = "Additional principals (group:/user:) allowed to VIEW key metadata. Never grant sign or decrypt to humans here."
  type        = list(string)
  default     = []
}

variable "kms_key_rotation_period" {
  description = "Automatic rotation for symmetric keys (seconds with s suffix). Asymmetric keys cannot rotate automatically: rotate them with the runbook (docs/ops/RUNBOOKS.md, signing-key compromise)."
  type        = string
  default     = "7776000s" # 90 days
}

variable "kms_workload_identity_pool" {
  description = "Workload identity pool principal that the Fly machines present (principalSet://iam.googleapis.com/projects/NUMBER/locations/global/workloadIdentityPools/POOL/attribute.app/viadere-server). The server impersonates the dedicated service account through it; there is no downloaded key."
  type        = string
}

variable "security_alert_notification_channel_ids" {
  description = "Cloud Monitoring notification channel ids (pager/email) for key-use alerts."
  type        = list(string)
  default     = []
}

# ---- Neon ---------------------------------------------------------------------------------------------------
variable "neon_org_id" {
  type = string
}

variable "neon_region_id" {
  description = "Neon region, next to the Fly primary region (aws-us-east-1 for iad)."
  type        = string
  default     = "aws-us-east-1"
}

variable "neon_pg_version" {
  description = "PostgreSQL major version (policy: 18). The plan checks that the provider accepts it."
  type        = number
  default     = 18
}

variable "neon_history_retention_seconds" {
  description = "Point-in-time-restore window. Production target 7 days (604800); raise if the plan allows. Drives RPO (docs/ops/RESILIENCE.md)."
  type        = number
  default     = 604800
}

variable "neon_allowed_ips" {
  description = "Optional IP allow-list for Neon connections (Fly egress addresses). Empty = Neon default (TLS + password). Fly machines have no static egress unless you allocate static egress IPs (`fly ips allocate-egress`)."
  type        = list(string)
  default     = []
}

# ---- Azure origin through Cloudflare Tunnel (cloudflare_tunnel.tf; docs/ops/AZURE-SETUP.md section 9) ------------------------------
variable "enable_azure_tunnel" {
  description = "Create the Cloudflare Tunnel for the Azure Container Apps origin (Infra/azure). Off until the Azure environment exists."
  type        = bool
  default     = false
}

variable "azure_test_hostname_label" {
  description = "Label of a test hostname routed through the tunnel before cutover (e.g. viadere-api-az). Empty = none."
  type        = string
  default     = ""
}

variable "api_origin" {
  description = "Where the api (and Tier E mTLS) hostname points: fly (today) or azure (Cloudflare Tunnel; needs enable_azure_tunnel). Cutover and rollback are a change of this value."
  type        = string
  default     = "fly"
  validation {
    condition     = contains(["fly", "azure"], var.api_origin)
    error_message = "api_origin must be fly or azure."
  }
}

variable "azure_tunnel_origin_service" {
  description = "Origin service the tunnel forwards to: Infra/azure output tunnel_origin_service (the api by app name inside the Container Apps environment)."
  type        = string
  default     = "http://ca-viadere-api"
  validation {
    condition     = can(regex("^https?://[a-z0-9.-]+(:[0-9]+)?$", var.azure_tunnel_origin_service))
    error_message = "azure_tunnel_origin_service must be an http(s) URL without a path."
  }
}

variable "azure_tunnel_origin_host_header" {
  description = "Host header cloudflared sends to the origin (Container Apps routes environment-internal traffic by the app name)."
  type        = string
  default     = "ca-viadere-api"
}
