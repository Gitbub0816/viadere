# Cloudflare: DNS, TLS policy, HSTS, WAF managed rules, edge rate limits, Authenticated Origin Pulls, origin shared header, site.
# ADR-01 / ADR-04. Requirements: SEC-TR-001..003 (docs/SECURITY-TRUST-PLATFORM-SPEC.md §4.1).

locals {
  api_host = "${var.api_hostname_label}.${var.apex_domain}"
  # Enterprise hostname (Tier E, API Shield mTLS). Same Fly origin, same API layer: only the edge asks for a client certificate here.
  mtls_host = "${var.mtls_hostname_label}.${var.apex_domain}"
  # Azure test hostname served through the Cloudflare Tunnel (migration phase 1, cloudflare_tunnel.tf); empty when not used.
  azure_test_host = var.enable_azure_tunnel && var.azure_test_hostname_label != "" ? "${var.azure_test_hostname_label}.${var.apex_domain}" : ""
  # Hosts that serve the API (edge rate limits, cache bypass). With one host the expression keeps its original `eq` form.
  api_hosts            = compact([local.api_host, local.azure_test_host])
  api_hosts_expression = length(local.api_hosts) == 1 ? "http.host eq \"${local.api_host}\"" : "http.host in {${join(" ", [for h in local.api_hosts : "\"${h}\""])}}"
  # Hosts whose requests reach the API origin; the origin headers below are set (and client-supplied copies overwritten) on all of them.
  origin_hosts            = concat(var.enable_mtls ? [local.api_host, local.mtls_host] : [local.api_host], local.azure_test_host == "" ? [] : [local.azure_test_host])
  origin_hosts_expression = "http.host in {${join(" ", [for h in local.origin_hosts : "\"${h}\""])}}"
  # Zone-wide settings only exist once per zone: staging and production zones are separate (staging.<apex> is a child zone or
  # its own domain in the staging workspace). This module is applied once per environment with its own zone id and state.
}

# ---------------------------------------------------------------------------------------------------------------------
# TLS policy (SEC-TR-001/002). TLS 1.3 enabled; the minimum is 1.2 under the reviewed compatibility policy in
# docs/ops/TLS-COMPATIBILITY-POLICY.md; 1.0/1.1 and SSL are refused by the minimum. TLS 1.2 is limited to ECDHE + AEAD suites.
# ---------------------------------------------------------------------------------------------------------------------
resource "cloudflare_zone_setting" "min_tls_version" {
  zone_id    = var.cloudflare_zone_id
  setting_id = "min_tls_version"
  value      = var.min_tls_version
}

resource "cloudflare_zone_setting" "tls_1_3" {
  zone_id    = var.cloudflare_zone_id
  setting_id = "tls_1_3"
  value      = "on"
}

resource "cloudflare_zone_setting" "ciphers" {
  zone_id    = var.cloudflare_zone_id
  setting_id = "ciphers"
  value      = var.tls12_cipher_suites
}

# Cloudflare -> origin: validate the origin certificate (Fly's Let's Encrypt certificate for api.<apex>).
resource "cloudflare_zone_setting" "ssl" {
  zone_id    = var.cloudflare_zone_id
  setting_id = "ssl"
  value      = "strict"
}

resource "cloudflare_zone_setting" "always_use_https" {
  zone_id    = var.cloudflare_zone_id
  setting_id = "always_use_https"
  value      = "on"
}

resource "cloudflare_zone_setting" "automatic_https_rewrites" {
  zone_id    = var.cloudflare_zone_id
  setting_id = "automatic_https_rewrites"
  value      = "on"
}

# HSTS (SEC-TR-003).
resource "cloudflare_zone_setting" "hsts" {
  zone_id    = var.cloudflare_zone_id
  setting_id = "security_header"
  value = {
    strict_transport_security = {
      enabled            = true
      max_age            = var.hsts_max_age_seconds
      include_subdomains = true
      preload            = var.hsts_preload
      nosniff            = true
    }
  }
}

resource "cloudflare_zone_setting" "opportunistic_encryption" {
  zone_id    = var.cloudflare_zone_id
  setting_id = "opportunistic_encryption"
  value      = "on"
}

resource "cloudflare_zone_setting" "browser_check" {
  zone_id    = var.cloudflare_zone_id
  setting_id = "browser_check"
  value      = "on"
}

resource "cloudflare_zone_setting" "security_level" {
  zone_id    = var.cloudflare_zone_id
  setting_id = "security_level"
  value      = "medium"
}

resource "cloudflare_zone_dnssec" "this" {
  zone_id = var.cloudflare_zone_id
  status  = "active"
}

# ---------------------------------------------------------------------------------------------------------------------
# DNS: apex, www, api (proxied to Fly), status. The _acme-challenge CNAME is NOT proxied (Fly validates it by DNS-01).
# ---------------------------------------------------------------------------------------------------------------------
resource "cloudflare_dns_record" "api" {
  zone_id = var.cloudflare_zone_id
  name    = local.api_host
  type    = "CNAME"
  content = local.api_origin_target
  proxied = true
  ttl     = 1 # automatic
  comment = var.api_origin == "azure" ? "Azure Container Apps through Cloudflare Tunnel (Infra/azure). Proxied: WAF and rate limits apply." : "Fly.io origin (Infra/fly). Proxied: all traffic passes the WAF and rate limits."

  lifecycle {
    precondition {
      condition     = var.api_origin == "fly" || var.enable_azure_tunnel
      error_message = "api_origin = \"azure\" needs enable_azure_tunnel = true (the CNAME points at the tunnel)."
    }
  }
}

resource "cloudflare_dns_record" "api_acme_challenge" {
  count   = var.fly_acme_challenge_cname == "" ? 0 : 1
  zone_id = var.cloudflare_zone_id
  name    = "_acme-challenge.${local.api_host}"
  type    = "CNAME"
  content = var.fly_acme_challenge_cname
  proxied = false
  ttl     = 300
  comment = "Fly certificate DNS-01 validation."
}

# Until the site Worker exists, apex and www are proxied placeholders (traffic never reaches them: a Cloudflare 4xx/5xx
# page is served). With manage_site_custom_domain the Worker custom domain owns the records instead.
resource "cloudflare_dns_record" "apex_placeholder" {
  count   = var.manage_site_custom_domain ? 0 : 1
  zone_id = var.cloudflare_zone_id
  name    = var.apex_domain
  type    = "AAAA"
  content = "100::" # discard prefix (RFC 6666)
  proxied = true
  ttl     = 1
  comment = "Placeholder; replaced by the Workers custom domain (manage_site_custom_domain)."
}

resource "cloudflare_dns_record" "www_placeholder" {
  count   = var.manage_site_custom_domain ? 0 : 1
  zone_id = var.cloudflare_zone_id
  name    = "www.${var.apex_domain}"
  type    = "AAAA"
  content = "100::"
  proxied = true
  ttl     = 1
  comment = "Placeholder; replaced by the Workers custom domain (manage_site_custom_domain)."
}

resource "cloudflare_dns_record" "status" {
  count   = var.status_page_target == "" ? 0 : 1
  zone_id = var.cloudflare_zone_id
  name    = "status.${var.apex_domain}"
  type    = "CNAME"
  content = var.status_page_target
  proxied = false # hosted status page: must NOT depend on our own stack (OPS-009 contact paths independent of Viadere)
  ttl     = 300
  comment = "Hosted status page, intentionally independent of Fly/Cloudflare Workers."
}

# Certificate issuance allow-list. Cloudflare Universal SSL uses these CAs; Fly uses Let's Encrypt.
resource "cloudflare_dns_record" "caa" {
  for_each = toset(["letsencrypt.org", "digicert.com", "pki.goog", "ssl.com", "sectigo.com"])
  zone_id  = var.cloudflare_zone_id
  name     = var.apex_domain
  type     = "CAA"
  ttl      = 3600
  data = {
    flags = 0
    tag   = "issue"
    value = each.value
  }
  comment = "Permitted certificate authorities."
}

# ---------------------------------------------------------------------------------------------------------------------
# Site: Workers Static Assets. The script and its asset manifest are created by Site/deploy/upload.py through the REST
# direct-upload API (ADR-04); Terraform does NOT own the script content (a state-managed upload would fight the uploader).
# It only binds the hostnames, once the script exists. cloudflare_workers_script is deliberately not used for this reason.
# ---------------------------------------------------------------------------------------------------------------------
resource "cloudflare_workers_custom_domain" "apex" {
  count      = var.manage_site_custom_domain ? 1 : 0
  account_id = var.cloudflare_account_id
  zone_id    = var.cloudflare_zone_id
  hostname   = var.apex_domain
  service    = var.site_worker_name
}

resource "cloudflare_workers_custom_domain" "www" {
  count      = var.manage_site_custom_domain ? 1 : 0
  account_id = var.cloudflare_account_id
  zone_id    = var.cloudflare_zone_id
  hostname   = "www.${var.apex_domain}"
  service    = var.site_worker_name
}

# ---------------------------------------------------------------------------------------------------------------------
# Authenticated Origin Pulls (mTLS from Cloudflare to the origin). Enabling it makes Cloudflare present a client certificate.
# ENFORCEMENT happens at the origin, and the Fly proxy cannot verify client certificates: see Infra/fly/README.md step 6.
# ---------------------------------------------------------------------------------------------------------------------
resource "cloudflare_authenticated_origin_pulls_settings" "zone" {
  zone_id = var.cloudflare_zone_id
  enabled = true
}

# Per-zone client certificate (instead of Cloudflare's shared one). Uncomment once a certificate is issued by your own CA:
# resource "cloudflare_authenticated_origin_pulls_certificate" "zone" { ... }  # see the provider docs for the exact schema in use

# ---------------------------------------------------------------------------------------------------------------------
# Headers the origin trusts, set at the edge (gap G-10, SEC-TR-005; docs/ops/KILL-SWITCHES.md):
#  1. X-Viadere-Edge-Token: the shared secret. The server refuses (421) every request that lacks it, in constant time.
#  2. X-Viadere-Client-Cert-*: what Cloudflare itself verified about the client certificate (API Shield mTLS). They are **always overwritten**
#     here, for every request to the API hosts, so a client can never smuggle its own values through Cloudflare to the origin; on a host or
#     request without a certificate they read `false` and empty. The server believes them only on a request that carries the edge token.
# One entry-point ruleset exists per zone and phase, so both live in the same resource.
# ---------------------------------------------------------------------------------------------------------------------
resource "cloudflare_ruleset" "origin_edge_token" {
  zone_id = var.cloudflare_zone_id
  name    = "Viadere origin headers"
  kind    = "zone"
  phase   = "http_request_late_transform"
  rules = [
    {
      action = "rewrite"
      action_parameters = {
        headers = {
          "X-Viadere-Edge-Token" = {
            operation = "set"
            value     = var.edge_token
          }
        }
      }
      expression  = local.origin_hosts_expression
      description = "Set the origin shared header"
      enabled     = var.enable_origin_edge_token
    },
    {
      action = "rewrite"
      action_parameters = {
        headers = {
          "X-Viadere-Client-Cert-Verified" = {
            operation  = "set"
            expression = "to_string(cf.tls_client_auth.cert_verified)"
          }
          "X-Viadere-Client-Cert-Sha256" = {
            operation  = "set"
            expression = "cf.tls_client_auth.cert_fingerprint_sha256"
          }
          "X-Viadere-Client-Cert-Issuer-Ski" = {
            operation  = "set"
            expression = "cf.tls_client_auth.cert_issuer_ski"
          }
          # Cloudflare exposes no SHA-256 of the issuer certificate. The header is removed so a client can never supply one; the origin treats an
          # absent value as "not forwarded" and relies on the SKI plus Viadere's refusal of duplicate identifiers across tenants (SECURITY.md).
          "X-Viadere-Client-Cert-Issuer-Sha256" = {
            operation = "remove"
          }
        }
      }
      expression  = local.origin_hosts_expression
      description = "Overwrite the client-certificate headers with what Cloudflare verified"
      enabled     = true
    },
  ]
}

# ---------------------------------------------------------------------------------------------------------------------
# Tier E enterprise connectivity: API Shield mutual TLS on a separate hostname (SEC-TR-005). Ordinary businesses use the normal API hostname
# with no certificate and no VPN; an enterprise points its integration at the mTLS hostname and presents a client certificate issued by a CA
# that Viadere uploaded for it (account-level `mtls_certificates` plus a hostname association, done per tenant at onboarding through the
# Cloudflare API: docs/ops/RUNBOOKS.md "Enterprise mTLS onboarding"). The edge refuses a request without a verified certificate on this
# hostname; the server additionally checks that the certificate is bound to the tenant that owns the API key.
# ---------------------------------------------------------------------------------------------------------------------
resource "cloudflare_dns_record" "api_mtls" {
  count   = var.enable_mtls ? 1 : 0
  zone_id = var.cloudflare_zone_id
  name    = local.mtls_host
  type    = "CNAME"
  content = local.api_origin_target
  proxied = true
  ttl     = 1 # automatic
  comment = var.api_origin == "azure" ? "Tier E: API Shield mTLS hostname (same Azure origin through the tunnel)." : "Tier E: API Shield mTLS hostname (same Fly origin). Add its certificate on Fly: fly certs add."
}

resource "cloudflare_ruleset" "mtls_enforce" {
  count   = var.enable_mtls ? 1 : 0
  zone_id = var.cloudflare_zone_id
  name    = "Viadere API Shield mTLS"
  kind    = "zone"
  phase   = "http_request_firewall_custom"
  rules = [{
    action      = "block"
    expression  = "http.host eq \"${local.mtls_host}\" and not cf.tls_client_auth.cert_verified"
    description = "Enterprise hostname: refuse requests without a verified client certificate"
    enabled     = true
  }]
}

# The API is dynamic: bypass the cache for it. (Static, immutable assets are served by the origin with their own cache headers.)
resource "cloudflare_ruleset" "api_cache_bypass" {
  zone_id = var.cloudflare_zone_id
  name    = "Viadere API cache bypass"
  kind    = "zone"
  phase   = "http_request_cache_settings"
  rules = [{
    action = "set_cache_settings"
    action_parameters = {
      cache = false
    }
    expression  = "${local.api_hosts_expression} and not starts_with(http.request.uri.path, \"/connect-button/v1/\")"
    description = "No caching of API, dashboard and operator responses"
    enabled     = true
  }]
}

# ---------------------------------------------------------------------------------------------------------------------
# WAF managed rules (OWASP Core and Cloudflare Managed). Start in log mode on a new zone if false positives are a concern, then
# switch action to "block". Provider webhooks (Twilio, RCS) are signed and skip nothing here; add narrowly scoped skip rules
# only with evidence from the firewall log.
# ---------------------------------------------------------------------------------------------------------------------
resource "cloudflare_ruleset" "waf_managed" {
  zone_id = var.cloudflare_zone_id
  name    = "Viadere managed WAF"
  kind    = "zone"
  phase   = "http_request_firewall_managed"
  rules = [
    {
      action = "execute"
      action_parameters = {
        id = var.managed_ruleset_ids["cloudflare_managed"]
      }
      expression  = "true"
      description = "Cloudflare Managed Ruleset"
      enabled     = true
    },
    {
      action = "execute"
      action_parameters = {
        id = var.managed_ruleset_ids["owasp_core"]
      }
      expression  = "true"
      description = "OWASP Core Ruleset"
      enabled     = true
    },
  ]
}

# ---------------------------------------------------------------------------------------------------------------------
# Edge rate limits for the credential-bearing paths (a coarse first layer: the server enforces precise per-account, per-phone
# and per-address limits in the shared database, docs/SECURITY.md §2.23). Thresholds are per source IP per Cloudflare PoP.
# ---------------------------------------------------------------------------------------------------------------------
locals {
  rate_limits = {
    auth = {
      description = "Passkey login/registration and token refresh"
      expression  = "starts_with(http.request.uri.path, \"/v1/auth/\")"
      requests    = 30
      period      = 60
      timeout     = 600
    }
    device_enroll = {
      description = "Device enrollment and confirmation"
      expression  = "starts_with(http.request.uri.path, \"/v1/devices\") and http.request.method eq \"POST\""
      requests    = 20
      period      = 60
      timeout     = 600
    }
    recovery = {
      description = "Account recovery (begin, complete, codes)"
      expression  = "starts_with(http.request.uri.path, \"/v1/recovery\")"
      requests    = 10
      period      = 60
      timeout     = 3600
    }
    otp_link = {
      description = "SMS link tokens and verification codes"
      expression  = "starts_with(http.request.uri.path, \"/v1/sms/link-tokens/\") or starts_with(http.request.uri.path, \"/l/\") or starts_with(http.request.uri.path, \"/h/\")"
      requests    = 20
      period      = 60
      timeout     = 600
    }
    dashboard_auth = {
      description = "Dashboard and operator sign-up, email codes, login, invitations"
      expression  = "http.request.method eq \"POST\" and (starts_with(http.request.uri.path, \"/dashboard/signup\") or starts_with(http.request.uri.path, \"/dashboard/verify\") or starts_with(http.request.uri.path, \"/dashboard/login\") or starts_with(http.request.uri.path, \"/dashboard/invite\") or starts_with(http.request.uri.path, \"/operator/login\"))"
      requests    = 15
      period      = 60
      timeout     = 900
    }
    redemption = {
      description = "Redemption code validation by businesses"
      expression  = "http.request.uri.path eq \"/v1/business/redemptions/consume\""
      requests    = 120
      period      = 60
      timeout     = 300
    }
  }
}

resource "cloudflare_ruleset" "rate_limits" {
  zone_id = var.cloudflare_zone_id
  name    = "Viadere edge rate limits"
  kind    = "zone"
  phase   = "http_ratelimit"
  rules = [for name, r in local.rate_limits : {
    action      = "block"
    expression  = "${local.api_hosts_expression} and (${r.expression})"
    description = "${name}: ${r.description}"
    enabled     = true
    ratelimit = {
      characteristics     = ["cf.colo.id", "ip.src"]
      period              = r.period
      requests_per_period = ceil(r.requests * var.rate_limit_scale)
      mitigation_timeout  = r.timeout
    }
  }]
}
