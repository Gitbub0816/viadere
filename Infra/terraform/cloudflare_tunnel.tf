# Cloudflare Tunnel to the Azure origin (ADR-0010; docs/IMPLEMENTATION-PLAN-v3.md sections 4 and 5.4; docs/ops/AZURE-SETUP.md section 9).
# The connector (cloudflared) runs as the container app ca-cloudflared inside the internal Container Apps environment (Infra/azure) and
# opens OUTBOUND connections to Cloudflare; the api has no public ingress at all. Cloudflare still adds X-Viadere-Edge-Token on every
# origin host (cloudflare.tf, `origin_hosts`), which the server keeps enforcing as a second layer.
#
# Migration phases: 1. enable_azure_tunnel = true with azure_test_hostname_label (e.g. "viadere-api-az"): a test host on the tunnel, the
# production hostnames unchanged. 5. api_origin = "azure": the api (and Tier E mTLS) hostname CNAMEs move from Fly to the tunnel. Rollback
# = api_origin = "fly". The tunnel token is NOT read here (it would land in state): the owner fetches it once from the Cloudflare API and
# stores it in Key Vault secret cloudflared-tunnel-token (AZURE-SETUP.md section 9).

locals {
  tunnel_enabled = var.enable_azure_tunnel
  tunnel_cname   = local.tunnel_enabled ? "${cloudflare_zero_trust_tunnel_cloudflared.azure[0].id}.cfargotunnel.com" : ""
  # The api / mTLS records point at the tunnel only after cutover (api_origin = "azure").
  api_origin_target = var.api_origin == "azure" && local.tunnel_enabled ? local.tunnel_cname : var.fly_origin_hostname
  tunnel_hostnames = concat(
    local.azure_test_host == "" ? [] : [local.azure_test_host],
    var.api_origin == "azure" ? (var.enable_mtls ? [local.api_host, local.mtls_host] : [local.api_host]) : [],
  )
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "azure" {
  count      = local.tunnel_enabled ? 1 : 0
  account_id = var.cloudflare_account_id
  name       = "viadere-${var.environment}-azure"
  config_src = "cloudflare" # remotely managed: ingress rules below, the connector only needs its token
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "azure" {
  count      = local.tunnel_enabled ? 1 : 0
  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.azure[0].id
  source     = "cloudflare"
  config = {
    ingress = concat(
      [for host in local.tunnel_hostnames : {
        hostname = host
        service  = var.azure_tunnel_origin_service
        origin_request = {
          # Container Apps routes internal traffic by Host: the api's app name inside the environment.
          http_host_header = var.azure_tunnel_origin_host_header
          connect_timeout  = 10
          tls_timeout      = 10
          no_tls_verify    = false
        }
      }],
      # Anything else that reaches the tunnel is refused at the connector.
      [{ service = "http_status:404" }],
    )
  }
}

resource "cloudflare_dns_record" "azure_test" {
  count   = local.azure_test_host == "" ? 0 : 1
  zone_id = var.cloudflare_zone_id
  name    = local.azure_test_host
  type    = "CNAME"
  content = local.tunnel_cname
  proxied = true
  ttl     = 1
  comment = "Azure origin through Cloudflare Tunnel (migration phase 1 test host). WAF, rate limits and the edge token apply."
}
