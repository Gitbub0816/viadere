output "api_hostname" {
  value = local.api_host
}

output "mtls_hostname" {
  description = "Tier E enterprise hostname (empty unless enable_mtls)."
  value       = var.enable_mtls ? local.mtls_host : ""
}

output "azure_tunnel_id" {
  description = "Cloudflare Tunnel id. Fetch its token once for Key Vault: docs/ops/AZURE-SETUP.md section 9."
  value       = cloudflare_zero_trust_tunnel_cloudflared.azure.id
}

output "azure_tunnel_hostnames" {
  value = local.tunnel_hostnames
}
