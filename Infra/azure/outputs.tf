# Values the owner, the deploy workflow and Infra/terraform (Cloudflare Tunnel) need. None is secret.

output "profile" {
  value = var.profile
}

output "resource_groups" {
  value = { for k, v in azurerm_resource_group.this : k => v.name }
}

output "container_apps_environment" {
  value = {
    name           = azapi_resource.cae.name
    id             = azapi_resource.cae.id
    default_domain = try(azapi_resource.cae.output.properties.defaultDomain, null)
    static_ip      = try(azapi_resource.cae.output.properties.staticIp, null)
  }
}

output "api_app_name" {
  value = azurerm_container_app.api.name
}

output "migrate_job_name" {
  value = azurerm_container_app_job.migrate.name
}

output "tunnel_origin_service" {
  description = "Origin service for the Cloudflare Tunnel ingress rule (Infra/terraform variable azure_tunnel_origin_service): the api by app name inside the environment."
  value       = "http://${azurerm_container_app.api.name}"
}

output "api_internal_fqdn" {
  value = azurerm_container_app.api.ingress[0].fqdn
}

output "image_registry" {
  description = "Where the deploy workflow puts images: the ACR login server (standard) or ghcr.io (lean)."
  value       = local.p.registry ? azurerm_container_registry.this[0].login_server : "ghcr.io"
}

output "acr_name" {
  value = local.p.registry ? azurerm_container_registry.this[0].name : ""
}

output "key_vault" {
  value = {
    name = azurerm_key_vault.this.name
    uri  = azurerm_key_vault.this.vault_uri
    id   = azurerm_key_vault.this.id
  }
}

output "key_vault_secret_names" {
  description = "Secrets the owner must set (AZURE-SETUP.md section 7)."
  value       = sort(tolist(local.all_secret_names))
}

output "service_bus_fqdn" {
  value = "${azurerm_servicebus_namespace.this.name}.servicebus.windows.net"
}

output "postgres" {
  value = {
    name     = azurerm_postgresql_flexible_server.this.name
    fqdn     = azurerm_postgresql_flexible_server.this.fqdn
    database = local.database_name
    roles    = local.db_roles
  }
}

output "workload_identities" {
  description = "Names, client ids and principal (object) ids. The display names are what pgaadauth_create_principal takes (AZURE-SETUP.md section 8)."
  value = { for k, v in azurerm_user_assigned_identity.workload : k => {
    name         = v.name
    client_id    = v.client_id
    principal_id = v.principal_id
  } }
}

output "github_deploy" {
  description = "Set these as variables of the GitHub environment (AZURE-SETUP.md section 5)."
  value = {
    environment           = local.github_deploy_environment
    AZURE_CLIENT_ID       = azurerm_user_assigned_identity.gh_deploy.client_id
    AZURE_TENANT_ID       = var.tenant_id
    AZURE_SUBSCRIPTION_ID = var.subscription_id
    AZURE_RESOURCE_GROUP  = azurerm_resource_group.this["app"].name
    AZURE_PROFILE         = var.profile
    AZURE_ACR_NAME        = local.p.registry ? azurerm_container_registry.this[0].name : ""
  }
}

output "egress_ip" {
  description = "Static egress IP (standard: NAT gateway). Lean uses the environment's platform-managed outbound address."
  value       = local.p.nat_gateway ? azurerm_public_ip.nat[0].ip_address : null
}

output "health_peer_networks" {
  value = local.subnets.cae
}

output "key_vault_secret_map" {
  description = "Environment variable -> Key Vault secret, for Infra/azure/kv_tool.py put-env (AZURE-SETUP.md section 7)."
  value       = merge(local.api_secrets, local.worker_secrets, local.migrate_secrets)
}
