# Values the owner and the authority workflows need. None is secret.
output "authority_enabled" {
  value = var.authority_enabled
}

output "resource_group" {
  value = try(azurerm_resource_group.auth[0].name, null)
}

output "authority_internal_fqdn" {
  description = "Internal FQDN of ca-viadere-authority; the api's AUTHORITY_URL (HTTPS)."
  value       = try("https://${azurerm_container_app.authority[0].ingress[0].fqdn}", null)
}

output "key_vault" {
  value = try({ name = azurerm_key_vault.auth[0].name, uri = azurerm_key_vault.auth[0].vault_uri }, null)
}

output "key_names" {
  description = "Key objects created (standby ones are disabled and carry no role)."
  value       = { active = sort(keys(local.active_keys)), standby = sort(keys(local.standby_keys)) }
}

output "authority_secret_names" {
  description = "Secrets the officers must set (placeholders exist)."
  value       = sort(values(local.authority_secrets))
}

output "registry" {
  value = try({ name = azurerm_container_registry.auth[0].name, login_server = azurerm_container_registry.auth[0].login_server }, null)
}

output "identities" {
  description = "Client and principal ids: the Entra app-role assignment script and the pgaadauth_create_principal bootstrap take these."
  value = local.on == 0 ? null : {
    authority          = { name = azurerm_user_assigned_identity.authority[0].name, client_id = azurerm_user_assigned_identity.authority[0].client_id, principal_id = azurerm_user_assigned_identity.authority[0].principal_id }
    authority_admin    = { name = azurerm_user_assigned_identity.authority_admin[0].name, client_id = azurerm_user_assigned_identity.authority_admin[0].client_id, principal_id = azurerm_user_assigned_identity.authority_admin[0].principal_id }
    authority_migrator = { name = azurerm_user_assigned_identity.authority_migrator[0].name, client_id = azurerm_user_assigned_identity.authority_migrator[0].client_id, principal_id = azurerm_user_assigned_identity.authority_migrator[0].principal_id }
  }
}

output "github_deploy_auth" {
  description = "Variables of the GitHub environment authority-<env> (authority-deploy.yml)."
  value = local.on == 0 ? null : {
    environment               = var.deploy_environment
    AZURE_CLIENT_ID           = azurerm_user_assigned_identity.gh_deploy_auth[0].client_id
    AZURE_TENANT_ID           = var.tenant_id
    AZURE_SUBSCRIPTION_ID     = var.subscription_id
    AZURE_AUTH_RESOURCE_GROUP = azurerm_resource_group.auth[0].name
    AZURE_AUTH_ACR_NAME       = azurerm_container_registry.auth[0].name
  }
}

output "github_authority_admin" {
  description = "Variables of the GitHub environment authority-admin-<env> (authority-admin.yml)."
  value = local.on == 0 ? null : {
    environment               = var.admin_environment
    AZURE_CLIENT_ID           = azurerm_user_assigned_identity.gh_authority_admin[0].client_id
    AZURE_TENANT_ID           = var.tenant_id
    AZURE_SUBSCRIPTION_ID     = var.subscription_id
    AZURE_AUTH_RESOURCE_GROUP = azurerm_resource_group.auth[0].name
  }
}

output "network" {
  value = { subnet = local.subnets.auth, nsg = "nsg-viadere-${local.env}-auth" }
}
