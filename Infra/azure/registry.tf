# Azure Container Registry (standard profile). Premium because private endpoints require it; admin user off, anonymous pull off, public
# network access disabled. The release workflow verifies the GHCR image (cosign + provenance) and then imports it BY DIGEST with
# `az acr import` (a control-plane operation run by the registry service, which is why "AzureServices" may bypass the network rules).
# Lean pulls from GHCR directly (no registry, no fixed fee).

resource "azurerm_container_registry" "this" {
  count                         = local.p.registry ? 1 : 0
  name                          = "crviadere${local.uniq}"
  location                      = var.location
  resource_group_name           = azurerm_resource_group.this["app"].name
  sku                           = "Premium"
  admin_enabled                 = false
  anonymous_pull_enabled        = false
  public_network_access_enabled = false
  network_rule_bypass_option    = "AzureServices"
  zone_redundancy_enabled       = true
  export_policy_enabled         = false
  quarantine_policy_enabled     = false
  retention_policy_in_days      = 30
  tags                          = local.tags
}

resource "azurerm_role_assignment" "acr_pull" {
  count                            = local.p.registry ? 1 : 0
  scope                            = azurerm_container_registry.this[0].id
  role_definition_name             = "AcrPull"
  principal_id                     = azurerm_user_assigned_identity.acrpull[0].principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  description                      = "workload:acrpull: pull images for every app and job"
}

resource "azurerm_role_assignment" "gh_deploy_acr_import" {
  count                            = local.p.registry ? 1 : 0
  scope                            = azurerm_container_registry.this[0].id
  role_definition_name             = "Container Registry Data Importer and Data Reader"
  principal_id                     = azurerm_user_assigned_identity.gh_deploy.principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  description                      = "deploy:gh-deploy: import the verified release image by digest"
}

resource "azurerm_private_endpoint" "acr" {
  count               = local.p.registry ? 1 : 0
  name                = "pe-viadere-${local.env}-acr"
  location            = var.location
  resource_group_name = azurerm_resource_group.this["app"].name
  subnet_id           = azurerm_subnet.pe[0].id
  tags                = local.tags

  private_service_connection {
    name                           = "acr"
    private_connection_resource_id = azurerm_container_registry.this[0].id
    subresource_names              = ["registry"]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = "acr"
    private_dns_zone_ids = [azurerm_private_dns_zone.this["acr"].id]
  }
}
