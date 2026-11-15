# The authority's own container registry (TRUST_BOUNDARIES section 9, ADR-0029 section 6): the authority has no Internet egress, so it never
# pulls from GHCR. authority-deploy.yml verifies the signed release image (cosign + SLSA provenance) and imports it BY DIGEST with
# `az acr import`, a control-plane operation run by the registry service. Admin user off, anonymous pull off, Entra only.
#  lean:     Basic (about USD 5.07/month). Basic has no firewall or private endpoint: the public endpoint stays, protected by Entra tokens
#            only; the NSG still limits the authority to the AzureContainerRegistry / Storage service tags (recorded lean exception,
#            policy rule ACR-AUTH-PUBLIC).
#  standard: Premium with a private endpoint is part of the Stage 6 standard decision (not created here until that profile is applied).
resource "azurerm_container_registry" "auth" {
  count                         = local.on
  name                          = local.cr_name
  location                      = var.location
  resource_group_name           = azurerm_resource_group.auth[0].name
  sku                           = local.p.acr_sku
  admin_enabled                 = false
  anonymous_pull_enabled        = false
  public_network_access_enabled = !local.standard
  network_rule_bypass_option    = "AzureServices"
  export_policy_enabled         = local.standard ? false : true # Basic cannot disable export
  tags                          = local.tags
}
