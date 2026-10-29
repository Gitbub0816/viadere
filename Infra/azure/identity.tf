# User-assigned managed identities, GitHub OIDC federation and the role assignments that are not tied to one data resource (section 5.3).
# Rules (enforced by policy_check.py on every plan):
#  * no role assignment at subscription or management-group scope from this module;
#  * workload identities hold roles only at RESOURCE scope (a key, a secret, a namespace, a container), never on a resource group;
#  * the deploy identity holds Container Apps Contributor on the app resource group and no data-plane role;
#  * every assignment carries a `description` that classifies it (workload: / deploy: / human:), so the checker can tell them apart.
# The OpenTofu plan/apply identities are created by the bootstrap (docs/ops/AZURE-SETUP.md section 4), not here: a module must not grant
# rights to the identity that applies it.

resource "azurerm_user_assigned_identity" "workload" {
  for_each            = toset(local.workload_identities)
  name                = "id-viadere-${each.key}"
  location            = var.location
  resource_group_name = azurerm_resource_group.this["sec"].name
  tags                = local.tags
}

# Image pulls from ACR (standard only). Separate identity so pulling never coexists with data-plane rights.
resource "azurerm_user_assigned_identity" "acrpull" {
  count               = local.p.registry ? 1 : 0
  name                = "id-viadere-acrpull"
  location            = var.location
  resource_group_name = azurerm_resource_group.this["sec"].name
  tags                = local.tags
}

resource "azurerm_user_assigned_identity" "gh_deploy" {
  name                = "id-gh-deploy-${local.env}"
  location            = var.location
  resource_group_name = azurerm_resource_group.this["sec"].name
  tags                = local.tags
}

# Only jobs that run in the GitHub environment get a token with this subject; production's environment has required reviewers.
resource "azurerm_federated_identity_credential" "gh_deploy" {
  name                      = "github-${local.github_deploy_environment}"
  user_assigned_identity_id = azurerm_user_assigned_identity.gh_deploy.id
  issuer                    = "https://token.actions.githubusercontent.com"
  audience                  = ["api://AzureADTokenExchange"]
  subject                   = "repo:${var.github_repository}:environment:${local.github_deploy_environment}"
}

# ---- Deploy identity --------------------------------------------------------------------------------------------------
resource "azurerm_role_assignment" "gh_deploy_container_apps" {
  scope                            = azurerm_resource_group.this["app"].id
  role_definition_name             = "Container Apps Contributor"
  principal_id                     = azurerm_user_assigned_identity.gh_deploy.principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  description                      = "deploy:gh-deploy: update the api image and run the migrate job"
}

# Updating a container app re-sends its identity list; ARM then checks assign/action on each user-assigned identity.
resource "azurerm_role_assignment" "gh_deploy_identity_operator" {
  for_each                         = toset(local.workload_identities)
  scope                            = azurerm_user_assigned_identity.workload[each.key].id
  role_definition_name             = "Managed Identity Operator"
  principal_id                     = azurerm_user_assigned_identity.gh_deploy.principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  description                      = "deploy:gh-deploy: assign ${each.key} to revisions (no token access)"
}

resource "azurerm_role_assignment" "gh_deploy_acrpull_operator" {
  count                            = local.p.registry ? 1 : 0
  scope                            = azurerm_user_assigned_identity.acrpull[0].id
  role_definition_name             = "Managed Identity Operator"
  principal_id                     = azurerm_user_assigned_identity.gh_deploy.principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  description                      = "deploy:gh-deploy: assign acrpull to revisions (no token access)"
}

# ---- Workload identities: telemetry (WP-F2) -----------------------------------------------------------------------------
resource "azurerm_role_assignment" "telemetry" {
  for_each                         = toset(["api", "worker"])
  scope                            = azurerm_application_insights.this.id
  role_definition_name             = "Monitoring Metrics Publisher"
  principal_id                     = azurerm_user_assigned_identity.workload[each.key].principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  description                      = "workload:${each.key}: send telemetry with an Entra token"
}
