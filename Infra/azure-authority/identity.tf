# Identities of the authority tier (TRUST_BOUNDARIES 4.2, ADR-0028 sections 2, 5, 6). One resource block PER identity (no for_each): the
# policy checker (policy_check.py, AUTH-* rules) reads which identity a role assignment or app uses from the plan's references.
# Rules: no role at subscription scope; workload identities only at resource scope; every assignment carries a classifying description
# (workload: / deploy: / human:). The OpenTofu apply identity id-gh-infra-auth-apply-<env> is created by the bootstrap, not here.

resource "azurerm_user_assigned_identity" "authority" {
  count               = local.on
  name                = "id-viadere-authority"
  location            = var.location
  resource_group_name = azurerm_resource_group.auth[0].name
  tags                = local.tags
}

resource "azurerm_user_assigned_identity" "authority_admin" {
  count               = local.on
  name                = "id-viadere-authority-admin"
  location            = var.location
  resource_group_name = azurerm_resource_group.auth[0].name
  tags                = local.tags
}

# Reads the authority workspace (Key Vault AuditEvent rows) and the authority's sign records; holds no Key Vault role (ADR-0023 section 6).
resource "azurerm_user_assigned_identity" "authority_reconcile" {
  count               = local.reconcile
  name                = "id-viadere-authority-reconcile"
  location            = var.location
  resource_group_name = azurerm_resource_group.auth[0].name
  tags                = local.tags
}

resource "azurerm_user_assigned_identity" "authority_migrator" {
  count               = local.on
  name                = "id-viadere-authority-migrator"
  location            = var.location
  resource_group_name = azurerm_resource_group.auth[0].name
  tags                = local.tags
}

# The authority's own deploy identity: it can touch only rg-viadere-<env>-auth (AUTH-DEPLOY-SEPARATE).
resource "azurerm_user_assigned_identity" "gh_deploy_auth" {
  count               = local.on
  name                = "id-gh-deploy-auth-${local.env}"
  location            = var.location
  resource_group_name = azurerm_resource_group.auth[0].name
  tags                = local.tags
}

# Starts job-viadere-authority-admin and nothing else (ADR-0028 section 6.5).
resource "azurerm_user_assigned_identity" "gh_authority_admin" {
  count               = local.on
  name                = "id-gh-authority-admin-${local.env}"
  location            = var.location
  resource_group_name = azurerm_resource_group.auth[0].name
  tags                = local.tags
}

# Only the named workflow, on main, in the reviewer-gated GitHub environment obtains a token (subject pinned with job_workflow_ref once the
# repository's OIDC subject template includes it: var.oidc_subject_workflow_ref).
resource "azurerm_federated_identity_credential" "gh_deploy_auth" {
  count                     = local.on
  name                      = "github-${var.deploy_environment}"
  user_assigned_identity_id = azurerm_user_assigned_identity.gh_deploy_auth[0].id
  issuer                    = "https://token.actions.githubusercontent.com"
  audience                  = ["api://AzureADTokenExchange"]
  subject                   = local.deploy_subject
}

resource "azurerm_federated_identity_credential" "gh_authority_admin" {
  count                     = local.on
  name                      = "github-${var.admin_environment}"
  user_assigned_identity_id = azurerm_user_assigned_identity.gh_authority_admin[0].id
  issuer                    = "https://token.actions.githubusercontent.com"
  audience                  = ["api://AzureADTokenExchange"]
  subject                   = local.admin_subject
}

# ---- Deploy identity --------------------------------------------------------------------------------------------------
resource "azurerm_role_assignment" "gh_deploy_auth_container_apps" {
  count                            = local.on
  scope                            = azurerm_resource_group.auth[0].id
  role_definition_name             = "Container Apps Contributor"
  principal_id                     = azurerm_user_assigned_identity.gh_deploy_auth[0].principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  description                      = "deploy:gh-deploy-auth: update the authority image and run the authority migrate job (resource group rg-viadere-<env>-auth only)"
}

resource "azurerm_role_assignment" "gh_deploy_auth_operator_authority" {
  count                            = local.on
  scope                            = azurerm_user_assigned_identity.authority[0].id
  role_definition_name             = "Managed Identity Operator"
  principal_id                     = azurerm_user_assigned_identity.gh_deploy_auth[0].principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  description                      = "deploy:gh-deploy-auth: assign id-viadere-authority to revisions (no token access)"
}

resource "azurerm_role_assignment" "gh_deploy_auth_operator_admin" {
  count                            = local.on
  scope                            = azurerm_user_assigned_identity.authority_admin[0].id
  role_definition_name             = "Managed Identity Operator"
  principal_id                     = azurerm_user_assigned_identity.gh_deploy_auth[0].principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  description                      = "deploy:gh-deploy-auth: assign id-viadere-authority-admin to the admin job (no token access)"
}

resource "azurerm_role_assignment" "gh_deploy_auth_operator_migrator" {
  count                            = local.on
  scope                            = azurerm_user_assigned_identity.authority_migrator[0].id
  role_definition_name             = "Managed Identity Operator"
  principal_id                     = azurerm_user_assigned_identity.gh_deploy_auth[0].principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  description                      = "deploy:gh-deploy-auth: assign id-viadere-authority-migrator to the migrate job (no token access)"
}

# `az acr import` of the verified release image by digest (a registry control-plane operation). Narrower than AcrPush: it cannot push layers.
resource "azurerm_role_assignment" "gh_deploy_auth_acr_import" {
  count                            = local.on
  scope                            = azurerm_container_registry.auth[0].id
  role_definition_name             = "Container Registry Data Importer and Data Reader"
  principal_id                     = azurerm_user_assigned_identity.gh_deploy_auth[0].principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  description                      = "deploy:gh-deploy-auth: import the verified authority image by digest into the authority registry"
}

# ---- Admin starter: custom role on exactly one job -----------------------------------------------------------------------
resource "azurerm_role_definition" "job_starter" {
  count       = local.on
  name        = "Viadere Container Apps Job Starter (${local.env})"
  scope       = azurerm_resource_group.auth[0].id
  description = "Start executions of one Container Apps job and read their status. Nothing else."

  permissions {
    actions = [
      "Microsoft.App/jobs/read",
      "Microsoft.App/jobs/start/action",
      "Microsoft.App/jobs/executions/read",
    ]
  }
  assignable_scopes = [azurerm_resource_group.auth[0].id]
}

resource "azurerm_role_assignment" "gh_authority_admin_start" {
  count                            = local.on
  scope                            = azurerm_container_app_job.admin[0].id
  role_definition_name             = azurerm_role_definition.job_starter[0].name
  principal_id                     = azurerm_user_assigned_identity.gh_authority_admin[0].principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  description                      = "deploy:gh-authority-admin: start job-viadere-authority-admin (reviewer-gated workflow authority-admin.yml)"
}

# No log reader (ledger S6-06, policy rule AUTH-INVENTORY-CHANNEL): the key inventory is a reviewed change file that the serving authority
# verifies against Key Vault; authority-admin.yml reads only the exit status of `key-inventory-check`, never a log.

# ---- Registry pull (lean ACR Basic / standard ACR Premium in the authority group; never GHCR) -------------------------------------
resource "azurerm_role_assignment" "acr_pull" {
  for_each = local.on == 1 ? {
    authority = azurerm_user_assigned_identity.authority[0].principal_id
    admin     = azurerm_user_assigned_identity.authority_admin[0].principal_id
    migrator  = azurerm_user_assigned_identity.authority_migrator[0].principal_id
  } : {}
  scope                            = azurerm_container_registry.auth[0].id
  role_definition_name             = "AcrPull"
  principal_id                     = each.value
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  description                      = "workload:authority-${each.key}: pull the authority image from the authority registry"
}

# ---- Telemetry: the authority sends its own App Insights telemetry with an Entra token ------------------------------------------------
resource "azurerm_role_assignment" "telemetry" {
  count                            = local.on
  scope                            = azurerm_application_insights.auth[0].id
  role_definition_name             = "Monitoring Metrics Publisher"
  principal_id                     = azurerm_user_assigned_identity.authority[0].principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  description                      = "workload:authority: send telemetry with an Entra token"
}

# ---- Reconciliation job identity: AcrPull and Log Analytics Reader on the authority workspace; no Key Vault role --------------------------
resource "azurerm_role_assignment" "reconcile_acr_pull" {
  count                            = local.reconcile
  scope                            = azurerm_container_registry.auth[0].id
  role_definition_name             = "AcrPull"
  principal_id                     = azurerm_user_assigned_identity.authority_reconcile[0].principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  description                      = "workload:authority-reconcile: pull the authority image from the authority registry"
}

# The reconciliation reads Key Vault AuditEvent rows of kv-vdr-auth from the authority's own workspace (it holds only authority data).
resource "azurerm_role_assignment" "reconcile_logs" {
  count                            = local.reconcile
  scope                            = azurerm_log_analytics_workspace.auth[0].id
  role_definition_name             = "Log Analytics Reader"
  principal_id                     = azurerm_user_assigned_identity.authority_reconcile[0].principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  description                      = "workload:authority-reconcile: read Key Vault AuditEvent rows of the authority workspace"
}
