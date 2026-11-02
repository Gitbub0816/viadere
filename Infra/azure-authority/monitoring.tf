# The authority's OWN Log Analytics workspace and Application Insights (ADR-0024 section 7.3 names "the authority workspace"; the admin
# identity may read only this workspace). Local (shared-key) authentication is off. Diagnostic settings carry the Key Vault AuditEvent
# stream that the sign/unwrap/decrypt reconciliation job reads (ADR-0028 section 2), the Container Apps logs and the PostgreSQL logs of the
# shared server are NOT duplicated here (the server's own diagnostic setting stays in the ordinary workspace).

resource "azurerm_log_analytics_workspace" "auth" {
  count                        = local.on
  name                         = "log-viadere-${local.env}-auth"
  location                     = var.location
  resource_group_name          = azurerm_resource_group.auth[0].name
  sku                          = "PerGB2018"
  retention_in_days            = local.p.la_retention
  daily_quota_gb               = local.la_daily_cap_gb
  local_authentication_enabled = false
  tags                         = local.tags
}

resource "azurerm_application_insights" "auth" {
  count                        = local.on
  name                         = "appi-viadere-${local.env}-auth"
  location                     = var.location
  resource_group_name          = azurerm_resource_group.auth[0].name
  workspace_id                 = azurerm_log_analytics_workspace.auth[0].id
  application_type             = "other"
  local_authentication_enabled = false
  daily_data_cap_in_gb         = local.la_daily_cap_gb > 0 ? local.la_daily_cap_gb : 100
  ip_masking_enabled           = true
  # Egress is denied at the NSG for everything but the AzureMonitor tag; ingestion stays on the public Azure Monitor endpoint.
  internet_ingestion_enabled = true
  internet_query_enabled     = false
  tags                       = local.tags
}

resource "azurerm_monitor_diagnostic_setting" "key_vault" {
  count                      = local.on
  name                       = "diag-to-log"
  target_resource_id         = azurerm_key_vault.auth[0].id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.auth[0].id
  enabled_log {
    category_group = "audit"
  }
}

resource "azurerm_monitor_diagnostic_setting" "container_apps" {
  count                      = local.on
  name                       = "diag-to-log"
  target_resource_id         = azapi_resource.cae[0].id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.auth[0].id
  enabled_log {
    category_group = "allLogs"
  }
}

# ---- Alerts (ADR-0028 section 7). Cost-conscious: ONE log query alert (about USD 1.5/month) plus free Activity Log alerts. ----------------
resource "azurerm_monitor_action_group" "auth" {
  count               = local.on == 1 && var.alert_email != "" ? 1 : 0
  name                = "ag-viadere-${local.env}-auth"
  resource_group_name = azurerm_resource_group.auth[0].name
  short_name          = "vdrauth"
  tags                = local.tags

  email_receiver {
    name                    = "owner"
    email_address           = var.alert_email
    use_common_alert_schema = true
  }
}

# Any Key Vault data-plane operation by a caller other than id-viadere-authority. Officer operations (PIM-activated users) alert BY DESIGN:
# every key create/update/delete/backup and every secret write in kv-vdr-auth must be expected and match a change record.
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "kv_unexpected_principal" {
  count                = local.on == 1 && var.alert_email != "" ? 1 : 0
  name                 = "alert-viadere-${local.env}-auth-kv-unexpected-principal"
  resource_group_name  = azurerm_resource_group.auth[0].name
  location             = var.location
  evaluation_frequency = "PT15M"
  window_duration      = "PT15M"
  scopes               = [azurerm_log_analytics_workspace.auth[0].id]
  severity             = 1
  description          = "A Key Vault data-plane operation on kv-vdr-auth by a principal other than id-viadere-authority (officer operations alert by design)."
  tags                 = local.tags

  criteria {
    query                   = <<-KQL
      AzureDiagnostics
      | where ResourceProvider == "MICROSOFT.KEYVAULT" and Category == "AuditEvent"
      | where OperationName in ("Sign","Decrypt","UnwrapKey","KeyGet","KeyCreate","KeyUpdate","KeyDelete","KeyBackup","SecretGet","SecretSet","SecretDelete")
      | extend oid = tostring(parse_json(identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g))
      | where oid != "${azurerm_user_assigned_identity.authority[0].principal_id}"
    KQL
    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0
    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.auth[0].id]
  }
}

resource "azurerm_monitor_activity_log_alert" "auth_control_plane" {
  count               = local.on == 1 && var.alert_email != "" ? 1 : 0
  name                = "alert-viadere-${local.env}-auth-control-plane"
  resource_group_name = azurerm_resource_group.auth[0].name
  location            = "global"
  scopes              = [azurerm_resource_group.auth[0].id]
  description         = "Role assignments, NSG rules or Container Apps environment/app changes in rg-viadere-<env>-auth."
  tags                = local.tags

  criteria {
    resource_group = azurerm_resource_group.auth[0].name
    category       = "Administrative"
    operation_name = "Microsoft.Authorization/roleAssignments/write"
  }
  action {
    action_group_id = azurerm_monitor_action_group.auth[0].id
  }
}

resource "azurerm_monitor_activity_log_alert" "auth_network" {
  count               = local.on == 1 && var.alert_email != "" ? 1 : 0
  name                = "alert-viadere-${local.env}-auth-network"
  resource_group_name = azurerm_resource_group.auth[0].name
  location            = "global"
  scopes              = [azurerm_resource_group.auth[0].id, "/subscriptions/${var.subscription_id}/resourceGroups/${local.ordinary.rg_net}"]
  description         = "Changes to the authority NSG or its rules."
  tags                = local.tags

  criteria {
    category       = "Administrative"
    operation_name = "Microsoft.Network/networkSecurityGroups/write"
  }
  action {
    action_group_id = azurerm_monitor_action_group.auth[0].id
  }
}
