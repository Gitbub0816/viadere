# Log Analytics + workspace-based Application Insights (plan section 5.1). Local (shared-key / instrumentation-key) authentication is off:
# the Container Apps environment sends logs through Azure Monitor diagnostic settings, and telemetry ingestion (WP-F2) uses Entra tokens of
# the workload identities (Monitoring Metrics Publisher on the component).

resource "azurerm_log_analytics_workspace" "this" {
  name                         = "log-viadere-${local.env}"
  location                     = var.location
  resource_group_name          = azurerm_resource_group.this["ops"].name
  sku                          = "PerGB2018"
  retention_in_days            = local.p.la_retention_days
  daily_quota_gb               = local.la_daily_cap_gb
  local_authentication_enabled = false
  tags                         = local.tags
}

resource "azurerm_application_insights" "this" {
  name                         = "appi-viadere-${local.env}"
  location                     = var.location
  resource_group_name          = azurerm_resource_group.this["ops"].name
  workspace_id                 = azurerm_log_analytics_workspace.this.id
  application_type             = "other"
  local_authentication_enabled = false
  daily_data_cap_in_gb         = local.la_daily_cap_gb > 0 ? local.la_daily_cap_gb : 100
  ip_masking_enabled           = true # never store client IPs in telemetry
  internet_ingestion_enabled   = true
  internet_query_enabled       = true
  tags                         = local.tags
}

# Diagnostic logs. Key Vault audit events (every key and secret operation, with the caller) are the evidence for "any key operation by an
# unexpected principal" alerts (section 5.3); the queries live with WP-F2.
resource "azurerm_monitor_diagnostic_setting" "key_vault" {
  name                       = "diag-to-log"
  target_resource_id         = azurerm_key_vault.this.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id
  enabled_log {
    category_group = "audit"
  }
}

resource "azurerm_monitor_diagnostic_setting" "container_apps" {
  name                       = "diag-to-log"
  target_resource_id         = azapi_resource.cae.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id
  enabled_log {
    category_group = "allLogs"
  }
}

resource "azurerm_monitor_diagnostic_setting" "postgres" {
  name                       = "diag-to-log"
  target_resource_id         = azurerm_postgresql_flexible_server.this.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id
  enabled_log {
    category = "PostgreSQLLogs"
  }
}

resource "azurerm_monitor_diagnostic_setting" "service_bus" {
  name                       = "diag-to-log"
  target_resource_id         = azurerm_servicebus_namespace.this.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id
  enabled_log {
    category = "OperationalLogs" # available on every tier (RuntimeAuditLogs is Premium only)
  }
}
