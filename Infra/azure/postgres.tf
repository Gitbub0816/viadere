# Azure Database for PostgreSQL Flexible Server 18 (ADR-0011, plan sections 5.1, 5.9). Private access only (VNet integration in a delegated
# subnet + private DNS zone; no public endpoint, no firewall rules) in BOTH profiles. Version 18 is offered by Azure (new servers get 18.6,
# Microsoft Learn "supported versions" 2026-08-26) and accepted by azurerm 5.12.0 (`version` values 11..18).
#  lean:     Burstable B1ms, 32 GiB, 7-day PITR, no HA (Burstable has none), locally redundant backup.
#  standard: General Purpose D2ds_v5, 128 GiB, zone-redundant HA, 35-day PITR, geo-redundant backup.
# Roles: an Entra admin GROUP (no workload uses it); viadere_migrator / viadere_app / viadere_worker are created by the bootstrap runbook
# (pgaadauth_create_principal for the managed identities; password roles only until WP-B2: AZURE-SETUP.md section 8).

resource "azurerm_postgresql_flexible_server" "this" {
  name                          = "psql-viadere-${local.uniq}"
  location                      = var.location
  resource_group_name           = azurerm_resource_group.this["data"].name
  version                       = "18"
  sku_name                      = local.p.pg_sku
  storage_mb                    = local.p.pg_storage_mb
  auto_grow_enabled             = true
  backup_retention_days         = local.p.pg_backup_days
  geo_redundant_backup_enabled  = local.p.pg_geo_backup
  delegated_subnet_id           = azurerm_subnet.pg.id
  private_dns_zone_id           = azurerm_private_dns_zone.this["postgres"].id
  public_network_access_enabled = false
  zone                          = local.p.pg_ha ? "1" : null

  authentication {
    active_directory_auth_enabled = true
    password_auth_enabled         = var.postgres_password_auth_enabled
    tenant_id                     = var.tenant_id
  }

  # Local administrator: needed by Azure only while password auth is enabled. The password is write-only (never in state) and is sent only
  # on the apply that sets postgres_set_admin_password = true (the first one); later plans leave it out, and rotation goes through
  # `az postgres flexible-server update --admin-password` (AZURE-SETUP.md section 8).
  administrator_login               = var.postgres_password_auth_enabled ? "viadere_local_admin" : null
  administrator_password_wo         = var.postgres_set_admin_password ? var.postgres_admin_password : null
  administrator_password_wo_version = var.postgres_set_admin_password ? var.postgres_admin_password_version : null

  dynamic "high_availability" {
    for_each = local.p.pg_ha ? [1] : []
    content {
      mode                      = "ZoneRedundant"
      standby_availability_zone = "2"
    }
  }

  maintenance_window {
    day_of_week  = 0 # Sunday
    start_hour   = 7 # UTC (02:00/03:00 US Eastern)
    start_minute = 0
  }

  tags = local.tags

  depends_on = [azurerm_private_dns_zone_virtual_network_link.this]

  lifecycle {
    # Azure moves the standby zone after a failover; do not fight it. The admin login must never force a replacement (turning password
    # auth off after WP-B2 would otherwise recreate the server), and the password version is only meaningful on the apply that sets it.
    ignore_changes = [zone, high_availability[0].standby_availability_zone, administrator_login, administrator_password_wo_version]
  }
}

resource "azurerm_postgresql_flexible_server_active_directory_administrator" "admins" {
  server_name         = azurerm_postgresql_flexible_server.this.name
  resource_group_name = azurerm_resource_group.this["data"].name
  tenant_id           = var.tenant_id
  object_id           = var.db_admin_group_object_id
  principal_name      = var.db_admin_group_display_name
  principal_type      = "Group"
}

resource "azurerm_postgresql_flexible_server_database" "viadere" {
  name      = local.database_name
  server_id = azurerm_postgresql_flexible_server.this.id
  charset   = "UTF8"
  collation = "en_US.utf8"
  lifecycle {
    prevent_destroy = true
  }
}

# TLS 1.3 only between the server and its clients (all of them are ours and use SwiftNIO-SSL), TLS required.
resource "azurerm_postgresql_flexible_server_configuration" "tls" {
  for_each = {
    require_secure_transport = "on"
    ssl_min_protocol_version = "TLSv1.3"
    log_connections          = "on"
    log_disconnections       = "on"
    log_checkpoints          = "on"
    # Never log statement parameters (they carry personal data).
    log_min_duration_statement = "-1"
  }
  name      = each.key
  server_id = azurerm_postgresql_flexible_server.this.id
  value     = each.value
}
