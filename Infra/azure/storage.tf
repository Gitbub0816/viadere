# Audit-head export (standard profile; WP-B2 AzureBlobHeadSink): StorageV2 with version-level immutability (WORM), shared keys disabled,
# Entra-only, private endpoint, public network access disabled. The lean profile creates no audit account (a private endpoint would add a
# fixed fee, and a public storage endpoint is not an allowed lean exception); AUDIT_HEAD_EXPORT stays empty there, as on Fly staging today.

resource "azurerm_storage_account" "audit" {
  count                             = local.p.audit_storage ? 1 : 0
  name                              = "stvdraudit${local.uniq}"
  location                          = var.location
  resource_group_name               = azurerm_resource_group.this["data"].name
  account_kind                      = "StorageV2"
  account_tier                      = "Standard"
  account_replication_type          = "ZRS"
  min_tls_version                   = "TLS1_2"
  https_traffic_only_enabled        = true
  shared_access_key_enabled         = false
  default_to_oauth_authentication   = true
  allow_nested_items_to_be_public   = false
  public_network_access             = "Disabled"
  allowed_copy_scope                = "PrivateLink"
  infrastructure_encryption_enabled = true

  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = 30
    }
    container_delete_retention_policy {
      days = 30
    }
  }

  # Version-level immutability: every blob version is retained unmodifiable for this period. "Unlocked" until the WP-B2 export is
  # verified; then the owner sets audit_immutability_locked = true (irreversible, AZURE-SETUP.md section 12).
  immutability_policy {
    allow_protected_append_writes = false
    period_since_creation_in_days = 400
    state                         = var.audit_immutability_locked ? "Locked" : "Unlocked"
  }

  network_rules {
    default_action = "Deny"
    bypass         = ["None"]
  }

  tags = local.tags
}

resource "azurerm_storage_container" "audit_heads" {
  count                 = local.p.audit_storage ? 1 : 0
  name                  = "audit-heads"
  storage_account_id    = azurerm_storage_account.audit[0].id
  container_access_type = "private"
}

resource "azurerm_role_assignment" "audit_writer" {
  count                            = local.p.audit_storage ? 1 : 0
  scope                            = azurerm_storage_container.audit_heads[0].id
  role_definition_name             = "Storage Blob Data Contributor"
  principal_id                     = azurerm_user_assigned_identity.workload["worker"].principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  description                      = "workload:worker: create audit-head blobs (immutability prevents overwrite and delete)"
}

resource "azurerm_private_endpoint" "audit_blob" {
  count               = local.p.audit_storage ? 1 : 0
  name                = "pe-viadere-${local.env}-audit-blob"
  location            = var.location
  resource_group_name = azurerm_resource_group.this["data"].name
  subnet_id           = azurerm_subnet.pe[0].id
  tags                = local.tags

  private_service_connection {
    name                           = "blob"
    private_connection_resource_id = azurerm_storage_account.audit[0].id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = "blob"
    private_dns_zone_ids = [azurerm_private_dns_zone.this["blob"].id]
  }
}

# Brand Kit assets (WP-2.1, ADR-0017): re-encoded PNGs by content hash (`brand/{business}/{sha256}.png`), written and read only by the api's
# managed identity (Storage Blob Data Contributor on the one container; ingestion and serving both run in the api). Customers never reach the
# account: the api serves `https://{ASSET_DOMAIN}/b/{sha256}.png` through the Cloudflare Tunnel, and Cloudflare caches it (immutable names).
# Shared keys disabled, Entra only, no public blobs, Deny-by-default firewall in both profiles.
#  standard: public network access disabled, private endpoint (blob).
#  lean:     the account's public endpoint with a firewall that admits only the Container Apps subnet (free Microsoft.Storage service
#            endpoint); no private endpoint (fixed fee). A CLAUDE.md exception (policy_check.py `ST-BRAND-PUBLIC`), refused in standard.
resource "azurerm_storage_account" "brand" {
  name                              = "stvdrbrand${local.uniq}"
  location                          = var.location
  resource_group_name               = azurerm_resource_group.this["data"].name
  account_kind                      = "StorageV2"
  account_tier                      = "Standard"
  account_replication_type          = local.p.zone_redundant ? "ZRS" : "LRS"
  min_tls_version                   = "TLS1_2"
  https_traffic_only_enabled        = true
  shared_access_key_enabled         = false
  default_to_oauth_authentication   = true
  allow_nested_items_to_be_public   = false
  public_network_access             = local.p.private_endpoints ? "Disabled" : "Enabled"
  allowed_copy_scope                = local.p.private_endpoints ? "PrivateLink" : "AAD"
  infrastructure_encryption_enabled = true

  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = 30
    }
    container_delete_retention_policy {
      days = 30
    }
  }

  network_rules {
    default_action             = "Deny"
    bypass                     = ["None"]
    virtual_network_subnet_ids = local.p.private_endpoints ? [] : [azurerm_subnet.cae.id]
  }

  tags = local.tags
}

resource "azurerm_storage_container" "brand_assets" {
  name                  = "brand-assets"
  storage_account_id    = azurerm_storage_account.brand.id
  container_access_type = "private"
}

resource "azurerm_role_assignment" "brand_assets_api" {
  scope                            = azurerm_storage_container.brand_assets.id
  role_definition_name             = "Storage Blob Data Contributor"
  principal_id                     = azurerm_user_assigned_identity.workload["api"].principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  description                      = "workload:api: create and read brand asset blobs (create-only writes, content-addressed names)"
}

resource "azurerm_private_endpoint" "brand_blob" {
  count               = local.p.private_endpoints ? 1 : 0
  name                = "pe-viadere-${local.env}-brand-blob"
  location            = var.location
  resource_group_name = azurerm_resource_group.this["data"].name
  subnet_id           = azurerm_subnet.pe[0].id
  tags                = local.tags

  private_service_connection {
    name                           = "blob"
    private_connection_resource_id = azurerm_storage_account.brand.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = "blob"
    private_dns_zone_ids = [azurerm_private_dns_zone.this["blob"].id]
  }
}
