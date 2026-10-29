# Key Vault (ADR-0012, plan sections 5.3 and 5.6). RBAC only (no access policies), purge protection, 90-day soft delete.
#  lean:     Standard SKU (software-protected keys), public endpoint with Entra-only access whose firewall admits only the Container Apps
#            subnet (service endpoint) and optional admin IPs (CLAUDE.md exception).
#  standard: Premium SKU (EC-HSM P-256 signing keys, RSA-HSM 3072 key-encryption key), private endpoint, public access disabled.
# Keys and secret placeholders are created through the ARM control plane (Microsoft.KeyVault/vaults/keys|secrets), so OpenTofu needs no
# data-plane network path or data-plane role, and no secret value ever enters the state. Workloads get Crypto User / Secrets User on the
# individual key or secret, never on the vault; key creation/rotation beyond these initial versions is a crypto-officer task.

resource "azurerm_key_vault" "this" {
  name                            = "kv-vdr-${local.uniq}"
  location                        = var.location
  resource_group_name             = azurerm_resource_group.this["sec"].name
  tenant_id                       = var.tenant_id
  sku_name                        = local.p.kv_sku
  rbac_authorization_enabled      = true
  purge_protection_enabled        = true
  soft_delete_retention_days      = 90
  public_network_access_enabled   = !local.p.private_endpoints
  enabled_for_deployment          = false
  enabled_for_disk_encryption     = false
  enabled_for_template_deployment = false

  # Deny by default in both profiles. Lean admits the Container Apps subnet (service endpoint) and the owner's admin IPs, if any; standard
  # admits nothing on the public endpoint (which is disabled) and is reached through its private endpoint.
  network_acls {
    bypass                     = "None"
    default_action             = "Deny"
    virtual_network_subnet_ids = local.p.private_endpoints ? [] : [azurerm_subnet.cae.id]
    ip_rules                   = local.p.private_endpoints ? [] : var.key_vault_allowed_ip_ranges
  }

  tags = local.tags
}

resource "azapi_resource" "kv_key" {
  for_each  = local.kv_keys
  type      = "Microsoft.KeyVault/vaults/keys@2026-02-01"
  name      = each.key
  parent_id = azurerm_key_vault.this.id
  body = {
    properties = merge(
      {
        kty    = each.value.kty
        keyOps = each.value.ops
        attributes = {
          enabled    = true
          exportable = false
        }
      },
      each.value.curve != null ? { curveName = each.value.curve } : {},
      each.value.size != null ? { keySize = each.value.size } : {},
    )
  }
  # Later key versions are created by crypto officers (rotation runbook); OpenTofu only ensures the key exists.
  lifecycle {
    ignore_changes = [body]
  }
}

# Placeholders: the owner sets the real value afterwards (a new version); the server fails closed on the placeholder (it is not valid
# base64url of the required length, nor a postgres URL). sensitive_body is write-only, so even the placeholder never reaches the state.
resource "azapi_resource" "kv_secret" {
  for_each  = local.all_secret_names
  type      = "Microsoft.KeyVault/vaults/secrets@2026-02-01"
  name      = each.key
  parent_id = azurerm_key_vault.this.id
  body = {
    properties = {
      contentType = "text/plain"
      attributes  = { enabled = true }
    }
  }
  sensitive_body = {
    properties = {
      value = "unset-placeholder"
    }
  }
  lifecycle {
    ignore_changes = [body]
  }
}

resource "azurerm_role_assignment" "key_user" {
  for_each = merge([for id, keys in local.key_grants : { for k in keys : "${id}/${k}" => { identity = id, key = k } }]...)

  scope                            = azapi_resource.kv_key[each.value.key].id
  role_definition_name             = "Key Vault Crypto User"
  principal_id                     = azurerm_user_assigned_identity.workload[each.value.identity].principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  description                      = "workload:${each.value.identity}: use key ${each.value.key} (sign or wrap/unwrap), no management"
}

resource "azurerm_role_assignment" "secret_user" {
  for_each = local.secret_grants

  scope                            = azapi_resource.kv_secret[each.value.secret].id
  role_definition_name             = "Key Vault Secrets User"
  principal_id                     = azurerm_user_assigned_identity.workload[each.value.identity].principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  description                      = "workload:${each.value.identity}: read secret ${each.value.secret}"
}

# Humans (vault scope is a resource scope): crypto officers manage keys; secrets officers set secret values on the data plane.
resource "azurerm_role_assignment" "kv_crypto_officers" {
  count                = var.key_vault_crypto_officers_group_object_id == "" ? 0 : 1
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Crypto Officer"
  principal_id         = var.key_vault_crypto_officers_group_object_id
  principal_type       = "Group"
  description          = "human:grp-viadere-kv-crypto-officers: create and rotate keys; nobody in the group runs workloads"
}

resource "azurerm_role_assignment" "kv_secrets_officers" {
  count                = var.key_vault_secrets_officers_group_object_id == "" ? 0 : 1
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = var.key_vault_secrets_officers_group_object_id
  principal_type       = "Group"
  description          = "human:secrets-officers: set secret values"
}

resource "azurerm_private_endpoint" "key_vault" {
  count               = local.p.private_endpoints ? 1 : 0
  name                = "pe-viadere-${local.env}-kv"
  location            = var.location
  resource_group_name = azurerm_resource_group.this["sec"].name
  subnet_id           = azurerm_subnet.pe[0].id
  tags                = local.tags

  private_service_connection {
    name                           = "kv"
    private_connection_resource_id = azurerm_key_vault.this.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = "kv"
    private_dns_zone_ids = [azurerm_private_dns_zone.this["vault"].id]
  }
}
