# kv-vdr-auth-<env>: the authority's own Key Vault (ADR-0012, ADR-0028, ADR-0034). RBAC only, purge protection, 90-day soft delete.
#  lean:     Standard SKU (software-protected keys), public endpoint with Entra-only access, firewall admits only snet-auth (service endpoint)
#            and listed officer IPs, trusted Azure services for ARM key creation (CLAUDE.md lean exceptions, same rows as kv-vdr).
#  standard: Premium (HSM keys), private endpoint, public access disabled.
# Keys and secret placeholders are created through the ARM control plane (no data-plane path needed by OpenTofu; no secret value in state).
# Nothing in this vault is ever granted to an ordinary identity (AUTH-KEY-SCOPE).

resource "azurerm_key_vault" "auth" {
  count                           = local.on
  name                            = local.kv_name
  location                        = var.location
  resource_group_name             = azurerm_resource_group.auth[0].name
  tenant_id                       = var.tenant_id
  sku_name                        = local.p.kv_sku
  rbac_authorization_enabled      = true
  purge_protection_enabled        = true
  soft_delete_retention_days      = 90
  public_network_access_enabled   = !local.p.private_ep
  enabled_for_deployment          = false
  enabled_for_disk_encryption     = false
  enabled_for_template_deployment = false

  network_acls {
    bypass                     = "AzureServices" # ARM key creation (network layer only; no data-plane role is granted to trusted services)
    default_action             = "Deny"
    virtual_network_subnet_ids = local.p.private_ep ? [] : [azurerm_subnet.auth[0].id]
    ip_rules                   = local.p.private_ep ? [] : var.key_vault_allowed_ip_ranges
  }

  tags = local.tags
}

resource "azapi_resource" "kv_key" {
  for_each  = local.on == 1 ? local.all_keys : {}
  type      = "Microsoft.KeyVault/vaults/keys@2026-02-01"
  name      = each.key
  parent_id = azurerm_key_vault.auth[0].id
  body = {
    properties = merge(
      {
        kty    = each.value.kty
        keyOps = each.value.ops
        attributes = {
          # Standby objects are created DISABLED (ADR-0033 section 3.2): they cannot be used before a recorded rollover enables them.
          enabled    = !contains(keys(local.standby_keys), each.key)
          exportable = false
        }
      },
      each.value.curve != null ? { curveName = each.value.curve } : {},
      each.value.size != null ? { keySize = each.value.size } : {},
    )
  }
  # New versions (rotation) and the standby's activation are crypto-officer / admin-job tasks (docs/ops/KEY_ROTATION.md).
  lifecycle {
    ignore_changes = [body]
  }
}

resource "azapi_resource" "kv_secret" {
  for_each  = local.on == 1 ? toset(values(local.authority_secrets)) : toset([])
  type      = "Microsoft.KeyVault/vaults/secrets@2026-02-01"
  name      = each.key
  parent_id = azurerm_key_vault.auth[0].id
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

# ---- Custom roles (S1-A3-11): data actions the built-in Crypto User role would over-grant (it includes backup and update, checked on
# Microsoft Learn "Azure built-in roles for Security", 2026-11-02). ---------------------------------------------------------------------
# NOTE (L-12 re-check): the Key Vault data action for unwrapping is `Microsoft.KeyVault/vaults/keys/unwrap/action` (not `unwrapKey/action`
# as ADR-0028 wrote it); the Learn page lists keys/{read,update,backup,encrypt,decrypt,wrap,unwrap,sign,verify}. The roles below use the
# real names; policy_check.py accepts exactly these.
resource "azurerm_role_definition" "signer" {
  count       = local.on
  name        = "Viadere Authority Signer (${local.env})"
  scope       = azurerm_resource_group.auth[0].id
  description = "Read a key's public part and sign with it. No backup, update, encrypt, decrypt, wrap or unwrap."

  permissions {
    data_actions = [
      "Microsoft.KeyVault/vaults/keys/read",
      "Microsoft.KeyVault/vaults/keys/sign/action",
    ]
  }
  assignable_scopes = [azurerm_resource_group.auth[0].id]
}

resource "azurerm_role_definition" "unwrapper" {
  count       = local.on == 1 && !local.p.jwe_rsa_seal ? 1 : 0
  name        = "Viadere Authority Unwrapper (${local.env})"
  scope       = azurerm_resource_group.auth[0].id
  description = "Read a key's public part and unwrap with it (recovery-seal-kek only; lean HPKE construction, ADR-0034 section 5)."

  permissions {
    data_actions = [
      "Microsoft.KeyVault/vaults/keys/read",
      "Microsoft.KeyVault/vaults/keys/unwrap/action",
    ]
  }
  assignable_scopes = [azurerm_resource_group.auth[0].id]
}

resource "azurerm_role_definition" "decrypter" {
  count       = local.on == 1 && local.p.jwe_rsa_seal ? 1 : 0
  name        = "Viadere Authority Decrypter (${local.env})"
  scope       = azurerm_resource_group.auth[0].id
  description = "Read a key's public part and decrypt with it (recovery-seal-rsa only; ADR-0034 section 9)."

  permissions {
    data_actions = [
      "Microsoft.KeyVault/vaults/keys/read",
      "Microsoft.KeyVault/vaults/keys/decrypt/action",
    ]
  }
  assignable_scopes = [azurerm_resource_group.auth[0].id]
}

locals {
  role_name = local.on == 1 ? {
    signer    = azurerm_role_definition.signer[0].name
    unwrapper = try(azurerm_role_definition.unwrapper[0].name, "")
    decrypter = try(azurerm_role_definition.decrypter[0].name, "")
  } : {}
}

# ---- Active keys: id-viadere-authority, custom role, KEY scope ----------------------------------------------------------------------
resource "azurerm_role_assignment" "authority_key" {
  for_each = local.on == 1 ? local.active_keys : {}

  scope                            = azapi_resource.kv_key[each.key].id
  role_definition_name             = local.role_name[local.key_role[each.key]]
  principal_id                     = azurerm_user_assigned_identity.authority[0].principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  description                      = "workload:authority: use key ${each.key} (${local.key_role[each.key]}), key scope, no backup or management"
}

# ---- Standby keys: NO role until a recorded rollover (AUTH-STANDBY-ROLE). The role comes only from a reviewer-gated apply that sets
# rollover_standby_grants together with rollover_change_file. ------------------------------------------------------------------------
resource "azurerm_role_assignment" "rollover" {
  for_each = local.on == 1 ? toset(var.rollover_standby_grants) : toset([])

  scope                            = azapi_resource.kv_key[each.key].id
  role_definition_name             = local.role_name[local.key_role[each.key]]
  principal_id                     = azurerm_user_assigned_identity.authority[0].principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  description                      = "workload:authority: ROLLOVER of ${each.key} recorded in ${var.rollover_change_file}"

  lifecycle {
    precondition {
      condition     = var.rollover_change_file != ""
      error_message = "A standby key role needs rollover_change_file (AUTH-STANDBY-ROLE)."
    }
  }
}

# ---- Secrets: Key Vault Secrets User at SECRET scope --------------------------------------------------------------------------------
resource "azurerm_role_assignment" "authority_secret" {
  for_each = local.on == 1 ? toset(values(local.authority_secrets)) : toset([])

  scope                            = azapi_resource.kv_secret[each.key].id
  role_definition_name             = "Key Vault Secrets User"
  principal_id                     = azurerm_user_assigned_identity.authority[0].principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  description                      = "workload:authority: read secret ${each.key}"
}

# ---- Humans: the authority crypto-officer group (PIM, time-bound) is the only holder of backup rights (AUTH-KEY-BACKUP) -----------------
resource "azurerm_role_assignment" "officers" {
  count                = local.on == 1 && var.authority_crypto_officers_group_object_id != "" ? 1 : 0
  scope                = azurerm_key_vault.auth[0].id
  role_definition_name = "Key Vault Crypto Officer"
  principal_id         = var.authority_crypto_officers_group_object_id
  principal_type       = "Group"
  description          = "human:grp-viadere-auth-crypto-officers: create and rotate authority keys through PIM; backup only by runbook"
}

resource "azurerm_role_assignment" "secrets_officers" {
  count                = local.on == 1 && var.authority_secrets_officers_group_object_id != "" ? 1 : 0
  scope                = azurerm_key_vault.auth[0].id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = var.authority_secrets_officers_group_object_id
  principal_type       = "Group"
  description          = "human:auth-secrets-officers: set authority secret values"
}

# ---- Standard: private endpoint ----------------------------------------------------------------------------------------------------------
data "azurerm_subnet" "pe" {
  count                = local.on == 1 && local.p.private_ep ? 1 : 0
  name                 = local.ordinary.pe_subnet
  virtual_network_name = local.ordinary.vnet
  resource_group_name  = local.ordinary.rg_net
}

data "azurerm_private_dns_zone" "vault" {
  count               = local.on == 1 && local.p.private_ep ? 1 : 0
  name                = local.ordinary.vault_zone
  resource_group_name = local.ordinary.rg_net
}

resource "azurerm_private_endpoint" "key_vault" {
  count               = local.on == 1 && local.p.private_ep ? 1 : 0
  name                = "pe-viadere-${local.env}-kv-auth"
  location            = var.location
  resource_group_name = azurerm_resource_group.auth[0].name
  subnet_id           = data.azurerm_subnet.pe[0].id
  tags                = local.tags

  private_service_connection {
    name                           = "kv-auth"
    private_connection_resource_id = azurerm_key_vault.auth[0].id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = "kv-auth"
    private_dns_zone_ids = [data.azurerm_private_dns_zone.vault[0].id]
  }
}
