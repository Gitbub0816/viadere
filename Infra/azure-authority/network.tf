# Resource group, snet-auth, its NSG (deny-by-default both ways, named service tags only) and private DNS (TRUST_BOUNDARIES section 9).
# The VNet, the PostgreSQL server and (standard) the private-endpoint subnet belong to Infra/azure and are only READ here.

data "azurerm_virtual_network" "ordinary" {
  count               = local.on
  name                = local.ordinary.vnet
  resource_group_name = local.ordinary.rg_net
}

data "azurerm_postgresql_flexible_server" "ordinary" {
  count               = local.on
  name                = local.ordinary.pg_server
  resource_group_name = local.ordinary.rg_data
}

resource "azurerm_resource_group" "auth" {
  count    = local.on
  name     = local.rg_auth
  location = var.location
  tags     = local.tags

  lifecycle {
    precondition {
      condition     = contains(["centralus", "eastus", "eastus2", "southcentralus", "northcentralus", "westcentralus", "westus", "westus2", "westus3"], var.location)
      error_message = "The authority must run in an Azure US region (decision 13, RESIDENCY-US)."
    }
    precondition {
      condition     = var.image != "" && var.authority_entra_audience != ""
      error_message = "authority_enabled needs image (by digest) and authority_entra_audience (bootstrap/create-entra-app.sh)."
    }
    precondition {
      condition     = length(var.rollover_standby_grants) == 0 || var.rollover_change_file != ""
      error_message = "rollover_standby_grants needs rollover_change_file: a standby key gets a role only through a recorded rollover (AUTH-STANDBY-ROLE)."
    }
  }
}

resource "azurerm_management_lock" "auth" {
  count      = local.on == 1 && local.resource_locks ? 1 : 0
  name       = "lock-viadere-${local.env}-auth"
  scope      = azurerm_resource_group.auth[0].id
  lock_level = "CanNotDelete"
  notes      = "Viadere ${var.environment}: the private authority and its key material. Removal needs the owner's approval."
}

# snet-auth is delegated to Microsoft.App/environments (workload-profiles environment). /27 is the documented minimum for workload
# profile environments; the Learn page "Securing a Virtual Network in Azure Container Apps" (checked 2026-11-02) lists no larger minimum.
resource "azurerm_subnet" "auth" {
  count                = local.on
  name                 = "snet-auth"
  resource_group_name  = local.ordinary.rg_net
  virtual_network_name = data.azurerm_virtual_network.ordinary[0].name
  address_prefixes     = [local.subnets.auth]

  # Lean: Key Vault keeps its public endpoint but its firewall admits only this subnet (free service endpoint). Standard uses a private endpoint.
  dynamic "service_endpoint" {
    for_each = local.p.private_ep ? [] : ["Microsoft.KeyVault"]
    content {
      service = service_endpoint.value
    }
  }

  delegation {
    name = "containerapps"
    service_delegation {
      name    = "Microsoft.App/environments"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

# NSG nsg-viadere-<env>-auth. The outbound allow-list was checked against Microsoft Learn "Securing a Virtual Network in Azure Container Apps"
# (workload profile environment, page dated 2026-04-01, read 2026-11-02): MicrosoftContainerRegistry and AzureFrontDoor.FirstParty (its
# dependency, an EXTRA tag next to ADR section 9's list, recorded here), AzureActiveDirectory (managed identity), AzureMonitor, DNS to
# 168.63.129.16 (never denied), AzureContainerRegistry + Storage.<region> (registry), plus this module's own: PostgreSQL 5432 to snet-pg and
# AzureKeyVault.<region> 443. Everything else on the Internet is denied by the last rule (AUTH-EGRESS).
resource "azurerm_network_security_group" "auth" {
  count               = local.on
  name                = "nsg-viadere-${local.env}-auth"
  location            = var.location
  resource_group_name = local.ordinary.rg_net
  tags                = local.tags

  # ---- inbound ----
  security_rule {
    name                       = "allow-https-from-cae"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = local.subnets.cae
    source_port_range          = "*"
    destination_address_prefix = local.subnets.auth
    destination_port_ranges    = ["443", "31443"]
  }
  security_rule {
    name                       = "allow-load-balancer-probes"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = "AzureLoadBalancer"
    source_port_range          = "*"
    destination_address_prefix = local.subnets.auth
    destination_port_range     = "30000-32767"
  }
  security_rule {
    name                       = "allow-within-subnet"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_address_prefix      = local.subnets.auth
    source_port_range          = "*"
    destination_address_prefix = local.subnets.auth
    destination_port_range     = "*"
  }
  security_rule {
    name                       = "deny-all-inbound"
    priority                   = 4000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_address_prefix      = "*"
    source_port_range          = "*"
    destination_address_prefix = "*"
    destination_port_range     = "*"
  }

  # ---- outbound ----
  security_rule {
    name                       = "allow-postgres"
    priority                   = 100
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = local.subnets.auth
    source_port_range          = "*"
    destination_address_prefix = local.subnets.pg
    destination_port_range     = "5432"
  }
  security_rule {
    name                       = "allow-within-subnet"
    priority                   = 110
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "*"
    source_address_prefix      = local.subnets.auth
    source_port_range          = "*"
    destination_address_prefix = local.subnets.auth
    destination_port_range     = "*"
  }
  dynamic "security_rule" {
    for_each = {
      "allow-entra"                  = { prio = 120, tag = "AzureActiveDirectory" }
      "allow-key-vault"              = { prio = 130, tag = "AzureKeyVault.${var.location}" }
      "allow-azure-monitor"          = { prio = 140, tag = "AzureMonitor" }
      "allow-container-registry"     = { prio = 150, tag = "AzureContainerRegistry.${var.location}" }
      "allow-registry-storage"       = { prio = 160, tag = "Storage.${var.location}" }
      "allow-microsoft-registry"     = { prio = 170, tag = "MicrosoftContainerRegistry" }
      "allow-front-door-first-party" = { prio = 180, tag = "AzureFrontDoor.FirstParty" }
    }
    content {
      name                       = security_rule.key
      priority                   = security_rule.value.prio
      direction                  = "Outbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_address_prefix      = local.subnets.auth
      source_port_range          = "*"
      destination_address_prefix = security_rule.value.tag
      destination_port_range     = "443"
    }
  }
  security_rule {
    name                       = "allow-azure-dns"
    priority                   = 190
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "*"
    source_address_prefix      = local.subnets.auth
    source_port_range          = "*"
    destination_address_prefix = "168.63.129.16"
    destination_port_range     = "53"
  }
  security_rule {
    name                       = "deny-internet-outbound"
    priority                   = 4000
    direction                  = "Outbound"
    access                     = "Deny"
    protocol                   = "*"
    source_address_prefix      = "*"
    source_port_range          = "*"
    destination_address_prefix = "Internet"
    destination_port_range     = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "auth" {
  count                     = local.on
  subnet_id                 = azurerm_subnet.auth[0].id
  network_security_group_id = azurerm_network_security_group.auth[0].id
}

# ---- Private DNS for the authority environment's default domain, linked to the shared VNet so snet-cae resolves it ---------------
resource "azurerm_private_dns_zone" "cae" {
  count               = local.on
  name                = azapi_resource.cae[0].output.properties.defaultDomain
  resource_group_name = azurerm_resource_group.auth[0].name
  tags                = local.tags
}

resource "azurerm_private_dns_a_record" "cae_wildcard" {
  count               = local.on
  name                = "*"
  private_dns_zone_id = azurerm_private_dns_zone.cae[0].id
  ttl                 = 60
  records             = [azapi_resource.cae[0].output.properties.staticIp]
}

resource "azurerm_private_dns_zone_virtual_network_link" "cae" {
  count                = local.on
  name                 = "link-authority"
  private_dns_zone_id  = azurerm_private_dns_zone.cae[0].id
  virtual_network_id   = data.azurerm_virtual_network.ordinary[0].id
  registration_enabled = false
  tags                 = local.tags
}
