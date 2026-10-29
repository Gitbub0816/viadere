# Resource groups, VNet, subnets, NSGs, private DNS zones, NAT gateway (standard) (plan sections 5.1, 5.2).

resource "azurerm_resource_group" "this" {
  for_each = local.rg
  name     = each.value
  location = var.location
  tags     = local.tags
}

# Locks on the data and security groups (standard by default). They also block `tofu destroy` and any replacement inside those groups:
# remove the lock deliberately (AZURE-SETUP.md section 12) when a replacement is intended.
resource "azurerm_management_lock" "rg" {
  for_each   = local.resource_locks ? toset(["data", "sec"]) : toset([])
  name       = "lock-viadere-${local.env}-${each.key}"
  scope      = azurerm_resource_group.this[each.key].id
  lock_level = "CanNotDelete"
  notes      = "Viadere ${var.environment}: system-of-record and key material. Removal needs the owner's approval."
}

resource "azurerm_virtual_network" "this" {
  name                = "vnet-viadere-${local.env}"
  location            = var.location
  resource_group_name = azurerm_resource_group.this["net"].name
  address_space       = [local.vnet_cidr]
  tags                = local.tags
}

# Container Apps environment (workload-profiles type, Consumption profile only). Egress: the environment's platform-managed outbound address
# in lean; the NAT gateway's static IP in standard (one address for provider allow-lists).
resource "azurerm_subnet" "cae" {
  name                 = "snet-cae"
  resource_group_name  = azurerm_resource_group.this["net"].name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [local.subnets.cae]

  # Lean: Key Vault keeps its public endpoint but its firewall admits only this subnet (free service endpoint; Key Vault references and
  # the server's data-plane calls leave through the environment's subnet). Standard uses the private endpoint instead.
  dynamic "service_endpoint" {
    for_each = local.p.private_endpoints ? [] : ["Microsoft.KeyVault"]
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

resource "azurerm_subnet" "pg" {
  name                 = "snet-pg"
  resource_group_name  = azurerm_resource_group.this["net"].name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [local.subnets.pg]

  delegation {
    name = "postgresql"
    service_delegation {
      name    = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_subnet" "pe" {
  count                             = local.p.private_endpoints ? 1 : 0
  name                              = "snet-pe"
  resource_group_name               = azurerm_resource_group.this["net"].name
  virtual_network_name              = azurerm_virtual_network.this.name
  address_prefixes                  = [local.subnets.pe]
  default_outbound_access_enabled   = false
  private_endpoint_network_policies = "Enabled" # NSG rules apply to private endpoints
}

# ---- NSGs -----------------------------------------------------------------------------------------------------------
# snet-cae: nothing inbound from the Internet (the environment is internal and Cloudflare reaches it through the outbound tunnel). Outbound
# stays at the platform defaults: Container Apps needs Entra ID, Azure Monitor, MCR and the registry, and an FQDN egress allow-list needs
# Azure Firewall (owner decision O-8); the server's application-level allow-list is WP-B2.
resource "azurerm_network_security_group" "cae" {
  name                = "nsg-viadere-${local.env}-cae"
  location            = var.location
  resource_group_name = azurerm_resource_group.this["net"].name
  tags                = local.tags

  security_rule {
    name                       = "deny-internet-inbound"
    priority                   = 4000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_address_prefix      = "Internet"
    source_port_range          = "*"
    destination_address_prefix = "*"
    destination_port_range     = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "cae" {
  subnet_id                 = azurerm_subnet.cae.id
  network_security_group_id = azurerm_network_security_group.cae.id
}

# snet-pg: 5432 only from the Container Apps subnet (and from the subnet itself, which HA replication needs).
resource "azurerm_network_security_group" "pg" {
  name                = "nsg-viadere-${local.env}-pg"
  location            = var.location
  resource_group_name = azurerm_resource_group.this["net"].name
  tags                = local.tags

  security_rule {
    name                       = "allow-postgres-from-cae"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = local.subnets.cae
    source_port_range          = "*"
    destination_address_prefix = local.subnets.pg
    destination_port_range     = "5432"
  }
  security_rule {
    name                       = "allow-within-pg-subnet"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_address_prefix      = local.subnets.pg
    source_port_range          = "*"
    destination_address_prefix = local.subnets.pg
    destination_port_range     = "*"
  }
  security_rule {
    name                       = "deny-other-vnet-inbound"
    priority                   = 4000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_address_prefix      = "VirtualNetwork"
    source_port_range          = "*"
    destination_address_prefix = "*"
    destination_port_range     = "*"
  }
  security_rule {
    name                       = "deny-internet-inbound"
    priority                   = 4010
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_address_prefix      = "Internet"
    source_port_range          = "*"
    destination_address_prefix = "*"
    destination_port_range     = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "pg" {
  subnet_id                 = azurerm_subnet.pg.id
  network_security_group_id = azurerm_network_security_group.pg.id
}

# snet-pe (standard): 443 only from the Container Apps subnet.
resource "azurerm_network_security_group" "pe" {
  count               = local.p.private_endpoints ? 1 : 0
  name                = "nsg-viadere-${local.env}-pe"
  location            = var.location
  resource_group_name = azurerm_resource_group.this["net"].name
  tags                = local.tags

  security_rule {
    name                       = "allow-https-from-cae"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = local.subnets.cae
    source_port_range          = "*"
    destination_address_prefix = local.subnets.pe
    destination_port_range     = "443"
  }
  security_rule {
    name                       = "deny-other-vnet-inbound"
    priority                   = 4000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_address_prefix      = "VirtualNetwork"
    source_port_range          = "*"
    destination_address_prefix = "*"
    destination_port_range     = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "pe" {
  count                     = local.p.private_endpoints ? 1 : 0
  subnet_id                 = azurerm_subnet.pe[0].id
  network_security_group_id = azurerm_network_security_group.pe[0].id
}

# ---- NAT gateway (standard): one static egress IP for provider allow-lists --------------------------------------------
resource "azurerm_public_ip" "nat" {
  count               = local.p.nat_gateway ? 1 : 0
  name                = "pip-viadere-${local.env}-nat"
  location            = var.location
  resource_group_name = azurerm_resource_group.this["net"].name
  allocation_method   = "Static"
  sku                 = "Standard"
  zones               = ["1", "2", "3"]
  tags                = local.tags
}

resource "azurerm_nat_gateway" "this" {
  count                   = local.p.nat_gateway ? 1 : 0
  name                    = "ng-viadere-${local.env}"
  location                = var.location
  resource_group_name     = azurerm_resource_group.this["net"].name
  sku_name                = "Standard"
  idle_timeout_in_minutes = 10
  tags                    = local.tags
}

resource "azurerm_nat_gateway_public_ip_association" "this" {
  count                = local.p.nat_gateway ? 1 : 0
  nat_gateway_id       = azurerm_nat_gateway.this[0].id
  public_ip_address_id = azurerm_public_ip.nat[0].id
}

resource "azurerm_subnet_nat_gateway_association" "cae" {
  count          = local.p.nat_gateway ? 1 : 0
  subnet_id      = azurerm_subnet.cae.id
  nat_gateway_id = azurerm_nat_gateway.this[0].id
}

# ---- Private DNS ------------------------------------------------------------------------------------------------------
locals {
  private_dns_zones = merge(
    { postgres = "viadere-${local.env}.private.postgres.database.azure.com" },
    local.p.private_endpoints ? {
      vault      = "privatelink.vaultcore.azure.net"
      servicebus = "privatelink.servicebus.windows.net"
      blob       = "privatelink.blob.core.windows.net"
      acr        = "privatelink.azurecr.io"
    } : {},
  )
}

resource "azurerm_private_dns_zone" "this" {
  for_each            = local.private_dns_zones
  name                = each.value
  resource_group_name = azurerm_resource_group.this["net"].name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "this" {
  for_each             = local.private_dns_zones
  name                 = "link-${each.key}"
  private_dns_zone_id  = azurerm_private_dns_zone.this[each.key].id
  virtual_network_id   = azurerm_virtual_network.this.id
  registration_enabled = false
  tags                 = local.tags
}
