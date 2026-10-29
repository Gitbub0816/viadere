# Service Bus (ADR-0014, plan section 5.7). Entra-only (local SAS auth disabled) in both profiles.
#  lean:     Basic (queues, dead-letter queues, scheduled messages; no duplicate detection: the transactional outbox + processed_messages
#            make consumers idempotent). Public endpoint, Entra tokens only (CLAUDE.md exception). Basic has no IP firewall.
#  standard: Premium 1 messaging unit, private endpoint, public access disabled, duplicate detection (10 min).

resource "azurerm_servicebus_namespace" "this" {
  name                          = "sb-viadere-${local.uniq}"
  location                      = var.location
  resource_group_name           = azurerm_resource_group.this["app"].name
  sku                           = local.p.sb_sku
  capacity                      = local.p.sb_capacity
  premium_messaging_partitions  = local.p.sb_partitions
  local_auth_enabled            = false
  public_network_access_enabled = !local.p.private_endpoints
  minimum_tls_version           = "1.2"
  tags                          = local.tags

  dynamic "network_rule_set" {
    for_each = local.p.private_endpoints ? [1] : []
    content {
      default_action                = "Deny"
      public_network_access_enabled = false
      trusted_services_allowed      = false
    }
  }
}

resource "azurerm_servicebus_queue" "this" {
  for_each     = local.queues
  name         = each.key
  namespace_id = azurerm_servicebus_namespace.this.id

  lock_duration                           = "PT1M"
  max_delivery_count                      = each.value.max_delivery
  default_message_ttl                     = each.value.ttl
  dead_lettering_on_message_expiration    = true
  requires_session                        = false
  requires_duplicate_detection            = local.p.duplicate_detection
  duplicate_detection_history_time_window = local.p.duplicate_detection ? "PT10M" : null
  partitioning_enabled                    = false
  max_size_in_megabytes                   = 1024
}

resource "azurerm_role_assignment" "sb_sender" {
  for_each                         = toset(["api", "worker"])
  scope                            = azurerm_servicebus_namespace.this.id
  role_definition_name             = "Azure Service Bus Data Sender"
  principal_id                     = azurerm_user_assigned_identity.workload[each.key].principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  description                      = "workload:${each.key}: send queue messages (outbox publisher, scheduled expiries)"
}

resource "azurerm_role_assignment" "sb_receiver" {
  scope                            = azurerm_servicebus_namespace.this.id
  role_definition_name             = "Azure Service Bus Data Receiver"
  principal_id                     = azurerm_user_assigned_identity.workload["worker"].principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  description                      = "workload:worker: receive, complete and dead-letter queue messages"
}

resource "azurerm_private_endpoint" "service_bus" {
  count               = local.p.private_endpoints ? 1 : 0
  name                = "pe-viadere-${local.env}-sb"
  location            = var.location
  resource_group_name = azurerm_resource_group.this["app"].name
  subnet_id           = azurerm_subnet.pe[0].id
  tags                = local.tags

  private_service_connection {
    name                           = "sb"
    private_connection_resource_id = azurerm_servicebus_namespace.this.id
    subresource_names              = ["namespace"]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = "sb"
    private_dns_zone_ids = [azurerm_private_dns_zone.this["servicebus"].id]
  }
}
