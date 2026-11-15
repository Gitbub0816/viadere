# Separate database `viadere_authority` on the existing Flexible Server (lean; ADR-0019 section 4.5). The standard profile decides in Stage 6
# between a separate server and a separate subscription; this root creates only the database object. Roles and grants are SQL, run once by
# the database administrator group through the bootstrap job (Infra/azure-authority/bootstrap/authority-database.sql, owner checklist):
#   CREATE ROLE ... for the three Entra principals (pgaadauth_create_principal), REVOKE CONNECT ON DATABASE viadere_authority FROM PUBLIC,
#   REVOKE CONNECT ON DATABASE viadere_authority FROM viadere_app / viadere_worker / viadere_migrator and the converse for the new roles.
# The apply identity needs only write on this one database object (a custom role on the server, checklist step), not on the server.
resource "azurerm_postgresql_flexible_server_database" "authority" {
  count     = local.on
  name      = local.authority_db
  server_id = data.azurerm_postgresql_flexible_server.ordinary[0].id
  charset   = "UTF8"
  collation = "en_US.utf8"

  lifecycle {
    prevent_destroy = true
  }
}
