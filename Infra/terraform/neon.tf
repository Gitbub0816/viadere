# Neon (ADR-02): PostgreSQL 18, direct TLS (verify-full) from the server. The kislerdm/neon provider is community-maintained.
# One project per environment (production, staging) keeps blast radius and billing separate; a long-lived `staging` branch
# of the production project is NOT used for staging because it would carry production data. Ephemeral test branches are cut from
# an empty schema-only parent by CI, never from production.

resource "neon_project" "viadere" {
  name       = "viadere-${var.environment}"
  org_id     = var.neon_org_id
  region_id  = var.neon_region_id
  pg_version = var.neon_pg_version

  history_retention_seconds = var.neon_history_retention_seconds # PITR window; see docs/ops/RESILIENCE.md
  allowed_ips               = var.neon_allowed_ips
  default_branch_protected  = var.environment == "production"

  # Always-on compute in production: scale-to-zero would add cold-start latency to every auth and approval after quiet periods.
  # Production: suspend_timeout_seconds = 0 (never suspend). Staging: 5 minutes to save cost.
  suspend_timeout_seconds  = var.environment == "production" ? 0 : 300
  autoscaling_limit_min_cu = var.environment == "production" ? 0.5 : 0.25
  autoscaling_limit_max_cu = var.environment == "production" ? 4 : 1

  # The default role/database the provider creates are used only for bootstrap; the server uses the least-privilege role below.
  store_password = "yes"

  maintenance_window {
    weekdays   = [6]
    start_time = "07:00"
    end_time   = "08:00"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# Application database and roles. neon_role generates a password (kept in sensitive state: protect the state backend).
# viadere_migrator owns the schema and runs migrations (fly release command; its URL is the Fly secret DATABASE_MIGRATION_URL, host =
# `neon_database_host`, user `viadere_migrator`). viadere_app is the runtime role (DATABASE_URL, DATABASE_APP_ROLE=viadere_app): it owns nothing
# and has no DDL. The `RuntimeRoleGrants` migration gives it SELECT/INSERT/UPDATE/DELETE and sequence usage on every table, sets default
# privileges for tables the migrator creates later and revokes CREATE on the public schema; the server refuses to start in staging/production
# when DATABASE_MIGRATION_URL is set and the runtime role could still change the schema (docs/ops/RUNBOOKS.md "Database role bootstrap").
resource "neon_role" "migrator" {
  project_id = neon_project.viadere.id
  branch_id  = neon_project.viadere.default_branch_id
  name       = "viadere_migrator"
}

resource "neon_role" "app" {
  project_id = neon_project.viadere.id
  branch_id  = neon_project.viadere.default_branch_id
  name       = "viadere_app"
}

# The two role passwords are in sensitive state: compose the two URLs outside Terraform and set them with `fly secrets set`.
resource "neon_database" "viadere" {
  project_id = neon_project.viadere.id
  branch_id  = neon_project.viadere.default_branch_id
  name       = "viadere"
  owner_name = neon_role.migrator.name
}

# Production only: a read-only role for restore tests and analytics on a branch (never for the application).
resource "neon_role" "readonly" {
  count      = var.environment == "production" ? 1 : 0
  project_id = neon_project.viadere.id
  branch_id  = neon_project.viadere.default_branch_id
  name       = "viadere_readonly"
}

# Daily snapshot of the production default branch, retained in addition to PITR (backup-restore tests in docs/ops/RESILIENCE.md).
resource "neon_branch_backup_schedule" "daily" {
  count      = var.environment == "production" ? 1 : 0
  project_id = neon_project.viadere.id
  branch_id  = neon_project.viadere.default_branch_id
  schedule = [{
    frequency         = "daily"
    hour              = 3
    retention_seconds = 2592000 # 30 days
  }]
}

# Restore-test branch: created on demand by the restore drill (RESILIENCE.md), not kept permanently. Terraform only documents the
# shape; use `tofu apply -var restore_test_timestamp=...` in the drill workspace if you automate it.
