-- Owner-run ONCE by a member of grp-viadere-db-admins (the PostgreSQL Entra administrator), after `tofu apply` created the database object
-- `viadere_authority` and the three managed identities. Connect to the `postgres` database with an Entra token (docs/ops/AZURE-SETUP.md
-- section 8 shows the job/psql routes), then run the principal creation, then connect to `viadere_authority` for the grants.
-- UNTESTED against a live server (written 2026-11-02). Review every line; nothing here grants anything to the api or worker roles.

-- 1. Entra principals (names are the identities' display names).
SELECT * FROM pgaadauth_create_principal('id-viadere-authority', false, false);
SELECT * FROM pgaadauth_create_principal('id-viadere-authority-admin', false, false);
SELECT * FROM pgaadauth_create_principal('id-viadere-authority-migrator', false, false);
-- Only with reconcile_job_enabled = true (job-viadere-authority-reconcile, role viadere_authority_reconcile):
SELECT * FROM pgaadauth_create_principal('id-viadere-authority-reconcile', false, false);
-- The runtime role names the server expects are aliases created as ordinary roles that members map onto (or rename the principals to match
-- Infra/azure-authority/locals.tf db_roles: viadere_authority, viadere_authority_admin, viadere_authority_migrator).

-- 2. Separation: nobody connects to the authority database by default, and the ordinary roles never do.
REVOKE CONNECT ON DATABASE viadere_authority FROM PUBLIC;
REVOKE CONNECT ON DATABASE viadere_authority FROM viadere_app, viadere_worker, viadere_migrator;
REVOKE CONNECT ON DATABASE viadere FROM viadere_authority, viadere_authority_admin, viadere_authority_migrator;
GRANT CONNECT ON DATABASE viadere_authority TO viadere_authority, viadere_authority_admin, viadere_authority_migrator;

-- 3. Schema ownership: the migrator owns the schema; `ViadereAuthority migrate` grants DML to the runtime role and the narrow admin grants of
--    TRUST_BOUNDARIES 4.2 (INSERT on authority_policy_versions, authority_oidc_clients, authority_link_clients, authority_tenant_keys,
--    authority_keylog_imports, authority_seal_keys, authority_registration_nonces; UPDATE of role/state on authority_seal_keys only).
\connect viadere_authority
ALTER SCHEMA public OWNER TO viadere_authority_migrator;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO viadere_authority, viadere_authority_admin;

-- 4. (Run after the first `ViadereAuthority migrate` created the Authority.v2 tables.) Stage 6 key log, recovery, link service and reconciliation. The runtime role gets DML on them through the migrator's
--    default privileges; the admin role only what its commands write (TRUST_BOUNDARIES 4.2); the reconcile role reads sign records and writes
--    audit events. UNTESTED against a live server, like the rest of this file.
GRANT CONNECT ON DATABASE viadere_authority TO viadere_authority_reconcile;
GRANT USAGE ON SCHEMA public TO viadere_authority_reconcile;
GRANT SELECT ON authority_sign_records TO viadere_authority_reconcile;
GRANT INSERT ON authority_audit_events TO viadere_authority_reconcile;
GRANT INSERT, SELECT ON authority_key_inventory TO viadere_authority_admin;
GRANT INSERT, SELECT ON authority_seal_keys TO viadere_authority_admin;
GRANT UPDATE (state) ON authority_seal_keys TO viadere_authority_admin;
GRANT SELECT ON authority_recovery_codes TO viadere_authority_admin;
GRANT UPDATE (state) ON authority_recovery_codes TO viadere_authority_admin;
GRANT INSERT ON authority_audit_events TO viadere_authority_admin;
