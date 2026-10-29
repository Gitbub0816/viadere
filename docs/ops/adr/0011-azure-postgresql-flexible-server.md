# ADR-0011: Azure Database for PostgreSQL Flexible Server 18 with private access and Entra roles

- **Status:** proposed (2026-10-29)
- **Plan reference:** `docs/IMPLEMENTATION-PLAN-v3.md` decision PO-2; WP-B1, WP-B2; section 5 (decided by: Product owner, platform; Engineering, configuration)
- **Supersedes:** 0002 (PostgreSQL 18 on Neon)
- **Related:** `Server/Sources/ViadereServerKit/Migrations/RuntimeRoleGrants.swift`, `Server/Sources/ViadereServerKit/App.swift`, docs/ops/RESILIENCE.md, docs/ops/RUNBOOKS.md
- **Review:** revisit at each phase gate, when residency requirements change (spec §13 item 4), or when a new PostgreSQL major is GA on Azure

## Context

The database is the system of record and holds rate limits, replay nonces, queues (until ADR-0014), the audit chain and every account, device and approval. The spec (§9, §10) requires private connectivity, HA, PITR with tested restore, and least-privilege managed identities. Today Neon (project `viadere`, branch `production`, database `viadere`) is reached over a public endpoint with password roles `viadere_migrator` and `viadere_app`, and staging PITR retention is one day. The staging database holds no user data (0 accounts, businesses or audit events on 2026-10-29).

Azure Database for PostgreSQL Flexible Server supports PostgreSQL 18 and creates new servers on minor **18.6** (Microsoft Learn, supported versions, 2026-08-26), which matches CLAUDE.md. Managed identities authenticate with an Entra access token used as the password (5 to 60 minute validity, checked at connection time); roles for identities are created with `pgaadauth_create_principal`. PostgresNIO 1.33.2, which the server uses, accepts only a static password.

## Decision

1. One Flexible Server per environment, **PostgreSQL 18**, **private access** (VNet integration in a delegated subnet, private DNS zone), no public endpoint, TLS with `verify-full` against the Azure root CAs shipped in the image.
2. Production: General Purpose (D2ds_v5 to start, sized from measured load), **zone-redundant HA**, PITR **35 days**, geo-redundant backup per the residency decision, quarterly restore drill into a scratch server with row-count and audit-chain verification. Staging: Burstable B1ms without HA (Burstable has none) and PITR 7 days, unless the owner funds HA for staging.
3. The role split stays and moves to Entra: `viadere_migrator` (schema owner, used only by the migration job's identity), `viadere_app` (API, DML only, no UPDATE on `audit_events`), `viadere_worker` (queue handlers, narrower grants), a read-only restore-test role, and an Entra admin **group** that no workload uses. `GrantRuntimeRolePrivileges` grants to the Entra principal roles; the serving process keeps refusing to start if its role can change the schema.
4. Workloads connect with **Entra tokens**: the server gets a connection source that fetches a token for every new connection (pooled connections stay valid after token expiry). Until that ships, staging alone may use a password for `viadere_app` stored in Key Vault, recorded as a time-boxed CLAUDE.md exception; production runs "Microsoft Entra authentication only".
5. Migrations run from a Container Apps Job under the migrator identity before any new revision receives traffic; they stay forward-only and expand/contract.
6. Azure applies minor versions during monthly maintenance; CI keeps testing against the community `postgres:18` image and both SQLite and PostgreSQL suites gate every upgrade (CLAUDE.md rule 6).

## Consequences

- No long-lived database credential exists in production; the staging password is the only one and has a removal condition.
- Writing the token-based connection source is new security-relevant code in the database path (tests first; failure mode is refusing new connections, never falling back to a password).
- HA failover and planned maintenance cause short connection drops; the existing transient-retry helper (`DB.retryingTransient`) and fail-closed limiters must be exercised in the F1 drills.
- Neon's branch-based workflows go away; restore tests use PITR to a new server instead.
- Cost: staging ≈ USD 16/month (B1ms), production ≈ USD 285/month (D2ds_v5 with HA and 128 GiB), from the Azure Retail Prices API on 2026-10-29.
