# ADR-0002: PostgreSQL 18 on Neon

- **Status:** superseded by 0011 (proposed 2026-10-29; stays in force for the transitional Neon staging database until 0011 is accepted and cutover completes)
- **Plan reference:** ADR-02 in `docs/IMPLEMENTATION-PLAN-v2.md` (decided by: Product owner)
- **Related:** Infra/terraform/neon.tf
- **Review:** revisit at each phase gate or when a stated assumption changes

## Context

The server needs a managed PostgreSQL with point-in-time recovery and TLS. Cloudflare has no managed Postgres. CLAUDE.md requires PostgreSQL 18.x in production. Rate limiting, replay protection, queues and the audit chain all live in the database (Server/README.md, "State in the database"), so the database is the system of record and the main availability dependency.

## Decision

Use Neon PostgreSQL 18, one project per environment, with direct (non-pooled) TLS connections using `sslmode=verify-full`. Production compute never suspends. PITR history retention 7 days plus daily snapshots. Separate roles for migrations, runtime and read-only restore tests.

## Consequences

- Neon is a single-region dependency: its outage degrades the service (security-critical limiters fail closed; see RESILIENCE.md).
- RPO is bounded by Neon's WAL/PITR, not by us; restore tests are mandatory (RESILIENCE.md).
- The Neon Terraform provider is community-maintained (`kislerdm/neon`); the exposure is limited to project/role/branch management.
- Encrypted columns mean a Neon-side leak exposes ciphertext, not phone numbers or message bodies, as long as `DATA_ENCRYPTION_KEY` stays outside the database.
