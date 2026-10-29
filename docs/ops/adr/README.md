# Architecture decision records

One file per decision in the ADR table of `docs/IMPLEMENTATION-PLAN-v2.md` (ADR-01 to ADR-09 map to 0001 to 0009). The plan stays the source
for the decision date and owner; these records add context, the decision and its consequences. New decisions get the next number
and a status (`proposed`, `accepted`, `superseded by NNNN`). Template: Context, Decision, Consequences. Part of OPS-001.

ADRs 0010 to 0014 come from `docs/IMPLEMENTATION-PLAN-v3.md` (the Security Architecture Expansion and the Azure migration).

## Index

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-fly-io-behind-cloudflare.md) | Server on Fly.io behind Cloudflare | superseded by 0010 (proposed) |
| [0002](0002-postgresql-18-on-neon.md) | PostgreSQL 18 on Neon | superseded by 0011 (proposed) |
| [0003](0003-google-cloud-kms.md) | Google Cloud KMS (HSM, EC P-256) for service keys | superseded by 0012 (proposed) |
| [0004](0004-swift-static-site-workers-static-assets.md) | Swift static site on Cloudflare Workers Static Assets | accepted |
| [0005](0005-verify-evidence-wallet-and-didit.md) | Verify evidence: Apple Wallet IDs and Didit | accepted |
| [0006](0006-pairwise-approval-keys.md) | Pairwise per-business approval keys | accepted |
| [0007](0007-e2ee-hpke-key-directory.md) | E2EE with HPKE and an authenticated key directory | accepted |
| [0008](0008-authenticator-vault-sync-gate.md) | Authenticator vault sync behind a release gate | accepted |
| [0009](0009-infrastructure-as-code-and-ci.md) | OpenTofu and GitHub Actions with Go/Swift/Python tools | accepted (scope moves to Azure with 0010) |
| [0010](0010-azure-container-apps-swift-runtime.md) | Swift/Vapor server on Azure Container Apps behind Cloudflare Tunnel (deviation from the spec's ASP.NET Core) | proposed |
| [0011](0011-azure-postgresql-flexible-server.md) | Azure Database for PostgreSQL Flexible Server 18 with private access and Entra roles | proposed |
| [0012](0012-azure-key-vault-premium.md) | Azure Key Vault Premium (HSM keys), not Managed HSM | proposed |
| [0013](0013-device-first-pseudonymous-accounts.md) | Device-first pseudonymous accounts and trust tiers D0/D1/D2 | proposed |
| [0014](0014-service-bus-job-queues.md) | Service Bus queues with a transactional outbox, DLQ and idempotent consumers | proposed |
