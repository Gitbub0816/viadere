# ADR-0003: Google Cloud KMS (HSM, EC P-256) for service keys

- **Status:** accepted
- **Plan reference:** ADR-03 in `docs/IMPLEMENTATION-PLAN-v2.md` (decided by: Product owner)
- **Related:** Infra/terraform/kms.tf
- **Review:** revisit at each phase gate or when a stated assumption changes

## Context

Service signing keys (audit heads, connect links, webhooks) and the keys that protect stored secrets are today environment variables (`CONNECT_LINK_SIGNING_KEY`, `DATA_ENCRYPTION_KEY`, `AUDIT_CHAIN_KEY`). Environment secrets are extractable by anyone with deploy access or a compromised process. Cloudflare offers no KMS.

## Decision

Move service keys behind a `KeyManagementService` protocol with two implementations: Google Cloud KMS HSM keys (production and staging) and a local software implementation for development and tests only. Asymmetric signing uses `EC_SIGN_P256_SHA256` HSM keys, one per purpose. HPKE (RFC 9180) is not a Cloud KMS operation, so HPKE private keys and the field-encryption key are generated in the server and stored wrapped by symmetric HSM key-encryption keys (envelope encryption). The server's dedicated service account may only sign and wrap/unwrap; administration is a separate human principal; all key use is audit-logged and alerted.

## Consequences

- Roughly USD 2.5 to 3 per HSM key version per month; signing adds a network round trip per signature (cache public keys, sign off the hot path where possible).
- GCP becomes a dependency for signing: the vendor-outage runbook defines degraded behavior (verification continues, new signatures wait).
- Asymmetric keys cannot rotate automatically in Cloud KMS: rotation is a runbook with overlapping key ids.
- Until WP1 ships the protocol, the keys are provisioned but unused; the environment secrets remain the live keys, and their compromise runbook is the manual one.
