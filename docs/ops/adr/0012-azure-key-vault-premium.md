# ADR-0012: Azure Key Vault Premium (HSM keys) for service keys and secrets, not Managed HSM

- **Status:** proposed (2026-10-29)
- **Plan reference:** `docs/IMPLEMENTATION-PLAN-v3.md` decision PO-2; WP-B2; sections 5.3 and 5.6 (decided by: Product owner, service tier; Engineering, key design)
- **Supersedes:** 0003 (Google Cloud KMS)
- **Related:** `Server/Sources/ViadereServerKit/Operations/AuditExport.swift`, `Infra/fly/secrets.txt`, docs/ops/KEY-ROTATION.md, SECURITY.md §2.21, §2.22, §2.51, §2.77, §2.79
- **Review:** revisit at each phase gate, when AES (`oct-HSM`) keys leave preview in Key Vault Premium, or when a contract or regulator requires a single-tenant HSM

## Context

ADR-0003 put service keys behind a `KeyManagementService` protocol with Google Cloud KMS; in practice only the audit-head signature uses KMS, and every other key (`DATA_ENCRYPTION_KEY`, `SERVER_PEPPER`, `AUDIT_CHAIN_KEY`, `SUBJECT_REF_KEY`, `CONNECT_LINK_SIGNING_KEY`, `KEY_DIRECTORY_LOG_KEY`) is an environment secret. The spec (§9, §10) asks for Key Vault with managed identity, rotation, audit and separation of duties, and Managed HSM "if warranted"; HSM keys protect server secrets and signatures, never users' device keys.

Key Vault Premium offers HSM-protected EC keys (P-256, P-384, P-521, P-256K) and RSA keys (2048 to 4096); new key versions are on HSM Platform 2 (FIPS 140-3 Level 3). AES `oct-HSM` keys in vaults are **preview** (Microsoft Learn, About keys, 2026-07-07). Managed HSM is single-tenant at about USD 3.20 per hour (≈ USD 2,336 per month); Premium HSM keys cost USD 5 per key per month for EC and RSA 3072+ (first tier) (Azure Retail Prices API, 2026-10-29).

## Decision

1. One **Key Vault Premium** per environment, Azure RBAC authorization, purge protection, 90-day soft delete, private endpoint with public access disabled, diagnostic logs to Log Analytics.
2. Keys (non-exportable HSM keys):
   - `audit-head-signing`: EC-HSM P-256, ES256, signs exported audit-chain heads (replaces the GCP key);
   - `kd-log-signing`: EC-HSM P-256, signs key-directory tree heads (replaces `KEY_DIRECTORY_LOG_KEY`);
   - `link-descriptor`: EC-HSM P-256, signs link-session descriptors and results (spec §5, WP-C1);
   - `kek-data`: RSA-HSM 3072, RSA-OAEP-256, wraps the symmetric service keys (field encryption, pepper, audit-chain HMAC key, `subject_ref` key, connect-link key) and HPKE and Wallet private keys (envelope encryption, unwrapped at boot, never written to disk).
3. AES `oct-HSM` keys are **not** used while they are preview (CLAUDE.md rule 3); revisit at GA.
4. **Managed HSM is not adopted now.** Triggers to revisit: a contractual or regulatory requirement for a single-tenant HSM or customer-controlled HSM keys, or a need for HSM-resident AES/HMAC at volume.
5. The server implements `KeyManagementService` (sign, wrap/unwrap) against the Key Vault REST data plane with a pinned GA api-version, using its user-assigned managed identity; a local software implementation exists for development and tests only. Third-party secrets (MailerSend, APNs, Didit, Twilio, RCS, tunnel token) are Key Vault secrets referenced by managed identity; previous versions replace the `*_PREVIOUS` variables.
6. Separation of duties: workload identities hold Key Vault Crypto User or Secrets User on individual keys and secrets only; key creation and rotation belong to a human crypto-officer group; deployment identities have no data-plane rights; any key operation by an unexpected principal alerts.

## Consequences

- No service key exists as a plain environment variable in Azure; a process compromise still exposes unwrapped symmetric keys in memory, which is the accepted residual (as with ADR-0003).
- Signing adds a network round trip; audit heads and tree heads are low-rate, so latency is acceptable.
- Rotation: asymmetric keys rotate by new key version with overlapping public keys published; wrapped symmetric keys rotate by the existing key-id scheme (KEY-ROTATION.md updated).
- Cost ≈ USD 22 to 25 per month per environment for four HSM keys plus operations; GCP KMS and its workload-identity federation are removed at decommission (key rings cannot be deleted in GCP; versions are disabled).

## Implementation notes (2026-10-30, WP-B2)

- `KeyManagementService` (`sign(keyRef:digest:)` returning raw low-S `r ‖ s`, `publicKey`, `wrap`/`unwrap` with RSA-OAEP-256, `resolveVersion`) has two implementations: `AzureKeyVaultKMS` (keys REST API `2025-07-01`, the same for Standard and Premium vaults) and `LocalKMS` (development and tests; refused in staging and production). Every Key Vault signature is checked against the published public key of the exact version that made it before it is used.
- Service keys arrive as `<NAME>_WRAPPED` = `kms1:<kek>/<version>:<base64url>` and are unwrapped once at boot (SECURITY.md §2.92); plain variables keep working on Fly and in tests. `Infra/azure`'s default secret map still names the plain variables; storing wrapped values (and renaming the map entries to `*_WRAPPED`) is an owner step in AZURE-SETUP.md section 7.
- `kd-log-signing` replaces `KEY_DIRECTORY_LOG_KEY` on Azure (both together refuse the boot); `audit-head-signing` signs exported audit heads, written create-only to the immutable `audit-heads` container (the GCS/R2 sinks and the Google workload-identity code are removed). The Wallet key unwrapper (HANDOFF open item) is `KMSWalletKeyUnwrapper` on `kek-data`.
