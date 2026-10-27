# ADR-0008: Authenticator includes E2EE vault sync behind a release gate

- **Status:** accepted
- **Plan reference:** ADR-08 in `docs/IMPLEMENTATION-PLAN-v2.md` (decided by: Product owner)
- **Related:** docs/SECURITY-TRUST-PLATFORM-SPEC.md §5.1, Phase 4
- **Review:** revisit at each phase gate or when a stated assumption changes

## Context

The authenticator (passkey vault, TOTP) is valuable but a vault compromise is catastrophic and recovery is easy to get wrong (spec §5.1).

## Decision

Ship the vault with E2EE sync behind a release gate until an independent cryptography and recovery review passes (Phase 4 gate). Vault unlock and recovery are independent of identity verification.

## Consequences

- The gate is a launch blocker for the vault only; the rest of the product can launch without it.
- Server custody is ciphertext only: the Server data inventory marks vault blobs as `Passkey private keys: never server plaintext`.
- Operations must support a kill switch for vault sync independent of other features (gap G-4 in KILL-SWITCHES.md).
