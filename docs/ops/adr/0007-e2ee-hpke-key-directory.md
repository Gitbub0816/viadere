# ADR-0007: E2EE with HPKE and an authenticated business key directory

- **Status:** accepted
- **Plan reference:** ADR-07 in `docs/IMPLEMENTATION-PLAN-v2.md` (decided by: Engineering)
- **Related:** docs/IMPLEMENTATION-PLAN-v2.md WP1
- **Review:** revisit at each phase gate or when a stated assumption changes

## Context

Identity disclosures and sensitive payloads must not be readable by a compromised relay. Ad-hoc crypto is unacceptable; key substitution by the relay must be detectable (SEC-CR-006).

## Decision

Use HPKE (RFC 9180) with DHKEM(P-256), HKDF-SHA256 and AES-256-GCM through CryptoKit/swift-crypto. Publish business keys through an authenticated key directory: each key is signed by the business's enrolled root key, logged in an append-only Merkle transparency log and pinned on devices after first use.

## Consequences

- Service HPKE private keys are wrapped by a KMS key-encryption key (ADR-03).
- The transparency log is a new durable component: its head must be exported like the audit head (RUNBOOKS.md, relay compromise).
- A malicious relay can deny service but cannot substitute keys undetected after first use.
