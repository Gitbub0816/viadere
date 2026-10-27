# ADR-0006: Approve uses pairwise per-business approval keys

- **Status:** accepted
- **Plan reference:** ADR-06 in `docs/IMPLEMENTATION-PLAN-v2.md` (decided by: Engineering)
- **Related:** docs/SECURITY.md, Packages/ViadereCore
- **Review:** revisit at each phase gate or when a stated assumption changes

## Context

A single device key shared by every business would let two businesses correlate the same person (cross-business unlinkability, threat A3) and would make a business depend on Viadere to verify signed results.

## Decision

The phone generates a Secure Enclave key per business relationship at a business-authorized enrollment. The business receives that public key and key id and verifies every signed result itself (APP-002/004/005). No device identifier is shared across businesses.

## Consequences

- Key count grows with relationships: enrollment, backup-free loss handling and revocation are per relationship.
- Disputes use `export-dispute`, which exposes the global device id only to Viadere operators.
- Device loss means re-enrolling every relationship; cool-down rules apply (docs/SECURITY.md §2.5).
