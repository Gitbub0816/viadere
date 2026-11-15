# ADR-0005: Verify evidence: Apple Wallet IDs and Didit

- **Status:** accepted
- **Plan reference:** ADR-05 in `docs/IMPLEMENTATION-PLAN-v2.md` (decided by: Product owner)
- **Related:** docs/IMPLEMENTATION-PLAN-v2.md WP3
- **Review:** revisit at each phase gate or when a stated assumption changes

## Context

Age and identity verification (spec §6) need evidence. Apple Wallet IDs give birthdate-free `age_over_NN` assertions but not every person has one; Didit's SDK covers users without a Wallet ID (VER-008) but has no headless UI.

## Decision

Support both. Wallet: in-app identity presentment, the server verifies the HPKE envelope and the ISO 18013-5 DeviceResponse against issuer IACA roots. Didit: native iOS SDK themed through White Label, wrapped by Viadere screens; biometric capture and images go device to Didit directly. Viadere stores only minimized results and purges Didit sessions after reading.

## Consequences

- Didit becomes a processor of raw identity evidence: DPA, sub-processor listing, residency and breach-notification clauses are counsel items (DATA-INVENTORY.md).
- Didit outage disables non-Wallet verification only (RESILIENCE.md degraded mode).
- IACA root lists and issuer revocation need an operational process (RUNBOOKS.md, credential issuer revocation).
