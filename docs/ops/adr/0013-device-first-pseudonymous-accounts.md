# ADR-0013: Device-first pseudonymous accounts and device trust tiers D0/D1/D2

- **Status:** proposed (2026-10-29)
- **Plan reference:** `docs/IMPLEMENTATION-PLAN-v3.md` decision PO-3; WP-A2, WP-B4, WP-B5, WP-D1, WP-D2 (decided by: Product owner, account model; Engineering, protocol)
- **Related:** spec §2, §3, §4, §6, §8, §12; SECURITY.md §2.5, §2.17, §2.26; ADR-0006
- **Review:** revisit at the Phase 2 (Approve) gate re-review and before the Android client starts

## Context

Today an account is created by registering a passkey with a mandatory display name (`AuthService.registerBegin/registerFinish`), and devices are enrolled afterwards with a passkey assertion. The spec requires a pseudonymous, device-first account: the device's hardware key plus platform integrity evidence and a server challenge create the account; no personal field is mandatory; passkeys and recovery codes are optional recovery credentials; trust is tiered (D0 pseudonymous, D1 hardware key + user verification + integrity, D2 verified attributes); recovery is weaker than a trusted device; nothing in the core account schema or protocol is Apple-only. New devices get a fresh cool-down today, but trust lapses in automatically after 24 hours.

## Decision

1. **Account creation by device.** `POST /v1/accounts/enroll/begin` returns a single-use challenge and a **reserved** account id; the client proves possession of each key with the existing `VIADERE-ENROLL-V1` proof and attests the key list with the existing App Attest binding (both already include the account id, so no wire format changes); `POST /v1/accounts` consumes the ceremony atomically and creates the account, the device and a device-bound session. No name, email, phone or password is required or stored.
2. **Optional recovery credentials** after first run: a passkey (synced where the platform allows) and/or offline recovery codes, each added with a user-verified approval-key proof from the device. Passkey sign-in stays as an account-discovery method for existing passkey accounts and new devices.
3. **Platform-neutral protocol and schema:** integrity evidence is an envelope with a `format` (`apple-app-attest` now; `android-key-attestation` + Play Integrity verifier when the Android app starts; unknown formats are treated as unattested); key registrations carry an algorithm (`ES256` only); push tokens carry a provider (`apns`, later `fcm`).
4. **Trust tiers, decided by the server only:** D0 for any registered device; D1 requires a hardware approval key with user verification, verified integrity evidence where the platform supports it, and either first-device creation with verified attestation, approval from an existing D1 device over a server nonce, or business (relying-party) re-enrollment; D2 is D1 plus a live Verify result for the requested claim. High-risk approvals require D1. Time alone does not elevate a device that belongs to an account with another D1 device or that was created by recovery.
5. **Recovery** (codes or a synced passkey) restores the account at D0 after the existing 72-hour hold with notices and cancellation; high-risk MFA needs trusted-device pairing or business re-enrollment.
6. Account ids stay UUIDv4 (122 bits from the system CSPRNG), internal only, never used as a bearer value and never shown to businesses (`subject_ref` is the external id); this is recorded in SECURITY.md as an accepted deviation from "128+ bit".

## Consequences

- Sign-up loses the passkey's cost to an attacker; account farming is countered by App Attest (`require` in production), one account per App Attest key, per-IP and global budgets, the sign-up kill switch and, later, DeviceCheck per-device budgets.
- A person who skips every recovery credential and loses their only device loses the account; the app says so plainly before they skip.
- The staging database has no accounts (2026-10-29), so the migration is schema-only and additive (`DeviceFirstAccounts.v1`); passkey-first accounts created in development keep working.
- Household and passkey labels need a fallback when no display name exists.
- App copy changes (no "nothing to phish"); marketing must not claim phishing resistance for push approvals (spec §7).
