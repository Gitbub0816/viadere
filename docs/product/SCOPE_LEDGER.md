# Scope ledger (reconciled, Stage 0)

| | |
|---|---|
| Spec | `docs/product/AUTH-DELIVERY-SPEC-v2.md` §2, §2.1, §14, §17 |
| Authority | `docs/product/AUTH-OWNER-DECISIONS.md` decisions 1-12 override the spec where they differ |
| Evidence | `docs/architecture/CURRENT_STATE.md`, `docs/architecture/GAP_ANALYSIS.md` |
| Date | 2026-11-02 |
| Author | A0, reconciling the A14 draft ledger against the repository and decisions 9-12 (A14 saw only decisions 1-8) |

Anti-scope-creep rule: anything not on this ledger needs a change request recorded here, with the owner's approval, before work starts. Status words (Implemented, Partial, Planned, Absent) are defined in `GAP_ANALYSIS.md`; they describe code in the repository, not production readiness.

## 1. Baseline: preserve (do not rewrite without a documented defect or dependency need)

| # | Capability | State | Notes and constraints from the decisions |
|---|---|---|---|
| B1 | Anonymous / device-first enrollment | Implemented | Account ids are random; no name, email or phone. Phone ownership proof must stop using SMS codes (decision 9). |
| B2 | Device-linked identity (Secure Enclave keys, D0/D1 tiers, App Attest, cool-downs) | Implemented | Preserve wire formats `VIADERE-SIG-V1`, `VIADERE-ENROLL-V1`, `VIADERE-DECISION-V1`. |
| B3 | Cross-device linking (device confirm, business link sessions, gated vault pairing) | Partial | No magic-link cross-device handoff (new work, Phase A). |
| B4 | Business connections (codes, handles, QR, Connect button) | Implemented | Connect button path `v1` is immutable. |
| B5 | Business messaging | Implemented (in-app, SMS), Partial (RCS), Absent (Apple Messages for Business) | SMS gateway is kept **only as an on-ramp** for people without the app (decision 9). It is not an authentication channel. |
| B6 | Push approvals (interactions, Approve v2) | Partial, Approve v2 gated off | Phase B closes number matching and push content. |
| B7 | Age / identity verification options | Partial, gated off everywhere | Never mandatory for all users. |
| B8 | Account recovery (codes, passkey, 72 h hold, device notices) | Implemented | Spec lists it as optional future work; it ships today. Keep. |
| B9 | Partner brand kits (tokens and re-encoded images only) | Implemented | No partner HTML/CSS/JS in native surfaces. |
| B10 | Customer pages and widgets | Implemented | |
| B11 | Optional business Loops | Implemented, dark by default | Declarative only. |
| B12 | Tenant separation (pairwise subject refs) | Implemented | Cross-tenant suite for auth-delivery to be added (Stage 7). |
| B13 | Actionable notifications and Live Activities | Partial (Apple code not compiled on Linux) | Fix list in `GAP_ANALYSIS.md` F-08, F-09, F-14, F-15, F-16. |
| B14 | Device-local key material | Implemented (Apple-only, device-unverified) | |
| B15 | Business console and operator console | Implemented | |
| B16 | On-device TOTP authenticator and passkey vault | Implemented, vault sync off by default | Spec §2.1 says no proprietary authenticator in Phase A; decision 3 keeps the on-device authenticator. Do not expand it in Phase A. |
| B17 | Household delegation, customer profiles with selective sharing | Implemented | Not named in spec §2 or §17; treated as baseline pending owner confirmation (open question O-6 below). |

## 2. New work by phase

Phase labels follow spec §14 and the owner decisions. Each row names the owner decision that shapes it.

### Phase A: secure delivery (flagged, partner API, business-owned verification)

| # | Item | Decision | Stage |
|---|---|---|---|
| A1 | Auth-delivery API (create, status without secrets, cancel), contract, state machine, events | 4 | 2, 3 |
| A2 | Business-supplied single-use magic links on verified domains (default) | 2 | 2, 3 |
| A3 | Optional Viadere link generation and redemption service (ADR first; never redeems on open or prefetch) | 2 | 1, 3 |
| A4 | Destination policy and verified domain binding, redirect and host-confusion rules | 2 | 2, 3 |
| A5 | Secure notification handoff (opaque push, resolve, confirm screen, open verified HTTPS) | 4 | 4 |
| A6 | OTP delivery by email and in-app, never in push body, webhook or log | 1, 4 | 3 |
| A7 | Delivery of partner-generated TOTP codes (transport only; Viadere does not verify) | 3 | 3 |
| A8 | Delivery status and callbacks with signature v2 | 4 | 2, 3 |
| A9 | Expiry, resend, cancel policy; pending delivery secrets live minutes | 7 | 1, 2 |
| A10 | Retention alignment: security transaction metadata 30 days; audit events (no secrets) longer and access-restricted | 7, 10 | 1, 2 |
| A11 | SMS removed from authentication: remove phone-link SMS OTP and SMS account-link/hand-off links; replace with an in-app phone-ownership proof (customer-originated message from the device is the stated direction) | 1, 9 | 1 (design), 2-3 |
| A12 | Business console pages: auth templates, emulator, domain scopes, sandbox | 4 | 3 |
| A13 | Pilot behind flags in staging | 4 | 8 |

### Phase B: assurance, MFA, SDKs

| # | Item | Decision | Stage |
|---|---|---|---|
| B-1 | Push MFA with transaction binding and **number matching** | 4 | 1, 4, 5 |
| B-2 | Payment / high-value step-up | 4 | 5 |
| B-3 | Passkey-biased sign-in links (business-hosted RP/origin design) | 4 | 1, 2, 4 |
| B-4 | Signed factor assertions; separate proof of delivery from proof of authentication | spec §17 | 1, 5 |
| B-5 | Policy-based grant evaluation for Viadere-managed sign-in only | 5 | 5, 6 |
| B-6 | Replay and abuse controls for new flows (fail-closed namespaces) | spec §17 | 3, 5 |
| B-7 | Swift SDK extension, TypeScript web SDK (zero runtime dependencies), partner harness, examples, `tests/security/` | 8 | 3 |
| B-8 | Kotlin Android SDK (FCM, App Links, Credential Manager) from the separate branch | O-1 | 4 |
| B-9 | Webhook signature v2 and durable receiver dedup | spec §6.3 | 2 |
| B-10 | watchOS security classification (no FIDO2 claim) | spec §14.1 | 4 |

### Phase C: hardened authorities (built in staging per decision 5)

| # | Item | Decision | Stage |
|---|---|---|---|
| C-1 | Grant/policy authority and signer as a private Container App (internal ingress only, own managed identity, own Key Vault signing key) | 5 | 6 |
| C-2 | New grant/OIDC keys live only in the signer from day one | 12 | 6 |
| C-3 | Existing api-held keys (`kd-log-signing`, `link-descriptor`, `loop-publication`, `brand-manifest`, `kek-data`) remain with the api as a **tracked exception** with a migration plan | 12 | 1 (record), 6 |
| C-4 | Separate signer deploy identity and environment; compromise tests | 5 | 6, 7 |
| C-5 | Retire Fly.io, GCP KMS and Neon from CI and IaC | 11 | 6 |
| C-6 | Alerts for key/RBAC/DNS changes, drift job, audit immutability (standard profile) | spec §9.2 | 6 |

### Phase D: optional identity provider

| # | Item | Decision | Stage |
|---|---|---|---|
| D-1 | OIDC provider (authorization code + PKCE, discovery, JWKS, logout) in staging behind a staging-only flag | 6 | 9 |
| D-2 | RP client registration (redirect URI allow-list) | 6 | 9 |
| D-3 | SAML identity provider: design only | 6 | 9 |
| D-4 | Production promotion: explicit owner approval after release gates | 6, "Production" | n/a |

## 3. Explicitly out of scope

| Item | Source |
|---|---|
| Mandatory government ID for all users | spec §17 |
| Replacing business identity providers by default | spec §17 |
| Custom cryptographic protocols as new inventions (existing `VIADERE-*` formats are baseline, to be reviewed by A3) | spec §17, §2 |
| SMS-first growth strategy, SMS as an authenticator, OTP or links by SMS | spec §17; decisions 1 and 9 |
| Arbitrary partner HTML or code in native surfaces | spec §17 |
| A universal identity profile independent of the business relationship | spec §2.1 |
| Agent deployment to production | decision "Production" |
| Viadere verifying a business's TOTP server-side | decision 3 |
| SAML implementation | decision 6 |
| Any change to the SMS gateway beyond the on-ramp scope | decision 9 |

## 4. Conflicts and how the decisions resolve them

| ID | Conflict | Resolution |
|---|---|---|
| C-1 | Phone-link SMS OTP and SMS account-link / hand-off links exist; spec and decision 1 say no SMS authentication. A14 left this to the owner. | **Resolved by decision 9**: no OTPs, links or codes over SMS. Remove (A11, finding F-06). The SMS gateway stays as an on-ramp only. |
| C-2 | The product is SMS-first for messaging; spec §17 puts an "SMS-first growth strategy" out of scope. | Resolved: the gateway is baseline (B5); decisions 1 and 9 confine it to the on-ramp and prohibit authentication use. Do not grow SMS features. |
| C-3 | CLAUDE.md "Swift end to end" and the old Node rule vs spec §8/§21 (TypeScript, Kotlin). | TypeScript: resolved by decision 8 (rule 4 on disk already allows it). Kotlin: **open** (O-1). |
| C-4 | Lean Azure exceptions (public Key Vault and Service Bus endpoints, software keys) vs spec §9/§22 private networking and HSM keys. | Acceptable for staging only; each exception row must cover the signer environment and carry a removal condition. Production needs the `standard` profile. |
| C-5 | Existing custom `VIADERE-*` wire formats vs "no custom cryptographic protocols". | Baseline stays; A3 reviews before any new token or grant format (F-23). |
| C-6 | Retention: approval requests 400 days, link tokens 7 days, signed decisions kept vs 30 days and "minutes". | **Resolved by decisions 7 and 10** in principle: align to 30 days, audit events (no secrets) keep longer retention. Classification of signed decisions and approval JWS is open (O-3). |
| C-7 | Residency US-only vs `OTP_ALLOWED_COUNTRIES` default `US, CA` and MailerSend US/CA. | Residency (where data is stored) is US Azure regions per decision 7. Destination countries for messaging are a separate setting; record the distinction. Neon region is moot after decision 11. |
| C-8 | Recoverable accounts and recovery already exist but spec calls them optional Phase C/D. | Moved to baseline (B8); Phase D adds only the IdP surface. |
| C-9 | Phase letters differ inside the spec (TOTP in A vs B, grant authority in B vs C, IdP in C vs D). | Use the §14 numbering as the owner decisions do: A delivery, B assurance and SDKs, C hardened authorities, D IdP. Record in the Stage 1 phase-table ADR. |
| C-10 | Spec §2.1 non-goal "no proprietary authenticator in Phase A" vs the shipped vault authenticator. | Decision 3 keeps the on-device authenticator; Phase A adds no authenticator features. |
| C-11 | "First-party actions" is undefined in the spec. | Treated as the existing first-party surfaces (Live Activity decisions, notification actions, rewards, Wallet, Loop actions) under B13/B9; owner to confirm (O-6). |
| C-12 | Profiles and household delegation absent from spec §2/§17. | Baseline B17 pending O-6. |
| C-13 | Staging target ambiguous (Fly docs vs Azure). | **Resolved by operator facts and decision 11**: Azure lean is the only staging. Fly/GCP/Neon retired (C-5 in Phase C). |
| C-14 | New components (OIDC library, TypeScript toolchain, Kotlin) need CLAUDE.md versions rows and exception rows. | Every Stage that adds a dependency updates the table in the same commit (CLAUDE.md rules 1, 5, 8, 9). |
| C-15 | Business-supplied links vs "no storage of arbitrary URLs or bearer credentials". | Compatible if no bearer URL is persisted in plaintext and none is placed in push bodies or logs (spec §19.1); design must state which fields are stored. |
| C-16 | Decision 12 leaves five existing signing/wrapping keys on the public api, which spec §4.3/§22 forbid for grant-capable keys. | Accepted as a tracked exception for **non-grant** keys only; no grant, OIDC or token-minting key may be added to the api. Exception row to be added to CLAUDE.md in Stage 1/6. |

## 5. Open questions (owner)

- **O-1** Kotlin for the Android package and Wear OS companion.
- **O-3** Retention class of signed decisions and approval result JWS.
- **O-4** GHCR package visibility.
- **O-5** Which legacy cloud resources (Fly, Neon, GCP) exist in live accounts.
- **O-6** Confirm household delegation, customer profiles and "first-party actions" as baseline.
