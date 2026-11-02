# Authentication delivery — owner decisions (spec v2 §28 / §14.1)

Recorded 2026-11-02 before any coding, as `docs/product/AUTH-DELIVERY-SPEC-v2.md` §28 requires. Changes need a new entry here and an ADR.

| # | Question (§28 / §14.1) | Decision |
|---|---|---|
| 1 | Should Viadere ever deliver SMS? | **No SMS for authentication in this round.** The owner sees no value that outweighs SIM-swap/phishing exposure. The delivery engine keeps a transport-adapter seam so an SMS adapter could be added later only through a new ADR and owner approval; never a silent fallback. |
| 2 | Business-supplied magic links or a Viadere link service? | **Both:** businesses supply short-lived single-use URLs on their verified domains (default), **and** an optional Viadere link-generation and redemption service is offered. |
| 3 | TOTP: Viadere authenticator or transport? | **Both:** keep the on-device Viadere authenticator (seeds never leave the device) and deliver partner-generated codes. Viadere does not verify a business's TOTP server-side. |
| 4 | First pilot (staging) scope | **Passkey-biased when available**, covering sign-in links, push MFA (transaction-bound, number matching), payment / high-value step-up, and one-time-code delivery. Pilot runs on staging behind feature flags. |
| 5 | Hardened authorities (Phase C) | **Build it in staging:** a separate grant/policy authority and signer as a private Container App (internal ingress only, own managed identity, own Key Vault signing key). The public api cannot sign or mint grants. |
| 6 | Viadere identity provider (Phase D) | **Build OIDC in staging** behind a staging-only flag (OIDC first; SAML stays design-only unless separately approved). Production promotion needs explicit owner approval after the release gates. |
| 7 | Residency and retention | **US-only** (Azure US regions). Pending delivery secrets: minutes (until completion/expiry). Security transaction metadata: **30 days**. High-value audit evidence: longer, access-restricted, per the existing audit policy. |
| 8 | Web SDK language | **TypeScript allowed** (CLAUDE.md rule 4 revised): shipped bundles keep zero runtime dependencies; dev tooling pinned with a lockfile. |
| 9 | Existing SMS uses (after Stage 0 discovery) | **Keep the SMS messaging gateway only as an on-ramp** for customers without the app (menus, routing, STOP/HELP, "get Viadere" links). **No authentication over SMS at all:** no OTPs, no account-link or hand-off links, no codes. Phone-number ownership is proven in-app (design in Stage 1, e.g. a customer-originated message from the device, never a Viadere-sent code). Owner's direction: Viadere replaces shortcodes and SMS; SMS stays only where it is the sole reach to non-app customers. |
| 10 | Existing retention | **Align to 30 days:** approval-request and link-token metadata follow the 30-day rule; tamper-evident audit events (no secrets) keep their longer, access-restricted retention. |
| 11 | Legacy infrastructure | **Retire Fly.io, GCP KMS and Neon** from CI and IaC (Azure is the only staging). |
| 12 | Existing Key Vault signing keys | **New grant/OIDC keys live only in the private signer from day one;** existing keys (key-directory log, link descriptor, Loop publication, Brand manifest, data KEK) stay with the api for now as a tracked exception with a migration plan. |
| — | Production | No agent deploys to production. Staging only. |
