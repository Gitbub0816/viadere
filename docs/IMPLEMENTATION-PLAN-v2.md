# Implementation plan v2 — Security, Trust, Business Platform & Compliance

Maps [`SECURITY-TRUST-PLATFORM-SPEC.md`](SECURITY-TRUST-PLATFORM-SPEC.md) (v1.0, 2026-10-27) onto the existing build. Requirement IDs refer to that spec. Every work package (WP) lands with tests that reproduce its acceptance criteria, follows [`../CLAUDE.md`](../CLAUDE.md) (current versions, no Node.js/PHP), and updates `docs/SECURITY.md` with new wire formats and threat rows.

## Architecture decisions (ADRs)

| # | Decision | Rationale | Source |
|---|---|---|---|
| ADR-01 | **Server on Fly.io** (always-on machines, deployed with `flyctl`/Machines API — no Node). **Cloudflare** in front for DNS, WAF, TLS policy and the static website. | Cloudflare Containers sleep after 10 min, have ephemeral disk, and their Worker front has only Node-based deploy tooling today. | Product owner, 2026-10-27 |
| ADR-02 | **PostgreSQL 18 on Neon**, direct TLS (`verify-full`) from the server. | Cloudflare has no managed Postgres; Neon pairs with Cloudflare and has a connector in our tooling. | Product owner |
| ADR-03 | **Google Cloud KMS (HSM, EC P-256)** for service signing/encryption keys behind a `KeyManagementService` protocol; local software implementation for dev/test only. | Non-exportable hardware-backed keys at ~$2.50/key/month; Cloudflare has no KMS. | Product owner |
| ADR-04 | **Marketing + developer site is a Swift static site**, deployed to Cloudflare Workers Static Assets through its REST direct-upload API (Python stdlib uploader). | No Node; static hosting isolated from the API (Boundary D). | Product owner |
| ADR-05 | **Verify evidence:** Apple Wallet IDs (in-app identity presentment; server verifies the HPKE envelope and ISO 18013-5 DeviceResponse against issuer IACA roots) **and Didit** (native iOS SDK themed to Viadere via White Label; Viadere screens wrap it). Biometric capture and images go device → Didit directly; Viadere stores only minimized results and purges Didit sessions after reading. | Wallet gives birthdate-free `age_over_NN`; Didit covers users without a Wallet ID (VER-008). Didit's SDK has no headless UI. | Product owner |
| ADR-06 | **Approve uses pairwise per-business approval keys.** The phone generates a Secure Enclave key per business relationship at a business-authorized enrollment; the business receives that public key (and key ID) and verifies every signed result itself (APP-002/004/005). No device identifier is shared across businesses. | Satisfies independent business verification and the cross-business unlinkability fix (A3) together. | Engineering |
| ADR-07 | **E2EE with HPKE (RFC 9180)** — CryptoKit/swift-crypto `HPKE`, suite DHKEM(P-256)/HKDF-SHA256/AES-256-GCM — for identity disclosures and sensitive payloads. Business keys are published through an **authenticated key directory**: each business key is signed by the business's enrolled root key, logged in an append-only Merkle transparency log, and pinned on devices after first use (SEC-CR-006). | Vetted standard; a relay compromise cannot substitute keys undetected. | Engineering |
| ADR-08 | **Authenticator includes E2EE vault sync**, shipped behind a release gate until an independent cryptography/recovery review passes (Phase 4 gate). Vault unlock and recovery are independent of identity verification. | Product owner; spec §5.1 and Phase 4 gate. | Product owner |
| ADR-09 | **Infrastructure as code with Terraform/OpenTofu** (Cloudflare, GCP KMS, Neon providers) and `fly.toml`; CI on GitHub Actions with Go/Swift-based scanners (no Node actions where a non-Node alternative exists). | Policy compliance. | Engineering |

## Gap analysis

| Spec area | Already built | Gap → WP |
|---|---|---|
| §3.2 tenant isolation, pairwise refs | Tenant-scoped queries, per-business pseudonyms, device pseudonyms | Formal `subject_ref` (HMAC-derived, non-enumerable) on every business API → WP2 |
| §4.1 transport | HSTS, TLS at edge, SPKI pinning in app | Edge TLS 1.3 policy + reviewed 1.2 compat, mTLS for Tier E, service-to-service mTLS → WP8, WP6 |
| §4.2 crypto | Device-signed decisions, digest of displayed context, low-S, replay guards, AAD binding | HPKE E2EE, authenticated business key directory, algorithm IDs/key IDs/version negotiation on every protocol (SEC-CR-007), KMS-backed service keys → WP1, WP8 |
| §4.3 API keys & webhooks | Hashed keys, scopes, revocation, signed webhooks, idempotency | Non-secret key ID + verifier, expiry, overlap rotation, environment binding, per-key last-used, webhook delivery ID + versioned key ID, endpoint ownership verification, test events → WP6 |
| §5 device | Secure Enclave keys, App Attest, cool-downs, recovery, notices | Freeze approvals, prompt-fatigue limits, accessibility notes, vault separation → WP1, WP5 |
| §5.1 passkey vault | — | Credential-provider extension (passkeys iOS 17, TOTP iOS 18, CXF import iOS 26), E2EE sync → WP5 |
| §6 identity & age | — | Assurance taxonomy, Wallet mdoc verifier, Didit, `age.minimum`, verification requests, result refs, consent receipts → WP3 |
| §6.4 capability catalog | Purpose-scoped consents, interaction kinds | Typed capability catalog + policy engine (entitlement ∩ consent ∩ evidence ∩ law/policy) → WP2 |
| §7 Approve | Signed approvals with display digest; server verification | Pairwise keys, business-authorized enrollment, audience-bound signed result, business verification SDK, `transaction.approve` contract, freeze → WP1 |
| §8 onboarding & tiers | Pending→verified operator review, handles/codes | Domain verification, legal-entity step, contract acceptance versions, go-live review, tiers M/A/V/E, periodic re-verification → WP6 |
| §9 console | Dashboard (keys, webhooks, templates, QR, consent, audit, team, billing), 5 roles | Full IA (Verify, Approve, Security, Compliance, Support sections), 9 roles + separation of duties, session inventory, suspicious-login alerts, WCAG 2.2 AA → WP6 |
| §10 website | — | Swift static site, developer portal from OpenAPI, legal pages with version/effective date/owner/counsel status/archive → WP7 |
| §11 legal | — | Drafts of every listed document, marked *counsel review pending*; data inventory, DPIA templates → WP7, WP8 |
| §12 ops | Audit chain, kill switches (suspend), retention purges | Risk register, ADRs, runbooks (OPS-005), SBOM, scanning, provenance, VDP + security.txt, RTO/RPO, DR drills, capability kill switches → WP8 |
| §13 retention | Per-table purges | Data inventory with class-based retention config → WP8 |
| §14 API contracts | — | `/v1/verification-requests`, `transaction.approve`, opaque event envelope with `result_ref` → WP1, WP3, WP6 |

## Work packages

Packages run in two waves to keep file ownership disjoint. Each owns a new module directory; shared registration edits are one-liners.

**Wave 1 (parallel)**
- **WP2 — Capability catalog & policy engine** (Core + Server `Policy/`): typed catalog (`contact.reachable`, `message.send`, `consent.request`, `auth.challenge`, `transaction.approve`, `age.minimum`, `identity.name`, `identity.address`, `identity.verified`), per-capability definition (inputs, evidence, sensitivity tier, output schema, max retention, audit fields, revocation), business entitlements and risk tiers M/A/V/E, `subject_ref` pairwise derivation, scope enforcement so a messaging credential can't call Verify/Approve (acceptance 1).
- **WP5 — Authenticator** (App credential-provider extension + Kit `Vault/` + Server `Vault/`): passkey registration/assertion, TOTP, vault encryption, E2EE sync with anti-rollback, separate vault recovery, release gate flag.
- **WP7 — Website & legal content** (`Site/`): Swift static generator, all §10.1 pages, developer portal, legal drafts with metadata and archive, marketing-integrity lint (banned claims), Cloudflare uploader (Python stdlib).
- **WP8 — Infra, KMS & operations** (`Infra/`, `.github/`, `docs/ops/`, Server `KeyManagement/`): Fly.io config, Terraform for Cloudflare/GCP KMS/Neon, KMS provider (GCP REST, current API version) + local provider, CI (build/test both DBs, SBOM, secret/dependency/container scanning, provenance), risk register, runbooks, VDP/security.txt, data inventory and retention matrix, RTO/RPO.

**Wave 2 (after WP2)**
- **WP1 — Approve v2 + business key directory + E2EE** (Core `Approve/`, `E2EE/`; Server; BusinessSDK verifier; Kit/App).
- **WP3 — Verify** (Core `Verify/`; Server `Verify/` with Wallet mdoc verifier and Didit adapter; App Wallet + Didit flows).
- **WP6 — Business platform** (Server `Dashboard/`, `Platform/`): onboarding stages, tiers, console IA, roles, API-key lifecycle, webhook upgrades, Tier E mTLS, kill switches, audit export.

**Wave 3:** independent adversarial reviews of each package against the spec's phase gates (enrollment/key substitution/replay/recovery for Approve; issuer validation/non-disclosure/unlinkability for Verify; vault crypto/recovery for Authenticator), then fixes.

## Release gates

The spec's gates (§17) are enforced as release flags in configuration: Verify, Approve v2, Authenticator sync and Tier E connectivity stay disabled in production until their gate is recorded as passed (independent assessment, legal validation by market). Code completion does not open a gate.

## External dependencies the product owner must action

- Apple: in-app identity presentment entitlement (per bundle ID), Wallet merchant ID and encryption certificate; App Attest; push and Wallet pass certificates.
- Didit: account, workflow IDs, webhook secret, White Label theme, shortest retention setting.
- Fly.io, Cloudflare, Neon and Google Cloud accounts; DNS for `viadere.com`.
- Counsel: every [LEGAL] item and all draft legal pages.
