# Gap analysis against AUTH-DELIVERY-SPEC-v2 (Stage 0)

| | |
|---|---|
| Spec | `docs/product/AUTH-DELIVERY-SPEC-v2.md` §14, §17, §24 |
| Decisions applied | `docs/product/AUTH-OWNER-DECISIONS.md` 1-12 |
| Evidence base | `docs/architecture/CURRENT_STATE.md` (same commit), plus the file reads cited below |
| Date | 2026-11-02 |
| Author | A0, reconciling A4, A5, A6, A8, A14. Review roles for sign-off are in `docs/reviews/IMPLEMENTATION_LEDGER.md`. |

## Legend

- **Implemented**: code path exists, reachable under default configuration, tests exist in the repository. Not a production-readiness claim (no suite was run in Stage 0).
- **Partial**: some of the capability exists, is gated off in staging, or differs from the spec.
- **Planned**: specified in a document or IaC, no code.
- **Absent**: nothing found.
- **Gated** in the evidence column means the feature flag is off in staging (for example `APPROVE_V2_ENABLED=false`).
- Stage numbers follow spec §24: 1 threat model + ADRs, 2 API + data contracts, 3 delivery engine, 4 native handoffs, 5 Viadere MFA proofs, 6 cloud hardening, 7 red team + QA, 8 controlled pilot, 9 optional IdP. Stage 0 is this discovery.
- Phase labels follow spec §14 and the owner decisions (A delivery, B assurance and SDKs, C hardened authorities, D optional IdP). Spec §17 and §14 label phases differently (see `docs/product/SCOPE_LEDGER.md` conflict C-9); this document uses the §14 numbering, with each §17 capability mapped.

## 1. Baseline capabilities (spec §17 "currently scoped - preserve")

| Capability | Status | Evidence | Gap / instruction | Stage |
|---|---|---|---|---|
| Anonymous / device-linked enrollment | Implemented | `Services/AccountEnrollmentService.swift`, `Services/AuthService.swift`, ADR-0013; tests `DeviceFirstAccountTests`, `DeviceAuthTests`, `TrustTierExploitTests` | Preserve. Device farms create D0 accounts (documented residual, SECURITY §2.5a). Phone-ownership proof must be redesigned without SMS codes (decision 9, see F-06). | 1 (design), 2-3 |
| Cross-device linking concept | Partial | Device confirm with proof (`POST /v1/devices/{id}/confirm`), business link sessions (`Link/*`), vault pairing (gated). No `POST /v1/devices/link` route and no magic-link cross-device handoff. | Preserve existing flows. The new handoff is Phase A work. | 3, 4 |
| Business messaging | Implemented (in-app, SMS); Partial (RCS); Absent (Apple Messages for Business) | `Services/ConversationService.swift`, `SMS/*`, `Channels/*`; tests `SMSGatewayTests`, `RCSTests` | Preserve. Decision 9 keeps the SMS gateway **only as an on-ramp** (menus, routing, STOP/HELP, "get Viadere" links). | 1 (scope rules) |
| Push approvals | Partial | Approve v2 (`Approve/*`) is Gated off; legacy `authenticate`/`authorize` closed to live traffic unless an operator grants an entitlement (sunset 2027-06-30, carried from A14); decisions via `InteractionService`. | Preserve; close gaps in Phase B (number matching, push content). | 5 |
| Age and identity assertions | Partial (Gated) | `Verify/*`, `VERIFY_ENABLED` off everywhere; results returned to the business are not signed | Preserve; unsigned results are a finding (F-21). | 5 (if signing needed) |
| Partner brand kits | Implemented | `BrandKits/*`, ADR-0017, `BrandKitServerTests` | Preserve. Key `brand-manifest` moves under the key-migration plan (decision 12). | 6 |
| Customer pages / widgets | Implemented | `Server/Public/connect-button/v1/`, `Web/ConnectButtonRoutes.swift`, browser test in Python | Preserve; path `v1` is immutable. Web SDK may wrap it, not replace it. | 2 |
| Optional business Loops | Implemented, dark by default | `Loops/*`, ADR-0016/0018 | Preserve. Key `loop-publication` in decision 12 exception. | 6 |
| Tenant separation | Implemented | pairwise `subject_ref`, application-level per-query isolation, no Postgres RLS | Preserve. A dedicated cross-tenant suite for auth-delivery does not exist yet (spec §13). Consider RLS as an ADR option. | 1, 7 |
| Account recovery (spec lists as optional future) | Implemented | `Services/RecoveryService.swift`, `RecoveryCredentialService.swift` (72 h hold, notices, revoke all on activation) | Preserve. Spec §23 downgrade rules (email-only recovery must not lower a high-assurance account) need an explicit review; iOS recovery-downgrade copy is absent (A6). | 1, 4 |
| Business console and API keys | Implemented | `Dashboard/*`, `Security/APIKeyLifecycle.swift` | Preserve. | 2 |

## 2. Phase A: secure delivery

| Capability | Status | Evidence | Gap | Stage |
|---|---|---|---|---|
| Delivery API: `POST /v1/auth-deliveries`, `GET .../{id}`, `.../cancel` | Absent | not in `Packages/ViadereCore/.../API/APIRoutes.swift` or `docs/openapi.yaml` | Contract, aggregate, state machine, idempotency, tenant context, fields `request_id`, `correlation_id`, `expires_at`, `audience`, `purpose`, allowed destination | 2, 3 |
| Contract artifacts: `contracts/openapi/auth-delivery-v1.yaml`, event and webhook JSON Schemas | Absent | only `docs/openapi.yaml` (business API); `docs/protocol/schemas/` has none for webhooks | Create contract + parity test; decide `contracts/` vs extending `docs/openapi.yaml` | 2 |
| State machine CREATED to COMPLETED / EXPIRED / CANCELLED / DENIED / FAILED (§6.2) | Absent | nearest is approval request status (`ApproveRequestService.swift:271-288`) | Build, with OPENED distinct from COMPLETED; add queue message type and fail-closed rate-limit namespaces | 3 |
| Business-supplied magic links on verified domains (decision 2, default) | Absent | no `magic` symbol; `Platform/DomainControl.swift` verifies domains but has no per-purpose destination policy | Destination allow-list bound to verified domains, redirect/host-confusion policy, TTL 2-10 min, single use; store no bearer URL in plaintext (spec §19.1) | 2, 3 |
| Optional Viadere link generation and redemption service (decision 2) | Absent | none | ADR required; redemption must never happen on open, GET or prefetch | 1, 3 |
| Secure notification handoff (opaque push, resolve, confirm, open) | Partial | approvals fetch over authenticated API (`ApproveSupport.swift:43-58`); `/h/` handoff redeems on open (F-08); no business-URL handoff screen in the app | iOS confirm screen naming business and destination host, system-API open only, no auto-redeem | 4 |
| OTP delivery by email / in-app (decision 4 pilot) | Partial | dashboard email codes (`Dashboard/EmailVerification.swift`: 6 digits, 15 min, 5 attempts, HMAC); no business-initiated OTP API | Delivery API method `otp`, keyed-hash storage, attempt limits, never in push body or webhook | 3 |
| OTP delivery by SMS | Excluded (decisions 1, 9); exists in code for phone linking | `Services/PhoneLinkService.swift:76-93` | Remove or replace (F-06). The transport-adapter seam stays; any SMS adapter needs a new ADR + owner approval | 1, 2, 3 |
| TOTP: on-device Viadere authenticator (decision 3) | Partial | `Vault/TOTP.swift`, `VaultEngine.swift`, `AuthenticatorView.swift`; vault sync off by default | Preserve. Core has no step-reuse tracking (relevant only if Viadere ever verifies TOTP, which decision 3 forbids) | 5 (note only) |
| Delivery of partner-generated codes (decision 3, transport only) | Absent | none | Delivery method `totp_code` / `otp`; Viadere never verifies the partner's TOTP | 3 |
| TOTP provisioning / enrollment prompt | Planned | none | Seed protection (§6.5) | 3, 4 |
| Verified domain registration | Implemented (onboarding) | `Platform/DomainControl.swift`, `business_domains` | Wire to auth-delivery destination validation | 2, 3 |
| Delivery status and callbacks | Partial | signed webhooks, retries, dead letters (`Services/WebhookService.swift`); SMS statuses; no auth-delivery events, no DELIVERED/OPENED | New event types with signed envelope v2; webhook signature v2 (F-04) | 2, 3 |
| Request inbox | Partial | console inbox, Loop inbox, approval inbox | Auth-request inbox type | 3 |
| Expiry, resend, cancel policy | Partial | per-feature TTLs exist; no generic link TTL policy | One policy table (decision 7 and 10: pending secrets live minutes) | 1, 2 |
| Secret hygiene: no bearer material in push, logs, webhooks | Partial | log redaction exists; no auth-link feature yet to test | Privacy tests (spec §13) | 3, 7 |
| Pilot flags (sign-in links, code delivery) | Planned | decision 4 | Feature flags in `Infra/azure` env allow-list and `ServerConfig` | 8 |

## 3. Phase B: assurance, MFA and SDKs

| Capability | Status | Evidence | Gap | Stage |
|---|---|---|---|---|
| Viadere-owned verification of device-bound push factors | Implemented (approvals, interactions); Gated for Approve v2 | `Approve/ApproveRequestService.swift:408-505`, `Services/InteractionService.swift:326-485` | Enable behind pilot flag after Stage 5 | 5, 8 |
| Push MFA with transaction binding | Partial (Gated) | `txn_digest`, `ApprovalTransaction.swift` | Owner decision 4 requires it in the pilot | 5 |
| **Number matching** (decision 4) | Absent | repository search found no display-code logic for approvals | Server-generated number bound to the challenge; shown on the requesting surface and the approving device (not on the Lock Screen); wrong number counts toward lock | 1 (design), 5, 4 |
| Payment / high-value step-up | Partial (Gated) | `transaction.approve` capability, D1 requirement for high risk | Pilot scope; needs number matching | 5 |
| Signed factor assertions | Partial | `ApprovalResultJWS` verified by `ApprovalVerifier` (business can verify independently); interaction decisions give the business only a server attestation (F-12) | Decide per flow which evidence the business receives; separate proof of delivery from proof of authentication | 1, 5 |
| Policy-based grant evaluation for Viadere-managed sign-in | Partial | entitlement policy (`Policy/PolicyService.swift`, `Core/Policy/PolicyEngine.swift`); not a grant evaluator | Phase C authority (see section 4) | 5, 6 |
| Replay and abuse controls | Implemented | `DatabaseReplayGuard`, fail-closed rate-limit namespaces, `AbuseService`, prompt-fatigue, invalid-submission lock | Add auth-delivery namespaces to the fail-closed list | 3, 5 |
| Passkey-biased business sign-in (decision 4) | Partial | Viadere-account and dashboard passkeys only (`ApplePasskeyService.swift`, `PasskeyVerifier.swift`); no business sign-in-link passkey flow; webauthn-swift is pinned to an untagged revision (CLAUDE.md exception) | RP/origin design for business-hosted links; passkey ceremony script as a reusable versioned file | 1, 2, 4 |
| Adaptive delivery choice | Absent | none | Policy for method selection (§3) | 5 |
| Assurance taxonomy + independent factor testing | Partial | `Interaction/Assurance.swift`, `Verify/AssuranceDimensions` | Independent testing is Stage 7 | 7 |
| Recovery notices and cooling-off | Partial | notices + 72 h hold exist; iOS downgrade/transfer copy absent | UX copy | 4 |
| Webhook signature binding method, path, event id, tenant (§6.3) | Partial | `t.body` MAC only (F-04) | New signature version `v2` + ADR; Core change with SDK updated in the same change | 2 |
| Receiver replay defense | Partial | 300 s window; only `InMemoryWebhookDeduplicator` ships | Durable dedup interface + example | 2, 3 |
| Business API request signing | Absent | bearer-only (`Security/Principals.swift`); spec §6.1 expects signed calls | Decide in ADR: signing vs mTLS binding vs keep bearer + idempotency | 1, 2 |
| Swift SDK for auth-delivery | Partial | `ViadereBusinessSDK` has no delivery or challenge methods; unpublished | Extend; publish with semver + provenance | 3, 5 |
| TypeScript web SDK (decision 8) | Absent | no TS in repo; Connect button only | Zero-runtime-dependency bundles, lockfile for dev tooling, CSP-compatible, no `localStorage` for secrets | 3 |
| Kotlin / Android SDK | Absent on main | separate unmerged branch (not inspected); server `AndroidKeyAttestationVerifier` is a stub; FCM refused; no `assetlinks.json` | Merge review, FCM sender behind a push-provider seam, Play Integrity + key attestation verifier, App Links | 4 |
| Generated clients, partner test harness, example apps, `tests/security/` | Absent | none | Harness + scripted replay/expired/denied cases | 3, 7 |
| Business console: templates, emulator, risk policy for auth | Partial | console covers keys, webhooks, sandbox | Auth-delivery pages | 3 |
| watchOS security classification | Absent | no document; watch can only deny security items | Classification note + decision | 4 |
| Client-side prompt throttling / collapse (§7.2) | Partial | server prompt-fatigue exists; no client collapse | Stage 4/5 | 4, 5 |

## 4. Phase C: hardened authorities (decision 5: build in staging; decision 12: key placement)

| Capability | Status | Evidence | Gap | Stage |
|---|---|---|---|---|
| Separate grant/policy authority and signer as a private Container App (internal ingress only, own managed identity, own Key Vault signing key) | Absent | one Vapor process; `ROLE` only splits jobs; no signer app, identity or vault in `Infra/azure` | New environment/subnet, `ca-viadere-signer`, `id-viadere-signer` excluded from the existing deploy identity's Managed Identity Operator loop, separate vault and key `grant-signing`, own deploy identity scoped to its resource group; design sketch in A5 report (not copied here) | 6 |
| New grant/OIDC keys only in the private signer (decision 12) | Absent | none | Policy-check rules (`GRANT-KEY-SCOPE`, `GRANT-NO-INGRESS`, `GRANT-IDENTITY-SEPARATE`) | 6 |
| Existing keys stay with the api as a tracked exception with migration plan (decision 12) | Violates spec §4.3/§22 today; exception not yet recorded | `locals.tf:124-127` | Add the exception row to CLAUDE.md and a migration plan for `kd-log-signing`, `link-descriptor`, `loop-publication`, `brand-manifest`, `kek-data` | 1 (ADR), 6 |
| Signed authorization artifacts (nonce, audience, expiry, grant id) between api and authority | Absent | prior art `ApprovalResultJWS` | Contract; independent verification | 1, 5, 6 |
| Service-to-service authentication | Absent | none; origin lock is a shared header | Entra workload-token check at the signer (not subnet, because api and cloudflared share a subnet); mTLS optional | 6 |
| Gateway-compromise cannot sign or change grant policy (test) | Absent (not testable today, api holds sign rights) | `locals.tf` | Red-team scenario after the split | 6, 7 |
| Separate CI/CD credential per trust role | Absent / violated | single `id-gh-deploy-<env>` reaches all workload identities (F-02) | Dedicated deploy identity and environment for the signer | 6 |
| Egress deny-by-default for the authority | Absent | default outbound internet in both profiles | NSG with service-tag allow-list on the signer subnet; verify required outbound list first | 6 |
| Audit immutability and key/DNS/RBAC change alerts | Absent in lean | no WORM store, no alert rules, no drift job | Alert rules, drift job; WORM only in `standard` (exception) | 6 |
| HSM-backed keys | Planned (`standard` only) | `locals.tf` profiles | Lean software keys for the signer need an exception row; production requires HSM | 6 |
| Separate recovery authority | Absent | recovery runs in-process | Evaluate in ADR; not required for the pilot | 1 |
| Compromise containment exercise | Absent | none | A11 + A12 | 7 |
| mTLS Tier E for business API | Partial | implemented in server; `enable_mtls = false` in Cloudflare IaC; no certificate | Optional per tenant | 6 |

## 5. Phase D: optional identity provider (decision 6: OIDC in staging behind a staging-only flag; SAML design only)

| Capability | Status | Evidence | Gap | Stage |
|---|---|---|---|---|
| OAuth 2.0 authorization code + PKCE, OIDC discovery, JWKS, logout | Absent | no authorize/token/JWKS/discovery code; "OIDC" hits are GitHub Actions federation only | Library choice + CLAUDE.md versions row, conformance plan, new architecture review (spec §24 stage 9 requires pilot evidence and explicit approval) | 9 |
| Relying-party client registration (redirect URI allow-list) | Absent | API keys exist; no redirect registry | Design | 9 |
| Token issuer with HSM keys | Absent | consumer tokens are opaque bearer tokens | Signer from Phase C | 9 |
| SAML identity provider | Planned, design only (decision 6) | none | Do not build | 9 |
| Recoverable accounts | Implemented (device-first accounts) | see section 1 | Verified-email recovery at limited assurance remains Absent and is not approved | 9 |
| Production promotion | Blocked | decision "Production" | Owner approval after release gates | n/a |

## 6. Findings to fix

Severity scale: **Critical** exploitable now with large impact; **High** violates a binding decision or spec invariant with material security impact, or removes a key control; **Medium** weakens a control or violates a spec rule with limited blast radius; **Low** hygiene or design debt. "Verified" means A0 opened the cited lines; "carried" means the claim rests on a discovery report; "unverified" cannot be proved from the repository.

| ID | Sev | Finding | Evidence | Status of evidence | Fix (stage) |
|---|---|---|---|---|---|
| F-01 | High | **The public api identity holds all signing keys and every service secret.** `id-viadere-api` has Crypto User on `kd-log-signing`, `link-descriptor`, `loop-publication`, `brand-manifest`, `kek-data` and Secrets User on all api secrets. A compromise of the internet-facing process can sign link descriptors and transparency-log heads and unwrap data keys. Spec §4.3, §5 (edge gateway holds no grant keys), §22; owner decision 5. Decision 12 accepts this for existing keys only as a tracked exception. | `Infra/azure/locals.tf:124-127`; `identity.tf`; `docs/ops/KEY-ROTATION.md` | Verified (IaC); live role assignments unverified | Record the exception and migration plan (Stage 1 ADR); new keys only in the signer (Stage 6) |
| F-02 | High | **One CI deploy identity per environment can run any app with any workload identity.** `id-gh-deploy-<env>` has Container Apps Contributor on the app resource group and Managed Identity Operator on all four workload identities, so it can redeploy an app as `id-viadere-api` and reach its keys and secrets. Its federated subject is `environment:<env>` only (no branch, workflow or job claim), so the GitHub environment's deployment-branch rule (not in the repository) is the only gate. Violates spec §9.2/§22 ("no shared CI/CD credential can deploy gateway, MFA, grant and signer"). | `Infra/azure/identity.tf:40,45-57` | Verified (IaC); GitHub environment rules unverified | Separate signer deploy identity and environment, add `job_workflow_ref`-style constraints where Entra supports them, test the compromise path (Stage 6, 7) |
| F-03 | Medium | **Apply identity is effectively subscription Owner for the staging subscription** (Contributor + RBAC Administrator with a role-list condition that includes Key Vault Crypto User and Secrets Officer). Reviewer approval on `azure-infra-<env>` is the only real control. A separate subscription or management boundary for signing is missing (spec §9.2). | AZURE-SETUP section 4 | Carried (A5), outside OpenTofu; live state unverified | Stage 6: scope review, PIM or break-glass procedure, consider a separate subscription for the signer tier |
| F-04 | Medium (High once auth events ship) | **Webhook signature does not bind method, path, event id or tenant.** `v1 = HMAC-SHA256(secret, "<t>." + body)`. Event id and tenant travel as unsigned headers; in the v2 envelope they are inside the signed body. Spec §6.3 requires method, path, timestamp, body digest, event id and tenant context. Receiver dedup ships only in memory. | `Packages/ViadereCore/.../Security/WebhookSignature.swift:28-31` (verified); `Webhooks.swift` (carried) | Verified | New `v2` signature scheme + ADR, Core and SDK changed together, durable dedup interface (Stage 2) |
| F-05 | High (for the pilot) | **No number matching for push MFA.** Owner decision 4 requires it for the pilot; the approval challenge is a random nonce never shown to the user, so a fatigued user can approve an attacker-initiated request. Prompt-fatigue lock exists but is not a substitute. | repository search (A0 re-ran); only SAS in `Link/LinkSession.swift` and `ApprovalEnrollmentBinding.swift` | Verified (absence) | Design Stage 1, protocol Stage 5, UI Stage 4 |
| F-06 | High | **SMS is used for OTP and for links against decisions 1 and 9.** A 6-digit verification code is sent by SMS for phone linking; account-link URLs (`/l/{token}`, 15 min) and secure-handoff URLs (`/h/{token}`, 10 min) are sent by SMS; Core renders SMS/RCS "secure handoff" text. Decision 9: no OTPs, no account-link or hand-off links, no codes over SMS; phone ownership must be proven in-app (for example a customer-originated message from the device). | `Services/PhoneLinkService.swift:76-93`, `SMS/GatewayService.swift:203-213`, `Packages/ViadereCore/.../Rendering/ChannelRenderer.swift` (SMS handoff text, carried) | Verified | Stage 1 design of the in-app proof; Stage 2-3 remove the SMS OTP and link minting (keep on-ramp copy: menus, routing, STOP/HELP, "get Viadere"); migration for in-flight links; update SECURITY §2.8 |
| F-07 | Medium | **Retention does not match decision 10 (30 days).** Approval requests are purged after 400 days; link tokens after 7 days past expiry (`linkTokenDays = 7`), decisions (signed payloads) are append-only and kept for dispute handling; approval result JWS are kept for dispute evidence. Spec §19.1 and decision 7: pending delivery secrets live minutes. Only webhook deliveries and outbound rows (30 days) already comply. Audit events (no secrets) may keep longer retention under decision 10. | `Approve/ApproveRequestService.swift:295-296` (verified), `Config/PlatformConfig.swift:126` (verified), `docs/SECURITY.md` lines 484, 767 (verified) | Verified | Retention table ADR classifying each store as pending secret / security transaction metadata / audit evidence (Stage 1); sweeps and tests (Stage 2); owner confirmation needed on whether signed decisions and approval JWS count as "high-value audit evidence" (open question O-3) |
| F-08 | Medium | **`/h/` hand-off redeems on open with no confirmation.** `AppModel.handle(.handoff)` calls `redeemHandoff` as soon as the universal link is handled. Spec §19.1/§7.1: never redeem before an explicit user interaction. Mitigation: the call is device-signed and the token was minted for that consumer, so the impact is a burned token and a navigation, not a grant (A6 rated High; downgraded here). Moot for SMS once F-06 is fixed, but the pattern must not carry into the new handoff. | `Packages/ViadereKit/Sources/ViadereKit/Stores/AppModel.swift:286-300`; `APIRoutes.swift:120-122`; `Routes/AuthRoutes.swift:93` | Verified | Confirm screen before redeem (Stage 4) |
| F-09 | Medium | **Live Activity discloses the business on the Lock Screen.** Push-to-start attributes carry `businessName`, `businessId` and `interactionId`; eligible decisions show the business's confirm title/detail/option labels (bounded, sanitized, not redacted). Security requests are excluded from Live Activities, so the exposure is for non-security confirm/choose flows. Spec §7.2 asks for minimal disclosure; decision on a policy switch is open. | `Push/APNsSender.swift:61-68` (verified), `Services/LiveActivityService.swift`, `Packages/ViadereKit/.../LiveDecision.swift` | Verified (attributes); Lock Screen rendering unverified on device | Policy setting (hide detail until unlock) + test (Stage 4) |
| F-10 | Medium | **Retired platform still has live deploy paths.** `release.yml` deploys Fly staging and Fly production on every `v*.*.*` tag; `staging-deploy.yml` builds and deploys Fly staging on every push to the working branch and does not verify the cosign signature. Each holds a `FLY_API_TOKEN` per environment. `Infra/terraform` defines GCP KMS, Neon and a Cloudflare ruleset that writes the edge token into state if applied. Decision 11 retires Fly, GCP KMS and Neon. | `.github/workflows/release.yml:121-199`, `.github/workflows/staging-deploy.yml:5-60` (verified); `Infra/terraform/*` | Verified | Remove Fly/GCP/Neon from CI and IaC and rotate/destroy the tokens (Stage 6; owner action for live resources) |
| F-11 | Low | **Documentation and ADR drift.** `docs/ops/STAGING-SETUP.md` describes Fly + Neon; ADR-0001/0002/0003 state Fly, Neon and GCP KMS "in force"; ADR-0010/0011/0012 (Azure) still "proposed"; `App.swift:158`, `OperationsConfig.swift:219` (GCP workload-identity env names), `ConsoleCompliance.swift:153` (Neon PITR copy) still reference the legacy stack. | files cited (verified) | Verified | Supersede/accept ADRs, rewrite staging doc, drop legacy config (Stage 6) |
| F-12 | Medium (design trade-off) | **The business cannot independently verify an interaction decision.** The raw signed decision is withheld deliberately because it names the global device id; the business receives `deviceRef` and a server attestation (`evidenceRef`). Spec §5.2 step 6 expects a verifiable signed outcome. Approve v2 JWS meets the bar but is gated off. | `Services/InteractionService.swift:419-431`, `Services/WebhookService.swift:166-180` (verified); SECURITY §2.4 | Verified | Per-flow decision in the Stage 1 ADR: use Approve JWS (pairwise key) for authentication proofs; keep the privacy rule |
| F-13 | Medium | **Origin protection is a shared header and traffic is plain HTTP inside the environment.** `allow_insecure_connections = true`; any app in the environment can reach the api and `ca-cloudflared` metrics (0.0.0.0:2000). No service-to-service authentication. | `Infra/azure/containerapps.tf:170-174` (verified); `docs/SECURITY.md` G-11 | Verified | Stage 6 (workload-token authentication for the signer; evaluate for the api) |
| F-14 | Medium (device unverified) | **Dead-end approve on low-assurance sign-in.** `authenticate` at low risk requires `deviceSignature`, so `requiresSecureFlow` is false and "Yes, it's me" is not `.foreground`; the handler returns `.requiresApp` for approve on security-sensitive kinds, so the action does nothing visible in a process the user did not bring forward. Usability failure that trains users to open the app by other means; not a bypass. | `ChannelRenderer.swift:259-278`, `NotificationActionHandler.swift:85-93` (verified) | Verified in source; device behavior unverified | Always foreground approve on security kinds, add a reproducing test (Stage 4) |
| F-15 | Medium (device unverified) | **Approve v2 push carries no `iid` and uses an unregistered category.** The tap takes `.open(nil)` and lands on Alerts, not on the request. | `Approve/ApproveSupport.swift:45-58`, `NotificationActionHandler.swift:36-39` (verified); grep shows no registration of the category | Verified in source | Opaque request id in the payload + category or Approvals route (Stage 4/5) |
| F-16 | Medium | **Deny is not visually equal to Approve** (tinted destructive vs filled primary; slide variant has a small Deny below). Spec §7.2/§20. | `App/Shared/DesignSystem/ViadereDesignSystem.swift` (carried, A6) | Carried | Equal-weight buttons (Stage 4) |
| F-17 | Medium | **Lean profile lacks audit immutability, alerting and network egress control.** No WORM store, no alert rules, no drift detection, default outbound internet, 30-day logs. Acceptable under the existing exceptions for lean but required before the signer holds authority. | `Infra/azure/monitoring.tf`, `network.tf` (carried, A5) | Carried | Stage 6 |
| F-18 | Medium | **Secret-handling hygiene.** `configure-staging.sh` prints `EDGE_TOKEN` to the terminal; `kv_tool.py psql-job` puts an Entra admin token in a Container Apps job secret for the job's lifetime; the GHCR pull credential is a personal read:packages PAT; Cloud Shell path bypasses GitHub reviewers. | `Infra/azure/cloudshell/*.sh`, `kv_tool.py` (carried, A5) | Carried | Stage 6; owner to confirm whether the GHCR package can be public to drop the PAT |
| F-19 | Low | **Business API is bearer-only; interaction issue idempotency is optional and body-based.** Spec §6.1 expects signed requests. | `Security/Principals.swift:179-245`, `Services/InteractionService.swift:60-66` (carried) | Carried | ADR in Stage 1 (signing vs mTLS vs idempotency required on all writes) |
| F-20 | Low | **Message push `threadID = business.<business id>`** and no `apns-collapse-id` on interaction pushes (duplicates possible on retry; the state machine prevents double action). | `Push/APNsSender.swift:153,168` (verified) | Verified; id class unverified | Use an opaque per-device thread id; Stage 4 |
| F-21 | Low | **Verification results returned to the business are not signed.** | `Verify/VerifyHTTPRoutes.swift:32-42` (carried) | Carried | Stage 5 if the verify path is used for assurance |
| F-22 | Low | **Receiver-side webhook dedup is in-memory only** in the shipped SDK. | `Packages/ViadereBusinessSDK/.../Webhooks.swift` (carried) | Carried | Stage 2/3 |
| F-23 | Info | **Custom `VIADERE-*` wire formats** (SIG, DECISION, CTX, ENROLL, LINK, `vrp1.`, `VRK1-`, vault format) coexist with the spec's "no custom cryptographic protocols" non-goal and §9.3's "standards-based signatures and vetted libraries". They compose standard primitives (ECDSA P-256, HMAC-SHA256, HPKE, JWS). Needs A3 review before any new token or grant format. | `docs/SECURITY.md` section 2 | Carried | Stage 1 (A3) |
| F-24 | Info | **Android attestation verifier is a stub** that never attests; FCM refused. Relevant when the Kotlin package merges. | `Security/DeviceIntegrity.swift:131-140` (carried) | Carried | Stage 4 |
| F-25 | Low | **Accessibility and watch gaps.** No reflow at AX5 sizes, Reduce Motion in two components only, watch sends deny where "This wasn't me" should be report, no usability metrics. | `App/ViadereWatch/WatchRootView.swift:86-87` and others (carried, A6) | Carried; device-unverified | Stage 4 |
| F-26 | Low | **Project rules vs spec on stack wording.** CLAUDE.md "Swift end to end" sentence predates the TypeScript decision; Kotlin and Wear OS are not covered by any repository rule. | `CLAUDE.md` | Verified | Owner ruling on Kotlin (open question O-1) |
| F-27 | Info | **Test status is unknown.** No suite was run in Stage 0; `docs/HANDOFF.md` says verification after the last gate fixes was not run. | `docs/HANDOFF.md` | Carried | Stage 7 baseline run on SQLite and PostgreSQL before any item is called production-ready |

## 7. Stage closure map

| Stage | Closes |
|---|---|
| 1 Threat model + ADRs | F-01 exception record, F-06 in-app proof design, F-07 retention table, F-12 evidence model, F-19, F-23; number-matching design; phase table; link-service ADR; SMS-adapter seam rule |
| 2 API + data contracts | Auth-delivery OpenAPI and schemas, F-04, F-07 sweeps, retention schema, F-22 interface |
| 3 Delivery engine | State machine, magic link, OTP, code delivery, TypeScript SDK, Swift SDK methods, harness, F-06 removal |
| 4 Native handoffs | F-08, F-09, F-14, F-15, F-16, F-20, F-24, F-25, Android review |
| 5 Viadere MFA proofs | F-05 protocol, F-21, signed assertions, replay tests |
| 6 Cloud hardening | F-01 migration plan, F-02, F-03, F-10, F-11, F-13, F-17, F-18, signer environment |
| 7 Red team + QA | F-27, compromise tests, tenant breakout, replay, token theft |
| 8 Pilot | Flags, rollback, owner approval |
| 9 IdP | Phase D, only after pilot evidence and explicit approval |

## 8. Open questions for the owner

- **O-1** Kotlin/Android and Wear OS: CLAUDE.md still says the stack is Swift end to end, while spec §8/§21 require a Kotlin SDK. Confirm Kotlin is allowed for the Android package and name its review path.
- **O-2** Phone-ownership proof (decision 9) needs a design choice in Stage 1: customer-originated message from the device is the stated direction; confirm acceptable carrier/shortcode behavior.
- **O-3** Do signed decisions and approval result JWS count as "high-value audit evidence" (longer, access-restricted retention) or as 30-day security transaction metadata (decision 10)?
- **O-4** Whether the GHCR package may be public (drops the personal PAT).
- **O-5** Whether the dormant Fly apps and the Neon/GCP resources have been created in live accounts (needed to schedule decommissioning).
