# Implementation plan v3: Security Architecture Expansion and the Azure migration

Maps [`SECURITY-ARCHITECTURE-EXPANSION-v1.md`](SECURITY-ARCHITECTURE-EXPANSION-v1.md) (v1.0, 2026-10-29, "the spec") onto the build as it stands on branch `claude/inspiring-cannon-t5hxfw` (commit `83ffc2c`). It extends [`IMPLEMENTATION-PLAN-v2.md`](IMPLEMENTATION-PLAN-v2.md); v2's work packages are built and gate-reviewed (see [`HANDOFF.md`](HANDOFF.md)), so v3 plans only what the new spec adds or changes.

Every work package (WP) follows [`../CLAUDE.md`](../CLAUDE.md): current stable versions only, no Node.js or PHP, security fixes start with a test that reproduces the exploit path, no control in [`SECURITY.md`](SECURITY.md) is weakened, shared logic lives in `ViadereCore`, and new wire formats are added to `SECURITY.md` §2 in the same change.

Status: **draft for product-owner review**, 2026-10-29. The new ADRs (0010 to 0014) are `proposed`.

---

## 1. Decisions and what changes from v2

### 1.1 Product-owner decisions (binding)

| # | Decision | Effect on the spec | Recorded in |
|---|---|---|---|
| PO-1 | **Keep the Swift/Vapor server and the shared Swift `ViadereCore`; run it on Azure Container Apps.** No ASP.NET Core port. | Deliberate deviation from ADR-VDR-001 (spec §9 table row "API services: … ASP.NET Core (.NET LTS)") and from §11 Phase 2 "Port Vapor endpoints to ASP.NET Core". §11 Phase 2 explicitly allows "protocol-compatible services", which a Swift service on the same versioned contract is. | ADR-0010 |
| PO-2 | **Target infrastructure otherwise as the spec says:** Cloudflare edge/DNS/WAF; Azure Container Apps; Azure Database for PostgreSQL Flexible Server (private networking, HA, PITR); Azure Service Bus + workers (durable queues, DLQ, idempotency); Azure Key Vault **Premium** (HSM-backed keys, not Managed HSM); Microsoft Entra managed identities; Azure Monitor / Application Insights; GitHub Actions with OIDC federation. Fly.io/Neon staging stays transitional until cutover. Google Cloud KMS is replaced by Key Vault. | §9 table adopted except the runtime language. | ADR-0010, 0011, 0012, 0014 |
| PO-3 | **Android: platform-neutral protocol, schema and server now** (attestation abstraction that can take Play Integrity + key attestation, push abstraction for FCM, no Apple-only fields in the core account schema). The Kotlin app is **not** planned now. | §1 scope keeps Android; §4 step 3/5, §6 "no Apple-only dependency" become Core/Server work; Android app rows are "Out of scope now". | ADR-0013 |
| PO-4 | **Infrastructure as code stays OpenTofu** with the `azurerm` provider. | ADR-0009 continues (its Fly/GCP/Neon scope shrinks at decommission). | ADR-0010, §6 |

### 1.2 What changes from v2

| Area | v2 (built) | v3 |
|---|---|---|
| Account creation | Passkey first: `register/begin` requires a display name, `register/finish` needs a WebAuthn credential, then device enrollment (`AuthService.swift:32-88`, `OnboardingViewModel.swift:94-105`) | **Device first** (ADR-0013): device key + App Attest + server challenge creates a pseudonymous account; passkey and recovery codes become optional recovery credentials; no personal field is required |
| Trust | Assurance by key purpose (`DecisionAssurance`), new-device 24/72 h cool-down that lapses on its own (`AuthService.swift:293-308`, `DeviceTrust.swift:10-12`) | Explicit device **trust tiers D0/D1/D2** in Core; elevation only by trusted-device approval, relying-party (business) re-enrollment, or a recorded policy; recovery yields D0 |
| Business linking | Consumer-initiated public connect code (`RelationshipService.swift:113-156`) + Approve v2 key enrollment for an *existing* relationship (`ApproveEnrollmentService.swift:30-88`) | **Business link sessions** (§5): business-authenticated, single-use, expiring session that creates the pairwise connection and (optionally) the approval key in one ceremony, with anti-session-swapping controls and a signed result |
| Multi-device | Second device discovers the account through a synced passkey; trust lapses in after 24 h unless the owner cancels | Trusted-device approval with a signed, short-lived, account/device-bound challenge; QR device pairing (cross-platform); per-device recent approvals and key rotation in the UI |
| Runtime | Fly.io machines, `release_command` migrations, in-process 5 s job loop (`BackgroundJobs.swift:20-79`) | Azure Container Apps (api, worker, cloudflared), Container Apps Jobs for migrations and sweeps, Service Bus queues with DLQ via a transactional outbox |
| Database | Neon PostgreSQL 18, password roles over TLS | Azure Database for PostgreSQL Flexible Server 18 (18.6 is current on Azure), private access, Entra managed-identity roles |
| Keys | GCP Cloud KMS (audit-head signing only, workload identity from Fly OIDC: `AuditExport.swift:38-79`) | Key Vault Premium: EC-HSM P-256 signing keys, RSA-HSM 3072 key-encryption keys, secrets referenced by managed identity |
| Origin | `EDGE_TOKEN` header (`EdgeLock.swift:25-42`) | Cloudflare Tunnel to an internal-only Container Apps ingress, `EDGE_TOKEN` kept as a second layer (section 5.4) |
| CI/CD | `flyctl deploy` with `FLY_API_TOKEN` (`.github/workflows/release.yml:102-142`) | Entra workload-identity federation (no long-lived token), `az` CLI (Python, not a JavaScript action) |

### 1.3 Verified facts this plan relies on (sources, checked 2026-10-29)

| Fact | Source |
|---|---|
| Azure Database for PostgreSQL Flexible Server supports PostgreSQL 18; the current minor is **18.6**, and new servers are created with it (page dated 2026-08-26) | <https://learn.microsoft.com/en-us/azure/postgresql/configure-maintain/concepts-supported-versions> |
| Managed identities authenticate to PostgreSQL with an Entra access token as the password (resource `https://ossrdbms-aad.database.windows.net`), tokens valid 5 to 60 minutes, roles created with `pgaadauth_create_principal`, "Microsoft Entra authentication only" mode available (page dated 2026-07-14) | <https://learn.microsoft.com/en-us/azure/postgresql/security/security-entra-configure> |
| PostgresNIO 1.33.2 (our resolved version) takes a static `password: String?` in `PostgresConnection.Configuration`; there is no token-provider hook | `Server/.build/checkouts/postgres-nio/Sources/PostgresNIO/Pool/PostgresClient.swift:183-236` |
| Container Apps managed identity: `IDENTITY_ENDPOINT` + `X-IDENTITY-HEADER`, `api-version=2019-08-01` or later, `client_id` for a user-assigned identity; per-identity `lifecycle` (`Init`/`Main`/`All`/`None`); managed-identity ACR pull (page dated 2025-06-03) | <https://learn.microsoft.com/en-us/azure/container-apps/managed-identity> |
| Container Apps ingress IP restrictions: IPv4 CIDR allow **or** deny rules (not mixed) (2026-03-19) | <https://learn.microsoft.com/en-us/azure/container-apps/ip-restrictions> |
| Container Apps client certificates: `clientCertificateMode` `require`/`accept`/`ignore`; the certificate is **forwarded** in `X-Forwarded-Client-Cert` (`Hash`, `Cert`, `Chain`); self-signed certificates are accepted, so the app must validate the issuer itself (2025-06-30) | <https://learn.microsoft.com/en-us/azure/container-apps/client-certificate-authorization> |
| Container Apps billing: Consumption free grant 180,000 vCPU-s, 360,000 GiB-s and 2 M requests per subscription per month; private endpoints and planned maintenance on an environment incur the Dedicated Plan Management charge (2025-12-09) | <https://learn.microsoft.com/en-us/azure/container-apps/billing> |
| Service Bus **private endpoints and service endpoints are Premium only**; Standard supports IP firewall rules (via ARM/CLI/IaC, not the portal) (2026-05-02) | <https://learn.microsoft.com/en-us/azure/service-bus-messaging/private-link-service>, <https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-ip-filtering> |
| Service Bus Premium: 1, 2, 4, 8 or 16 messaging units, VNet/Private Link, geo-replication; Standard: shared capacity, sessions, duplicate detection, 256 KB messages (2026-10-06) | <https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-premium-messaging> |
| Service Bus REST peek-lock receive (`POST {queue}/messages/head?timeout=`), complete (DELETE the `Location`), unlock; accepts Entra bearer tokens (2026-10-13) | <https://learn.microsoft.com/en-us/rest/api/servicebus/peek-lock-message-non-destructive-read> |
| Key Vault Premium HSM keys: EC-HSM P-256/P-384/P-521/P-256K, RSA-HSM 2048/3072/4096, **oct-HSM (AES) is preview** in vaults; new key versions on HSM Platform 2 (FIPS 140-3 Level 3) (2026-07-07) | <https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys> |
| OpenTofu current stable **1.13.2** | <https://get.opentofu.org/tofu/api.json> |
| `hashicorp/azurerm` current **5.12.0** on registry.terraform.io (published 2026-10-29T15:00Z); the OpenTofu registry serves **5.11.0** today | <https://registry.terraform.io/v1/providers/hashicorp/azurerm>, <https://registry.opentofu.org/v1/providers/hashicorp/azurerm/versions> |
| `cloudflare/cloudflare` 5.28.1 (repo pin is current) | <https://registry.terraform.io/v1/providers/cloudflare/cloudflare> |
| Prices (USD, `eastus`, consumption, effective dates in section 5.8) | Azure Retail Prices API <https://prices.azure.com/api/retail/prices> queried 2026-10-29 |
| Staging Neon project `viadere` (`cold-scene-35948882`, aws-us-east-1, PG 18), single branch `production` (`br-broad-lake-b7l6l8ii`), database `viadere`, 21 Fluent migrations applied, **0 rows** in `consumers`, `devices`, `passkey_credentials`, `businesses`, `relationships`, `dashboard_users`, `audit_events`, `approve_keys`; PITR history retention 86,400 s (1 day) | Read-only query through the Neon connector, 2026-10-29 |

---

## 2. Requirement-by-requirement gap analysis

Status key: **Done** (meets the statement), **Partial** (part built, named gap), **Gap** (not built), **Conflicts** (today's behaviour contradicts the statement), **Out of scope now** (excluded by a PO decision; the platform-neutral groundwork is still planned). WP ids refer to section 3.

### 2.1 §1 scope, assumptions, non-goals (constraints on the design)

| ID | Spec statement | Current state | Status | WP |
|---|---|---|---|---|
| S1.1 | Scope includes iOS, iPadOS, macOS, watchOS companion and Android clients | iOS app, App Clip, watch companion, widgets, notification and credential-provider extensions (`App/project.yml`); `DevicePlatform` already lists `iOS, iPadOS, watchOS, macOS, web, android` (`Packages/ViadereCore/Sources/ViadereCore/Models/Device.swift:4-5`); no macOS or Android client | Partial | A2 (neutral protocol); Android app out of scope (PO-3); macOS client not planned |
| S1.2 | Existing users, secrets and integrations inventoried before any destructive migration | No inventory document; staging DB is empty (section 1.3) | Gap | F4 Phase 0 (section 4) |
| S1.3 | Non-goal: legal identity at enrollment; no mandatory email/phone/password | Phone is optional ("Skip for now", `App/Viadere/Features/Onboarding/OnboardingView.swift:270`); no email or password; **display name is mandatory** (`OnboardingViewModel.swift:61`, `AuthService.swift:33-36`, `consumers.display_name` NOT NULL `Server/Sources/ViadereServerKit/Models/ConsumerModels.swift:8`); a passkey is mandatory | Conflicts | B4 |
| S1.4 | Non-goal: Apple ID enumeration; universal seamless enrollment without device authorization | Nothing enumerates Apple IDs; every device enrolls with its own keys | Done | none |
| S1.5 | Non-goal: app attestation as proof of human identity | `VerificationLabel.registeredAuthenticator` "does not prove who the person is" (`Packages/ViadereCore/Sources/ViadereCore/Verify/VerificationAssurance.swift:49-74`) | Done | none |
| S1.6 | Pseudonymous is not anonymous; IP, device signals, push tokens, business mappings, audit records need privacy controls | Site lint bans "anonymous" (`Site/Sources/SiteKit/Lint.swift:26`); `docs/ops/DATA-INVENTORY.md` exists; audit records carry the global consumer UUID as actor (`Server/Sources/ViadereServerKit/Models/OperationalModels.swift:29-33`) | Partial | B4 (audit actor pseudonym), F2 (privacy review) |

### 2.2 §2 trust model and invariants

| ID | Spec statement | Current state | Status | WP |
|---|---|---|---|---|
| T1 | One account, many devices; each device has its own non-exportable approval key, independently revocable | `devices` + `device_keys` per device (`ConsumerModels.swift:135-178`, `:237-260`); Secure Enclave keys `.privateKeyUsage` + `.userPresence`/`.biometryCurrentSet`, `ThisDeviceOnly` (`Packages/ViadereKit/Sources/ViadereKit/Keys/SecureEnclaveKeyStore.swift:14-19`, `:90-97`); per-device revoke (`Server/Sources/ViadereServerKit/Services/AuthService.swift:457-469`); Approve v2 adds a per-device **and** per-business key (`ApproveModels.swift:93`) | Done | none |
| T2 | Business connection is a pairwise opaque id, not the global account id; no business can query another's relationships | `subject_ref = "sub_" + base64url(HMAC-SHA256(SUBJECT_REF_KEY, "VIADERE-SUBJECT-V1\n{businessId}\n{consumerId}"))` (`Packages/ViadereCore/Sources/ViadereCore/Policy/SubjectRef.swift:44-60`); tenant-scoped queries (`ApproveEnrollmentService.swift:93-97` returns 404 across tenants); but business DTOs still accept/return `relationshipId`, the internal row UUID (`Packages/ViadereCore/Sources/ViadereCore/API/BusinessDTOs.swift:40-42`) | Partial | C2 (business API uses `subject_ref`/`connection_id` only; `relationshipId` deprecated) |
| T3 | Business enrollment needs fresh authorization from both an authenticated business session and the account/device | Approve v2: business creates the enrollment with its API key, device signs a statement, business verifies binding tag/SAS and confirms (`ApproveEnrollmentService.swift:5-19`, `docs/SECURITY.md` §2.53). Plain **connect** needs no business authorization at all (`RelationshipService.swift:113-156`) | Partial | C1 |
| T4 | Push is a delivery signal only | Push carries no business, amount or payee; app fetches over the authenticated API (`Server/Sources/ViadereServerKit/Approve/ApproveSupport.swift:43-62`, `Push/APNsSender.swift:4-6`) | Done | none |
| T5 | Every sensitive approval signs a canonical, server-generated challenge bound to RP, action, nonce, expiry, device and transaction context | Approve v2 `ApprovalResult` JWS (ES256, `aud`, `sub`, `amr`, `iat`, `exp`, `txn_digest`, challenge) verified by `ApprovalResultVerifier` (`Packages/ViadereCore/Sources/ViadereCore/Approve/ApprovalResult.swift:60-84`, `ApproveRequestService.swift:397-415`); v1 `VIADERE-DECISION-V1` (`Security/DecisionSigning.swift:36-43`). Approve v2 is **off** in staging and production until its gate (`Infra/fly/fly.staging.toml:24`) and the legacy path trusts the relay (`Approve/LegacyApproval.swift:5-11`) | Partial | C2 (gate evidence, legacy sunset) |
| T6 | Recovery authority weaker than trusted-device authority; recovery alone must not grant high-risk MFA | Recovery: 72 h hold, notices, cancel from any trusted device; activation revokes every device and session (`RecoveryService.swift:7-17`, `:284-320`). The device enrolled afterwards cools down 24 h, then is trusted for high-risk legacy approvals with no further check (`AuthService.swift:298-308`, `DeviceTrust.swift:10-12`). Approve v2 keys die with the old devices, so v2 MFA needs business re-enrollment (good) | Partial | B5, D2 |
| T7 | Authorization decisions by the backend from verified signatures and policy | `VIADERE-SIG-V1` request signing (`Security/RequestSigning.swift:32-41`), `PolicyService` (SECURITY.md §2.29), server verifies every decision; legacy path is relay-trusted for the business (see T5) | Partial | C2 |

### 2.3 §3 account and device data model

| ID | Spec entity / statement | Current tables and code | Status | WP |
|---|---|---|---|---|
| D1 | **Account**: account_id (random 128+ bit opaque), state, created_at, policy_version | `consumers` (`ConsumerModels.swift:5-29`): `id` UUIDv4 (122 random bits), `status` (`active`/`sandbox`/deleted), `created_at`; **no** `policy_version`; carries `display_name` (mandatory) and `user_handle` (WebAuthn, mandatory) | Partial | B4: add `policy_version`; make `display_name`, `user_handle` nullable; record UUIDv4 (122 bits from the system CSPRNG, never a bearer value) as an accepted engineering deviation from "128+" in SECURITY.md |
| D2 | **Device**: device_id, account_id, platform, public_key, key_algorithm, attestation metadata, trust_tier, last_seen, revoked_at | `devices` (`ConsumerModels.swift:135-178`): id, consumer_id, platform, last_seen_at, revoked_at, client_kind, approvals_locked_until, attestation_status, enrollment_method; keys in `device_keys` (purpose, public_key, hardware_backed, attested); App Attest in `app_attest_keys` (`Models/IdentityModels.swift:8`). **No** `key_algorithm` (P-256 implied, `Security/DeviceKeys.swift:4-29`), **no** `trust_tier` | Partial | B4 (`key_algorithm`, `trust_tier`, `integrity_format`, `elevated_at/_by`), B5 |
| D3 | **RecoveryCredential**: credential_id, account_id, public key or verifier, type, status, created_at | `passkey_credentials` (`ConsumerModels.swift:31-54`; no `status`), `recovery_profiles` + `recovery_codes` (peppered HMACs, `IdentityModels.swift:39-84`) | Partial | D2: add `status` to passkeys; document the type mapping (`passkey`, `recovery_code`) rather than merge tables |
| D4 | **BusinessConnection**: connection_id, business_id, account_id (internal), status, permissions, enrollment evidence, created_at | `relationships` (`Models/RelationshipModels.swift:6-33`): id, consumer_id, business_id, status, source, connected_at, `subject_ref`; permissions = `consent_grants` + entitlements; **no enrollment evidence** | Partial | C1 (`link_session_id`, `evidence_digest`) |
| D5 | **EnrollmentSession**: session_id, business_id, authenticated_subject_ref (business-held), nonce, expiry, state, proof digest | `approve_enrollments` (`Approve/ApproveModels.swift:56`): business_id, subject_ref (Viadere's pairwise ref, so a relationship must already exist), code_hash, status, expires_at, statement, binding_tag. No business-held customer reference | Partial | C1 (`link_sessions`) |
| D6 | **ApprovalChallenge**: challenge_id, connection_id, action_hash, display payload, nonce, expiry, status, policy, attempt count | `approve_requests` (`ApproveModels.swift:126`): request_id, relationship_id, subject_ref, capability, request_hash, challenge, details_sealed, status, expires_at; **no attempt count** (invalid submissions are audited, not counted per request: `ApproveRequestService.swift:368-372`) | Partial | C2 (`attempts`, max 5 then `locked`) |
| D7 | **ApprovalEvidence**: challenge_id, device_id, signature, UV evidence, verification result, timestamp | Stored on the request: `decided_kid`, `amr`, `result_jws`, `decided_at` (`ApproveRequestService.swift:429-431`); device via `approve_deliveries.device_id` | Done | none |
| D8 | **AuditEvent**: event_id, actor pseudonym, action, correlation_id, policy version, result, immutable log pointer | `audit_events` (`Models/OperationalModels.swift:25-44`): seq, actor_kind, actor_id (global consumer UUID), action, outcome, correlation_id, hash chain (`prev_hash`, `hash`, `key_epoch`); head exported write-once (`Operations/AuditExport.swift:160-163`). **No** policy_version, actor is not a pseudonym | Partial | B4 (`actor_ref` HMAC pseudonym, `policy_version`, chain version 3) |
| D9 | Distinct internal ids and external pairwise ids | `subject_ref` external; `relationshipId` still exposed to businesses (T2) | Partial | C2 |
| D10 | Encrypt sensitive columns; minimize retention; never log private keys, full tokens, identity documents, recovery secrets | `FieldCipher` (`Core/FieldCipher.swift`, SECURITY.md §2.21), `LogRedaction.swift`, retention purges (`Operations/Retention.swift`), recovery codes stored as HMACs | Done | none |

### 2.4 §4 first-run anonymous enrollment

| ID | Spec statement | Current state | Status | WP |
|---|---|---|---|---|
| E1 | Concise consent/privacy; explain device registration; no unnecessary registration fields | Welcome step (`OnboardingView.swift:117`) then "Create your account" requires "Your name … Shown to businesses you connect with" and "Create passkey" (`OnboardingView.swift:154-181`) | Conflicts | B4 |
| E2 | Hardware-protected signing key with explicit biometric/passcode access control | Secure Enclave, `.biometryCurrentSet` / `.userPresence` (`SecureEnclaveKeyStore.swift:90-97`); `DeviceKeyProvisioner` | Done | none |
| E3 | Client requests a server challenge; attaches App Attest (iOS) or Play Integrity + key attestation (Android) | Challenge exists **only after** an account and session exist (`AuthService.swift:172-184`, `Kit/Account/AccountService.swift:89-114`); App Attest evidence bound to `consumerId`, challenge and key list (`Packages/ViadereCore/Sources/ViadereCore/API/AuthDTOs.swift:231-265`); evidence type is Apple-specific (`AppAttestEvidence`, `AuthDTOs.swift:234-244`; `DeviceIntegrityVerifier`, `Security/DeviceIntegrity.swift:68-78`) | Partial | B4 (pre-account challenge), A2 (`IntegrityEvidence` enum) |
| E4 | Server validates challenge, attestation chain/policy, freshness, replay; creates account and device; returns scoped session | Validation is strong (single-use challenge CAS, proof per key, attestation key reuse refused, `APP_ATTEST_MODE` `require`/`report`: `AuthService.swift:251-291`) but the account is created by **passkey registration** (`AuthService.swift:58-88`) | Conflicts | B4 |
| E5 | Register APNs/FCM token separately; readiness only after backend confirms; degraded integrity → risk policy, not silent full trust | APNs token registered separately (`Routes/AuthRoutes.swift:115-138`); app advances only after `enrollDevice` returns (`OnboardingViewModel.swift:163-170`); unattested in `report` mode → flagged + 72 h cool-down (`AuthService.swift:300-310`). **But** the first device of a new account is exempt from any cool-down whatever its attestation (`AuthService.swift:293-301`), and the token model is APNs-only (`apns_tokens`) | Partial | B4/B5 (unattested first device = D0), E2 (FCM-ready push tokens) |
| E6 | App Attest ≠ legal identity or biometric presence; SE + LocalAuthentication verified independently; capability varies | App Attest result stored separately from key purposes; `hardwareBacked` "as claimed"; UV only via key access control (`ConsumerModels.swift:243-246`) | Done | none (tests in B4 keep it so) |

### 2.5 §5 business-to-user linking

| ID | Spec statement | Current state | Status | WP |
|---|---|---|---|---|
| L1 | Business authenticates its customer with its own procedure | Out of Viadere's control; SDK docs (`docs/BUSINESS-INTEGRATION.md`) | Done (business side) | C1 (SDK guidance: step-up before showing the QR) |
| L2 | Business backend creates an expiring, single-use session over a mutually authenticated service API, scoped to business, permissions and a non-sensitive transaction reference | Approve v2 enrollment: API key (hashed, scoped) + optional Tier E mTLS at Cloudflare (`SECURITY.md` §2.72, §2.74), ≤ 15 min, single use, scoped to capability (`ApproveEnrollmentService.swift:30-88`), **requires an existing relationship**; no transaction reference; mTLS is optional, not the default | Partial | C1 |
| L3 | QR contains only an opaque session reference / universal HTTPS URL; never persistent account ids, API credentials or reusable enrollment secrets | `https://{domain}/a/{CODE}?rk={root kid}#es={secret}` (`Approve/ApprovalEnrollmentCode.swift:31-38`). `CODE` is an opaque single-use 40-bit reference; `rk` is the business's public root key id; `es` is a **256-bit, per-enrollment, single-use** key-confirmation secret, never sent to Viadere (URL fragment), useless after the enrollment closes and unable on its own to enroll anyone (lookup only succeeds for the consumer the enrollment was created for, `ApproveEnrollmentService.swift:131-137`). It is therefore not "reusable" and not a credential, so it meets the statement; see section 2.12 for the analysis and the extra controls the new link session needs | Done (documented rationale needed) | C1 (SECURITY.md text) |
| L4 | App retrieves **signed** business identity, scope, expiry and display context over authenticated TLS | Lookup returns the directory `BusinessSummary`, capability, required assurance, expiry over SPKI-pinned TLS (`ApproveEnrollmentService.swift:127-146`); the device verifies the business key directory (signed tree heads, root key, `rk` pin, SECURITY.md §2.51, §2.53 step 2). The **connect** path shows an unsigned directory profile | Partial | C1 (signed `LinkSessionDescriptor`) |
| L5 | User confirms; device signs enrollment challenge with appropriate local verification | `ApprovalEnrollmentStatement` signed by the new pairwise key, biometric for high/critical (`ApproveEnrollmentService.swift:167-178`) | Done | none |
| L6 | Backend atomically consumes the session, creates a pairwise connection id, emits a signed/verified result by authenticated callback or poll | CAS `pending → device_completed` (`ApproveEnrollmentService.swift:208-216`), business confirms with a directory key, signed webhook + poll (`ApproveWebhooks.swift`, `GET /v1/business/approve/enrollments/{id}`). The pairwise connection already exists before; connect creates it without a session | Partial | C1 |
| L7 | Business binds the connection id to its authenticated customer record; immediate confirmation and out-of-band notice | Approve v2: the business knows which customer it created the enrollment for. Connect: business gets `relationship.connected` with `subject_ref` and **no way to bind it to a customer** (`RelationshipService.swift:144-152`); no out-of-band notice guidance | Gap | C1 |
| L8 | Universal Links / Android App Links carry the same short-lived session | Universal Links (AASA served by the server; `/a/`, `/c/`, `/l/`, `/h/` prefixes `API/APIRoutes.swift:435-439`); `ViadereCore.domain` is the constant `viadere.com`, so staging links point at production (HANDOFF open item) | Partial | C3 (configurable domain), Android App Links out of scope now (assetlinks.json planned in C3) |
| L9 | Browser flows: cross-device QR or deep link | Connect button (`Server/Tests/browser/test_connect_button.py`), QR | Done | none |
| L10 | WebAuthn/passkeys must not be conflated with the transaction-approval protocol | Separate code paths (`Services/PasskeyVerifier.swift` vs `Approve/*`) | Done | none |
| L11 | Anti-session-swapping protections | Approve v2: binding tag / SAS bound to the enrollment and the statement, lookup restricted to the intended consumer, unconfirmed keys expire (`ApprovalEnrollmentBinding.swift:4-73`, `ApproveEnrollmentService.swift:281-309`). Connect: none | Partial | C1 |
| L12 | Explicit business identity display | Verified business summary + directory check on enrollment; approval sheet shows the business | Done | none |
| L13 | Verified return channel | Business confirmation signed by its directory key, verified on device (SECURITY.md §2.53 step 5) | Done | none |

### 2.6 §6 multi-device and Apple ecosystem

| ID | Spec statement | Current state | Status | WP |
|---|---|---|---|---|
| M1 | Apple facts: no device enumeration; iCloud Keychain / CloudKit do not sync SE or App Attest keys | Design already assumes it (keys `ThisDeviceOnly`; App Attest key per device, reuse refused `AuthService.swift:276-283`) | Done | none |
| M2 | New device creates its own key, discovers the account via optional synced recovery/bootstrap credential or authenticated pairing, then requests enrollment | Discovery by **passkey sign-in** (iCloud Keychain synced passkey, `Kit/Account/AccountService.swift:64-69`) then enrollment with assertion; no authenticated pairing | Partial | D1 |
| M3 | Trust elevation: an existing trusted device approves the addition with a signed, short-lived, account/device-bound challenge showing name, platform, approximate region and permissions | `ConfirmationProof` (`VIADERE-CONFIRM-V1\n{subject}\n{subjectId}\n{deviceId}\n{signedAt}\n{assurance}`, `AuthDTOs.swift:348-374`) signed by another trusted device lifts the cool-down (`AuthService.swift:473-511`); the proof is not bound to a server nonce (time + replay guard instead); UI shows name and platform, not region or permissions; **without** confirmation trust arrives automatically when the 24 h cool-down lapses | Partial | D1 |
| M4 | Same-ecosystem convenience: optional iCloud Keychain discovery/recovery credential; CloudKit hints non-authoritative; iCloud presence ≠ MFA authorization | Synced passkey is the discovery credential; it never authorizes MFA by itself (device keys do); no CloudKit | Done | D2 (behaviour when iCloud Keychain is off) |
| M5 | Cross-platform: QR device pairing or portable passkey/recovery; no Apple-only dependency in core schema/protocol | No QR pairing; `AppAttestEvidence` and `apns_tokens` are Apple-only in Core/schema (`AuthDTOs.swift:234`, `Models/RelationshipModels.swift:116`) | Gap | A2, D1, E2 |
| M6 | Apple Watch only after evaluating watchOS key capabilities; no parity assumption | Watch holds no keys or credentials; every decision is signed on the iPhone (`App/ViadereWatch/WatchModel.swift:6-7`, `Kit/Watch/WatchSync.swift:4-6`) | Done | none |
| M7 | Device lifecycle: view devices, revoke individually, rotate keys, see recent approvals; loss/reset invalidates the device key | Trusted devices list, revoke, confirm, replacement cancel (`App/Viadere/Features/Settings/SettingsView.swift:301-335`); "Set up again" re-enrollment acts as rotation; no per-device recent approvals; keys are `ThisDeviceOnly` | Partial | D1 |

### 2.7 §7 MFA challenge and approval

| ID | Spec statement | Current state | Status | WP |
|---|---|---|---|---|
| A1 | Business requests approval for an enrolled connection via authenticated API | `POST /v1/business/approve/requests` (`API/APIRoutes.swift:324`), API key + policy (`ApproveRequestService.swift:31-73`) | Done | none |
| A2 | Unique, short-lived challenge with canonical action details, RP id, expiry, nonce | `request_id` unique per business, `challenge`, `transaction`/`authentication` subject, `request_hash`, lifetime bounds (`ApproveRequestService.swift:125-142`); canonical JSON (SECURITY.md §2.2, §2.54) | Done | none |
| A3 | Pending state stored durably | `approve_requests` + `approve_deliveries` in one transaction (`ApproveRequestService.swift:147-181`) | Done | none |
| A4 | Push is a wake-up hint | Generic push (`ApproveSupport.swift:43-62`), sent inline after commit and best effort | Done | B3 moves it to the durable push queue |
| A5 | Client fetches details directly | `GET /v1/approve/requests/{id}` device-signed (`ApproveRequestService.swift:350`), E2EE envelopes for end-to-end requests | Done | none |
| A6 | Unambiguous transaction context | `ApprovePrompt`, display digest bound into the signature (`txn_digest`) | Done | none |
| A7 | Local user verification by policy | `ApprovalAMR.required(for: sensitivity)`; biometric keys for high/critical (`ApproveRequestService.swift:395-398`) | Done | none |
| A8 | Domain-separated signature | ES256 JWS with `typ`, `alg` pinned, critical headers checked (`ApprovalResult.swift:14-41`) | Done | none |
| A9 | Server verifies key status, connection, signature, nonce, expiry, challenge state and policy | `submit` (`ApproveRequestService.swift:362-425`): delivery/device/key/relationship binding, active key, verified business, signature, challenge/transaction match, expiry, AMR, freeze, cool-down | Done | none |
| A10 | Atomic transition to approved/denied | CAS on `status` (`ApproveRequestService.swift:428-433`) | Done | none |
| A11 | Business receives only a signed/verified result | Signed result JWS fetched by `result_ref`, verified by the business SDK (`ApproveRequestService.swift:247`, BusinessSDK verifier). Legacy interaction path strips the decision signature (`LegacyApproval.swift:5-11`), closed for live traffic unless an operator entitlement | Partial | C2 (sunset legacy path) |
| A12 | Idempotency keys | `request_id` + request hash; concurrent duplicate replays the original (`ApproveRequestService.swift:73-79`, `:182-187`) | Done | none |
| A13 | Replay rejection | Decided requests refuse further results (`replayDetected`), result JWS bound to request and audience | Done | none |
| A14 | Push-fatigue limits | `ApprovalPromptPolicy` (window 1 h, warn at 3, max 6, auto-deny after 3 denials) evaluated under a row lock (`Core/Approve/ApprovePrompt.swift:7-65`, `ApproveRequestService.swift:98-157`) | Done | none |
| A15 | Cancellation | Business cancel (`ApproveRequestService.swift:239`), freeze (`approve_freezes`) | Done | none |
| A16 | Timeout | `expireDue` (`ApproveRequestService.swift:276`) from the job loop (`BackgroundJobs.swift:33`) | Done | B3 (scheduled message + sweep) |
| A17 | Do not promise phishing resistance from push approval; require transaction binding and user-verifiable RP context | Transaction binding and RP display exist; app copy says "Viadere uses a passkey: nothing to remember, nothing to phish" (`OnboardingView.swift:160`); site lint does not ban "phishing-proof/-resistant", "bank-grade", "financial-grade" (`Lint.swift:25-28`) | Partial | B4 (copy), F2 (lint terms) |
| A18 | Consider FIDO2/WebAuthn for standard sign-in and higher assurance | Passkeys used for consumer and dashboard sign-in (`AuthService.swift:92-133`, `Dashboard/DashboardAuth.swift`) | Done | D2 keeps passkeys as an optional credential |

### 2.8 §8 recovery and assurance tiers

| ID | Spec statement | Current state | Status | WP |
|---|---|---|---|---|
| R1 | **D0**: pseudonymous account + device, basic messaging, no real-world identity | Implicit (any enrolled device can message); no tier object | Partial | B5 |
| R2 | **D1**: hardware key + recent local UV + validated app/key integrity where supported; eligible for MFA subject to business policy | Implied by `DecisionAssurance` (`Interaction/Assurance.swift:6-18`) + `attested` + cool-down; not a single evaluated tier; business policy over it exists only as required AMR | Partial | B5 |
| R3 | **D2**: independently verified age/identity via approved providers; minimum claims (`age_over_21`) | Verify: Wallet mdoc and Didit, `VerificationLabel`, `age.minimum` capability, threshold-only disclosure (`Verify/VerificationAssurance.swift`, SECURITY.md §2.60); behind `VERIFY_ENABLED=false` gate | Done (gated) | B5 maps D2 onto Verify results |
| R4 | Recovery prioritizes trusted-device authorization; optional synced passkey or offline recovery code; risk review before high-assurance activation | Recovery codes (10 × 50 bits) issued at sign-up, recovery registers a new passkey after a 72 h hold (`RecoveryService.swift:7-17`); "Lost your devices?" path; re-enrolled device gets the 24 h cool-down then full trust; no risk review; regenerating codes requires a passkey (`RecoveryService.swift:350-370`) | Partial | D2 |
| R5 | High-risk replacement: step-up at the business, configurable delay, notices to existing devices, revoke the lost device, no takeover from one compromised cloud account | 72 h hold + notices + cancel (`RecoveryService.swift:171-206`); all old devices revoked on activation; Approve v2 keys revoked ⇒ business re-enrollment = step-up for v2. A compromised iCloud account yields the synced passkey ⇒ sign-in ⇒ new device enrolls with assertion ⇒ 24 h cool-down then trusted (owner gets notices and can cancel) | Partial | D1/D2 (no time-only elevation to D1; delay configurable per policy) |

### 2.9 §9 target infrastructure (ADR-VDR-001)

| ID | Spec statement | Current state | Status | WP |
|---|---|---|---|---|
| I1 | Replace Fly.io runtime and Neon production DB with Azure-managed services | Fly (`Infra/fly/fly.*.toml`), Neon (`Infra/terraform/neon.tf`) | Gap | B1, B2, F4 |
| I2 | Retain Cloudflare as edge/DNS/WAF; no assertion that Azure satisfies compliance | Cloudflare zone settings, WAF, rate limits, mTLS rules (`Infra/terraform/cloudflare.tf:19-391`) | Done | B1 (origin moves to the tunnel) |
| I3 | Edge: authenticated origin, DDoS controls, avoid edge secrets | Edge token shared secret in a Cloudflare transform rule (`cloudflare.tf:209`, `EdgeLock.swift:25-42`); AOP setting resource present, origin cannot verify (`cloudflare.tf:193-199`, SECURITY.md §2.74 "Not done in code") | Partial | B1 (Cloudflare Tunnel, section 5.4) |
| I4 | API services on Azure Container Apps, ASP.NET Core; separate identity, approval, messaging and business APIs | One Vapor binary serving everything plus the job loop (`App.swift:79-119`, `fly.staging.toml:166-169`) | Partial (language: **deviation by PO-1**) | B2 (api/worker/jobs split with separate identities) |
| I5 | Data: PostgreSQL Flexible Server, private networking, HA, PITR, tested restore | Neon, public endpoint, 1-day PITR on staging (section 1.3) | Gap | B1, ADR-0011 |
| I6 | Async: Service Bus + workers, durable queues, DLQ, idempotency | DB-polled CAS jobs every 5 s in every instance (`BackgroundJobs.swift:5-6`, `:82-127`); idempotent state machines exist; no DLQ | Partial | B3, ADR-0014 |
| I7 | Keys/secrets: Key Vault (Managed HSM if warranted), managed identity, rotation, audit, separation of duties | GCP KMS for audit-head signing only (`AuditExport.swift:62-79`, `Infra/terraform/kms.tf`); every other key is an environment secret (`Infra/fly/secrets.txt`); rotation runbooks with `*_PREVIOUS` (`docs/ops/KEY-ROTATION.md`) | Partial | B2, ADR-0012 |
| I8 | Workload auth: Entra managed identities; no embedded long-lived cloud credentials | GCP via Fly OIDC (no key file) (`AuditExport.swift:35-37`); DB passwords and R2 keys are long-lived secrets | Partial | B1, B2 |
| I9 | Telemetry: Azure Monitor / App Insights; redacted traces, security audit export, alerting | Prometheus endpoint with token (`Operations/Metrics.swift:190`), redacted logs, audit-head export; no traces | Partial | F2 |
| I10 | Build/deploy: GitHub Actions + OIDC, environment approvals, IaC, provenance | Signed images, SBOM, SLSA provenance, protected `production` environment (`release.yml:1-6`, `:150-182`); deploy uses `FLY_API_TOKEN` (long-lived) | Partial | B1 |
| I11 | Separate authorization core and messaging workers: workloads, identities, network policies, queues, schemas where justified | Single workload, single DB role (`viadere_app`) | Gap | B2, B3 |
| I12 | Avoid Kubernetes/AKS initially | Not used | Done | none |
| I13 | Size capacity and topology from measured SLOs | `docs/ops/RESILIENCE.md` targets exist; no measurement on Azure | Gap | F1 |

### 2.10 §10 security boundaries and control baseline

| ID | Spec statement | Current state | Status | WP |
|---|---|---|---|---|
| S1 | TLS 1.3 where feasible; mTLS/strong workload auth for partners; certificate/key rotation; authenticated callbacks | Edge min TLS 1.2 by reviewed exception (CLAUDE.md, `docs/ops/TLS-COMPATIBILITY-POLICY.md`), origin leg TLS 1.3 (`fly.staging.toml:131-136`); Tier E mTLS at Cloudflare API Shield (SECURITY.md §2.74); webhooks HMAC-signed with versioned keys and ownership verification (§2.73) | Partial | B1 (tunnel; environment peer encryption), C2 (mTLS default for Approve/link APIs at Tier V/E) |
| S2 | NIST-aligned algorithms, audited libraries; P-256 ECDSA or Ed25519; no invented primitives | P-256 ECDSA (CryptoKit/swift-crypto), HPKE RFC 9180, HMAC-SHA256, AES-GCM; low-S, canonical JSON | Done | A1 (test vectors) |
| S3 | Private DB connectivity, least-privilege managed identities, per-service authorization, segmentation, egress restriction | Public Neon endpoint with TLS; role split migrator/app (`Migrations/RuntimeRoleGrants.swift:6-38`); webhook SSRF guard pins vetted IPs (`Services/WebhookTransport.swift`); no network egress restriction | Partial | B1, B2 |
| S4 | HSM keys protect server-held secrets/signatures (not device keys); key inventory; emergency revocation | KMS keys provisioned but unused except audit heads (ADR-0003 consequences); `docs/ops/KEY-ROTATION.md` | Partial | B2 (Key Vault provider), F3 |
| S5 | Rate limits, anti-enumeration, anti-bot, integrity signals, anomaly detection, privacy-minimizing abuse controls | DB-backed limiter (SECURITY.md §2.23), uniform 401/404 on lookups, App Attest at enrollment; App Attest **assertions** are implemented but unused (`Services/IdentityGuards.swift:143-160`, only referenced by tests); `assessSensitiveRequest` returns `.unverified` (`DeviceIntegrity.swift:97-100`); `AbuseService` for messaging | Partial | B4 (enrollment bot budget, DeviceCheck), E1 (assertions on sensitive requests) |
| S6 | Append-only audit with integrity, retention, controlled access, alerting, independent export | Hash chain, `REVOKE UPDATE ON audit_events` (`RuntimeRoleGrants.swift:30-31`), signed head export to write-once storage (GCS/R2), retention gate | Done (export target moves) | B2 (Azure immutable Blob sink) |
| S7 | Tenant isolation, scoped service credentials, RBAC, dual control, tested admin recovery | Tenant-scoped queries, scoped API keys, 9 console roles, two-person approval, step-up (SECURITY.md §2.72, §2.75) | Done | F3 (admin-recovery drill on Azure) |
| S8 | Privacy impact review and regulatory counsel (biometrics, age verification, data protection, banking, cross-border) | Legal drafts marked `counsel_review: pending` (HANDOFF) | Gap (owner/counsel) | F2 |

### 2.11 §11 migration phases, §12 acceptance gates, §13 open decisions, §14 milestones

| ID | Spec statement | Current state | Status | WP |
|---|---|---|---|---|
| P0 | Phase 0 inventory and freeze; rollback artifacts; no deletion | Not started | Gap | F4 (checklist in section 4) |
| P1 | Phase 1 Azure foundation | Not started | Gap | B1 |
| P2 | Phase 2 service port (or protocol-compatible services) | Swift service kept (PO-1); Azure adapters needed | Partial | B2, B3 |
| P3 | Phase 3 data transition; rotate exposed/shared secrets | Staging DB empty: schema only; secrets regenerate (`Infra/fly/generate_secrets.py`) | Partial | F4 |
| P4 | Phase 4 dual-environment verification | Suites exist (Server 683 SQLite/PostgreSQL tests per HANDOFF); none against Azure | Gap | F1 |
| P5 | Phase 5 controlled cutover | Not started | Gap | F4 |
| P6 | Phase 6 decommission | Not started | Gap | F4 |
| V1 | Enrollment gate: no mandatory personal fields; invalid/replayed attestations and challenges rejected; no silent trust elevation | Replay/attestation tests exist (`Server/Tests/ViadereServerKitTests/AppAttestTests.swift`); name mandatory; first device exempt from cool-down | Partial | B4, B5 |
| V2 | Business linking gate: QR expires, one-time; swapping, tenant confusion, unauthorized linking rejected | Approve v2 enrollment tests; connect has no session | Partial | C1 |
| V3 | Multi-device gate: iPhone→Mac, iPhone→Android, loss/recovery tested; independent key; no inherited high trust without policy | Independent keys; time-based inheritance; no Mac/Android client | Partial | D1, D2 (Mac/Android device tests: Out of scope now) |
| V4 | MFA gate: replay, double approval, stale challenge, revoked key, spoofed business, notification tampering, races | Covered by Approve v2 tests and gate review (HANDOFF) | Done (re-verify on Azure) | F1 |
| V5 | Infra gate: backup/restore, regional failure, key rotation, least-privilege review, secret scanning, SAST/DAST, external pentest | gitleaks, semgrep, trivy, osv-scanner in CI (`.github/workflows/security.yml`); no DAST, no pentest, no Azure drills | Partial | F1, F3 |
| V6 | Ops gate: SLOs, audit retention, breach response, on-call | `RESILIENCE.md`, `RUNBOOKS.md`, `TABLETOP-EXERCISES.md`; on-call owner not named | Partial | F2 |
| O1–O6 | §13 open decisions | Section 7 | Gap (decisions) | A1 |
| MS | §14: no "financial-grade" claims before independent evaluation | Site lint bans several claims; not "financial-grade"/"bank-grade"/"phishing-proof" | Partial | F2 |

### 2.12 The `es` fragment secret against "never embed reusable enrollment secrets" (L3)

* **What it is.** 256 bits from the business's CSPRNG, one per enrollment (`ApprovalEnrollmentSecret`, `ApprovalEnrollmentBinding.swift:17-35`), carried in the URL fragment so neither Viadere nor a Referer sees it. It keys the device's binding tag over its own statement (`VIADERE-ENROLL-BIND-V1`) and derives the typed-path check code and SAS.
* **Why it is not a reusable secret.** It is bound to one enrollment id, the enrollment is single-use (CAS), expires in ≤ 15 min, and the tag is only meaningful over one statement. Knowing `es` alone enrolls nobody: lookup requires the authenticated consumer the enrollment was created for (`ApproveEnrollmentService.swift:131-137`). It is a one-time key-confirmation value, not a bearer credential, account id or API key. Verdict: **meets** the statement; SECURITY.md §2.53 should say this in those words.
* **Where it becomes risky.** A *link session* (C1) has no pre-existing relationship, so lookup cannot be limited to one consumer: whoever scans the QR can claim the session, and the same person also holds `es`, so the binding tag no longer separates the real customer from a QR thief (session swapping: an attacker photographs or phishes the QR and links *his* Viadere account to the victim's business account). C1 therefore must not rely on `es` for anti-swapping. Required controls: business step-up immediately before showing the QR; QR lifetime ≤ 5 min; the business session shows the device-chosen account pseudonym and a SAS that the person compares or types **in the business's authenticated session** before the business confirms; immediate out-of-band notice through the business's existing channel ("A Viadere app was linked to your account. Not you?") with one-tap revoke; per-business link rate limits; the app warns "Only scan a code you opened yourself on {verified business domain}". Residual: a real-time relay phishing attack (the victim reads the SAS to the attacker) is not fully preventable without proximity; record it in SECURITY.md residual risks and the risk register.

### 2.13 Summary counts

| Status | Count |
|---|---|
| Done | 41 |
| Partial | 50 |
| Gap | 14 |
| Conflicts | 3 (S1.3 mandatory name and passkey, E1 registration fields, E4 account created by passkey registration) |
| Out of scope now | no row on its own: the Android and macOS clients are the excluded part of S1.1, L8, V3 and WP-D1/E1 |
| **Total rows** | **108** ("Done (gated)", "Done (business side)", "Done (documented rationale needed)", "Done (re-verify on Azure)", "Done (export target moves)" count as Done; "Partial (language: deviation by PO-1)" as Partial; "Gap (owner/counsel)", "Gap (decisions)" as Gap) |

The ten most important gaps and conflicts, in order of risk:

1. **E4/S1.3/E1 (Conflicts)**: accounts are created by passkey registration with a mandatory display name; the spec's device-first, no-personal-field enrollment needs WP-B4.
2. **T3/L2/L6/L7/L11 (Partial/Gap)**: a business connection is created by a public code with no business-authenticated session, so the business cannot bind `subject_ref` to its customer and nothing stops session swapping on connect (WP-C1, section 2.12).
3. **T6/R4/R5/M3 (Partial)**: new and recovered devices become trusted when a 24 h cool-down lapses, without trusted-device approval or relying-party reauthorization (WP-B5, D1, D2).
4. **I5/S3 (Gap/Partial)**: the database is a public Neon endpoint with 1-day PITR; the target is private PostgreSQL Flexible Server with HA and tested restore (WP-B1, ADR-0011).
5. **I3 (Partial)**: origin protection rests on one shared header secret and a public origin (WP-B1, section 5.4).
6. **I7/S4 (Partial)**: every service key except the audit-head signer is an environment secret; HSM keys are unused (WP-B2, ADR-0012).
7. **I6/I11 (Partial/Gap)**: jobs are DB-polled in every serving instance with no DLQ and no workload separation (WP-B3, ADR-0014).
8. **T5/A11/T7 (Partial)**: Approve v2 is still behind its release gate and the legacy approval path makes the business trust the relay (WP-C2).
9. **S5 (Partial)**: App Attest assertions exist but are never required on sensitive requests; no anti-farming budget for passkey-less sign-up (WP-B4, C2, E1).
10. **M5/E3/E5 (Gap/Partial)**: Apple-only integrity evidence and push tokens in the Core protocol and schema block Android (WP-A2, E2).

---

## 3. Work packages in dependency order

Size: S ≤ 1 week, M 1–3 weeks, L 3–6 weeks of one engineer. "Tests first" lists the security tests that must exist and fail before the change (CLAUDE.md: every security fix starts with a test reproducing the exploit path). Acceptance criteria cite spec §12.

Recommended order (critical path in bold): **A1 → A2 → B4 → B5** ∥ **B1 → B2 → B3** → C3 → **C1 → C2** → **D1 → D2** → E1 → E2 → E3 → **F1 → F3 → F4** (F2 runs alongside from B1).

### Milestone A: threat model, protocol schema, ADR approval

**WP-A1 Threat model, protocol documents, ADR approval, test vectors (M)**
* Scope: accept ADR-0010…0014; add threat rows to `docs/SECURITY.md` §1 (account farming without passkeys; link-session swapping; recovery-to-MFA escalation; edge bypass to the origin; queue poisoning/replay; managed-identity token theft via SSRF to `IDENTITY_ENDPOINT`); new normative sections §2.5a (device-first account enrollment), §2.53a (business link session), §2.90 (integrity evidence envelope), §2.91 (queue message envelope); §13 decisions recorded (section 7). Cross-language test vectors: `docs/protocol/vectors/*.json` generated by a Core test target for `VIADERE-SIG-V1`, `VIADERE-ENROLL-V1`, `VIADERE-APPATTEST-ENROLL-V1`, `VIADERE-CONFIRM-V1`, `VIADERE-DECISION-V1`, approval statement/result JWS, binding tag/check code/SAS, `subject_ref`, HPKE envelope (spec §11 Phase 2 "preserve versioned API contracts and test vectors", §13 item 5).
* Files: `docs/SECURITY.md`, `docs/ops/adr/*`, `docs/ops/RISK-REGISTER.md`, `Packages/ViadereCore/Tests/…/ProtocolVectorTests.swift` (new).
* Tests first: vector tests that fail if any encoding drifts (they become the contract for an Android client).
* Acceptance: ADRs accepted by the PO; every new wire format has a vector.

**WP-A2 Platform-neutral protocol in Core (M)**
* Scope (additive, decodes old payloads): `IntegrityEvidence` enum `{format: "apple-app-attest" | "android-key-attestation" | "none", …}` wrapping today's `AppAttestEvidence`; `DeviceKeyRegistration.algorithm` (only `ES256` accepted; field optional on decode, default `ES256`); `PushRegistration {provider: apns|fcm, token, environment?, appId}` alongside `APNsTokenRegistration`; `DeviceTrustTier` (`d0`, `d1`, `d2`) and `TrustElevation` reason enum; `DeviceIntegrityVerifier` protocol takes `IntegrityEvidence` (Apple implementation is today's `AppAttestVerifier`, Android verifier is a stub returning `unverified` until the Android work starts).
* Files: `Packages/ViadereCore/Sources/ViadereCore/API/AuthDTOs.swift`, `Models/Device.swift`, new `Security/IntegrityEvidence.swift`, `Policy/TrustTier.swift`; `Server/Sources/ViadereServerKit/Security/DeviceIntegrity.swift`, `AppAttest.swift`.
* Tests first: an `android-key-attestation` evidence must never yield `attested` until a real verifier exists; unknown `format` → enrollment treated as unattested (never as attested); an `algorithm` other than `ES256` → 400.
* Acceptance: §6 "no Apple-only dependency in core account schema or protocol"; existing app payloads still accepted.

### Milestone B: Azure landing zone and identity/device enrollment

**WP-B4 Device-first pseudonymous accounts (L)** (ADR-0013; can start before Azure)
* Protocol (reuses the existing proof formats unchanged):
  1. `POST /v1/accounts/enroll/begin` (no auth; per-IP and global budgets; `SignupGateMiddleware(.signupConsumer)` kill switch) → `{ceremonyId, accountId (reserved, not yet created), challenge, expiresAt, integrity: {required: [apple-app-attest]}}`. Reserving the account id at begin keeps `VIADERE-ENROLL-V1\n{consumerId}\n…` (`AuthDTOs.swift:442-446`) and `VIADERE-APPATTEST-ENROLL-V1\n{consumerId}\n{challenge}\n{keyListDigest}` (`AuthDTOs.swift:231-265`) as they are.
  2. Client creates the Secure Enclave keys, attests them with a fresh App Attest key, and sends `POST /v1/accounts {ceremonyId, challenge, platform, deviceName?, keys, integrity, clientKind}`.
  3. Server: consume the ceremony (CAS), verify every proof, verify integrity under policy, refuse a reused App Attest key, then in one transaction create `consumers` (no name, no handle), `devices` (tier per B5), `device_keys`, `app_attest_keys`, a token family bound to the device, audit `account.created`; return `{accountId, device, session}`.
  4. Push token registered separately afterwards (unchanged route; `PushRegistration` from A2).
* Optional credentials afterwards: "Protect your account" step offers a passkey (`/v1/recovery-credentials/passkeys/begin|finish`, device-signed **and** a user-verified approval-key `ConfirmationProof` with a server nonce) and/or recovery codes (`/v1/recovery/codes` regenerated with a `ConfirmationProof` instead of a passkey assertion, replacing `RecoveryService.swift:350-370`). Both skippable; skipping shows "If you lose this iPhone and have no other device, your account can't be recovered".
* Passkey sign-in (`register`/`login` routes) stays for **existing** passkey accounts and as an account-discovery method on a new device (D1); `register/begin` stops requiring a display name, then is retired once the app ships device-first.
* Server files: new `Services/AccountEnrollmentService.swift`; `Routes/AuthRoutes.swift`; `Services/AuthService.swift` (`enroll` no longer the only device creator; `freshSessionMayEnroll` unchanged for legacy); `Services/RecoveryService.swift`; `Services/HouseholdService.swift:53, :401` and `RecoveryService.swift:145-146` (fallback label when no display name); `Services/AuditService.swift` (`actor_ref`).
* Core: `API/APIRoutes.swift` (`accountEnrollBegin`, `accountCreate`), `API/AuthDTOs.swift` (`AccountEnrollBeginResponse`, `AccountCreateRequest`, `AccountCreateResponse`).
* Kit: `Account/AccountService.swift` new `createAccount(deviceName:)` (begin → `DeviceKeyProvisioner.provision(consumerId: reserved, …)` → `EnrollmentAttester` → create → `store`), `signUp(displayName:)` kept only for the legacy path; `Stores/OnboardingViewModel.swift` new step order `welcome(consent) → device → notifications → protect (optional) → phone (optional) → done`, `canCreateAccount` no longer needs a name, `OnboardingFlow.resume` updated; `Recovery/RecoveryCodesViewModel.swift` reused from the protect step.
* App: `Features/Onboarding/OnboardingView.swift` (remove `AccountStep` name field and "Create passkey" as the primary action; consent copy that explains device registration and what is stored; drop "nothing to phish"); App Clip `ViadereClip/ClipFlowModel.swift:53` uses `createAccount` with a request-key-only device (D0, 7-day expiry as today). `swiftc -parse` on touched files.
* Migration `DeviceFirstAccounts.v1` (additive, forward-only): `consumers.display_name` and `consumers.user_handle` DROP NOT NULL (unique index on `user_handle` becomes partial `WHERE user_handle IS NOT NULL`); `consumers.policy_version INT NOT NULL DEFAULT 1`; `consumers.created_via TEXT NOT NULL DEFAULT 'passkey'`; new `account_enroll_ceremonies (id, reserved_account_id UNIQUE, challenge_hash, state, expires_at, created_at)`; `devices.key_algorithm TEXT NOT NULL DEFAULT 'ES256'`, `devices.trust_tier TEXT NOT NULL DEFAULT 'd0'`, `devices.integrity_format TEXT NULL`, `devices.elevated_at`, `devices.elevated_by TEXT NULL`; `app_attest_keys.format TEXT NOT NULL DEFAULT 'apple-app-attest'`; `passkey_credentials.status TEXT NOT NULL DEFAULT 'active'`; `audit_events.actor_ref TEXT NULL`, `audit_events.policy_version INT NULL` with audit chain version 3 covering both (older rows verify under their own `chain_version`). Backfill rule for existing rows: `trust_tier = 'd1'` where the device is an app device, not revoked, not cooling down, `attestation_status = 'attested'` and has an approval key; otherwise `d0`.
* Existing data: staging has **0 accounts** (section 1.3), so no user migration is needed; legacy passkey accounts created later in development keep working (sign-in path retained). Development databases migrate with the same additive migration.
* Tests first: replayed begin challenge → 401; two concurrent creates on one ceremony → exactly one account; App Attest attestation over another challenge, account id or key list → rejected in `require`; App Attest key already used by another account → refused; `report` mode unattested → account created at **D0** with no approval keys honoured for high/critical; a request carrying any name/email/phone field is not stored; begin endpoint returns nothing about existing accounts (anti-enumeration); global budget exhausted → 429; `signupConsumer` switch → 503; creating more than N accounts from one App Attest environment+IP bucket per hour → 429.
* Acceptance (§12 Enrollment): no mandatory personal fields; invalid/replayed attestations and challenges rejected; registration cannot silently elevate trust (first device is D1 only with a verified attestation and a UV approval key).

**WP-B5 Trust tiers D0/D1/D2 and policy (M)**
* Scope: `DeviceTrustTier` evaluated server-side from facts (hardware approval key present, attestation verified, not cooling down, not elevated-pending, recovery state); D2 = D1 + a live Verify result for the claim requested (no new identity data, only the existing `verification_results`). `DeviceTrust.isTrusted` (`Services/DeviceTrust.swift:10-12`) becomes "tier ≥ D1"; Approve v2 `complete` and `submit` require D1 (`ApproveEnrollmentService.swift:153`, `ApproveRequestService.swift:418-424`); legacy decisions require D1 for high/critical. **Time-based elevation removed** for devices created by recovery and for devices of accounts that have another D1 device (they need trusted-device approval, WP-D1, or business re-enrollment), kept only as an explicit, audited policy for a single-device account replacing itself (owner decision O-7, section 8).
* Files: Core `Policy/TrustTier.swift`; Server `Services/DeviceTrust.swift`, `AuthService.swift:293-308`, `Services/IdentityGuards.swift` (`IdentityMaintenance` replacement finalization), `Approve/*`.
* Tests first: a device whose cool-down lapsed without confirmation cannot approve a high-risk request when the account has another D1 device; a recovered account's first device is D0 and cannot complete an Approve v2 enrollment for `transaction.approve` until the business re-enrolls it after the hold; tier is never read from client input.
* Acceptance: §8 tiers and §12 Multi-device "does not inherit high-trust approval without policy authorization".

**WP-B1 Azure landing zone in OpenTofu (L)** (section 5)
* Scope: `Infra/azure/` (new root module) with `azurerm ~> 5.11` (5.12.0 is on registry.terraform.io; the OpenTofu registry serves 5.11.0 on 2026-10-29: bump when mirrored, as was done for `google`), OpenTofu `>= 1.13.2`; state in an Azure Storage backend with Entra auth, versioning and a resource lock. Resources and identities per section 5; Cloudflare Tunnel and DNS in `Infra/terraform/cloudflare.tf` (`cloudflare_zero_trust_tunnel_cloudflared`, CNAME to `<tunnel-id>.cfargotunnel.com`). GitHub OIDC: federated identity credentials on `id-gh-deploy-staging` and `id-gh-deploy-production` (subject `repo:<owner>/viadere:environment:staging|production`), `id-gh-infra-plan` (Reader) and `id-gh-infra-apply` (environment-gated).
* CI: `release.yml` deploy jobs use `az login --federated-token "$(curl … ACTIONS_ID_TOKEN_REQUEST_URL …)"` (Azure CLI is Python and preinstalled; `azure/login` is a third-party JavaScript action and is not allowed by CLAUDE.md rule 4 and the exceptions table); `az acr import`/`docker push` by digest, `az containerapp job start` (migrations) then `az containerapp update --image …@sha256:…`. `install-tools.sh` gains `tofu` 1.13.2 (checksum-pinned); `flyctl` removed at decommission.
* Tests first: `tofu validate` + a policy check script (Python) that fails on any public network access on PostgreSQL/Key Vault/Storage, any role assignment at subscription scope for a workload identity, any `local_auth_enabled = true` on Service Bus, any Key Vault without purge protection.
* Acceptance: §9 table (except runtime language), §10 S3, §12 Infrastructure "least-privilege review".

**WP-B2 Server portability to Azure (L)** (ADR-0010/0011/0012)
* Scope:
  * `AzureIdentity` token source (`IDENTITY_ENDPOINT`, `X-IDENTITY-HEADER`, `client_id`), cached until 5 min before `expires_on`, outbound only to the local endpoint (SSRF guard: the generic outbound client and webhook transport must refuse the identity endpoint host).
  * `KeyManagementService` protocol (the one ADR-0003 promised): `sign(keyRef, digest) -> ES256 raw r‖s` and `wrap/unwrap(keyRef, RSA-OAEP-256)`; implementations `AzureKeyVaultKMS` (REST data plane, pinned api-version) and `LocalKMS` (dev/tests). Used by `AuditHeadExporter` (replaces `GoogleAuth`/`KMSHeadSigner`, `AuditExport.swift:33-79`), the key-directory log STH signer (replaces `KEY_DIRECTORY_LOG_KEY`), and the Wallet key unwrapper (HANDOFF open item). Boot-time unwrap of envelope-wrapped `DATA_ENCRYPTION_KEY`, `SERVER_PEPPER`, `AUDIT_CHAIN_KEY`, `SUBJECT_REF_KEY`, `CONNECT_LINK_SIGNING_KEY` (section 5.6).
  * `AzureBlobHeadSink` (immutable container, `If-None-Match: *`, managed identity) replacing `GCSHeadSink`/`R2HeadSink` (`AuditExport.swift:100-156`).
  * PostgreSQL Entra auth: a `DatabaseConfigurationFactory` whose connection source fetches an Entra token for each **new** connection (PostgresNIO takes only a static password, section 1.3); existing pooled connections stay valid after the token expires because the token is checked at authentication; until this ships, staging may use a password for `viadere_app` held in Key Vault (time-boxed exception, section 5.6). `verify-full` against the Azure PostgreSQL root CA bundle shipped in the image.
  * Process roles: `ROLE=api|worker` env (api: HTTP only, `RUN_BACKGROUND_JOBS=false`; worker: queue consumers); `ViadereServer maintenance <task>` commands for scheduled jobs; `migrate` unchanged, run by a Container Apps Job.
  * Config: `FLY_PRIVATE_IP` (`OperationsConfig.swift:101-104`) replaced by `METRICS_BIND_HOST`; `healthPeerNetworks` (`OperationsConfig.swift:32`) configurable via `HEALTH_PEER_NETWORKS` (the Container Apps infrastructure subnet), Fly's `fdaa::/16` default removed; `fly-client-ip` stays in the proxy-header list; `TRUSTED_PROXY_COUNT` re-measured (client → Cloudflare → cloudflared → Envoy → app); `GCP_*`, `AUDIT_HEAD_EXPORT_ACCESS_KEY_*` removed; `Infra/fly/check_env_coverage.py` → `Infra/azure/check_env_coverage.py` (Python).
  * `GrantRuntimeRolePrivileges` (`Migrations/RuntimeRoleGrants.swift:10-38`) grants to Entra principal roles (`viadere_app`, `viadere_worker` created by `pgaadauth_create_principal` in the bootstrap runbook) and a narrower worker grant set.
* Tests first: a request whose URL resolves to the identity endpoint is refused by every outbound client; audit-head export refuses to overwrite (sink returns conflict); KMS signature verifies against the published public key and a wrong key version fails; the runtime role check (`DatabaseRoles.runtimeCanChangeSchema`) passes for `viadere_app` and fails for the migrator principal; a health request from outside `HEALTH_PEER_NETWORKS` without the edge token gets 421.
* Acceptance: §9 Keys/secrets, Workload auth; §10 S3, S4.

**WP-B3 Service Bus job queues (L)** (ADR-0014, section 5.7)
* Scope: `QueueTransport` protocol with `ServiceBusRESTTransport` (send with `BrokerProperties.MessageId`, peek-lock receive, complete, unlock, `ScheduledEnqueueTimeUtc`) and `DatabaseQueueTransport` (today's CAS semantics; dev/tests/fallback). Transactional outbox `outbox_messages (id, queue, payload_json, not_before, published_at, attempts)` written in the business transaction; publisher loop in the worker sends with `MessageId = outbox.id` (duplicate detection window 10 min) and marks published. Consumers idempotent: `processed_messages (message_id PK, queue, processed_at)` inserted in the same transaction as the effect; the existing CAS state machines stay the source of truth. Messages carry ids only (no PII). Queues and DLQ policy in section 5.7. Maintenance sweeps move to Container Apps scheduled jobs.
* Files: new `Server/Sources/ViadereServerKit/Queue/*`; `Jobs/BackgroundJobs.swift` split into per-task handlers; `Services/WebhookService.swift`, `SMS/*`, `Channels/ChannelRouter.swift`, `Approve/ApproveSupport.swift`, `Services/SecurityNotices.swift`, `Wallet/*`, `Operations/OperatorNotices.swift`, `Operations/ConsumerExport.swift` enqueue via the outbox; migration `QueueOutbox.v1`.
* Tests first: a message delivered twice performs its effect once; a message whose effect transaction rolled back is not marked processed; a poison message reaches the DLQ after `maxDeliveryCount` and raises an alert metric; an outbox row is never published before its transaction commits; a message with unknown `type`/`v` is dead-lettered, not executed.
* Acceptance: §9 Async jobs (durable, DLQ, idempotency).

### Milestone C: business linking and signed approval

**WP-C3 Configurable link domain (S)** (HANDOFF open item; prerequisite for C1 testing on staging)
* `ViadereCore.domain` becomes injectable (server config `LINK_DOMAIN`, app build setting); strict link parsers accept only the configured host. AASA and (for later Android) `/.well-known/assetlinks.json` served from the RP origin.
* Tests first: a link with a different host is rejected by every parser.

**WP-C1 Business link sessions (L)** (spec §5; section 2.12)
* Protocol: `POST /v1/business/link-sessions {customer_ref (business-held opaque value, hashed at rest), capabilities: [message.send, auth.challenge, transaction.approve…], display_hint (non-sensitive, e.g. masked account), expires_in_seconds ≤ 300}` → `{session_id, qr_url: https://{domain}/k/{session_ref}#es=…, check_code}` (SDK builds the URL as for Approve v2). Device: `POST /v1/link-sessions/lookup` → **signed** `LinkSessionDescriptor` (business id, verified display name, domain, capabilities, expiry, display hint) signed by the Viadere KMS key `link-descriptor` (EC-HSM P-256) and cross-checked against the business directory; user confirms; device signs `VIADERE-LINK-V1` statement (session id, business id, capabilities, new pairwise approval key if approval capabilities requested, HPKE key, binding tag); server CAS-consumes the session, creates or reactivates the relationship (pairwise `subject_ref`), stores `link_session_id` + `evidence_digest` on it, creates the pending approve key; business fetches the result (`GET …/link-sessions/{id}`, webhook `link.completed` in the opaque v2 envelope, payload JWS signed by `link-descriptor`), verifies binding tag/SAS, shows pseudonym + SAS in its authenticated session for comparison, confirms (`POST …/confirm`, signed by its directory confirmation key), then sends the out-of-band notice. Relationship becomes `active` only after business confirmation; unconfirmed sessions expire and are reported.
* Data: migration `LinkSessions.v1` (`link_sessions`, `relationships.link_session_id`, `relationships.evidence_digest`).
* Files: Core `Approve/` → new `Link/` (descriptor, statement, verifier), BusinessSDK `LinkSession*.swift`, Server `Link/*`, Kit `Link/*`, App `Features/Connect/*`.
* Tests first: second consume → 409; expired session → 410; session of business A confirmed with business B's key → refused (tenant confusion); a device of another account claiming a session whose business already confirmed → refused; relay-substituted statement fails the binding tag; descriptor signature from a non-published key rejected on device; confirm without the SAS comparison flag (SDK) refuses; link rate limit per business and per customer_ref.
* Acceptance (§12 Business linking): QR expires and is one-time; session swapping, tenant confusion and unauthorized linking rejected.

**WP-C2 Approval hardening (M)**
* Scope: `approve_requests.attempts` + lock after 5 invalid submissions; per-business device policy (`approve.device_policy`: `any_enrolled` default, `single_device`), recorded per key and decision (spec §13 item 2); business API accepts `subject_ref` (and `connection_id` alias) only, `relationshipId` deprecated with a sunset date; App Attest **assertions** required on `approve/requests/{id}/result` and link completion for attested devices (wire `AppAttestAssertions`, `IdentityGuards.swift:143-160`), `report` then `require`; legacy interaction approval sunset date enforced (`LegacyApproval.swift`); Approve v2 Phase 2 gate evidence collected so `APPROVE_V2_ENABLED` can open.
* Tests first: sixth invalid submission on one request → locked; replayed App Attest assertion counter → 401; a business using `relationshipId` after sunset → 400; legacy entitlement past sunset → 403.
* Acceptance: §12 MFA (re-run on Azure in F1).

### Milestone D: multi-device enrollment and recovery

**WP-D1 Trusted-device pairing and device lifecycle (L)**
* Scope: new device creates its keys and requests enrollment through (a) **QR pairing**: the trusted device shows `https://{domain}/p/{pairing_ref}#k={ephemeral X25519/P-256 public key}`; the new device posts its key registrations + integrity; the trusted device receives a pairing request (push wake-up + fetch), shows name, platform, approximate region (from the edge country header, edge-locked requests only) and the permissions requested, and signs `VIADERE-PAIR-V1` over a **server nonce**, the account id, the new device id and key digests, with a UV approval key; server activates the new device at D1; or (b) passkey sign-in discovery (existing) → new device at D0 until a trusted device approves it or a business re-enrolls it. `ConfirmationProof` gains a server nonce (v2 domain `VIADERE-CONFIRM-V2`). Device lifecycle UI: per-device recent approvals (from `approve_requests.decided_kid` → key → device), "Rotate keys" (re-enroll in place with a pairing proof from the same device), revoke.
* Files: Core `API/AuthDTOs.swift`, `Security/` (pairing); Server `Services/AuthService.swift`, new `Services/DevicePairingService.swift`; Kit `Account/*`, `Stores/SecuritySettingsViewModel.swift`; App `Features/Settings/SettingsView.swift`, new pairing screens; migration `DevicePairing.v1` (`device_pairings`).
* Tests first: pairing proof replayed → 401; proof over another account's nonce → refused; pairing approved by a D0 device → refused; new device never D1 without an approval, an RP enrollment or an audited policy.
* Acceptance (§12 Multi-device): iPhone→iPhone and loss/recovery tested on devices; iPhone→Mac and iPhone→Android **out of scope now** (no clients), the protocol tests run with a software key store and Android-format evidence stub.

**WP-D2 Recovery redesign (M)**
* Scope: recovery credentials optional; recovery by code no longer requires registering a new passkey: after the 72 h hold it enrolls the recovering device (device key + integrity) at **D0**, revokes everything else (unchanged), sends notices; high-risk MFA only after trusted-device pairing (impossible after loss) or business re-enrollment (Approve v2 / link session); messaging allowed immediately after the hold (decision O1). Passkey recovery path kept (synced passkey ⇒ sign-in ⇒ D0 device). When `backupEligible == false` on the only passkey (iCloud Keychain off), the app prompts for recovery codes. Configurable hold (policy, default 72 h, minimum 24 h).
* Files: `Services/RecoveryService.swift`, Core `API/RecoveryDTOs.swift`, Kit `Recovery/*`, App `Features/Recovery/AccountRecoveryView.swift`.
* Tests first: recovered account cannot approve high-risk even after any amount of time without RP re-enrollment; recovery cancel from a D1 device still kills the codes; recovery cannot start while a hold is active (existing test kept).
* Acceptance: §8 recovery, §12 Multi-device loss/recovery.

### Milestone E: native integrity adapters and console

**WP-E1 Integrity adapters (M)**: Apple: flip `APP_ATTEST_MODE=require` in staging once the shipping build attests (`fly.staging.toml:84` → Container Apps env), assertions on sensitive requests (C2), DeviceCheck two-bit per-device account-creation budget (privacy-preserving anti-farming). Android: server verifier design (key attestation chain to Google roots with revocation list, Play Integrity verdict decode server-side, nonce = SHA-256 of the same binding as App Attest) documented and stubbed; implemented when the Android app starts (**Out of scope now** for the app itself). Tests first: unsigned or wrong-nonce Android evidence never `attested`.

**WP-E2 Push abstraction (M)**: `PushProvider` protocol (`APNsSender` becomes one implementation, `Push/APNsSender.swift:99`), `push_tokens (provider, token, environment, app_id, device_id)` replacing `apns_tokens` (migration with dual-read; staging has no rows), FCM HTTP v1 sender designed, not built. Tests first: a token registered for provider A is never sent through provider B; invalid-token feedback disables only that token.

**WP-E3 Console (M)**: link sessions and connection evidence in the business console, device policy setting, operator view of trust tiers and recovery holds, Tier E mTLS guidance updated for the tunnel.

### Milestone F: load, security and operational readiness

**WP-F1 Dual-environment verification (M)**: run Core/Kit/SDK/Server suites against Azure PostgreSQL 18.6 (`TEST_DATABASE_URL` from a Container Apps Job inside the VNet), contract tests against the staging Azure API, crypto vectors, negative paths, concurrency (CAS races), load (k6 is Go: allowed; or a Swift load tool), PITR restore drill, zone/region failure exercise, Service Bus DLQ drill. Compare with Fly staging.

**WP-F2 Observability and operations (M)**: OpenTelemetry from Vapor (swift-otel, current stable, OTLP) to the Container Apps managed OTel agent → Application Insights; log redaction verified; alerts (5xx, latency, queue lag, DLQ depth, KMS unexpected use, edge-lock 421 spikes, PostgreSQL failover); SLOs and on-call owner; privacy impact review and counsel engagement (§10 S8); site lint adds "phishing-proof", "phishing-resistant", "bank-grade", "financial-grade".

**WP-F3 Security assurance (M)**: least-privilege review of every role assignment, key rotation drill (Key Vault versions + `*_PREVIOUS` overlap), secret scanning, SAST (semgrep), DAST (OWASP ZAP is Java: allowed, container image), external penetration test before sensitive production onboarding.

**WP-F4 Migration execution (Phases 0, 3, 5, 6) (M)**: section 4.

---

## 4. Migration phases 0–6 for this repository

### Phase 0: inventory and freeze (checklist)

Nothing is deleted in this phase. Record each item in `docs/ops/AZURE-MIGRATION-LOG.md` (created in F4) with date and owner.

- [ ] Fly app **`viadere-server-staging`**: region `iad`, `shared-cpu-1x`/512 MB, one machine, `release_command = "migrate --yes --env production"`, `[env]` as in `Infra/fly/fly.staging.toml:23-115`. Export `fly releases -a viadere-server-staging`, `fly machines list`, current image digest. Production app `viadere-server` (`fly.production.toml`): confirm whether it was ever created.
- [ ] Fly secrets: `fly secrets list -a viadere-server-staging` (names and digests only, never values) checked against `Infra/fly/secrets.txt`; note which optional groups are set (MailerSend SMS, APNs, Didit, RCS, pass certificates, R2).
- [ ] Neon project **`viadere`** (`cold-scene-35948882`, AWS us-east-1, PostgreSQL 18): branch **`production`** (`br-broad-lake-b7l6l8ii`, default), database **`viadere`**, roles **`viadere_migrator`** (owner) and **`viadere_app`** (DML). 21 Fluent migrations applied; 0 rows in the account, device, business, relationship and audit tables (2026-10-29). PITR history retention is **1 day** (ADR-0002 says 7: either fix now or accept for the transitional period). Note: `docs/ops/STAGING-SETUP.md` §4 names a project `viadere-staging` and branch `main`; the real names above win. Take a `pg_dump --schema-only` and a Neon snapshot as rollback artifacts.
- [ ] Cloudflare zone **`cksites.dev`**: hosts **`viadere.cksites.dev`** (RP/web origin, dashboard, AASA) and **`viadere-api.cksites.dev`** (API), both proxied to Fly; edge-token transform rule, WAF and rate-limit rules, TLS settings. Export the rulesets (API or `cf-terraforming`, a Go tool) because staging was configured by hand (`STAGING-SETUP.md` §3), not from `Infra/terraform/cloudflare.tf`.
- [ ] MailerSend: email via `https://api.mailersend.com/v1/email`, sender `no-reply@viadere.cksites.dev` (domain verification records in the zone); SMS provider `mailersend` with **placeholder** number `+15555550100` (`fly.staging.toml:96`); secrets `EMAIL_API_KEY`, `MAILERSEND_SMS_API_TOKEN`, `MAILERSEND_SMS_INBOUND_SECRET`, `MAILERSEND_SMS_WEBHOOK_SECRET`; inbound/status webhook URLs registered at MailerSend point at the Fly host and must move at cutover.
- [ ] Apple: team `M669H43X63`, APNs key id `NH9V2KR4LK` (`APNS_KEY_P8` secret), App Attest `report`/`development`, APNs `sandbox`, bundle `com.viadere.app`; AASA served from `viadere.cksites.dev`.
- [ ] Google Cloud: whether `Infra/terraform/kms.tf` and `audit_bucket.tf` were ever applied (staging has `AUDIT_HEAD_KMS_KEY` and `AUDIT_HEAD_EXPORT` empty); list projects, key rings (cannot be deleted, only disabled), service accounts, workload identity pools.
- [ ] GitHub: environments `staging`/`production`, secret `FLY_API_TOKEN` per environment, GHCR images and their cosign signatures/attestations, branch protections.
- [ ] OpenTofu state for Cloudflare/GCP/Neon (`Infra/terraform/backend.tf`): location and lock.
- [ ] Staging users and business integrations: none in the database; list TestFlight/Xcode installs pointed at staging and any test business API keys or webhooks issued outside the database (none expected).
- [ ] Jobs: the in-process loop (`BackgroundJobs.swift:20-79`); no external schedulers.
- [ ] Freeze: no new Fly/Neon/GCP resources; changes to Fly config only for fixes.

### Phase 1: Azure foundation (WP-B1)
Owner creates the tenant/subscription (section 8); `tofu apply` of `Infra/azure` for **staging** only; Entra groups and break-glass accounts; GitHub federated credentials; Cloudflare Tunnel created but no DNS change yet (a test hostname `viadere-api-az.cksites.dev`).

### Phase 2: service adaptation (WP-B2, B3; no port per PO-1)
Swift adapters for managed identity, Key Vault, Blob, Entra PostgreSQL auth and Service Bus; image unchanged otherwise; contract and vector tests prove protocol compatibility.

### Phase 3: data transition
Staging DB is empty: run migrations on Azure PostgreSQL through the migrator job; no data copy. Regenerate every secret (`Infra/fly/generate_secrets.py` successor writes to Key Vault, never to stdout in CI); KEKs and signing keys created in Key Vault; nothing is reused from Fly or Neon (spec "rotate exposed/shared secrets"). Validate: table list equals Neon's, constraints and grants match (`RuntimeRoleGrants`), row counts zero, retention settings seeded.

### Phase 4: dual-environment verification (WP-F1)
Fly staging and Azure staging side by side; the app's Staging build can be pointed at either base URL; run the suites listed in F1; record results in the migration log.

### Phase 5: controlled cutover
Cloudflare: switch `viadere-api.cksites.dev` and `viadere.cksites.dev` from the Fly origin to the tunnel (tunnel public hostnames), one host at a time (the proxied DNS record becomes the tunnel's CNAME; the change is effective at the edge immediately); watch 5xx, latency, queue lag; MailerSend webhooks and APNs unaffected by host change except the inbound SMS/status webhook URLs (same hostname, no change needed if the host name is kept). Rollback window 7 days: Fly app kept running with its own (empty) database; rollback = repoint the hostname. No write freeze needed while staging has no users.

### Phase 6: decommission
Delete Fly apps and `FLY_API_TOKEN` secrets; delete Neon project after exporting the schema dump; disable GCP key versions and delete the service account and workload identity pool (key rings remain by GCP design); remove `Infra/fly/`, `Infra/terraform/neon.tf`, `kms.tf`, `audit_bucket.tf` (GCS) and the `google`/`neon` providers; remove `GCP_*`, `FLY_*`, R2 variables from code and docs; update CLAUDE.md "Current versions" (Azure PostgreSQL, azurerm, OpenTofu) and ADR statuses; record the deletion evidence; verify no orphaned DNS records or tunnel connectors.

---

## 5. Azure target design

### 5.1 Resource list (staging; production differences in the last column)

| Resource | Name (staging) | SKU / tier | Production |
|---|---|---|---|
| Subscription | `viadere-staging` (separate from production) | Pay-as-you-go | `viadere-production` |
| Resource groups | `rg-viadere-stg-net`, `rg-viadere-stg-app`, `rg-viadere-stg-data`, `rg-viadere-stg-sec`, `rg-viadere-stg-ops` | n/a | same split; resource locks on data and sec |
| Region | `eastus` (next to today's `iad` / `us-east-1`) | n/a | `eastus`, availability zones (decision O4) |
| VNet | `vnet-viadere-stg` 10.40.0.0/16 | n/a | 10.50.0.0/16 |
| Container Apps environment | `cae-viadere-stg` | Workload-profile environment, **Consumption** profile, VNet-integrated, **internal** ingress only, peer-to-peer encryption on | zone redundant |
| Container app `ca-viadere-api` | HTTP API, dashboard, operator console | 0.5 vCPU / 1 GiB, min 1 max 3 | min 2 (zones), max 10 |
| Container app `ca-viadere-worker` | Queue consumers, outbox publisher | 0.25 vCPU / 0.5 GiB, min 1 | min 2 |
| Container app `ca-cloudflared` | Cloudflare Tunnel connector (Go binary image `cloudflare/cloudflared`, digest-pinned) | 0.25 vCPU / 0.5 GiB, min 1 | min 2 |
| Container Apps Jobs | `job-viadere-migrate` (manual), `job-viadere-maintenance` (cron `*/5 * * * *`), `job-viadere-hourly` (cron), `job-viadere-audit-export` (cron every 6 h) | Consumption | same |
| PostgreSQL | `psql-viadere-stg` | Flexible Server **PostgreSQL 18** (18.6), Burstable **B1ms**, 32 GiB, private access (delegated subnet), Entra + password (B2 exception), PITR 7 days, no HA (Burstable has none) | General Purpose **D2ds_v5**, zone-redundant HA, 128 GiB, PITR 35 days, Entra-only, geo-redundant backup per O4 |
| Service Bus | `sb-viadere-stg` | **Standard**, `local_auth_enabled = false` (Entra only), IP firewall: NAT gateway egress IP only, minimum TLS 1.2 | **Premium 1 MU**, private endpoint, public access disabled |
| Key Vault | `kv-viadere-stg` | **Premium**, RBAC, purge protection, soft delete 90 days, private endpoint, public access disabled | same (separate vault) |
| Storage | `stviaderestgaudit` | StorageV2 LRS, container `audit-heads` with **version-level immutability (WORM)** policy, shared keys disabled, private endpoint | ZRS/GRS per O4, policy locked |
| Container registry | `crviaderestg` | **Basic**, Entra auth, admin user off (no private endpoint on Basic; pulls by managed identity) | Premium with private endpoint (or keep Standard) |
| Monitoring | `log-viadere-stg` + `appi-viadere-stg` | Log Analytics (Analytics logs) + workspace-based Application Insights, 30-day retention, daily cap | 90 days + archive |
| NAT gateway | `ng-viadere-stg` + static public IP | Standard | same |
| Private DNS zones | `privatelink.vaultcore.azure.net`, `privatelink.blob.core.windows.net`, `viadere-stg.private.postgres.database.azure.com` (+ `privatelink.servicebus.windows.net` in production) | n/a | same |
| User-assigned identities | section 5.3 | n/a | separate per environment |
| Cloudflare | Tunnel `viadere-stg`, DNS CNAMEs | Free (tunnel) on the existing plan | same |

### 5.2 Network layout

| Subnet | CIDR | Purpose / rules |
|---|---|---|
| `snet-cae` | 10.40.0.0/23 | Delegated to `Microsoft.App/environments` (workload profiles need ≥ /27; /23 leaves room). NAT gateway attached (all egress via one static IP). NSG: no inbound from Internet; outbound 443 to Internet (APNs `api.push.apple.com`, MailerSend, Didit, Cloudflare API), 7844 TCP/UDP to Cloudflare (tunnel), 5432 to `snet-pg`, 443 to `snet-pe`, `AzureActiveDirectory` service tag. |
| `snet-pg` | 10.40.2.0/28 | Delegated to `Microsoft.DBforPostgreSQL/flexibleServers`; inbound 5432 only from `snet-cae`; outbound `AzureActiveDirectory` (Entra admin operations). |
| `snet-pe` | 10.40.3.0/27 | Private endpoints: Key Vault, Blob (audit), Service Bus (production), ACR (production). Inbound only from `snet-cae`. |
| `snet-ops` | 10.40.4.0/27 | Reserved for a jump host or Azure Bastion if ever needed (none by default; admin access to PostgreSQL through a Container Apps Job, not a VM). |

Egress control: the server already pins vetted IPs for webhooks (`WebhookTransport.swift`, SSRF); an application-level allowlist for provider hosts is added in B2. Azure Firewall Basic (FQDN filtering) is an owner cost decision for production (~USD 288/month, section 5.8).

### 5.3 Identities and least-privilege role assignments

| Identity | Used by | Role assignments (scope) | Database role |
|---|---|---|---|
| `id-viadere-api` (user-assigned, lifecycle `Main`) | `ca-viadere-api` | Key Vault Crypto User on keys `kek-data`, `kd-log-signing`, `link-descriptor` (key scope, not vault); Key Vault Secrets User on the secrets it needs (secret scope); Azure Service Bus Data Sender (namespace, or per queue in production) | `viadere_app` (DML, no DDL, no UPDATE on `audit_events`) |
| `id-viadere-worker` | `ca-viadere-worker`, maintenance jobs | Key Vault Crypto User on `kek-data`, `audit-head-signing`; Secrets User on provider secrets (MailerSend, APNs, Twilio, Didit, RCS, pass certificate); Service Bus Data Receiver + Sender; Storage Blob Data Contributor on container `audit-heads` only (immutability prevents overwrite/delete) | `viadere_worker` (DML on the tables its handlers touch; created in B2) |
| `id-viadere-migrator` | `job-viadere-migrate` only | none outside PostgreSQL | `viadere_migrator` (schema owner) |
| `id-viadere-acrpull` (lifecycle `None`) | image pulls for all apps and jobs | AcrPull on the registry | none |
| `id-cloudflared` (lifecycle `None`) | Container Apps secret reference for the tunnel token | Key Vault Secrets User on `cloudflared-tunnel-token` | none |
| `id-gh-deploy-staging` (federated: `environment:staging`) | release workflow | Container Apps Contributor on `rg-viadere-stg-app`; AcrPush on the registry; no data-plane roles | none |
| `id-gh-deploy-production` (federated: `environment:production`, required reviewers) | release workflow | same, production scopes | none |
| `id-gh-infra-plan` / `id-gh-infra-apply` | OpenTofu | Reader (plan); Contributor + Role Based Access Control Administrator **with a condition** limiting assignable roles to the list above (apply, environment-gated) | none |
| Humans | Entra groups | `grp-viadere-kv-crypto-officers` (Key Vault Crypto Officer: create/rotate keys; nobody in it runs workloads), `grp-viadere-db-admins` (PostgreSQL Entra admin; not used by apps), `grp-viadere-readers`; two break-glass accounts with alerts on sign-in | admin via Entra group |

Separation of duties: workloads can use keys (sign/unwrap) but never create, export, delete or change policy; key administration needs a crypto-officer human; deployment identities hold no data-plane rights; Key Vault diagnostic logs alert on any key operation by an unexpected principal (replaces the GCP log metrics in `kms.tf:155-184`).

### 5.4 How Cloudflare authenticates to the origin

| Option | Bypass resistance | Fit with Container Apps | Secrets / ops | Verdict |
|---|---|---|---|---|
| A. Keep `EDGE_TOKEN` header (today) | Shared secret; anyone who learns it and finds the public origin FQDN can bypass the WAF; the origin is public | Works (public ingress) | Secret in a Cloudflare rule and in the app; rotation with `EDGE_TOKEN_PREVIOUS` | Keep **as a second layer only** |
| B. Container Apps IP restrictions to Cloudflare IPv4 ranges | Blocks direct Internet traffic, but any Cloudflare customer can route through Cloudflare to our origin; IPv4 only; list must follow Cloudflare's published ranges | Supported (allow rules) | No secret; list maintenance | Not sufficient alone |
| C. Authenticated Origin Pulls (mTLS) | With a **per-zone custom** certificate the origin can tell our zone from others | Container Apps forwards the client certificate in `X-Forwarded-Client-Cert` without validating its issuer (section 1.3), so the app would have to validate issuer and pin our CA itself; ingress stays public | Custom CA and cert rotation | Workable, more code in the trust path |
| D. **Cloudflare Tunnel** (`cloudflared` in the environment, ingress **internal only**) | No public origin at all: the app is reachable only from inside the VNet; Cloudflare connects via outbound tunnel connections | `cloudflared` runs as a Container App (min 1/2 replicas), routes to the internal FQDN with `httpHostHeader` set | Tunnel token in Key Vault; connector is a Go binary (no Node); free | **Recommended** |

Recommendation: **D + A**. Internal-only ingress removes origin bypass and origin DDoS; `EDGE_TOKEN` stays enforced so a misrouted internal caller or a compromised neighbouring app in the environment still cannot impersonate the edge and inject `CF-*` or client-certificate headers (the lock gates trust in those headers, SECURITY.md §2.74). Tier E mTLS stays at Cloudflare API Shield (edge), unchanged. Fallback while the tunnel is being proven: B + A on a public ingress. Health probes come from the platform inside `snet-cae` without proxy headers and are exempted by `HEALTH_PEER_NETWORKS` (B2).

### 5.5 Container Apps ingress and custom domains
With the tunnel there is no Container Apps custom domain or managed certificate: Cloudflare terminates the public TLS (TLS 1.3 preferred, reviewed 1.2 policy unchanged), `cloudflared` reaches `ca-viadere-api.internal.<env-domain>` over the environment network with peer-to-peer encryption enabled. `PUBLIC_BASE_URL`, `RP_ID`, `RP_ORIGIN` keep the Cloudflare host names. Multiple-revision mode: a new revision receives traffic only after `/readyz` passes, previous revision kept for rollback.

### 5.6 Secrets inventory: Fly secret → Azure

| Current (Fly secret, `Infra/fly/secrets.txt`) | Azure target | Notes |
|---|---|---|
| `DATABASE_URL` | **Removed**: host/db/user are plain config; Entra token for `id-viadere-api` | Time-boxed exception until the token connection source ships (B2): KV secret `db-app-password`, staging only |
| `DATABASE_MIGRATION_URL` | **Removed**: migrator job uses `id-viadere-migrator` | Serving apps never hold migrator rights (closes HANDOFF item "separate Fly release app") |
| `CONNECT_LINK_SIGNING_KEY` (+ `_PREVIOUS`) | KV secret `connect-link-key`, stored **wrapped** by `kek-data` (RSA-HSM 3072, RSA-OAEP-256), unwrapped at boot | Versions replace `_PREVIOUS` |
| `SERVER_PEPPER` (+ `_PREVIOUS`) | KV secret `server-pepper`, wrapped by `kek-data` | |
| `DATA_ENCRYPTION_KEY` (+ `_PREVIOUS`) | KV secret `data-encryption-key`, wrapped by `kek-data` | Field-cipher key ids unchanged |
| `AUDIT_CHAIN_KEY` (+ `_PREVIOUS`) | KV secret `audit-chain-key`, wrapped by `kek-data` | Independent of the HSM head signature |
| `SUBJECT_REF_KEY` | KV secret `subject-ref-key`, wrapped by `kek-data` | Never rotated without a remap plan (pairwise ids) |
| `KEY_DIRECTORY_LOG_KEY` | **Replaced** by KV key `kd-log-signing` (EC-HSM P-256, sign only) | Non-exportable; public key published |
| `EMAIL_API_KEY` | KV secret `mailersend-api-token` | |
| `APNS_KEY_P8` | KV secret `apns-p8` | Later option: import as EC-HSM key and sign the provider JWT in Key Vault |
| `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_NUMBER`, `TWILIO_MESSAGING_SERVICE_SID` | KV secrets (only if Twilio is used; else not created) | SID and number are not secret: plain config |
| `MAILERSEND_SMS_API_TOKEN`, `MAILERSEND_SMS_INBOUND_SECRET`, `MAILERSEND_SMS_WEBHOOK_SECRET` | KV secrets | Number stays plain config (placeholder until issued) |
| `WALLET_ENCRYPTION_KEY_WRAPPED` | Re-wrapped under `kek-data`; KV secret `wallet-encryption-key-wrapped` | Implements the missing KMS unwrapper (HANDOFF) |
| `DIDIT_API_KEY`, `DIDIT_WEBHOOK_SECRET`, `DIDIT_WEBHOOK_SECRET_PREVIOUS` | KV secrets (versions) | Only when Verify is enabled |
| `RCS_PROVIDER_TOKEN`, `RCS_WEBHOOK_SECRET` | KV secrets (optional group) | |
| `PASS_CERTIFICATE_PEM`, `PASS_PRIVATE_KEY_PEM`, `PASS_WWDR_CERTIFICATE_PEM` | KV **certificate** `wallet-pass-type` (private key non-exportable later) + WWDR as plain config | CMS signing via Key Vault is a later option |
| `EMAIL_API_AUTH_HEADER`, `EMAIL_API_AUTH_SCHEME` | Plain configuration | Not secret |
| `AUDIT_CHAIN_LEGACY_THROUGH_SEQ` | **Removed** | Fresh database |
| `EDGE_TOKEN`, `EDGE_TOKEN_PREVIOUS` | KV secret `edge-token` (versions); also set in the Cloudflare rule by OpenTofu (sensitive variable) | Second layer behind the tunnel |
| `METRICS_TOKEN` | **Removed** with OTLP push (F2); KV secret only if a scrape endpoint is kept | |
| `DATA_ENCRYPTION_KEYS_PREVIOUS`, `SERVER_PEPPERS_PREVIOUS`, `AUDIT_CHAIN_KEYS_PREVIOUS`, `CONNECT_LINK_SIGNING_KEYS_PREVIOUS` | **Removed**: Key Vault secret versions (enabled previous versions listed at boot) | Rotation runbook updated |
| `AUDIT_HEAD_EXPORT_ACCESS_KEY_ID`, `AUDIT_HEAD_EXPORT_SECRET_ACCESS_KEY` (R2) | **Removed**: Blob via `id-viadere-worker` | |
| (env) `GCP_WORKLOAD_IDENTITY_AUDIENCE`, `GCP_SERVICE_ACCOUNT_EMAIL`, `GCP_SUBJECT_TOKEN_FILE`, `AUDIT_HEAD_KMS_KEY` | **Removed**; `AUDIT_HEAD_KMS_KEY` becomes a Key Vault key reference `audit-head-signing` | |
| (GitHub) `FLY_API_TOKEN` | **Removed**: OIDC federation | |
| (new) | KV secret `cloudflared-tunnel-token` | |

Keys created in Key Vault: `audit-head-signing` (EC-HSM P-256), `kd-log-signing` (EC-HSM P-256), `link-descriptor` (EC-HSM P-256, C1), `kek-data` (RSA-HSM 3072). AES `oct-HSM` keys are not used while they are preview in Premium vaults (CLAUDE.md rule 3); revisit at GA.

### 5.7 Job runner → Service Bus mapping (ADR-0014)

| Today (`BackgroundJobs.runOnce`, line) | Target | Idempotency key | DLQ / retry |
|---|---|---|---|
| `InteractionService.expireDue` (24) | Scheduled message `interaction.expire` at `expires_at` + `job-viadere-maintenance` sweep | interaction id (CAS on status) | maxDelivery 10 |
| `OutboundSMS.sendDue` (25) | Queue `sms-outbound` via outbox | `sms_outbound.id`, provider idempotency | maxDelivery 8, scheduled backoff; DLQ alert |
| `ChannelRouter.deliverDue` (26) | Queue `channel-outbound` | `channel_outbound.id` | same |
| `WebhookService.deliverDue` (27) | Queue `webhook-delivery`, retries as scheduled messages with the existing backoff | `webhook_deliveries.id` + attempt | DLQ ⇒ endpoint auto-pause + business notice (existing pause logic) |
| `RewardsService.releaseExpired` (29) | Maintenance sweep | CAS | n/a |
| `WalletService.deliverDue` (30) | Queue `wallet-push` | `wallet_push_outbox.id` | maxDelivery 8 |
| `HouseholdService.recordExpired` (31) | Maintenance sweep | CAS | n/a |
| `ApproveRequestService.expireDue` (33) | Scheduled message `approve.expire` + sweep | request id (CAS) | maxDelivery 10 |
| `IdentityMaintenance.run` (34) | Scheduled messages at `hold_until` / replacement due + sweep | recovery/device id (CAS) | maxDelivery 10, alert |
| `VerifyService.runMaintenance` (36) | Hourly job | CAS | n/a |
| `SubjectResolver.backfill` (38) | **Removed** (fresh DB; all rows get `subject_ref` at creation) | n/a | n/a |
| `AbuseService.sweep`, dashboard/email/wallet purges, limiter purge (40-50) | Maintenance job (5 min) | n/a | n/a |
| `RetentionService.purge` (51-53) | Maintenance job; refuses to purge audit rows not anchored by an export (unchanged) | n/a | n/a |
| `APIKeyLifecycle.sweep` (61) | Hourly job | CAS | n/a |
| `OperatorNotices.deliverDue` (62) | Queue `operator-notices` | notice id | maxDelivery 8 |
| `ConsumerExports.processQueued` (63) | Queue `consumer-export` | export id | maxDelivery 3, DLQ alert |
| `OnboardingAssurance.run`, `PendingChanges.expireDue` (64-67) | Hourly job | CAS | n/a |
| `AuditHeadExporter.runIfDue` (68-70) | `job-viadere-audit-export` every `AUDIT_HEAD_EXPORT_INTERVAL_HOURS` | head seq (create-only blob name) | job failure alert |
| `DatabaseReplayGuard.purge`, stale passkey ceremonies (71-76) | Maintenance job | n/a | n/a |
| Inline pushes: `ApproveNotifier.pushRequest` (`ApproveRequestService.swift:193`), `SecurityNotices.notifyOtherDevices` | Queue `push` (outbox in the same transaction; publisher wakes immediately after commit) | delivery id / notice id | maxDelivery 5, short TTL (2 min for approval wake-ups) |

Message envelope (SECURITY.md §2.91, A1): `{"v":1,"type":"sms.send","id":"<outbox uuid>","ref":"<row id>","not_before":"…"}`; no PII, no secrets; consumers re-read state from PostgreSQL. Lock duration 60 s with renewal for long tasks; queue TTL per type; duplicate detection on (10 min window). Alerts: active message age > 2 min, DLQ depth > 0.

Swift has no Azure Service Bus SDK, so the transport uses the documented REST API with Entra bearer tokens (section 1.3); AMQP is not needed at this volume.

### 5.8 Rough monthly cost at staging scale (USD, `eastus`, 730 h)

Prices from the Azure Retail Prices API on 2026-10-29 (meter effective dates in brackets); Container Apps from the billing page above. Excludes tax, Cloudflare (existing plan), Apple and MailerSend.

| Item | Basis | Staging (lean) | Production (indicative) |
|---|---|---|---|
| Container Apps (api 0.5/1, worker 0.25/0.5, cloudflared 0.25/0.5, always on; jobs) | Active vCPU USD 0.000024/s, idle 0.000003/s, memory 0.000003/GiB-s (2022-06-01), minus 180k vCPU-s and 360k GiB-s free | ~25–75 | ~150–250 (min 2 each) |
| PostgreSQL | B1ms USD 0.017/h (2021-12-01) = 12.41; storage 32 GiB × 0.115 (2021-06-01) = 3.68; backup within free allowance | ~16 | D2ds_v5 USD 0.178/h (2023-03-01) × 2 (HA) = 259.88; 128 GiB = 14.72; backup ~10 → ~285 |
| (Option) staging with HA | D2ds_v5 × 2 | +~245 | n/a |
| Service Bus | Standard base USD 10/month (2018-05-01), first 13 M operations included | ~10 | Premium 1 MU USD 0.9275/h (2018-05-01) = ~677 |
| Key Vault Premium | EC-HSM and RSA-3072-HSM keys USD 5/key/month (first tier, 2017-07-01) × 4 = 20; operations USD 0.03 and advanced USD 0.15 per 10k | ~22 | ~25 |
| Managed HSM (not chosen) | Standard B1 USD 3.20/h (2021-08-01) | (≈ 2,336) | (≈ 2,336 per HSM pool) |
| NAT gateway + static IP | USD 0.045/h (32.85) + 0.045/GB; IP USD 0.005/h (3.65) | ~37 | ~40 |
| Private endpoints | Key Vault, Blob (2 in staging; +Service Bus, ACR in production); Private Link page shows no figure in text: assume ≈ USD 7.30 each (0.01/h) and confirm in the calculator | ~15 | ~30 |
| Private DNS zones | USD 0.50/zone (2019-12-01) | ~2 | ~2 |
| Log Analytics / App Insights | USD 2.30/GB ingested after the free allowance (2018-02-01); assume 2–5 GB | ~0–12 | ~25–60 (10–25 GB) |
| Container Registry | Basic USD 0.1666/day = 5.07 (2018-01-01) | ~5 | Standard 0.6666/day = ~20; Premium 1.6666/day = ~51 |
| Storage (audit heads) | Hot LRS USD 0.0208/GB | <1 | <1 |
| Azure Firewall Basic (optional) | USD 0.395/h = 288 + 0.065/GB | not used | ~290 if chosen |
| **Total** | | **≈ 140–200** (≈ 385–445 with HA PostgreSQL) | **≈ 1,250–1,450** without Azure Firewall, **≈ 1,550–1,750** with it |

The largest production line is Service Bus Premium (private endpoint requirement). A cheaper production variant (Standard + Entra-only + IP firewall to the NAT IP) saves ~USD 665/month at the cost of a public Service Bus endpoint: owner decision O-9.

### 5.8a Lean testing profile (the default until launch; owner decision 2026-10-29: about $30/month)

The product owner capped testing infrastructure at roughly $30/month. The testing environment therefore uses the **lean profile** below; the
staging/production profile in 5.1 and 5.8 stays defined in the OpenTofu modules (`profile = "lean" | "standard"`) and is applied only when the
owner approves the spend. The server code is identical in both profiles: every difference is a SKU or a network setting, never a code path.

| Piece | Lean profile | ≈ USD/month (Retail Prices API, `eastus`, 2026-10-29) |
|---|---|---|
| PostgreSQL Flexible Server | Burstable **B1ms** ($0.017/h), 32 GiB, PostgreSQL 18, VNet integration (no private endpoint needed), 7-day PITR, **no HA** | ≈ $16 (free for 12 months on a new Azure account) |
| Container Apps | **Consumption-only** environment with VNet; `api` app 0.25 vCPU / 0.5 GiB, min 1 replica (min 0 accepted for testing); `migrate` as a Container Apps Job | ≈ $3–8 (idle $3e-6/vCPU-s and /GiB-s after the monthly free grant) |
| Service Bus | **Basic** (queues + dead-letter queues; no topics, sessions or duplicate detection, which the transactional outbox and idempotency keys already cover); local SAS auth disabled, Entra RBAC only | ≈ $0.05 per million operations |
| Key Vault | **Standard** (software-protected keys, same REST API and key types as Premium); RBAC, purge protection, no private endpoint | < $1 (operations only) |
| Monitoring | Log Analytics + Application Insights within the 5 GB/month free ingestion; daily cap set | $0 |
| Images | GitHub Container Registry (pull credential in Key Vault) instead of Azure Container Registry | $0 |
| Edge | Cloudflare Tunnel (free) to the internal-only ingress, plus `EDGE_TOKEN` | $0 |
| **Total** | | **≈ $20–26** |

Exceptions this creates (recorded in CLAUDE.md's exceptions table when the lean environment is deployed; remove when the standard profile is applied):
- Service Bus and Key Vault are reached over **authenticated public endpoints** (Entra tokens only, local auth disabled), not private endpoints.
  Private endpoints (~$7.30/month each) and Service Bus Premium (~$677/month, the only tier with private networking) come with the standard profile.
- Server keys are **software-protected** (Key Vault Standard), not HSM-backed. ADR-0012 (Key Vault Premium) applies to the standard profile.
- PostgreSQL has **no HA standby** and 7-day PITR (standard: zone-redundant HA, 35 days, geo-redundant backup).
- No data in the lean environment is production data: real customers are onboarded only on the standard profile.

### 5.9 How migrations run
`job-viadere-migrate` (manual trigger, parallelism 1, timeout 10 min) runs the same image digest as the release with `migrate --yes --env production` under `id-viadere-migrator`. The release workflow: update the job image → start → poll the execution until `Succeeded` → only then update `ca-viadere-api`/`ca-viadere-worker` to the new digest (new revisions). Migrations stay forward-only and expand/contract, so the previous revision keeps working during rollout and rollback. The serving apps never receive migrator credentials; `DatabaseRoles.mustVerifyRuntimeRole` (`RuntimeRoleGrants.swift:51-55`) keeps refusing to serve with DDL rights.

---

## 6. Versions and policy upkeep

* OpenTofu **1.13.2**; `azurerm` **5.12.0** upstream / **5.11.0** on the OpenTofu registry (pin `~> 5.11` until the mirror catches up, then raise the floor; record in CLAUDE.md). `azapi` 2.13.0 only if a Container Apps property (for example `clientCertificateMode` or peer-to-peer encryption) is missing from `azurerm`.
* PostgreSQL **18.6** on Azure equals CLAUDE.md's required 18.6; the minor is now platform-managed: add a CLAUDE.md note that Azure applies minors in its monthly maintenance and CI keeps testing the community `postgres:18` image.
* Key Vault data-plane and Service Bus REST api-versions: pin the newest GA version listed in Microsoft's versions pages at implementation time and add them to the "Current versions" table (partners on current API versions, rule 2).
* New exceptions rows for CLAUDE.md when ADR-0010 is accepted: none for language (Swift is the policy); "Key Vault oct-HSM (AES) not used while preview"; "Staging PostgreSQL password for `viadere_app` until the Entra token connection source ships" (remove when B2 lands).

---

## 7. §13 open decisions: recommended defaults

| # | Decision | Recommended default | Who decides |
|---|---|---|---|
| O1 | Can a recovered account immediately restore low-risk messaging? | Yes, **after** the 72 h hold completes (never during it): the account is D0, messaging and reading history allowed; high-risk MFA denied until trusted-device pairing or business re-enrollment (Approve v2 / link session). | Product owner, with security review |
| O2 | Can multiple devices approve the same business connection? | Yes by default (`any_enrolled`, up to 8 keys per connection as today, `ApproveSettings.swift:23`), first valid decision wins (CAS), every device key independently audited; per-business policy `single_device`; quorum not planned. | Product owner (default), each business (policy) |
| O3 | Portable recovery credential and iCloud Keychain disabled | Optional synced passkey (iCloud Keychain / Google Password Manager) plus optional offline recovery codes; when the passkey is not backup-eligible (`passkey_credentials.backup_eligible`) the app prompts for codes; no CloudKit hints at launch. | Product owner (UX), security |
| O4 | Residency, topology, recovery objectives | US-only launch in `eastus` with availability zones; PostgreSQL zone-redundant HA, PITR 35 days, geo-redundant backup to the paired region; initial targets RPO ≤ 5 min, RTO ≤ 4 h, revisited when EU customers appear. | Product owner + counsel |
| O5 | Exact cryptographic encoding and signing profile | Keep the normative formats in SECURITY.md §2 (canonical JSON, ES256 P-256 raw r‖s low-S, domain-separated strings, HPKE suite of §2.50), publish them as versioned protocol documents with the cross-language vectors from A1; Ed25519 not adopted (Secure Enclave and Android StrongBox key attestation favour P-256). | Engineering/security; PO informed |
| O6 | Cloudflare Workers for non-sensitive edge routing | No Workers in the API path; the static site keeps Workers Static Assets (ADR-0004); no authoritative approval decision at the edge. | Engineering; PO informed |

Additional decisions raised by this plan (section 8): O-7 time-based device elevation, O-8 production Azure Firewall, O-9 Service Bus tier for production, O-10 HA for staging PostgreSQL.

---

## 8. Items that need the product owner

1. **Azure tenant and subscriptions**: a dedicated Microsoft Entra tenant (or the company tenant), subscriptions `viadere-staging` and `viadere-production`, billing owner, budget alerts. Region confirmation (`eastus`).
2. **Budget approval**: staging ≈ USD 140–200/month (≈ 385–445 with HA PostgreSQL, O-10); production ≈ USD 1,250–1,450/month (+ ≈ 290 with Azure Firewall, O-8). Service Bus Premium (≈ 677/month) vs Standard for production (O-9). Managed HSM explicitly not bought (≈ 2,336/month).
3. **Accept ADR-0010…0014**, including the recorded deviation from the spec's ASP.NET Core runtime.
4. **People and access**: Entra groups (crypto officers, DB admins, readers), two break-glass accounts, GitHub `production` environment reviewers (two, not the release author).
5. **Cloudflare**: approve Cloudflare Tunnel on the account; continued use of `cksites.dev` for staging; registration of `viadere.com` for production.
6. **Policy decisions**: §13 O1–O6 (section 7); **O-7** whether a single-device account's replacement device may become D1 by time alone (recommended: only with notices and a 72 h delay, never for recovered accounts); hold length for recovery.
7. **Counsel and privacy**: privacy impact review (§10 S8): pseudonymous accounts, device signals, DeviceCheck, push tokens, audit pseudonyms; Verify per market.
8. **External assurance**: penetration-test vendor and timing (before sensitive production onboarding, §12); no "financial-grade" marketing claims until then (§14).
9. **Apple**: when the shipping build attests, approve `APP_ATTEST_MODE=require` for staging; DeviceCheck enablement.
10. **Providers**: real MailerSend SMS number (placeholder today), Twilio kept or dropped.
11. **Decommission sign-off**: deletion of Fly apps, Neon project, GCP resources after the rollback window.
12. **Android**: timeline for the Kotlin app (not planned now; the platform-neutral groundwork is in A2, E1, E2).
