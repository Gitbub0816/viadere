# Viadere current state (Stage 0 discovery)

| | |
|---|---|
| Spec | `docs/product/AUTH-DELIVERY-SPEC-v2.md` §16 (discovery), §25 (deliverables) |
| Owner decisions | `docs/product/AUTH-OWNER-DECISIONS.md`, decisions 1-12 (binding) |
| Inspected | branch `claude/inspiring-cannon-t5hxfw` at `a4b1e31`, source and IaC only |
| Date | 2026-11-02 |
| Author | A0 (principal architect), reconciling discovery reports A4, A5, A6, A8, A14 |
| Status | Draft for Stage 0 review. Nothing here was run: no build, no test suite, no live Azure, GitHub, Cloudflare or device check. |

## How to read this document

- "Verified" means A0 opened the cited file and confirmed the claim. "Carried (agent)" means the claim comes from a discovery report, was not re-opened, and is plausible from the evidence that report cites. "Unverified" means it cannot be proved from the repository (live settings, devices, production values). Section 12 lists every unverified item.
- The spec names services (Delivery API, MFA Authority, Grant Authority, Token Issuer, OIDC provider) that do **not** exist in this repository. Where this document says "none", a search of `Server/Sources`, `Packages/*/Sources`, `Infra/azure` and `App` found nothing.
- Staging is Azure (centralus, lean profile, OpenTofu in `Infra/azure`) behind a Cloudflare Tunnel (operator statement, consistent with `Infra/azure/containerapps.tf` and `docs/ops/AZURE-SETUP.md`). Fly, GCP KMS and Neon are legacy and are retired by decision 11. They are described only where the repository still wires them.
- An Android "Verify with Viadere" Kotlin package is being built on a separate, unmerged branch. "No Android code on main" is correct and is not a gap in this document's accuracy.

## 1. Services, entrypoints and external dependencies

| Item | Detail | Source |
|---|---|---|
| Language and framework | Swift 6, Vapor 4 (single codebase). Roles `api`, `worker`, `migrate` selected by `ROLE`. The worker has no ingress. | `Server/Sources/ViadereServerKit/App.swift`, `Server/Sources/ViadereServer/main.swift` |
| Shared contract | `ViadereCore`: identifiers, interaction protocol, assurance policy, signing formats, route catalog (`APIRoutes.swift`), DTOs. Linux + Apple. | `Packages/ViadereCore/Sources/ViadereCore/` |
| Business SDK | Swift, depends only on `ViadereCore`. Not published as a versioned release. | `Packages/ViadereBusinessSDK/` |
| iOS app logic | Linux-testable logic plus Apple-only security code. | `Packages/ViadereKit/`, `App/` |
| Process topology in staging | `ca-viadere-api` (ingress internal, `external_enabled = false`, plain HTTP inside the environment), `ca-cloudflared` (tunnel connector, no ingress), `job-viadere-migrate` (manual). `ca-viadere-worker` and scheduled jobs exist in IaC but are off by default (`enable_worker`, `enable_scheduled_jobs`); the api runs the background job loop in-process. | `Infra/azure/containerapps.tf` (verified: `external_enabled = false`, `allow_insecure_connections = true`) |
| Public edge | Internet, Cloudflare (TLS 1.2+, WAF, header rule), Cloudflare Tunnel, `ca-cloudflared`, `ca-viadere-api`. Origin lock = shared `X-Viadere-Edge-Token` header checked by `EdgeLockMiddleware`. No workload-to-workload authentication exists. | `Infra/azure/containerapps.tf`, `Server/Sources/ViadereServerKit/Security/MTLS.swift`, `Operations/EdgeLock.swift`, `docs/SECURITY.md` (G-10, G-11) |
| Queue | Transactional outbox + `processed_messages` idempotency; Azure Service Bus (REST) or a DB queue. Queues: push, sms-outbound, channel-outbound, webhook-delivery, wallet-push, operator-notices, consumer-export, expiry, loop-delivery, loop-timeout. Envelope carries ids only (<= 1 KiB). There is no message type for authentication delivery. | `Server/Sources/ViadereServerKit/Queue/*`, `Azure/ServiceBusRESTTransport.swift` |
| Push | APNs through APNSwift. FCM tokens are refused at registration (`422`); no FCM sender exists. | `Push/APNsSender.swift`, `Push/APNSwiftSender.swift`, `Routes/AuthRoutes.swift` |
| Email | HTTP provider (generic / MailerSend shape). Used for dashboard codes and invitations. | `Email/EmailSender.swift` |
| SMS / RCS | Twilio and MailerSend SMS adapters; RCS provider seam. Used for the messaging gateway, phone-link OTP, secure-handoff and account-link URLs. | `SMS/*`, `Channels/*`, `Services/PhoneLinkService.swift` |
| Domain verification | DNS TXT (DNS-over-HTTPS) or `/.well-known/viadere-verification.txt`. Onboarding only; not connected to any authentication destination policy. | `Platform/DomainControl.swift` |
| Wallet / Verify | PassKit signing; age and identity verification (Didit, mdoc). `VERIFY_ENABLED` off everywhere. Verification results returned to the business are not signed. | `Wallet/*`, `Verify/*` |
| Other egress | Azure data plane (managed identity, Key Vault keys API `2025-07-01`, Blob `2026-10-06`, Service Bus), Microsoft Entra (PostgreSQL tokens), App Insights, MailerSend, APNs, Didit, Apple Wallet. | `Server/Sources/ViadereServerKit/Azure/*`, `CLAUDE.md` versions table |
| Site and browser code | Static developer portal generated from `docs/openapi.yaml`; Connect button custom element; inline passkey ceremony script pinned by CSP hash. | `Site/`, `Server/Public/connect-button/v1/`, `Server/Sources/ViadereServerKit/Dashboard/DashboardUI.swift` |
| Feature gates | `APPROVE_V2_ENABLED` is `"false"` in the staging variable example and defaults off in staging and production (routes answer 404). `VERIFY_ENABLED` and `VAULT_SYNC_ENABLED` default off. Legacy `authenticate`/`authorize` interactions are closed to live traffic unless an operator grants a legacy entitlement (sunset 2027-06-30; carried from A14). | `Infra/azure/terraform.tfvars.example:30`, `Server/Sources/ViadereServerKit/Config/ServerConfig.swift:161` |

## 2. Data stores

| Store | Detail | Source |
|---|---|---|
| PostgreSQL 18 Flexible Server `psql-viadere-stg…` | System of record. Entra tokens only (no passwords expected), TLS 1.3 server side, roles `viadere_migrator` (owner), `viadere_app`, `viadere_worker` (DML only). Lean: B1ms, no HA, 7-day PITR, LRS. 148 distinct `static let schema` tables (carried from A4, count not re-run). No Postgres row-level security: tenant isolation is application-level per-query filtering (search for `ROW LEVEL SECURITY` / `CREATE POLICY` found nothing). | `Infra/azure/postgres.tf`, `Server/Sources/ViadereServerKit/Core/TokenAuthPostgres.swift`, `Migrations/RuntimeRoleGrants.swift` |
| Key Vault `kv-vdr-stg…` | Standard SKU (lean), RBAC, purge protection, firewall to `snet-cae` + `AzureServices` bypass + admin IPs. Public endpoint (CLAUDE.md exception). | `Infra/azure/keyvault.tf`, `CLAUDE.md` |
| Service Bus (Basic) | Local auth off, Entra only. Doorbell only; source of truth is the database. Public endpoint (exception). | `Infra/azure/servicebus.tf` |
| Brand-asset storage | Content-addressed re-encoded PNG; shared keys off; firewall to `snet-cae`. | `Infra/azure/storage.tf` |
| Audit-head WORM storage | **Not created in lean.** `AUDIT_HEAD_EXPORT` empty, so no external tamper evidence in staging. | `Infra/azure/storage.tf` (standard only) |
| Log Analytics / App Insights | `allLogs`, Key Vault audit, PostgreSQL logs, Service Bus logs; 30-day retention, 0.15 GB/day cap in lean; IP masking on. No alert rules defined in IaC. | `Infra/azure/monitoring.tf` |
| OpenTofu state | Azure storage, Entra auth, public endpoint (exception). | `Infra/azure/versions.tf` |
| Legacy (to retire, decision 11) | Neon (`Infra/terraform/neon.tf`), GCP Cloud KMS and audit bucket (`Infra/terraform/kms.tf`, `audit_bucket.tf`), Fly apps (`Infra/fly/`). `Infra/terraform` state holds Neon passwords and the Cloudflare edge token if applied. | `Infra/terraform/*`, `Infra/fly/*` |

## 3. Identities and keys

### 3.1 Azure workload identities (verified against `Infra/azure/locals.tf`, `identity.tf`)

| Identity | Key Vault keys (Crypto User) | Secrets | Notes |
|---|---|---|---|
| `id-viadere-api` | `kek-data`, `kd-log-signing`, `link-descriptor`, `loop-publication`, `brand-manifest` (`locals.tf` `key_grants`, verified) | all api secrets (edge token, link HMAC key, pepper, data key, audit chain key, subject-ref key, mail/SMS/APNs credentials, brand selection key) | The public-facing process can sign with four keys and read every service secret. |
| `id-viadere-worker` | `kek-data`, `audit-head-signing` | same set as api | Not deployed in staging by default. |
| `id-viadere-migrator` | none | none in Entra mode | Database owner role. |
| `id-viadere-cloudflared` | none | tunnel token only | |
| `id-gh-deploy-<env>` (GitHub OIDC) | none | none | Container Apps Contributor on the app resource group and Managed Identity Operator on all four workload identities (`identity.tf` lines 45-57, verified). Federated subject `repo:<repo>:environment:<env>`, no branch or workflow claim (`identity.tf:40`, verified). Reviewers and branch rules of the GitHub environment are not in the repository. |
| `id-gh-infra-plan-stg`, `id-gh-infra-apply-stg` | none | none | Created outside OpenTofu (AZURE-SETUP section 4). Apply identity: subscription Contributor, lock role, RBAC Administrator with a condition (carried from A5). |

No grant, MFA, signer or recovery identity exists.

### 3.2 Signing and wrapping keys

| Key | Purpose | Held by | Protection | Source |
|---|---|---|---|---|
| `kd-log-signing` | key-directory transparency log heads | api | EC P-256, software (lean), non-exportable attribute | `locals.tf`, `docs/ops/KEY-ROTATION.md` |
| `link-descriptor` | business link-session descriptors (app trust anchor pinned in the build) | api | same | `locals.tf` |
| `loop-publication` | Loop publication manifests | api | same | `locals.tf` |
| `brand-manifest` | Brand Kit manifests | api | same | `locals.tf` |
| `audit-head-signing` | exported audit heads (export off in lean) | worker | same | `locals.tf` |
| `kek-data` | wraps `*_WRAPPED` secrets (`kms1:` format) | api and worker | RSA 3072 software | `Security/KMS/WrappedSecrets.swift` |
| `CONNECT_LINK_SIGNING_KEY` | HMAC for connect links | api, worker (secret) | symmetric secret | `Infra/azure/containerapps.tf` env map |

Lean keys are software-protected (CLAUDE.md exception, removal when the `standard` profile applies). HSM-backed keys exist only in the `standard` profile definition.

### 3.3 Device and consumer keys

- Device keys are Secure Enclave P-256 (`request`, `approvalUserPresence`, `approvalBiometric`); the server stores public keys only (`Packages/ViadereCore/Sources/ViadereCore/Security/DeviceKeys.swift`, `Packages/ViadereKit/Sources/ViadereKit/Keys/SecureEnclaveKeyStore.swift`). Approval keys are pairwise per enrollment (ADR-0006).
- Wire formats (normative in `docs/SECURITY.md`): `VIADERE-SIG-V1` request signing, `VIADERE-DECISION-V1` / v2 decisions with a context digest, `VIADERE-ENROLL-V1`, `VIADERE-LINK-V1`, `ApprovalResultJWS` (ES256, `typ=viadere-approval+jws`).

## 4. Authentication and account model

| Topic | Current behavior | Source |
|---|---|---|
| Consumer account | Device-first, pseudonymous: begin + create with proof of possession of every key, one transaction creates account, device, keys, App Attest key and a device-bound session. No name, email or phone required. Legacy passkey-first sign-up still exists. | `Services/AccountEnrollmentService.swift`, `Services/AuthService.swift`, ADR-0013 |
| Sessions | Opaque bearer tokens, SHA-256 at rest: access `vda_` 15 min, refresh `vdr_` 30 days, rotation with 60 s grace, reuse revokes the family and devices enrolled through it. Device-bound refresh requires a `VIADERE-SIG-V1` signature. | `Security/Tokens.swift`, `Services/AuthService.swift`, `Services/IdentityGuards.swift` |
| Device trust | D0/D1 tiers. D1 required for high-risk approvals and to approve another device. 24 h cool-down for a device added to an account that already has an app device; 72 h when unattested in report mode. Max 10 devices. App Attest mode defaults `off` in code; the deployed value is unverified. | `Services/DeviceTrust.swift`, `Services/AuthService.swift`, `Config/ServerConfig.swift:151` |
| Multi-device linking | Enrollment needs a fresh passkey assertion or a single-use fresh session; "set up again" needs a passkey; a replacement device is pending until a D1 device confirms or the cool-down ends. Business link sessions (`/k/`): single-use, <= 5 min, descriptor signed by `link-descriptor`, with a short authentication string. | `Services/AuthService.swift`, `Link/*` |
| Loss and recovery | Optional recovery credentials (passkey + 10 recovery codes) added only from a user-verified device. Recovery: spend a code, 72 h hold, every device told with "Not you? Cancel", activation revokes all devices and sessions. An account without recovery credentials is lost with its only device. This is **already shipped**, although the spec lists account recovery as optional future work. | `Services/RecoveryService.swift`, `Services/RecoveryCredentialService.swift` |
| Consumer passkeys | WebAuthn through a pinned `webauthn-swift` revision (CLAUDE.md exception); user verification required; separate verifier and realm for the dashboard. | `Services/PasskeyVerifier.swift`, `Dashboard/DashboardAuth.swift` |
| Dashboard sign-in | Passkey; email 6-digit code at sign-up (HMAC with pepper, 15 min, 5 attempts). No TOTP for operators. | `Dashboard/EmailVerification.swift`, `Dashboard/DashboardRoutes.swift` |
| Phone linking (SMS) | A 6-digit OTP is sent by SMS (10 min TTL, hashed, budgets) and SMS account-link URLs `/l/{token}` (15 min) and secure-handoff URLs `/h/{token}` (10 min) are minted. Conflicts with decisions 1 and 9. | `Services/PhoneLinkService.swift:76-93` (verified), `SMS/GatewayService.swift:203-213` (verified) |

## 5. Interaction and approval protocol

- Interaction kinds include authenticate, authorize, confirm, choose, approve, reply, deny, report, acknowledge (`Packages/ViadereCore/.../Interaction/InteractionEnums.swift`). `POST /v1/interactions` issues them; authenticate/authorize lifetimes are capped at 5 min.
- Assurance policy (pure, in Core): `channelReply(0)`, `deviceSignature(1)`, `userVerified(2)`, `deviceBoundBiometric(3)`; text channels (SMS, RCS, Apple Messages) can never satisfy authenticate/authorize (`Interaction/Assurance.swift`).
- Decisions are device-signed canonical JSON with a context digest (v2) and a DB-backed replay guard (`replay_nonces`) (`Services/InteractionService.swift`, `Security/DecisionSigning.swift`). **By design the business never receives the raw signed decision**: it receives a per-business `deviceRef` and a server attestation `DecisionVerification` (`evidenceRef`), because the signed payload names the global device id (verified in `InteractionService.swift:419-431` and `WebhookService.swift:166-180`; documented in `docs/SECURITY.md` section 2.4 and line 273). Viadere can export the signed payload for a dispute.
- Approve v2: the business signs an `ApprovalRequest` with a directory key; the device returns an `ApprovalResultJWS` verifiable by the business with `ApprovalVerifier` (SDK); replay key `approval:{aud}|{kid}|{challenge}`; prompt-fatigue lock after `maxInvalidSubmissions`; D1 required for high risk (`Approve/ApproveRequestService.swift`, `Packages/ViadereCore/.../Approve/*`). This is the only path in which the business can verify the device's evidence independently. It is gated off in staging.
- **Number matching: none.** No display-code logic for push approvals exists in Core, Server, SDK or App (grep re-run by A0). The only comparison code is the business link-session SAS and the six-digit enrollment SAS.
- Rate limiting: in-process limiter or `DatabaseRateLimitStore` (production default); fail-closed namespaces for OTP, link redemption, enrollment, device confirm, dashboard auth (`Security/DatabaseRateLimitStore.swift`). Auth-delivery namespaces do not exist yet.

## 6. Notification pipeline

| Topic | Current behavior | Source |
|---|---|---|
| Interaction push | Generic title "Viadere", generic body, custom keys `iid` and `loopInstanceId` only; mutable content so the Notification Service Extension fetches content over the authenticated API. No `apns-collapse-id`. | `Push/APNsSender.swift:136-153`, `Push/APNSwiftSender.swift`, `App/ViadereNotificationService/NotificationService.swift` |
| Approve v2 push | Generic body, category `viadere.approve`, **no `iid`**; the `viadere.approve` category is not registered anywhere in the app. Tapping routes to Alerts, not to the request (source-level; device behavior unverified). | `Approve/ApproveSupport.swift:45-58` (verified), `Packages/ViadereKit/.../NotificationActionHandler.swift:36-39` |
| Message push | `threadID = business.<business id>`: an internal business UUID is sent to Apple (whether the id is public or global was not verified). | `Push/APNsSender.swift:168` (verified) |
| Security notices | Fixed title, categories `viadere.security.notice` / `viadere.security.cancel`, time-sensitive; also persisted as in-app notices. | `Services/SecurityNotices.swift` |
| Live Activities | Start attributes include `businessName`, `businessId`, `interactionId` (verified, `APNsSender.swift:61-68`). Eligibility excludes anything needing the secure flow; the Lock Screen shows the business's confirm title/detail/option labels (bounded, sanitized). Intents `.requiresAuthentication`, refuse while protected data is unavailable, accept only confirm/decline/select. | `Services/LiveActivityService.swift`, `App/Shared/LiveActivity/ViadereDecisionIntent.swift`, `Packages/ViadereKit/.../LiveDecision.swift` |
| Notification actions | Built from `ChannelRenderer.notification`. Security-sensitive kinds allow only deny/report inline; approve returns `.requiresApp`. For `authenticate` at low assurance the "Yes, it's me" action is not `.foreground` (verified), so the tap may complete nothing visible (finding F-14, device behavior unverified). | `Packages/ViadereCore/.../Rendering/ChannelRenderer.swift:259-278`, `NotificationActionHandler.swift:85-93` |
| Click routing | Universal links via AASA: `/c/*`, `/l/*`, `/h/*`, `/a/*`, `/k/*`; strict parser (wrong host, userinfo, port, extra segments return nil). `/h/` calls `redeemHandoff` immediately on open (verified, `AppModel.swift:286-300`), with no confirmation step. No business-URL handoff exists. | `Server/Sources/ViadereServerKit/Web/WebRoutes.swift:41-49`, `Packages/ViadereKit/.../Routing/DeepLinkRouter.swift`, `.../Stores/AppModel.swift` |
| Dedup and delivery status | State dedup through compare-and-swap on interaction/approval status and `processed_messages`. Only `tokenInvalid` outcomes are acted on; no per-delivery receipt is stored or sent to the business (APNs offers none). | `Services/InteractionService.swift`, `Queue/*` |
| Push tokens | One APNs token per device; FCM refused; revoked devices lose tokens. | `Routes/AuthRoutes.swift`, `Security/Tokens.swift` |
| watchOS | Phone-mediated through WatchConnectivity; watch holds no keys or tokens; security items show "Approve on your iPhone" and deny only. | `Packages/ViadereKit/.../Watch/WatchSync.swift`, `App/ViadereWatch/` |

## 7. Business model

- Tenancy: businesses authenticate with API keys `vdk_<test|live>_<kid>.<secret>` (SHA-256 at rest, scopes, capability ceiling bounded by entitlements, IP allow-list, optional Tier E mTLS, per-business rate limits); relationship ownership is checked on every call and misses return a plain 404 (`Security/Tokens.swift`, `Security/Principals.swift`, `Services/InteractionService.swift:88`).
- Consumer pseudonymity: pairwise `subject_ref` per business; webhook tenant id is HMAC-derived (`Policy/SubjectRefs.swift`, `Services/WebhookService.swift`).
- Business-to-Viadere calls are bearer-only: no request signing. Replay control is idempotency keys (required for webhook create/rotate/cancel, conversation send, status, rewards, profile, verification; for interaction issue the key is optional and body-based) (`Services/BusinessIdempotency.swift`, `Services/InteractionService.swift:60-66`).
- Webhooks: `Viadere-Signature: t=<ts>,v1=<hex HMAC-SHA256(secret, "<t>." + body)>` (verified, `Security/WebhookSignature.swift`). Method, path, event id and tenant are not bound by the MAC; the v2 envelope carries event id and tenant inside the signed body (carried from A8). Headers `Viadere-Event-Id`, `-Event-Type`, `-Delivery-Id`, `-Key-Id`, `-Webhook-Version`. Retries 30 s, 2 min, 10 min, 1 h, 6 h, 12 h, 24 h, then dead letter; HTTPS only, no redirects, DNS pinning, ownership challenge before activation.
- Brand kits (declarative tokens and re-encoded images only), Loops (declarative, dark by default, fail closed without a publication key), customer pages (Connect button), business console (`Dashboard/*`, 27 files), operator console.
- Messaging versus actions: in-app and SMS messaging (SMS-first by design for non-app customers, `docs/MESSAGING-GATEWAY-SPEC.md`), RCS partial, Apple Messages for Business absent.

## 8. Deployment

- Staging: Azure Container Apps (lean) via OpenTofu `Infra/azure` (`azure.yml`: static checks on PR, plan on push, apply and deploy by manual dispatch, OIDC only, every `uses:` SHA-pinned, images cosign-verified before deploy). Cloudflare Tunnel hostnames set by `Infra/cloudflare/point_staging_to_azure.py`. An operator Cloud Shell path (`Infra/azure/cloudshell/*.sh`) also applies infrastructure and generates service secrets.
- Images: `release.yml` builds, scans, cosign-signs, attests SBOM and SLSA provenance, then **deploys to Fly** staging and production on `v*.*.*` tags. `staging-deploy.yml` builds and deploys Fly staging on every push to `claude/inspiring-cannon-t5hxfw` without cosign verification (verified: both workflows call `flyctl deploy`). Both are legacy under decision 11.
- Stale docs: `docs/ops/STAGING-SETUP.md` describes Fly and Neon; ADRs 0001-0003 (Fly, Neon, GCP KMS) remain "in force" text; ADRs 0010-0012 (Azure) are still "proposed" although Azure is the running staging; `App.swift:158`, `Migrations/RuntimeRoleGrants.swift`, `Config/OperationsConfig.swift` (GCP workload-identity env names) and `Dashboard/ConsoleCompliance.swift:153` ("Neon: 7 days point-in-time") still reference the legacy stack.
- No agent deploys to production (decision "Production").

## 9. Security baseline

| Control | State | Source |
|---|---|---|
| TLS | Cloudflare min TLS 1.2 (ECDHE+AEAD), 1.3 preferred; cloudflared to api is plain HTTP inside the environment (peer-to-peer encryption on); PostgreSQL TLS 1.3 server side, `verify-full` client side. TLS-compatibility policy status "proposed". | `Infra/terraform/cloudflare.tf`, `docs/ops/TLS-COMPATIBILITY-POLICY.md`, `Infra/azure/containerapps.tf` |
| mTLS | Business-API Tier E at Cloudflare is off by default (`enable_mtls = false`). No service-to-service mTLS. | `Infra/terraform/cloudflare.tf`, `Security/MTLS.swift` |
| Key storage | Key Vault, software keys in lean; `exportable=false`. Secrets are Container Apps secret references to Key Vault, optionally `kms1:`-wrapped. | `Infra/azure/keyvault.tf`, `Security/KMS/*` |
| Audit | Append-only audit events chained with a keyed MAC (`AUDIT_CHAIN_KEY`); head signing and WORM export only in `standard`. | `Operations/AuditExport.swift`, `docs/SECURITY.md` section 2.22 |
| Logging | Redaction layer; PostgreSQL parameter logging off; App Insights IP masking; edge refusal log keeps only /24 or /48. | `Security/LogRedaction.swift`, `Operations/EdgeLock.swift` |
| Egress | App-level `OutboundDestinationGuard` (IMDS, wire server, link-local refused). No network-level egress control: default outbound internet from the Container Apps subnet in both profiles. | `Operations/OutboundGuard.swift`, `Infra/azure/network.tf` |
| Supply chain | SHA-pinned actions, checksum-pinned tools, cosign keyless, SBOM, SLSA, gitleaks, trivy, osv-scanner, SAST; no `pull_request_target`, no `secrets: inherit`. | `.github/workflows/*`, `.github/scripts/install-tools.sh` |
| IaC policy | `Infra/azure/policy_check.py` enforces RBAC scope and ingress rules at plan time; it does not evaluate transitive reach (Contributor + Managed Identity Operator). | `Infra/azure/policy_check.py` |
| Tests | Server tests on SQLite and PostgreSQL, Core, Kit, SDK suites exist. Pass status was not run in Stage 0; `docs/HANDOFF.md` (2026-10-29) says full verification after the last gate fixes had not been run. `tests/security/` (spec §25) does not exist. | `Server/Tests/`, `Packages/*/Tests/` |

## 10. SDKs, web code and API contract

| Item | State | Source |
|---|---|---|
| Swift business SDK | Typed client, retries with jitter, idempotency helper, webhook verifier (300 s tolerance, multi-secret, in-memory dedup only), v2 envelope verification, approval verifier, link sessions, key authority. No auth-delivery or MFA-challenge methods. Not published or semver-tagged. | `Packages/ViadereBusinessSDK/Sources/` |
| TypeScript / web SDK | None. No `*.ts`, `package.json` or `tsconfig` in the repository. CLAUDE.md rule 4 now allows TypeScript (decision 8). | repository search |
| Browser code | `viadere-connect.js` (51 lines, dependency-free link button, immutable `v1` path); dashboard passkey script (CSP hash pinned). No reusable partner passkey script. | `Server/Public/connect-button/v1/` |
| Android | **No Android code on main** (correct; a Kotlin package is in a separate unmerged branch and was not inspected). Server hooks only: `AndroidKeyAttestationVerifier` is a stub that never attests; evidence format `android-key-attestation` defined; FCM refused; no `assetlinks.json`. | `Server/Sources/ViadereServerKit/Security/DeviceIntegrity.swift:131-140`, `Packages/ViadereCore/.../Security/IntegrityEvidence.swift` |
| API contract | `docs/openapi.yaml` (OpenAPI 3.1.0, `info.version` 2026-10-28, 56 operations, business API only). Parity test against the route catalog. No `contracts/openapi/auth-delivery-v1.yaml`, no webhook or auth-delivery JSON Schemas, no generated clients. Conformance vectors in `docs/protocol/vectors/` (8 files); none for webhook signatures or auth-delivery. | `docs/openapi.yaml`, `Packages/ViadereCore/Tests/ViadereCoreTests/OpenAPIParityTests.swift` |
| Sandbox and docs | Test keys and sandbox relationships; console pages for keys, webhooks, retry simulator, delivery log; developer portal and `docs/BUSINESS-INTEGRATION.md`. No example apps, no partner test harness for sign-in flows. The changelog shows only 2026-10-27 while `info.version` is 2026-10-28. | `Server/Sources/ViadereServerKit/Dashboard/ConsoleDevelopers.swift`, `Site/content/developers/` |
| iOS app | Targets: app, notification service and content extensions, credential provider, widgets (Live Activities), App Clip, watchOS. Deployment target iOS 17 / watchOS 10 (documented exception). On-device TOTP authenticator and vault (sync off by default). Passkeys with user verification required. | `App/project.yml`, `Packages/ViadereCore/.../Vault/TOTP.swift`, `Packages/ViadereKit/.../Platform/ApplePasskeyService.swift` |

## 11. Reconciliation of the discovery reports

| Topic | Reports | Resolution |
|---|---|---|
| Business never gets the signed decision | A4 called it a gap; A4 itself cites the stripping code | It is an intentional privacy design (SECURITY section 2.4 and line 273): the raw signed decision names the global device id. Treated as a design trade-off against spec §5.2 step 6, not a defect. Approve v2 JWS is the independently verifiable path. See GAP_ANALYSIS finding F-12. |
| Where the repo is deployed | A14 said staging "not evidenced" and the Fly/Azure docs disagree; A5 inventoried Azure and legacy | Operator statement plus `Infra/azure` settle it: Azure lean is staging; Fly/GCP/Neon are legacy. Documentation drift is recorded as finding F-11. |
| GCP KMS for audit heads | A14 said audit-head signing uses GCP KMS on Fly | The server's KMS adapters are Azure Key Vault and a local stand-in; only config names for a GCP workload identity remain (`OperationsConfig.swift:219`). The GCP pattern exists in `Infra/terraform/kms.tf`. |
| `/h/` redeem severity | A6 rated High | Redemption is an authenticated, device-signed call (`APIRoutes.swift:120-122`, `AuthRoutes.swift:93`) and the token was minted for that consumer, so impact is limited to burning a token and navigating to a request that still needs approval. Rated Medium (spec §19.1 violation). |
| Recovery as "Phase C" | A4 and A14 | Already implemented; moved to the preserve list. |
| CLAUDE.md language rule | A14 saw a version without a TypeScript carve-out | The on-disk `CLAUDE.md` allows TypeScript (rule 4, line 33). The sentence "The stack is Swift end to end" in the project-context section is now loose wording only. |

## 12. Unverified items

1. Live Azure state: role assignments actually present, Key Vault key versions, PostgreSQL Entra-only status, Service Bus SAS keys absent, Log Analytics retention, whether `job-viadere-dbadmin` was cleaned up.
2. GitHub settings: deployment-branch rules and reviewers for `staging`, `production`, `azure-plan-staging`, `azure-infra-staging`; whether a non-main branch can obtain an `environment:staging` token; whether the deploy identity can read Container App secret values through `listSecrets`.
3. Cloudflare: applied WAF, rate limits, origin header value, whether API Shield mTLS is on, whether the staging hostnames point at the tunnel.
4. Whether any Fly app (`viadere-server-staging`) still serves traffic; whether `Infra/terraform` was ever applied (GCP keys, Neon roles).
5. Deployed values: `APP_ATTEST_MODE`, `APP_ATTEST_ASSERTION_MODE`, `OTP_ALLOWED_COUNTRIES` (code default `US, CA`), numeric rate limits, webhook-ownership mode.
6. Device behavior (no build or device available): F-14 (low-assurance sign-in approve tap), F-15 (approve v2 tap routing), Live Activity Lock Screen content, AASA on the real domain, VoiceOver and large-text behavior.
7. Whether `threadID = business.<id>` exposes a public or a global identifier.
8. Test pass status of every suite (not run) and the exact table count.
9. The unmerged Android Kotlin package (not inspected).
10. Claims carried from A5/A8/A14 without re-opening the file: GitHub workflow permission details beyond the Fly steps, Cloudflare Terraform defaults, SDK line counts, the legacy-entitlement sunset date, and `SECURITY.md` section numbers other than those cited above.
