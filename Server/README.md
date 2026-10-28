# Viadere Server

Vapor 4 backend for **Viadere — a trusted way to connect**: the verified, privacy-conscious business-to-consumer
connection layer. This package implements phases **P0 (trust foundation), P1 (SMS broker), P2 (native minimal
experience backend), P3 (utility: rewards and loyalty, Wallet passes, Live Activity pushes, household delegation, acknowledgments), P4 (rich external channels: RCS with SMS fallback, an inert Apple Messages for Business placeholder) and
P5 (platform: business dashboard, operator console, metering, abuse controls, embeddable connect button)** of [`docs/COMPLETE-PRODUCT-SPEC.md`](../docs/COMPLETE-PRODUCT-SPEC.md). Wire formats are the
normative ones in [`docs/SECURITY.md`](../docs/SECURITY.md); all shared logic (identifiers, interaction protocol,
assurance policy, request/decision/webhook signing, SMS state machine) comes from
[`Packages/ViadereCore`](../Packages/ViadereCore) and is never duplicated here.

```
Server/
  Package.swift                 executable ViadereServer + library ViadereServerKit (Swift 6 mode)
  Sources/ViadereServer         main.swift: logging bootstrap, config, `serve` / `seed` / `migrate`
  Sources/ViadereServerKit
    Config/                     ServerConfig (env only, fails closed in production)
    Core/                       errors (APIError), clock, FieldCipher (AES-GCM), ServerContext, DB helpers
    Models/ Migrations/         Fluent models + one schema migration (Postgres + SQLite)
    Security/                   auth middlewares, replay guard, tokens, rate limiter, headers, log redaction
    Services/                   Auth, Directory/Registry, Relationships/Consent, Interactions, Webhooks,
                                Conversations, Phone links, Audit, PasskeyVerifier, Rewards (+ RewardEligibility), Household,
                                LiveActivity, Acknowledgments
    SMS/                        SMSProvider, Twilio and MailerSend adapters, DB DirectoryLookup, GatewayService, outbound queue
    Channels/                   ChannelAdapter protocol (SMS, RCS, AMB placeholder), RCSProvider + generic RBM adapter,
                                ChannelRouter (durable outbox, capability, SMS fallback), RCS postback tokens + inbound
    Dashboard/                  business dashboard + operator console: passkey ceremonies, sessions, CSRF, roles,
                                server-rendered pages (one hashed stylesheet, one hashed passkey script on sign-in pages)
    Policy/                     WP2: capability policy (`PolicyService`: entitlement ∩ key scope ∩ consent ∩ evidence ∩ law/policy,
                                audited), business entitlements + risk tiers (`EntitlementService`), operator kill switches and
                                law/policy rules (`PolicyAdmin`), per-request disclosure receipts, pairwise `subject_ref` resolution,
                                operator console pages. The pure engine and the capability catalog live in ViadereCore (`Policy/`)
    Platform/                   onboarding / verification / suspension, abuse thresholds + auto-throttle, business controls,
                                usage metering + invoice preview, QR encoder
    Push/                       APNsSender protocol (+ Live Activity pushes), PassPushSender, APNSwift implementations
    Wallet/                     PassSigner (+ X509PassSigner: PKCS#7 via swift-certificates), PKPass builder (ZIP, manifest, PNG),
                                WalletService (issue, PassKit web service, update-push outbox)
    Routes/ Web/                route registration from `APIRoutes`; /c /l /h pages, AASA, health, /connect-button/v1/*
    Jobs/                       background runner (webhooks, SMS + channel outboxes, expiry sweeps, abuse sweep), seed command
  Public/connect-button/v1/     the embeddable "Connect with Viadere" button (web component + plain CSS), immutable and SRI-pinned
  Tests/ViadereServerKitTests   end-to-end tests over HTTP (SQLite by default, PostgreSQL optional)
  Dockerfile  docker-compose.yml  .env.example
```

## Architecture

* **Contract-first routing.** Every route in `APIRoutes.all` is registered by `RoutesBuilder.api(_:)`, which attaches the
  middleware demanded by the endpoint's `AuthRequirement` (`none`, `bearer`, `deviceSignedBearer`, `businessAPIKey`,
  `providerSignature`). A test walks the whole catalog and asserts each route exists and rejects unauthenticated calls.
  The PassKit web service (`/wallet/v1/*`), the dashboard, operator console and connect-button routes are not part of the JSON catalog.
  `501 unavailable` is returned only when Wallet passes are not configured (no pass certificate).
* **State in the database, not in memory.** Replay nonces, single-use tokens, conversation state, queues and webhook
  deliveries are rows. Races are decided by unique indexes or compare-and-swap (`UPDATE … WHERE col = expected RETURNING`),
  so any number of instances can run the background jobs safely.
* **One transaction per inbound SMS.** dedup marker (unique insert) → context load → `SMSGatewayEngine` → CAS on
  `revision` → effects (queue rows, webhook deliveries, link tokens, consent, audit). A lost CAS rolls back everything and
  retries; nothing is half-applied. External I/O (SMS send, webhook HTTP) happens afterwards from durable queues.
* **Pluggable edges.** `APNsSender`, `PassSigner`, `PassPushSender`, `SMSProvider`, `PasskeyVerifier`, `WebhookTransport`, `RateLimitStore` and the clock are
  injected through `ServerContext`; tests replace them, production wires APNSwift, Twilio or MailerSend, and webauthn-swift.

## Running

```bash
export PATH=/opt/swift/usr/bin:$PATH        # Swift 6.4.1

# Local, zero config: in-memory SQLite, random ephemeral secrets (data does not survive a restart)
swift run ViadereServer serve --hostname 127.0.0.1 --port 8080

# Against PostgreSQL
export DATABASE_URL=postgres://viadere:password@localhost:5432/viadere AUTO_MIGRATE=true
swift run ViadereServer seed       # fictional demo businesses + one-time test API keys (refused in production)
swift run ViadereServer serve

# Docker (build context is the repo root because the server depends on Packages/ViadereCore)
cp .env.example .env && $EDITOR .env
docker compose up --build
docker compose run --rm server seed --env development
```

`seed` creates **Northwind Air** (`@northwindair`) and **Juniper Coffee** (`@junipercoffee`) — clearly fictional, verified,
with `vdk_test_…` keys printed once. It refuses to run when `ENVIRONMENT` is `production` or `staging`.

### Tests

```bash
swift test                                                   # SQLite in memory
TEST_DATABASE_URL=postgres://postgres@127.0.0.1:5432/viaderetest swift test   # the same suite on PostgreSQL
```

## Configuration (environment)

All secrets come from the environment only. **`ENVIRONMENT` is required** (`development`, `test`, `staging`, `production`): a missing
or misspelled value is a startup error, never a silent `development`. With `staging` or `production` every secret and `DATABASE_URL`
is mandatory, secrets must be distinct values, `PUBLIC_BASE_URL` and `RP_ORIGIN` must be https, and `seed` is refused. In
`development`/`test` missing secrets get random ephemeral values **only without `DATABASE_URL`** (in-memory SQLite): with a database
an unset secret is an error, because an ephemeral secret would make stored data unreadable after a restart.

| Variable | Purpose |
|---|---|
| `ENVIRONMENT` | **required**: `development`, `test`, `staging`, `production` (`staging` uses production rules) |
| `DATABASE_URL` | `postgres://user:pass@host:5432/db`. Unset → in-memory SQLite (never allowed in production) |
| `AUTO_MIGRATE` | `true` runs pending migrations at startup |
| `CONNECT_LINK_SIGNING_KEY` | base64url ≥ 32 B; HMAC key for signed `/c/{CODE}?ctx=&sig=` links |
| `SERVER_PEPPER` | base64url ≥ 32 B; keys OTP hashes, phone lookup hashes, per-business consumer pseudonyms |
| `DATA_ENCRYPTION_KEY` | base64url ≥ 32 B; AES-256-GCM key for phones, message bodies, webhook secrets and bodies, SMS context (row-bound additional data) |
| `AUDIT_CHAIN_KEY` | base64url ≥ 32 B; HMAC key of the audit hash chain (required in staging/production; keep it out of the database) |
| `SUBJECT_REF_KEY` | base64url ≥ 32 B; HMAC key of the pairwise `subject_ref` derivation (`sub_…`). **Required in staging/production and whenever `DATABASE_URL` is set; must differ from every other secret** (startup refuses reuse). Rotating it changes every `subject_ref` businesses hold |
| `AUDIT_CHAIN_LEGACY_THROUGH_SEQ` | set once when upgrading an existing deployment to the last pre-upgrade audit `seq` (default 0 = every event must be keyed) |
| `PUBLIC_BASE_URL` | public origin (https in production). Used for links and for Twilio signature URLs — never the Host header |
| `RP_ID`, `RP_NAME`, `RP_ORIGIN` | WebAuthn relying party (default `viadere.com`). Outside development `RP_ORIGIN` must be an https origin of `RP_ID` |
| `APP_ATTEST_MODE` | `off` \| `report` \| `require`: what to do with an enrollment without a valid Apple App Attest attestation. Default `require` in production/staging (an unattested app **or** App Clip device is refused, `403 attestation_required`), `off` elsewhere. `report` accepts and flags it with a 72 h cool-down |
| `APP_ATTEST_ENVIRONMENT` | `development` \| `production`: the App Attest AAGUID the app's builds attest with (default `production` in production, `development` elsewhere). TestFlight and App Store builds attest as `production` |
| `OTP_ALLOWED_COUNTRIES` | ISO regions that may receive verification codes (default `US,CA`; Caribbean +1 regions such as `JM`, `DO` are separate) |
| `SMS_MENU_RACE_SECONDS` | a menu digit this soon after a menu change re-shows the menu (default 3; 0 disables) |
| `WEBHOOK_RETENTION_DAYS`, `OUTBOUND_RETENTION_DAYS`, `LINK_TOKEN_RETENTION_DAYS` | retention for finished webhook deliveries (30), finished SMS/RCS outbound rows (30) and used/expired link tokens (7) |
| `APPLE_TEAM_ID`, `APP_STORE_ID` | AASA file; Smart App Banner |
| `APNS_KEY_P8` or `APNS_KEY_PATH`, `APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_TOPIC`, `APNS_ENVIRONMENT` | APNs token auth |
| `SMS_PROVIDER` | `twilio` (default) or `mailersend` |
| `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_NUMBER` / `TWILIO_MESSAGING_SERVICE_SID` | Twilio SMS |
| `MAILERSEND_SMS_API_TOKEN`, `MAILERSEND_SMS_FROM_NUMBER`, `MAILERSEND_SMS_INBOUND_SECRET`, `MAILERSEND_SMS_WEBHOOK_SECRET` | MailerSend SMS (US/CA); the two secrets are distinct, at least 16 characters |
| `EMAIL_API_FORMAT` | `simple` (default) or `mailersend` (body shape of the email API) |
| `RATE_LIMIT_STORE` | `database` (shared, atomic, default in staging/production) or `memory` (per instance; development). Needs the round-4 migration |
| `EMAIL_API_URL`, `EMAIL_API_KEY`, `EMAIL_FROM_ADDRESS` | transactional email for dashboard verification codes and invitations; **all three or none**; required in staging/production (https only there). Optional `EMAIL_API_AUTH_HEADER` (default `Authorization`) and `EMAIL_API_AUTH_SCHEME` (default `Bearer`; empty sends the bare key) |
| `TRUSTED_PROXY_COUNT` | reverse proxies whose `X-Forwarded-For` hop is trusted for rate limiting (default 0 = ignore header; **set this behind a load balancer**) |
| `CORS_ALLOWED_ORIGINS` | exact origins, comma separated (default none) |
| `RUN_BACKGROUND_JOBS`, `JOB_INTERVAL_SECONDS` | in-process delivery/maintenance loop (default on, 5 s) |
| `MAX_BODY_BYTES`, `FREE_DAILY_INTERACTION_QUOTA`, `LOG_LEVEL`, `PORT`, `BIND_HOST` | limits and runtime |
| `ALLOW_INSECURE_WEBHOOKS` | development only: allow `http://`/localhost webhook URLs |
| `PASS_TYPE_IDENTIFIER`, `PASS_CERTIFICATE_PEM` or `PASS_CERTIFICATE_PATH`, `PASS_PRIVATE_KEY_PEM` or `PASS_PRIVATE_KEY_PATH`, `PASS_WWDR_CERTIFICATE_PEM` or `PASS_WWDR_CERTIFICATE_PATH` | Wallet pass signing: **all four or none**. The Pass Type ID certificate (`pass.…`) and its **unencrypted** private key (PKCS#8, PKCS#1 or SEC1 PEM, RSA or EC) from the Apple Developer portal, plus Apple's WWDR intermediate certificate. Inline values accept `\n` escapes. Validated at startup (parseable, key matches certificate, not expired), never committed. The same certificate and key also authenticate the "pass changed" pushes to APNs. None configured = passes off (`501`). The team id is `APPLE_TEAM_ID` |
| `RCS_PROVIDER_BASE_URL`, `RCS_PROVIDER_TOKEN`, `RCS_AGENT_ID`, `RCS_WEBHOOK_SECRET` | generic RBM-style RCS provider; **all four or none** (none = RCS off, SMS only). The secret is base64url, ≥ 32 bytes |
| `FEATURE_APPLE_MESSAGES_FOR_BUSINESS` | defaults `false`; the AMB adapter is a non-functional placeholder even when `true` |
| `VAULT_SYNC_ENABLED` | **release gate and kill switch for credential-vault sync (WP5).** Defaults `false` everywhere; only the literal `true` enables it. Off: every `/v1/vault/**` route answers `404` (after authentication) and devices keep working from their local encrypted vaults. Keep it **off in production until the independent vault cryptography and recovery review passes** (spec §17, Phase 4 gate). Needs the `CreateVaultWP5Schema.v1` and `CreateVaultGateSchema.v1` migrations |
| `VERIFY_ENABLED` | **release gate and kill switch for Verify (WP3).** Defaults `false` everywhere; only the literal `true` enables it. Off: every `/v1/verification-*` and `/v1/verifications*` route answers `404`; in-flight provider sessions are still finished and purged. In `staging`/`production` enabling it **requires `VERIFY_GATE_REFERENCE`** (the id of the recorded Phase 3 gate decision) and at least one fully configured method. Per-capability kill switches (WP2) apply on top. Needs the `CreateVerifyWP3Schema.v1` migration |
| `VERIFY_GATE_REFERENCE` | ticket or document id of the recorded Phase 3 gate (legal validation by market, privacy assessment). Not a secret; it is audited by being required |
| `WALLET_MERCHANT_ID` | the Apple merchant identifier of the app's `PKIdentityRequest` (the same one the identity-encryption certificate was created for). Wallet is offered only when this, an encryption key and the IACA directory are configured |
| `WALLET_ENCRYPTION_KEY_WRAPPED` | comma-separated base64url blobs of the KMS-**wrapped** private key(s) of the Wallet identity-encryption certificate, current first (the previous one stays during a rotation so responses to earlier requests still open). Unwrapped in memory only, through `VerifyRuntime.keyUnwrapper` (**integration point for the WP8 KMS provider; until one is assigned the Wallet method is unavailable and the boot log says why**) |
| `WALLET_ENCRYPTION_KEY_PATHS` | development only: comma-separated PEM files of the identity-encryption private key(s). Refused in `staging`/`production` |
| `WALLET_IACA_DIR` | directory of trusted **IACA root certificates** (`.pem`, `.crt`, `.cer`, `.der`: one per issuing authority, plus Apple's Digital ID IACA <https://www.apple.com/certificateauthority/apki202505/>). Each must be a self-signed CA with keyCertSign, EC P-256/384/521, valid now. Viadere ships no trust list: you download the state roots from each DMV (Apple lists them) and review them |
| `WALLET_IACA_SHA256` | comma-separated SHA-256 fingerprints (hex of the DER) the directory is **pinned** to. Only listed certificates are trusted, so a file dropped into the directory cannot add an issuer. Required in `staging`/`production` |
| `DIDIT_API_KEY` | Didit application API key (`x-api-key`); needs `write:sessions`, `read:sessions`, `delete:sessions` and user-delete rights. Never logged |
| `DIDIT_NEW_SESSIONS_ENABLED` | default `true`; `false` starts no new document verification but keeps the purge client (it needs only `DIDIT_API_KEY`) so Didit sessions are still deleted. Removing the key is not a switch |
| `DIDIT_WORKFLOW_ID_IDENTITY` | the Didit workflow with **document check + liveness + face match** (and no biometric-template retention). The only workflow used for age thresholds and identity attributes |
| `DIDIT_WEBHOOK_SECRET`, `DIDIT_WEBHOOK_SECRET_PREVIOUS` | the destination's signing secret, and (for the 24 h after a rotation) the replaced one. The `status.updated` destination is `POST {PUBLIC_BASE_URL}/v1/providers/didit/webhook` |
| `DIDIT_API_BASE` | default `https://verification.didit.me`; must be `https` (plain `http` only outside staging/production, for local fakes) |
| `VERIFY_REQUIRE_E2EE_IDENTITY` | default `false`. `true`: `identity.name`/`identity.address` requests are refused for a business that has not published an `hpke-encryption` key in the key directory (with a key the attributes are always end-to-end encrypted to it) |
| `DASHBOARD_ORIGIN` | optional separate origin (same `RP_ID`) for dashboard passkeys, e.g. a `business.` sub-domain |
| `DASHBOARD_IDLE_MINUTES`, `DASHBOARD_ABSOLUTE_HOURS` | business session idle (30) and absolute (12) timeouts; operators are fixed shorter (15 min / 8 h) |
| `ABUSE_COMPLAINT_RATE`, `ABUSE_OPTOUT_RATE`, `ABUSE_MIN_SAMPLE`, `ABUSE_WINDOW_DAYS`, `ABUSE_THROTTLE_FACTOR` | auto-throttle thresholds (defaults 2 %, 10 %, 20, 7 d, ×0.25) |
| `BILLING_*` | metering preview rates in micro-USD (`BILLING_INCLUDED_INTERACTIONS`, `…_PLATFORM_MICROS_PER_INTERACTION`, `…_TRANSPORT_MICROS_PER_SMS_SEGMENT`, `…_TRANSPORT_MICROS_PER_RCS_MESSAGE`); transport defaults to 0 |

### Pointing the email sender at a provider

`HTTPEmailSender` sends one request per email: `POST EMAIL_API_URL`, `Content-Type: application/json`, the key in `EMAIL_API_AUTH_HEADER` (`Authorization: Bearer <key>` by default) and the body
`{"from": "<EMAIL_FROM_ADDRESS>", "to": "<recipient>", "subject": "…", "text": "…"}`. Any 2xx is success; the response body is ignored and never logged.

* **Resend (matches as is):** `EMAIL_API_URL=https://api.resend.com/emails`, `EMAIL_API_KEY=re_…`, `EMAIL_FROM_ADDRESS="Viadere <no-reply@yourdomain>"` (a sending domain verified at the provider).
* **A provider that takes the key in a custom header** (for example `X-Api-Key`): set `EMAIL_API_AUTH_HEADER=X-Api-Key` and `EMAIL_API_AUTH_SCHEME=` (empty).
* **A provider with another body shape** (Postmark `TextBody`/`From`, SendGrid `personalizations`, SES): put a few-line relay or serverless function in front that accepts the body above and forwards it, and point `EMAIL_API_URL` at it.

Use a dedicated sending domain with SPF, DKIM and DMARC. The messages contain a 6-digit code or a single-use link; do not enable provider click or open tracking (it would rewrite the link and report it to a third party). In development, with no provider settings, the message (code included) is printed to the log; in staging and production a code is never logged.

## Endpoints

Auth legend: **none** public (IP rate-limited) · **bearer** consumer access token · **device+bearer** access token **and**
`VIADERE-SIG-V1` device signature (verified signature, ±300 s skew, DB-backed nonce replay guard, device owned by the token's
consumer, not revoked) · **API key** business `Authorization: Bearer vdk_live_… / vdk_test_…` (scoped, revocable) ·
**provider** messaging-provider webhook signature.

| Method & path | Auth | Notes |
|---|---|---|
| `POST /v1/auth/register/begin` · `/finish` | none | passkey registration (RP `viadere.com`, UV required); returns session + refresh token **and, once, the account's 10 recovery codes with its recovery ID** (`recoveryCodes`) |
| `POST /v1/auth/login/begin` · `/finish` | none | passkey login (discoverable credentials) |
| `POST /v1/auth/refresh` | none (+ device signature) | refresh-token rotation; reuse revokes the whole family. **A session bound to a device must be refreshed with that device's `VIADERE-SIG-V1` headers** (grace replay included); unbound sessions refresh without |
| `POST /v1/recovery/begin` · `/finish` · `/complete` | none | account recovery with a recovery code (SECURITY.md §2.26): spend one code, register a NEW passkey, wait **72 h** (every device is notified, any trusted device can cancel), then activate. Rate-limited per IP, per recovery ID and globally (malformed input never touches the shared budgets), 5 wrong codes lock the account for 24 h, every failure is the same `401`; at most one open recovery per account (partial unique index); activation ends household grants and re-cools phone links |
| `POST /v1/recovery/{id}/cancel` · `GET /v1/recovery` | device+bearer | cancel a holding recovery (trusted device; closes every open recovery and invalidates the remaining codes) · remaining-code count and pending recoveries (`pending` + `pendingRecoveries`) |
| `POST /v1/recovery/codes/begin` · `/regenerate` | device+bearer | new recovery codes: trusted device **and** a fresh user-verified passkey assertion |
| `POST /v1/auth/logout` | device+bearer | ends this session only (never revokes a device) |
| `GET /v1/security-notices`, `POST /v1/security-notices/{id}/dismiss` | device+bearer | in-app notices for a new device, App Clip, phone link or a device set up again (dismiss needs a trusted device) |
| `POST /v1/devices/enroll/begin` · `POST /v1/devices` | bearer | proof of possession per key (`VIADERE-ENROLL-V1`), single-use challenge, **plus a fresh user-verified passkey assertion over that challenge** (begin returns the assertion options; a session minted by a passkey ceremony < 5 min ago may enroll once without it). `clientKind: appClip` / `clipDevice: true` = request key only, 7 days, never decides. `appAttest {keyId, attestation}` is verified against Apple's App Attestation Root CA, bound to the challenge, the account and the key list (`AppAttestBinding`); keys are `attested = true` only on success, and `APP_ATTEST_MODE=require` refuses the rest |
| `POST /v1/devices/{id}/confirm` | device+bearer | a *trusted other* device lifts the new device's 24 h approval cool-down (`ConfirmationProof`, **biometric** key). `POST /v1/devices` accepts `replacesDeviceId` ("Set up again"): a revoked old device is replaced at once, a **live** one stays until the new device is confirmed or its cool-down ends |
| `POST /v1/devices/{newDeviceId}/cancel-replacement` | device+bearer | "Not you? Cancel": a trusted device (normally the one being replaced) revokes the NEW device; the old one is untouched |
| `GET /v1/devices` · `DELETE /v1/devices/{id}` | device+bearer | list / revoke |
| `POST /v1/phone-links/start` · `/verify` | device+bearer | SMS OTP (HMAC-hashed, 5 attempts, rate-limited) |
| `GET /v1/sms/link-tokens/{token}/preview` | device+bearer | masked phone + expiry, rate-limited, does not consume |
| `POST /v1/sms/link-tokens/redeem` | device+bearer | link token + confirmation of the previewed number; the new link is not a delivery target or reply decider for 24 h unless confirmed |
| `POST /v1/phone-links/{id}/confirm` | device+bearer | a trusted device makes a new link usable now (`ConfirmationProof`) |
| `GET /v1/phone-links` · `DELETE /v1/phone-links/{id}` | device+bearer | list / unlink verified phones |
| `GET /v1/sessions` · `DELETE /v1/sessions/{id}` | device+bearer | signed-in sessions (token families) |
| `DELETE /v1/account` | device+bearer | revokes all devices/tokens, erases personal data, keeps pseudonymous audit |
| `POST /v1/handoff/redeem` | device+bearer | redeem `/h/{token}` in the app (added to `APIRoutes`) |
| `GET /v1/directory/search` · `/handles/{h}` · `/codes/{c}` · `POST /resolve` | none | verified businesses only |
| `POST/GET /v1/relationships` · `DELETE /v1/relationships/{id}` | device+bearer | connect / list / disconnect |
| `GET/PUT /v1/relationships/{id}/consents` | device+bearer | purpose-scoped, versioned; security/accountService not revocable |
| `GET /v1/interactions` · `GET /v1/interactions/{id}` | device+bearer | pending interactions |
| `POST /v1/interactions/{id}/decision` | device+bearer | `SignedDecision` verified with `DecisionVerifier` |
| `GET/POST /v1/conversations`, `GET/POST /v1/conversations/{id}/messages` | device+bearer | tenant-scoped history |
| `POST /v1/push/apns-token`, `POST /v1/live-activities/tokens` | device+bearer | token storage |
| `POST /v1/business/interactions` | API key `interactions:write` + capability of the kind | idempotent; policy (capability scope ∩ entitlement ∩ switches), consent + evidence + quota enforced; `authenticate` needs `auth.challenge`, `authorize` `transaction.approve`, others `message.send` (`403 insufficient_scope` / `not_entitled` / `capability_disabled`); the customer is named by `relationshipId` or `subjectRef` |
| `GET /v1/business/interactions/{id}` · `POST …/cancel` | API key `interactions:read` / `:write` + capability of the interaction's kind | outcome / cancel (tenant-scoped) |
| `POST /v1/business/messages` | API key `messages:write` + `message.send` | delivered to the active SMS session or held in history |
| `POST /v1/business/statuses` | API key `statuses:write` + `message.send` | ongoing-event updates replace earlier ones |
| `GET /v1/business/capabilities` | API key (any) | tiers, entitlements, the key's capabilities, `effective` now, and the capability catalog |
| `GET/POST /v1/business/webhooks`, `DELETE …/{id}`, `POST …/{id}/rotate-secret` | API key `webhooks:manage` | HTTPS only, SSRF-checked, secrets shown once |
| `POST /v1/providers/sms/inbound` · `/status` | provider | Twilio `X-Twilio-Signature` HMAC-SHA1, or MailerSend `Signature` hex HMAC-SHA256 of the raw body with the route's own secret; constant time, unsigned refused |
| `GET /c/{code}` · `/l/{token}` · `/h/{token}` | none | server-rendered fallback pages, strict CSP, Smart App Banner |
| `GET /.well-known/apple-app-site-association` | none | applinks, webcredentials, appclips |
| `GET /healthz` · `/readyz` | none | `{"status":"ok"}` only |
| `POST /v1/providers/rcs/inbound` | provider | RCS webhook: `X-RCS-Signature: t=…,v1=…` (HMAC-SHA256, ±300 s, constant time); text, suggestion postbacks, receipts |
| `GET /connect-button/v1/{viadere-connect.js,viadere-connect.css,integrity.json}` | none | immutable, SRI-ready assets (see below) |
| `GET /v1/rewards` · `/v1/rewards/overview` | device+bearer | rewards with the **server-computed** `RewardEligibility` (recurrence in the business's zone, per-day limits, points) |
| `GET /v1/loyalty/{businessId}` · `POST …/enroll` | device+bearer | program overview (`404` = none); enroll needs the current `termsVersion` (`409` if stale); member reference AES-GCM encrypted |
| `POST /v1/rewards/{id}/claim` · `/redeem` | device+bearer | claim (`409` if not claimable); redeem re-checks eligibility, reserves the slot/points and returns a single-use code (120 s) |
| `GET/POST /v1/wallet/passes` · `GET /v1/wallet/passes/{id}` | device+bearer | list / issue; the download is the signed `.pkpass` (`410` once voided, `501` without a pass certificate) |
| `/wallet/v1/devices/…/registrations/…`, `/wallet/v1/passes/{type}/{serial}`, `/wallet/v1/log` | pass token (`ApplePass`) | Apple's PassKit web service: register/unregister, changed serials, latest pass, device logs |
| `GET /v1/household` · `GET /v1/household/audit` | device+bearer | given/received grants with server-computed status · the household audit feed |
| `POST /v1/household/invitations` · `/preview` · `/accept` | device+bearer | hashed single-use 24 h codes, attempt-limited; sensitive scopes need an `approvalBiometric` step-up proof |
| `GET /v1/delegations` · `DELETE /v1/delegations/{id}` | device+bearer | active grants · revoke (grantor or delegate); `POST /v1/delegations` is `410` (use invitations) |
| `GET /v1/acknowledgments` | device+bearer | acknowledgment records with the server's timestamp |
| `PUT/GET /v1/business/loyalty/program`, `POST /v1/business/loyalty/points` | API key `rewards:write` | program, points (idempotent ledger) |
| `GET/POST /v1/business/rewards`, `POST …/{id}/revoke` | API key `rewards:write` | create (idempotent) / list / withdraw |
| `POST /v1/business/redemptions/consume` | API key `rewards:write` | validate **and** consume a code in one compare-and-swap; rate-limited |

### Business dashboard (`/dashboard`) and operator console (`/operator`)

Server-rendered HTML in Vapor: no framework, no third-party assets. Every page carries a strict CSP (`default-src 'none'`, the
stylesheet pinned by SHA-256, **no** `unsafe-inline`; sign-in pages add one inline passkey script pinned by SHA-256). Sign-in is
**passkey only**, with the same WebAuthn relying party as consumers (`RP_ID`, optionally a different origin via `DASHBOARD_ORIGIN`)
but separate credential tables, users and sessions, so a business passkey can never open a consumer session or the reverse.

| Page | Roles | Notes |
|---|---|---|
| `/dashboard/signup`, `/verify`, `/login`, `/invite/{token}` | public | sign-up creates an **unverified** user (passkey, no session); entering the emailed 6-digit code at `/dashboard/verify` activates it and creates a **pending** organization and an application (no handle, no code); then sign in with the passkey. Unverified accounts are purged after 24 h and never block the address (a sign-up under 15 minutes old is not replaced by another sign-up for the same address; 10 wrong codes per address per day, whatever the number of codes). An invitation page asks for a code emailed to the invited address |
| `/dashboard` overview | all | aggregate analytics only: issued / decided by kind, decision latency, webhook and SMS/RCS delivery, opt-outs, reports |
| `/dashboard/api-keys` | owner, admin, developer | create (operational scopes **and capability scopes within the organization's entitlements**, live/test, expiry; **passkey re-auth**, secret shown once), revoke, last used |
| `/dashboard/webhooks`, `/webhooks/deliveries` | owner, admin, developer | endpoints, secret rotation (**re-auth**), delivery log with redacted payloads, replay dead letters (compare-and-swap) |
| `/dashboard/templates` | all | copyable requests built from the real Core types (a test validates each one) |
| `/dashboard/campaigns` | owner, admin, developer | signed `ConnectLink` with campaign context + server-rendered SVG QR code (own encoder, verified against an independent implementation) |
| `/dashboard/consent` | owner, admin, support, analyst | consent counts per purpose; never individual customers |
| `/dashboard/audit` | owner, admin | this tenant's append-only, hash-chained events |
| `/dashboard/team` | owner, admin | invitations (a single-use link **emailed** to the invitee; the inviter never sees it), roles, removal; admins cannot touch owners; adding an owner needs **re-auth**; the last owner cannot leave |
| `/dashboard/billing` | owner, admin, analyst | metered usage and an **invoice preview** (platform fees and carrier/provider transport separate; no payment processor) |
| `/dashboard/organization` | owner, admin | application status; a declined application can be corrected and resubmitted |
| `/operator`, `/operator/applications/{id}` | operator | review and verify or decline applications (verification issues the handle and permanent code) |
| `/operator/businesses[/{id}]` | operator | suspend / reinstate, priority ceiling (downward only), throttle |
| `/operator/abuse` | operator | complaint / opt-out rates, rate-limit hits, throttle state |
| `/operator/businesses/{id}/entitlements` | operator | grant / revoke risk tiers and capabilities with a recorded purpose justification (identity attributes also a heightened-review reference); every change needs a fresh passkey and is audited |
| `/operator/policy` | operator | per-capability kill switches (global or per business) and law/policy rules (jurisdiction block / allow-only), reason required, audited |

Operators are created with `ViadereServer create-operator --email … --name …` (prints a one-time, one-hour passkey enrollment link).

**Sessions and CSRF.** Cookie `__Host-vd_session` (operators `__Host-vd_operator`): `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, no
`Domain` (so it requires HTTPS, even in development behind a TLS-terminating proxy). The value is 256 random bits; only its SHA-256 is stored.
A new session is created on every sign-in (a presented old cookie is revoked); idle timeout 30 min (operators 15), absolute 12 h (operators 8);
logout, role change and member removal take effect on the next request because the membership is re-read every time. Every state-changing
request needs the per-session CSRF token (an HMAC of the cookie under the server pepper, in a hidden `_csrf` field or `X-CSRF-Token`) and a
same-site `Origin` when the browser sends one. Sensitive actions (create API key, create webhook, rotate secret, add an owner, and every operator
mutation) need a passkey assertion from the last 5 minutes; the server answers with a "Confirm with passkey" page and does nothing until then.

**Capabilities, entitlements and policy (WP2).** Every verified business holds Tier M (messaging) and nothing else until an operator grants more;
an API key carries operational scopes **and** capabilities, and every capability request goes through `PolicyService`, which re-reads the
business's entitlements, the operator switches and the policy rules on each call, so a revoked entitlement or a kill switch applies to
existing keys at once (switch state is cached for at most 5 s). Normative catalog, decision order, error mapping, receipts, `subject_ref` and
the data migration of existing keys: `docs/SECURITY.md` §2.28 to §2.31. **Deploying:** set `SUBJECT_REF_KEY` first, then migrate
(`CreatePolicyWP2Schema.v1` grandfathers businesses that already issue `authenticate` / `authorize` interactions as tier A and gives existing keys
the messaging capabilities, plus the approval capabilities for exactly those businesses); the background job fills `relationships.subject_ref`
for existing rows within seconds. Tests: `PolicyWP2Tests` (acceptance 1, 2 and 6, ceiling at use time, kill switch, receipts, unlinkability).

**Verification gate.** Unverified organizations cannot create API keys or webhooks, their keys are refused by the API-key middleware, and
`InteractionService.issue` refuses them again; consumers cannot connect to them and the directory never lists them. Suspension flips the status
atomically, so the next API call is refused, pending interactions are cancelled and consumer decisions on them are refused.

### Rich channels (RCS, SMS fallback, AMB placeholder)

`ChannelAdapter` (`Channels/ChannelAdapter.swift`) gives SMS, RCS and Apple Messages for Business one shape: render a typed interaction with
`ChannelRenderer`, send, parse verified inbound events, report capability. When an interaction allows `rcs` or `sms` and the consumer has a
verified, non-opted-out phone, the issue transaction writes a row to a durable **outbox** (`channel_outbound`); the worker checks RCS capability
per phone (cached 24 h), sends, retries transient errors, and **falls back to SMS for the same interaction**. A sensitive interaction (or anything
that needs an answer SMS cannot carry safely) is rendered as a secure handoff link (`/h/{token}`, single use, bound to the consumer and the
interaction) on both channels, never as a yes/no. RCS suggestion taps carry an **opaque, signed, single-use token** (`vrp1.…`); the server
keeps the target. A postback is accepted only from the phone it was sent to, only while its menu is the phone's active version and unexpired
(the SMS menu rules), and only if `AssurancePolicy` lets an unauthenticated channel reply satisfy that interaction (never `authenticate`,
`authorize`, unknown kinds, or `high`/`critical`; never deny/report). Free text received over RCS joins the same gateway thread as SMS, so
`STOP` opts the number out everywhere.

`AppleMessagesForBusinessAdapter` is a stub behind `FEATURE_APPLE_MESSAGES_FOR_BUSINESS` (default off) with **no functional sending**: Apple has not
approved a single Viadere identity as a multi-merchant switchboard, and there must be no multi-merchant brokerage over AMB until it does in writing.

### Credential vault sync (WP5; `VAULT_SYNC_ENABLED`, default off)

The server is a verifying store for the Authenticator's end-to-end encrypted vault: it keeps **ciphertext, signed public manifests, public keys and HPKE envelopes only**, never item contents, device names or any key that opens them, and never logs bodies. Wire formats and the full protocol are in `docs/SECURITY.md` §2.40. All routes are `deviceSignedBearer`.

| Route | Notes |
|---|---|
| `GET /v1/vault` | status: exists, version, epoch, whether *this* account device is bound to a vault member, device count, recovery configured |
| `PUT /v1/vault` | one atomic compare-and-swap (`expectedVersion`, `0` creates): signed manifest + changed blobs + changed envelopes. Verified with Core's `VaultChainVerifier` (hash chain, signer is a member of the previous manifest, rotation and revision rules); blobs and envelopes must hash to the manifest; the calling account device must be bound to the signing member. Creating needs a trusted device. `409` carries `currentVersion`; bodies up to 4 MiB while enabled (a rotation re-uploads every blob; item ciphertext is capped at 2 MiB per vault so one always fits). A restore with the recovery key additionally needs the caller's open release window |
| `DELETE /v1/vault` | trusted + bound device: erases every vault row (devices keep local copies); notice `vaultDeleted` |
| `GET /v1/vault/manifests?after=N` | signed history, 100 per page; bound devices, or an unbound device only inside its own released-envelope window (below), at a tighter rate |
| `POST /v1/vault/blobs` · `GET /v1/vault/envelope` | ciphertext for bound devices; an unbound device may read blobs only inside its own released-envelope window |
| `POST /v1/vault/recovery-release` | trusted, unbound device asks for the recovery envelope: starts a **72 h hold**; every other account device gets an in-app notice and push (`vaultRecoveryRequested`, "Not you? Cancel"), stored in the same transaction. Idempotent for the asking device; `409` if another device's release is open. Devices that once acted for a removed member are refused |
| `POST /v1/vault/recovery-release/{releaseId}/cancel` | a vault device or any trusted account device; closes every open release; notice `vaultRecoveryCancelled`. `GET /v1/vault` shows the open release (`recoveryRelease`) |
| `GET /v1/vault/recovery-envelope` | only for the device whose release passed its hold, for 24 h after; 5 per hour per device; audited; every fetch is announced (`vaultRecoveryFetched`); useless without the recovery key. The restore PUT spends the window and is announced (`vaultRestored`) |
| `GET /v1/vault/devices` · `DELETE /v1/vault/devices/{memberId}` | members (names are sealed in the manifest) · ends a member's server access at once and notifies; the client then publishes a key-rotation manifest |
| `PUT/GET/DELETE /v1/vault/joins/{joinId}` · `PUT …/request` | new-device pairing channel; payloads are sealed under a secret the server never sees; one request per join, 10 min, 3 open per account |

Limits per account **and device** per hour (one account device cannot exhaust another's budget): writes 120 (burst 30), bound reads 1,200, unbound reads 60 (burst 20), joins 30, release requests / envelope fetches / restores 5; 16 devices, 2,000 items, 32 KiB per blob, 2 MiB of item ciphertext per vault. A removed vault member's account device is remembered (`vault_members.former_device_id`) and may never request a release, join or restore again; a manifest that drops a device without rotating the key is refused. The hold and window are `VaultSyncSettings.recoveryHold` / `recoveryWindow` (72 h / 24 h). Consumer accounts hold no e-mail address, so notices go by push and in-app only. Needs the `CreateVaultGateSchema.v1` migration (`vault_recovery_releases`, `vault_members.former_device_id`). Security notices (`vaultDeviceAdded`, `vaultDeviceRemoved`, `vaultDeleted`, `vaultRecoveryRequested`, `vaultRecoveryCancelled`, `vaultRecoveryReleased`, `vaultRecoveryFetched`, `vaultRestored`) and audit events (`vault.created`, `vault.updated`, `vault.device_removed`, `vault.deleted`, `vault.recovery_release_requested`, `vault.recovery_release_cancelled`, `vault.recovery_envelope_fetched`: counts and ids only). Account deletion wipes the vault whether or not the gate is on.

### Approve v2, business key directory and E2EE (WP1; `APPROVE_V2_ENABLED`, default off in staging and production)

Pairwise per-business approval keys with business-authorized enrollment, signed audience-bound results the business verifies itself, an authenticated key directory (business root key, root-signed statements, Merkle transparency log with signed tree heads), HPKE end-to-end requests and the opaque webhook v2 envelope. Wire formats, canonicalization and threat rows: `docs/SECURITY.md` sections 2.50 to 2.58. Integration guide with a full example: `docs/BUSINESS-INTEGRATION.md` section 5c.

| Variable | Purpose |
|---|---|
| `APPROVE_V2_ENABLED` | `true`/`false`. Default `false` in `staging`/`production` (the Phase 2 independent assessment must pass first), `true` in development and tests. `false` is also the kill switch: every route below answers `404`; keys and the log are untouched. |
| `KEY_DIRECTORY_LOG_KEY` | base64url 32-byte P-256 private scalar of the transparency log's signing key. **Required** when Approve v2 is enabled with a database (an ephemeral key would orphan every signed tree head). Interim until KMS (ADR-03); never log it. |
| `KEY_DIRECTORY_LOG_ID` | optional log identifier (default `viadere.key-directory.v1`); part of every signed tree head. |

`ViadereServer key-directory-log-key` prints the log's **public** key. Put it in the app build (`VIADERE_KEY_DIRECTORY_LOG_KEYS` in `App/Configs`) and give it to businesses for `viadere-key-monitor`.

| Route | Auth | Notes |
|---|---|---|
| `POST /v1/business/approve/enrollments` · `GET .../{id}` · `POST .../{id}/confirm` · `POST .../{id}/cancel` | API key `approvals:manage` + capability | single-use 8-character code (40 bits), 10 minutes by default, 3 open per relationship; the business verifies the device's statement and signs a confirmation |
| `POST /v1/approve/enrollments/lookup` · `POST /v1/approve/enrollments/{id}/complete` | device | lookup answers the same `404` for a wrong, expired or another customer's code; rate limited per consumer and globally |
| `GET /v1/approve/keys` · `POST /v1/approve/keys/{kid}/revoke` | device | the customer's keys; revoking also notifies the business (`approve.key.revoked`) |
| `GET /v1/business/approve/keys?subject_ref=` · `POST .../{kid}/revoke` | API key | reconciliation only; businesses authorize against their own store |
| `POST /v1/business/approve/requests` · `GET .../{requestId}` · `POST .../{requestId}/cancel` | API key | end to end (`envelopes`) or server visible; idempotent on `request_id`; prompt-fatigue policy enforced |
| `GET /v1/approve/requests` · `GET .../{id}` · `POST .../{id}/result` | device | the relay verifies the JWS with the stored key and rejects a frozen, expired, replayed or cool-down request |
| `GET /v1/business/approve/results/{resultRef}` | API key | recipient-bound; the signed JWS. The `status` of a request is never sufficient |
| `GET/POST /v1/approve/freeze` · `POST /v1/business/approve/freeze` | device / API key | customer freeze (account or relationship): freezing is one signed request, lifting needs a trusted device and a fresh biometric proof; a business lifts only its own |
| `GET /v1/business/approve/freezes/{freezeRef}` | API key | resolves the opaque `frz_...` reference of an `approve.frozen` webhook to the customer and the current state |
| `GET /v1/key-directory/sth` · `/consistency` · `/businesses/{id}` | none (rate limited per IP) | public; clients verify everything |
| `POST/GET /v1/business/key-directory/entries` | API key `keydirectory:manage` | publish a signed entry; read your own with proofs. A `root` or `root-succession` entry also needs a dashboard passkey authorization (`POST /dashboard/approve/root-authorizations`) and a verified domain |

Storage: `kd_log_entries` and `kd_tree_heads` are append-only (database triggers refuse `UPDATE`/`DELETE`); the log is appended under a database advisory lock and the tree is cached in memory per process (rebuilt from the table; a scaling item). Displayed details and challenges are cleared when a request reaches a terminal state and requests are purged after 400 days. Webhook subscriptions can opt into the opaque v2 envelope (`envelopeVersion: "2026-10-27"`): ids only, with `Viadere-Delivery-Id` and a versioned `Viadere-Key-Id`. Background jobs expire due requests and enrollments. Security notices: freeze, key revoked, root change, enrollment completed, substitution suspected.

### Verify: age thresholds and identity attributes (WP3; `VERIFY_ENABLED`, default off)

`POST /v1/verification-requests` (business, capability-gated, idempotent) creates a request the customer sees in the app; the customer
consents to the exact disclosure (a `DisclosureReceipt`), verifies with **an ID in Apple Wallet** (HPKE envelope + ISO 18013-5 mdoc
verified on the server) or **Didit** (SDK in the app, session from the server), and the business retrieves the result once with
`GET /v1/verification-results/{result_ref}`. Normative formats, the trust store and the data handling: `docs/SECURITY.md` §2.60.

* **Apple Wallet** (`Verify/Wallet`): `AppleIdentityEnvelope` (strict CBOR, `APPLE-HPKE-v1`, DHKEM(P-256)/HKDF-SHA256/AES-128-GCM, `info` = the
  session transcript), `MDocVerifier` (issuer chain to a pinned IACA, COSE ES256/384/512 only, digests of every item, MSO validity, device signature
  over the transcript), `WalletClaims` (only the requested elements). Verified against Apple's published sample (`identity_verification_sample.zip`,
  see `Tests/ViadereServerKitTests/Fixtures/AppleWalletSample`) and against synthetic issuers. The single-use nonce is the attempt's row.
* **Didit** (`Verify/Didit`): session creation with `vendor_data` = the attempt id, webhook verification (`X-Signature-V2`/`X-Signature`,
  `X-Timestamp` ±300 s, previous-secret overlap, `event_id` dedup), decision **re-fetched** from the API, mapped to the assurance taxonomy,
  reduced in memory to one claim, then the session and the vendor user are deleted (`privacy_erasure`) and the deletion is recorded; failures
  are retried by the background job. A selfie age estimate never becomes a verified age.
* **Results** are sealed per row, single use, audience-bound and expire after 15 minutes; identity attributes are sealed to the business's
  published HPKE key when it has one. Every non-positive end is the same `not_verified`.
* **Not configured is not broken**: without Wallet or Didit settings the methods are simply not offered. Test-mode keys complete requests
  with a simulated result (`sandbox_simulated`) and never reach a real person.

### Business platform and operations (WP6)

The business console is organized as the ten sections of the spec (Dashboard, Organization, Developers, Messaging, Verify, Approve, Security, Compliance, Billing, Support; `Dashboard/Console*.swift`),
with nine roles (`docs/ops/CONSOLE-ROLES.md`, generated from `DashboardPermission`), step-up re-authentication, optional two-person approval and per-organization security settings. The operator console
(`/operator`) gains switches, consumers, notices, data and retention, support and the per-business onboarding reviews. Everything is server-rendered, dependency-free and tested for WCAG 2.2 AA structure.

| Area | Code | Where it is documented |
|---|---|---|
| Onboarding state machine, domain control, assurance, contracts | `Platform/Onboarding.swift`, `DomainControl.swift`, `Assurance.swift`, `Contracts.swift` | SECURITY.md 2.70, 2.71; BUSINESS-INTEGRATION.md 1a |
| API keys: id + 256-bit secret, expiry, IP allow-lists, overlap rotation, operator revoke | `Security/Tokens.swift`, `APIKeyLifecycle.swift`, `Operations/IPNetwork.swift` | SECURITY.md 2.72; BUSINESS-INTEGRATION.md 1b |
| Webhook ownership, test, pause, schema preview, retry simulation | `Services/WebhookOwnership.swift`, `Routes/BusinessRoutes.swift` | SECURITY.md 2.73; openapi.yaml |
| Origin lock (`EDGE_TOKEN`), Tier E client certificates | `Operations/EdgeLock.swift`, `Security/MTLS.swift` | SECURITY.md 2.74; Infra/fly/README.md |
| Switches, notices, consumer freeze, metrics | `Operations/PlatformFlags.swift`, `OperatorNotices.swift`, `ConsumerFreeze.swift`, `Metrics.swift` | docs/ops/KILL-SWITCHES.md |
| Retention, holds, tenant/consumer rights, audit-head export | `Operations/Retention.swift`, `TenantRights.swift`, `ConsumerExport.swift`, `AuditExport.swift` | DATA-INVENTORY.md 6-7; SECURITY.md 2.77, 2.78 |
| Key rotation | `Operations/KeyRotation.swift` | docs/ops/KEY-ROTATION.md |
| Database roles | `Migrations/RuntimeRoleGrants.swift`, `App.swift` | Infra/fly/README.md 1a; RUNBOOKS.md RB-10 |

**New configuration** (all in `.env.example`, mapped to Fly by `Infra/fly/check_env_coverage.py`): `EDGE_TOKEN` (required in staging/production), `EDGE_TOKEN_PREVIOUS`, `METRICS_TOKEN`, `METRICS_PORT`,
`WEBHOOK_OWNERSHIP_VERIFICATION` (default required, cannot be `off` in staging/production), `API_KEY_MAX_OVERLAP_DAYS`, `DOMAIN_RECHECK_DAYS`, `ASSURANCE_GRACE_DAYS`, `SUPPORT_NOTIFY_EMAIL`, the key-rotation set
(`DATA_ENCRYPTION_KEY_ID`/`_KEYS_PREVIOUS`, `SERVER_PEPPER_ID`/`SERVER_PEPPERS_PREVIOUS`, `AUDIT_CHAIN_KEY_EPOCH`/`AUDIT_CHAIN_KEYS_PREVIOUS`, `CONNECT_LINK_SIGNING_KEY_ID`/`_KEYS_PREVIOUS`),
`DATABASE_MIGRATION_URL` and `DATABASE_APP_ROLE`, and the audit-head export (`AUDIT_HEAD_EXPORT`, `_TARGET`, `_PREFIX`, `_INTERVAL_HOURS`, `_ENDPOINT`, `AUDIT_HEAD_KMS_KEY`, `GCP_WORKLOAD_IDENTITY_AUDIENCE`,
`GCP_SERVICE_ACCOUNT_EMAIL`, `GCP_SUBJECT_TOKEN_FILE`, R2 keys). Invalid or inconsistent values stop the server at start and name the variable, never the value.

**Migrations (`CreatePlatformWP6Schema`, `CreateRetentionDeleteGate`, `GrantRuntimeRolePrivileges`).** Run `ViadereServer migrate` before rolling out (the release command does). Existing `admin`/`support` members become
`org_admin`/`messaging_operator`; every existing business gets an onboarding row marked grandfathered (verified businesses keep production keys and have 60 days to accept the current agreements); existing API keys keep
working without a key id. With `DATABASE_APP_ROLE` set (PostgreSQL) the migration grants the runtime role data privileges only.

**Commands.** `ViadereServer rotate-data-key`, `verify-data-key [--require-current]` (docs/ops/KEY-ROTATION.md); `audit-export [--force]` writes a signed audit head to the configured write-once storage now; the job loop does it on
the schedule. `audit-head`, `audit-verify [--head file]` are unchanged and understand key epochs and retention checkpoints.

**Targeted tests** (do not run the whole suite for a console change): `swift test --filter 'WP6'` runs the WP6 suites: `WP6OnboardingTests` (state machine, the section 9.4 acceptance flow, domain control, assurance,
re-acceptance, catalog vs. Site), `WP6RolesTests` (matrix = document, separation of duties, role migration, step-up, two-person), `WP6KeyTests`, `WP6EdgeTests` (origin lock, spoofed headers, mTLS binding), `WP6WebhookTests`,
`WP6KillSwitchTests` (maintenance, sign-up stops, pause, messaging restriction, freeze, notices, metrics), `WP6RetentionTests` (every class, holds, the append-only gate, audit purge), `WP6RightsTests`,
`WP6AuditExportTests`, `WP6RotationTests`, `WP6ConsoleTests` (IA, WCAG structure and contrast, secret redaction, the incident procedures end to end). The PostgreSQL pass is `TEST_DATABASE_URL=… TEST_RATE_LIMIT_STORE=database swift test`.

### "Connect with Viadere" button

`Public/connect-button/v1/` holds a dependency-free web component (`<viadere-connect code="AF2345">`) and a plain CSS variant, brand-styled
for light and dark, with the mark inlined. They render a link to `https://viadere.com/c/{CODE}` (optionally with a signed `ctx`/`sig`) and make
no requests, set no cookies, use no storage and no iframe. Files are served with `Cache-Control: public, max-age=31536000, immutable` under a
versioned path, with `Access-Control-Allow-Origin: *` (no credentials) so `integrity=` works cross-origin; a change ships as `/v2/`. The SRI hashes
are in [`docs/BUSINESS-INTEGRATION.md`](../docs/BUSINESS-INTEGRATION.md) (a test fails if they drift) and at `/connect-button/v1/integrity.json`.

Errors are always `{"error":{"code","message","requestId"}}` (`APIErrorResponse`); internals are never returned.

## Security measures

* **Auth.** Passkeys only (webauthn-swift behind a `PasskeyVerifier` protocol). Opaque 256-bit access (15 min) and refresh
  tokens, stored as SHA-256; refresh rotation with family revocation on reuse. Sensitive routes need bearer **and** a
  Secure-Enclave device signature. Device enrollment requires proof of possession of every key.
* **Decisions.** Server re-derives everything: canonical payload, signature by the key whose purpose matches the claimed
  assurance, interaction/business/device/challenge binding, expiry, ±skew, `AssurancePolicy` (SMS/RCS/AMB can never satisfy
  authenticate/authorize), single-use challenge via the replay guard, and an atomic `pending → decided` swap.
* **Tenant isolation.** Every business query filters on the API key's business id; cross-tenant ids are plain 404s. Businesses
  see a per-business pseudonym for the consumer and a one-way reference instead of the device challenge; webhooks carry
  neither the consumer id nor the phone number. Dashboard queries are scoped to the session's organization, whose membership is re-checked on
  every request; cross-tenant ids are plain 404s.
* **Trust Engine.** Priority is clamped by purpose/kind (marketing ≤ normal, non-security ≤ high, `urgent` only for security
  authenticate/authorize); paid tiers change quotas only. Security-kind sensitivity cannot be lowered. Operator overrides can only *restrict*
  (throttle, suspend, a priority **ceiling** of low/normal/high that is applied as `min`); nothing in the trust path reads the billing tier
  (a test fails if it does). Complaint rate (“not me” reports ÷ interactions) and opt-out rate (consent revocations + disconnects ÷ relationships)
  are tracked per business; above the configured thresholds the business is throttled to a fraction of its quota and API rate until it recovers.
* **Data at rest.** Phone numbers, message bodies, webhook secrets and SMS conversation state are AES-256-GCM encrypted with
  column-bound AAD; phones are indexed by keyed HMAC. OTPs are keyed hashes. One-time SMS secrets are wiped after sending.
* **Audit.** Append-only (DB triggers) and hash-chained; `AuditService.verifyChain` detects edits, deletions and reordering.
  Metadata is redacted (secrets dropped, phones masked, no message bodies).
* **Edge.** HSTS, CSP, `nosniff`, `Referrer-Policy: no-referrer`, frame-ancestors none; JSON-only bodies; 64 KiB body cap;
  locked-down CORS; token-bucket rate limits per IP / device / business / phone (pluggable store); JSON logs with redaction
  of bearer tokens, API keys, secrets, signatures and phone numbers; secrets from the environment only; constant-time
  comparisons; parameterized queries only; no redirects on webhook delivery; webhook destinations re-resolved and
  rejected if private, loopback, link-local or metadata addresses.
* **Dashboard.** Passkey-only sign-in, `__Host-` cookies, hashed session ids, rotation on login, idle + absolute timeouts, CSRF token + Origin
  check, passkey re-authentication for sensitive actions, least-privilege roles enforced server-side, nonce/hash-pinned CSP with no third-party
  assets, redacted webhook payloads in the delivery log, secrets shown once and never audited, audit of every administrative action.
* **RCS.** Inbound webhooks are HMAC-verified over `"{t}." + body` with a ±300 s window and constant-time comparison (one 403 for every failure);
  provider event ids are de-duplicated; postback tokens are opaque, MAC-signed, single use, phone-bound and version/TTL-checked; floods are
  rate limited per phone and audited.
* **Push.** Payloads contain a generic title/body, category, thread id, interruption level, `mutable-content` and an opaque
  interaction id. Amounts, merchants, locations and message text never leave the authenticated API.
* **SMS.** Webhook signature verified against the configured public URL; provider message-id dedup; per-phone and global
  rate limits (floods dropped silently, audited); STOP/HELP handled by the engine and enforced by the outbound queue (queued
  messages are cancelled after STOP); per-phone ordering and retries with backoff.

## Operations notes

* TLS terminates at the edge. Set `TRUSTED_PROXY_COUNT` or every client will share the proxy's rate-limit bucket.
* The in-process job runner is safe to run on every instance. To run it separately set `RUN_BACKGROUND_JOBS=false` on web
  nodes and `true` on a worker.
* Webhook deliveries retry at 30 s, 2 min, 10 min, 1 h, 6 h, 12 h, 24 h and then dead-letter (`webhook_deliveries.status = dead`,
  with per-attempt rows in `webhook_delivery_attempts`).
* Back up `DATA_ENCRYPTION_KEY` and `SERVER_PEPPER` separately from the database; losing them makes encrypted columns and
  OTP/phone hashes unrecoverable.

## Known gaps

Wallet pass signing (P3), Live Activity push, rewards and redemption, delegated access endpoints, a real Apple Messages for Business adapter
(blocked on Apple's written policy approval), vendor-specific RCS adapters (the shipped one is a generic RBM-style REST + HMAC webhook contract;
rich cards and carousels are not rendered), numbered-reply SMS for non-sensitive interactions (they fall back to a handoff link),
DNS-pinned webhook connections (the destination is re-resolved and checked immediately before sending but is not pinned to the connection).
WP6: `SERVER_PEPPER` rotation orphans the single-valued lookup hashes (docs/ops/KEY-ROTATION.md section 3); the Cloudflare to origin certificate leg (G-11) is open; the Terraform for the audit bucket and the mTLS hostname is not validated in CI yet; the consumer export has no web fallback (the app is required, by design).
Dashboard: operator enrollments are still shown once as links (everything else the dashboard sends goes through the email provider), no payment processor (metering and an invoice preview
only), no business-profile editing after verification, no operator-assisted recovery for a business user who loses every passkey (consumers have recovery codes),
and analytics scan per-tenant rows (fine for pilot volumes; add rollups before large scale).

Policy (WP2): `contact.reachable`, `consent.request`, `age.minimum` and `identity.*` are in the catalog and the engine but have no endpoints yet
(Verify ships them); the baseline messaging capabilities cannot be revoked one by one (suspend the business, or use a kill switch); `SUBJECT_REF_KEY`
rotation has no tooling (clear `relationships.subject_ref`, the job re-derives, businesses must re-fetch references); the `consumerReference`
pseudonym is deprecated but still returned; a denial is audited on every attempt, so a flooding compromised key also floods the audit chain (the
per-business API rate limit bounds it).

Approve v2 (WP1): the log key is an environment secret until KMS (ADR-03); the Merkle tree is rebuilt in memory per process; root registration is authenticated only by the `keydirectory:manage` scope (domain/entity proof comes with the WP6 onboarding); the relay can omit trailing entries of a single business until a monitor or a later head exposes it; the Secure Enclave key origin is not attested to the business; `DecisionPayload` v2 (notification-driven interactions) is unchanged and does not use pairwise keys.

## Security operations

| Command | Purpose |
|---|---|
| `ViadereServer audit-head` | prints the signed head of the audit chain (JSON). Run it on a schedule and store the output in write-once storage |
| `ViadereServer audit-verify [--head file.json]` | recomputes the keyed chain (honouring `AUDIT_CHAIN_LEGACY_THROUGH_SEQ`) and optionally checks an exported head |
| `ViadereServer reencrypt-fields` | rewrites legacy column-bound ciphertexts (and plaintext webhook bodies) as row-bound ones; idempotent |
| `ViadereServer export-dispute --interaction <id>` | prints the signed decision, global device id and device public keys for a dispute (businesses only get a pseudonym and an attestation); audited |
| `ViadereServer audit-export [--force]` | writes the signed audit head to the configured write-once storage (also scheduled by the job loop) |
| `ViadereServer rotate-data-key` / `verify-data-key [--require-current]` | re-encrypts every sealed column under the current `DATA_ENCRYPTION_KEY` / proves nothing is left under another key (docs/ops/KEY-ROTATION.md) |

Notes for operators:
* **Upgrading.** Set `ENVIRONMENT` and `AUDIT_CHAIN_KEY`; set `AUDIT_CHAIN_LEGACY_THROUGH_SEQ` to the highest existing `audit_events.seq`; run `reencrypt-fields` once. Existing sessions keep working (they bind to their device the first time it signs).
* **Round 3.** New migration `CreateSecurityRound3Schema` (sealed refresh-token successor, `security_notices`). Run `reencrypt-fields` again to strip `signedDecision` from queued `interaction.decided` deliveries. Trusted-device rules (household, phone link by code, revoking others, deletion) and the cool-down scope are in `docs/SECURITY.md` §2.5. Dashboard invitations never claim an existing account.
* **Round 4 (platform).** New migration `CreatePlatformRound4Schema` (`rate_limit_buckets`, `dashboard_email_codes`): run it (`AUTO_MIGRATE=true` or the `migrate` command) **before** rolling out, because with `RATE_LIMIT_STORE=database` the security-critical limiters fail closed while the table is missing. Staging and production now require `EMAIL_API_URL`, `EMAIL_API_KEY` and `EMAIL_FROM_ADDRESS`. Business accounts that already exist stay `active` (they are treated as verified).
* **Rate limiting is shared by default.** `RATE_LIMIT_STORE=database` (the default in staging/production) keeps one atomic token-bucket row per key in the database, so limits are global across instances; expired rows are deleted by the job loop. If the database is unreachable, one-time-code, link, enrollment, household, dashboard-auth and similar namespaces refuse requests and everything else (the per-IP limiter included) uses a per-instance in-memory limiter until it recovers. `RATE_LIMIT_STORE=memory` is per instance (development) and multiplies every limit by the instance count.
* **Email.** Dashboard verification codes and invitations are sent through a generic transactional-email HTTP API (see below). Without provider settings, development logs the message (with the code); staging and production refuse to start. A provider outage never fails a sign-up request (the user presses "send a new code"); a failed invitation email withdraws the invitation and tells the inviter.
* **Webhook SSRF.** Deliveries resolve the host once, vet every address and connect to the vetted address (DNS pinning); redirects are never followed.
* **Test keys** only address sandbox relationships (`POST /v1/business/sandbox/relationships`).
* **Round 4 (identity).** New migration `CreateIdentityRound4Schema` (`app_attest_keys`, `recovery_profiles`, `recovery_codes`, `account_recoveries`, `business_idempotency`, `devices.attestation_status` / `pending_replacement_by`, `security_notices.action`): run it before rolling out. **App Attest** is verified by `AppAttestVerifier` (Apple's App Attestation Root CA, embedded and fingerprint-checked at startup; SHA-256 `1CB9823B…42C932`, SECURITY.md §2.5). Set `APPLE_TEAM_ID`, choose `APP_ATTEST_ENVIRONMENT` and **roll out with `APP_ATTEST_MODE=report`** until the shipped app attests, then `require` (the production default; with an app that does not attest yet, `require` refuses every enrollment). Existing accounts have no recovery codes until a trusted device regenerates them (`/v1/recovery/codes/...`). A device that is being replaced stays live until the replacement is confirmed or cools down; the job loop (and the old device's next request) completes it. The business API now **requires** an `Idempotency-Key` on webhook create, secret rotation and interaction cancel (the BusinessSDK sends one).
* **Round 5 (re-review).** New migration `CreateRecoveryRound5Schema`: a partial unique index `uq_account_recoveries_open` on `account_recoveries(consumer_id)` for open states (existing duplicate open recoveries are cancelled, oldest kept, before the index is built). Run it before rolling out. Recovery activation now ends household grants and cools phone links down for 72 h; new notice topics `recoveryCompleted` and `delegationEnded`; `RecoveryInfo.pendingRecoveries`. New limiter names: `recovery-begin-id`, `dashboard-verify-failures`, `dashboard-resend-address`.
