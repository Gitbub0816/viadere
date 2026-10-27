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
    SMS/                        SMSProvider, Twilio adapter, DB DirectoryLookup, GatewayService, outbound queue
    Channels/                   ChannelAdapter protocol (SMS, RCS, AMB placeholder), RCSProvider + generic RBM adapter,
                                ChannelRouter (durable outbox, capability, SMS fallback), RCS postback tokens + inbound
    Dashboard/                  business dashboard + operator console: passkey ceremonies, sessions, CSRF, roles,
                                server-rendered pages (one hashed stylesheet, one hashed passkey script on sign-in pages)
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
  injected through `ServerContext`; tests replace them, production wires APNSwift, Twilio and webauthn-swift.

## Running

```bash
export PATH=/opt/swift/usr/bin:$PATH        # Swift 6.2

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
| `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_NUMBER` / `TWILIO_MESSAGING_SERVICE_SID` | SMS provider |
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
| `POST /v1/recovery/begin` · `/finish` · `/complete` | none | account recovery with a recovery code (SECURITY.md §2.25): spend one code, register a NEW passkey, wait **72 h** (every device is notified, any trusted device can cancel), then activate. Rate-limited per IP, 5 wrong codes lock the account for 24 h, every failure is the same `401` |
| `POST /v1/recovery/{id}/cancel` · `GET /v1/recovery` | device+bearer | cancel a holding recovery (trusted device; also invalidates the remaining codes) · remaining-code count and pending recovery |
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
| `POST /v1/business/interactions` | API key `interactions:write` | idempotent; consent + assurance + quota enforced |
| `GET /v1/business/interactions/{id}` · `POST …/cancel` | API key | outcome / cancel (tenant-scoped) |
| `POST /v1/business/messages` | API key `messages:write` | delivered to the active SMS session or held in history |
| `POST /v1/business/statuses` | API key `statuses:write` | ongoing-event updates replace earlier ones |
| `GET/POST /v1/business/webhooks`, `DELETE …/{id}`, `POST …/{id}/rotate-secret` | API key `webhooks:manage` | HTTPS only, SSRF-checked, secrets shown once |
| `POST /v1/providers/sms/inbound` · `/status` | provider | Twilio `X-Twilio-Signature` HMAC-SHA1, constant time |
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
| `/dashboard/signup`, `/verify`, `/login`, `/invite/{token}` | public | sign-up creates an **unverified** user (passkey, no session); entering the emailed 6-digit code at `/dashboard/verify` activates it and creates a **pending** organization and an application (no handle, no code); then sign in with the passkey. Unverified accounts are purged after 24 h and never block the address. An invitation page asks for a code emailed to the invited address |
| `/dashboard` overview | all | aggregate analytics only: issued / decided by kind, decision latency, webhook and SMS/RCS delivery, opt-outs, reports |
| `/dashboard/api-keys` | owner, admin, developer | create (scoped, live/test, expiry; **passkey re-auth**, secret shown once), revoke, last used |
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

Operators are created with `ViadereServer create-operator --email … --name …` (prints a one-time, one-hour passkey enrollment link).

**Sessions and CSRF.** Cookie `__Host-vd_session` (operators `__Host-vd_operator`): `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, no
`Domain` (so it requires HTTPS, even in development behind a TLS-terminating proxy). The value is 256 random bits; only its SHA-256 is stored.
A new session is created on every sign-in (a presented old cookie is revoked); idle timeout 30 min (operators 15), absolute 12 h (operators 8);
logout, role change and member removal take effect on the next request because the membership is re-read every time. Every state-changing
request needs the per-session CSRF token (an HMAC of the cookie under the server pepper, in a hidden `_csrf` field or `X-CSRF-Token`) and a
same-site `Origin` when the browser sends one. Sensitive actions (create API key, create webhook, rotate secret, add an owner, and every operator
mutation) need a passkey assertion from the last 5 minutes; the server answers with a "Confirm with passkey" page and does nothing until then.

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
rich cards and carousels are not rendered), numbered-reply SMS for non-sensitive interactions (they fall back to a handoff link), encryption-key rotation tooling,
DNS-pinned webhook connections (the destination is re-resolved and checked immediately before sending but is not pinned to the connection).
Dashboard: operator enrollments are still shown once as links (everything else the dashboard sends goes through the email provider), no payment processor (metering and an invoice preview
only), no business-profile editing after verification, no operator-assisted recovery for a business user who loses every passkey (consumers have recovery codes),
and analytics scan per-tenant rows (fine for pilot volumes; add rollups before large scale).

## Security operations

| Command | Purpose |
|---|---|
| `ViadereServer audit-head` | prints the signed head of the audit chain (JSON). Run it on a schedule and store the output in write-once storage |
| `ViadereServer audit-verify [--head file.json]` | recomputes the keyed chain (honouring `AUDIT_CHAIN_LEGACY_THROUGH_SEQ`) and optionally checks an exported head |
| `ViadereServer reencrypt-fields` | rewrites legacy column-bound ciphertexts (and plaintext webhook bodies) as row-bound ones; idempotent |
| `ViadereServer export-dispute --interaction <id>` | prints the signed decision, global device id and device public keys for a dispute (businesses only get a pseudonym and an attestation); audited |

Notes for operators:
* **Upgrading.** Set `ENVIRONMENT` and `AUDIT_CHAIN_KEY`; set `AUDIT_CHAIN_LEGACY_THROUGH_SEQ` to the highest existing `audit_events.seq`; run `reencrypt-fields` once. Existing sessions keep working (they bind to their device the first time it signs).
* **Round 3.** New migration `CreateSecurityRound3Schema` (sealed refresh-token successor, `security_notices`). Run `reencrypt-fields` again to strip `signedDecision` from queued `interaction.decided` deliveries. Trusted-device rules (household, phone link by code, revoking others, deletion) and the cool-down scope are in `docs/SECURITY.md` §2.5. Dashboard invitations never claim an existing account.
* **Round 4 (platform).** New migration `CreatePlatformRound4Schema` (`rate_limit_buckets`, `dashboard_email_codes`): run it (`AUTO_MIGRATE=true` or the `migrate` command) **before** rolling out, because with `RATE_LIMIT_STORE=database` the security-critical limiters fail closed while the table is missing. Staging and production now require `EMAIL_API_URL`, `EMAIL_API_KEY` and `EMAIL_FROM_ADDRESS`. Business accounts that already exist stay `active` (they are treated as verified).
* **Rate limiting is shared by default.** `RATE_LIMIT_STORE=database` (the default in staging/production) keeps one atomic token-bucket row per key in the database, so limits are global across instances; expired rows are deleted by the job loop. If the database is unreachable, one-time-code, link, enrollment, household, dashboard-auth and similar namespaces refuse requests and everything else (the per-IP limiter included) uses a per-instance in-memory limiter until it recovers. `RATE_LIMIT_STORE=memory` is per instance (development) and multiplies every limit by the instance count.
* **Email.** Dashboard verification codes and invitations are sent through a generic transactional-email HTTP API (see below). Without provider settings, development logs the message (with the code); staging and production refuse to start. A provider outage never fails a sign-up request (the user presses "send a new code"); a failed invitation email withdraws the invitation and tells the inviter.
* **Webhook SSRF.** Deliveries resolve the host once, vet every address and connect to the vetted address (DNS pinning); redirects are never followed.
* **Test keys** only address sandbox relationships (`POST /v1/business/sandbox/relationships`).
* **Round 4 (identity).** New migration `CreateIdentityRound4Schema` (`app_attest_keys`, `recovery_profiles`, `recovery_codes`, `account_recoveries`, `business_idempotency`, `devices.attestation_status` / `pending_replacement_by`, `security_notices.action`): run it before rolling out. **App Attest** is verified by `AppAttestVerifier` (Apple's App Attestation Root CA, embedded and fingerprint-checked at startup; SHA-256 `1CB9823B…42C932`, SECURITY.md §2.5). Set `APPLE_TEAM_ID`, choose `APP_ATTEST_ENVIRONMENT` and **roll out with `APP_ATTEST_MODE=report`** until the shipped app attests, then `require` (the production default; with an app that does not attest yet, `require` refuses every enrollment). Existing accounts have no recovery codes until a trusted device regenerates them (`/v1/recovery/codes/...`). A device that is being replaced stays live until the replacement is confirmed or cools down; the job loop (and the old device's next request) completes it. The business API now **requires** an `Idempotency-Key` on webhook create, secret rotation and interaction cancel (the BusinessSDK sends one).
