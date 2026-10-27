# Viadere Server

Vapor 4 backend for **Viadere — a trusted way to connect**: the verified, privacy-conscious business-to-consumer
connection layer. This package implements phases **P0 (trust foundation), P1 (SMS broker) and P2 (native minimal
experience backend)** of [`docs/COMPLETE-PRODUCT-SPEC.md`](../docs/COMPLETE-PRODUCT-SPEC.md). Wire formats are the
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
                                Conversations, Phone links, Audit, PasskeyVerifier
    SMS/                        SMSProvider, Twilio adapter, DB DirectoryLookup, GatewayService, outbound queue
    Push/                       APNsSender protocol + APNSwift implementation
    Routes/ Web/                route registration from `APIRoutes`; /c /l /h pages, AASA, health
    Jobs/                       background runner (webhooks, SMS queue, expiry sweeps), seed command
  Tests/ViadereServerKitTests   98+ end-to-end tests over HTTP (SQLite by default, PostgreSQL optional)
  Dockerfile  docker-compose.yml  .env.example
```

## Architecture

* **Contract-first routing.** Every route in `APIRoutes.all` is registered by `RoutesBuilder.api(_:)`, which attaches the
  middleware demanded by the endpoint's `AuthRequirement` (`none`, `bearer`, `deviceSignedBearer`, `businessAPIKey`,
  `providerSignature`). A test walks the whole catalog and asserts each route exists and rejects unauthenticated calls.
  P3–P5 routes (rewards, Wallet, delegation) are registered, authenticated, and answer `501 unavailable`.
* **State in the database, not in memory.** Replay nonces, single-use tokens, conversation state, queues and webhook
  deliveries are rows. Races are decided by unique indexes or compare-and-swap (`UPDATE … WHERE col = expected RETURNING`),
  so any number of instances can run the background jobs safely.
* **One transaction per inbound SMS.** dedup marker (unique insert) → context load → `SMSGatewayEngine` → CAS on
  `revision` → effects (queue rows, webhook deliveries, link tokens, consent, audit). A lost CAS rolls back everything and
  retries; nothing is half-applied. External I/O (SMS send, webhook HTTP) happens afterwards from durable queues.
* **Pluggable edges.** `APNsSender`, `SMSProvider`, `PasskeyVerifier`, `WebhookTransport`, `RateLimitStore` and the clock are
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
with `vdk_test_…` keys printed once. It refuses to run when `ENVIRONMENT=production`.

### Tests

```bash
swift test                                                   # SQLite in memory
TEST_DATABASE_URL=postgres://postgres@127.0.0.1:5432/viaderetest swift test   # the same suite on PostgreSQL
```

## Configuration (environment)

All secrets come from the environment only. With `ENVIRONMENT=production` every secret and `DATABASE_URL` is mandatory and
the process refuses to start without them; in development missing secrets get random ephemeral values.

| Variable | Purpose |
|---|---|
| `ENVIRONMENT` | `development` (default), `testing`, `production` |
| `DATABASE_URL` | `postgres://user:pass@host:5432/db`. Unset → in-memory SQLite (never allowed in production) |
| `AUTO_MIGRATE` | `true` runs pending migrations at startup |
| `CONNECT_LINK_SIGNING_KEY` | base64url ≥ 32 B; HMAC key for signed `/c/{CODE}?ctx=&sig=` links |
| `SERVER_PEPPER` | base64url ≥ 32 B; keys OTP hashes, phone lookup hashes, per-business consumer pseudonyms |
| `DATA_ENCRYPTION_KEY` | base64url ≥ 32 B; AES-256-GCM key for phones, message bodies, webhook secrets, SMS context |
| `PUBLIC_BASE_URL` | public origin (https in production). Used for links and for Twilio signature URLs — never the Host header |
| `RP_ID`, `RP_NAME`, `RP_ORIGIN` | WebAuthn relying party (default `viadere.com`) |
| `APPLE_TEAM_ID`, `APP_STORE_ID` | AASA file; Smart App Banner |
| `APNS_KEY_P8` or `APNS_KEY_PATH`, `APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_TOPIC`, `APNS_ENVIRONMENT` | APNs token auth |
| `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_NUMBER` / `TWILIO_MESSAGING_SERVICE_SID` | SMS provider |
| `TRUSTED_PROXY_COUNT` | reverse proxies whose `X-Forwarded-For` hop is trusted for rate limiting (default 0 = ignore header; **set this behind a load balancer**) |
| `CORS_ALLOWED_ORIGINS` | exact origins, comma separated (default none) |
| `RUN_BACKGROUND_JOBS`, `JOB_INTERVAL_SECONDS` | in-process delivery/maintenance loop (default on, 5 s) |
| `MAX_BODY_BYTES`, `FREE_DAILY_INTERACTION_QUOTA`, `LOG_LEVEL`, `PORT`, `BIND_HOST` | limits and runtime |
| `ALLOW_INSECURE_WEBHOOKS` | development only: allow `http://`/localhost webhook URLs |

## Endpoints

Auth legend: **none** public (IP rate-limited) · **bearer** consumer access token · **device+bearer** access token **and**
`VIADERE-SIG-V1` device signature (verified signature, ±300 s skew, DB-backed nonce replay guard, device owned by the token's
consumer, not revoked) · **API key** business `Authorization: Bearer vdk_live_… / vdk_test_…` (scoped, revocable) ·
**provider** messaging-provider webhook signature.

| Method & path | Auth | Notes |
|---|---|---|
| `POST /v1/auth/register/begin` · `/finish` | none | passkey registration (RP `viadere.com`, UV required); returns session + refresh token |
| `POST /v1/auth/login/begin` · `/finish` | none | passkey login (discoverable credentials) |
| `POST /v1/auth/refresh` | none | refresh-token rotation; reuse revokes the whole family |
| `POST /v1/auth/logout` | bearer | revokes the token family |
| `POST /v1/devices/enroll/begin` · `POST /v1/devices` | bearer | proof of possession per key (`VIADERE-ENROLL-V1`), single-use challenge |
| `GET /v1/devices` · `DELETE /v1/devices/{id}` | device+bearer | list / revoke |
| `POST /v1/phone-links/start` · `/verify` | device+bearer | SMS OTP (HMAC-hashed, 5 attempts, rate-limited) |
| `POST /v1/sms/link-tokens/redeem` | bearer | link token + explicit last-4 confirmation |
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
| rewards, Wallet pass, delegations, `POST /v1/business/rewards` | as catalog | registered, authenticated, `501 unavailable` (P3–P5) |

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
  neither the consumer id nor the phone number.
* **Trust Engine.** Priority is clamped by purpose/kind (marketing ≤ normal, non-security ≤ high, `urgent` only for security
  authenticate/authorize); paid tiers change quotas only. Security-kind sensitivity cannot be lowered.
* **Data at rest.** Phone numbers, message bodies, webhook secrets and SMS conversation state are AES-256-GCM encrypted with
  column-bound AAD; phones are indexed by keyed HMAC. OTPs are keyed hashes. One-time SMS secrets are wiped after sending.
* **Audit.** Append-only (DB triggers) and hash-chained; `AuditService.verifyChain` detects edits, deletions and reordering.
  Metadata is redacted (secrets dropped, phones masked, no message bodies).
* **Edge.** HSTS, CSP, `nosniff`, `Referrer-Policy: no-referrer`, frame-ancestors none; JSON-only bodies; 64 KiB body cap;
  locked-down CORS; token-bucket rate limits per IP / device / business / phone (pluggable store); JSON logs with redaction
  of bearer tokens, API keys, secrets, signatures and phone numbers; secrets from the environment only; constant-time
  comparisons; parameterized queries only; no redirects on webhook delivery; webhook destinations re-resolved and
  rejected if private, loopback, link-local or metadata addresses.
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

## Known gaps (planned, see the report for details)

Wallet pass signing (P3), Live Activity push, rewards and redemption, delegated access endpoints, RCS / Apple Messages for
Business adapters, the business dashboard and billing (P5), device attestation (App Attest) at enrollment, account recovery,
a shared (Redis) rate-limit store for multi-instance deployments, encryption-key rotation tooling, SMS delivery of
non-sensitive interactions, DNS-pinned webhook connections (the destination is re-resolved and checked immediately before
sending but is not pinned to the connection).
