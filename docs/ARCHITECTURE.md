# Viadere Architecture

Viadere is a verified business-to-consumer connection layer ("A trusted way to connect"). This document covers the repository layout, what each module owns, and the two main data flows. Wire formats are specified in [SECURITY.md](SECURITY.md), and requirements live in [COMPLETE-PRODUCT-SPEC.md](COMPLETE-PRODUCT-SPEC.md) and [MESSAGING-GATEWAY-SPEC.md](MESSAGING-GATEWAY-SPEC.md).

## Repository layout

```
Packages/ViadereCore   Shared contract: platform-neutral Swift 6 package (iOS 17, macOS 14, watchOS 10, Linux)
Packages/ViadereKit    iOS-only client SDK: Secure Enclave keys, API client, notification handling
Packages/ViadereBusinessSDK  Server-side Swift SDK for businesses: typed business-API client, webhook verification, idempotency helpers
Server/                Vapor 4 backend (Postgres in production, SQLite in tests); also serves the business dashboard, operator console and connect button
App/                   iOS 17 SwiftUI app plus extensions (XcodeGen project, bundle prefix com.viadere)
Design/                Brand assets and design tokens (charcoal, ivory, champagne)
docs/                  Specs, architecture and security
```

Dependency direction: `Server` → `ViadereCore`, `ViadereBusinessSDK` → `ViadereCore`, and `App` → `ViadereKit` → `ViadereCore`. ViadereCore depends only on Foundation and `apple/swift-crypto` (`import Crypto`).

## ViadereCore modules

| Area | Key types | Responsibility |
|---|---|---|
| Identifiers | `BusinessCode`, `BusinessHandle`, `TypedID<Tag>` (`BusinessID`, `ConsumerID`, …), `ConnectLink`, `PhoneNumber` | Normalization and validation of codes and handles, typed UUIDs, strict `https://viadere.com/c/{CODE}` parsing with an HMAC-signed context |
| Interaction protocol | `Interaction`, `InteractionPayload`, `InteractionKind`, `InteractionValidation`, `MoneyAmount` | Versioned envelope (schema v1), typed payloads per kind, and an unknown-kind fallback |
| Assurance | `AssurancePolicy`, `RequiredAssurance`, `ProvidedAssurance`, `DecisionAssurance` | Pure rules for which channel and evidence can satisfy an interaction |
| Rendering | `ChannelRenderer`, `SMSEncoding` | Interaction → SMS (numbered, GSM-7 aware), RCS suggestions, and native notification categories. Sensitive interactions get a secure handoff instead |
| Security | `RequestSigner`/`RequestVerifier`, `DecisionSigner`/`DecisionVerifier`, `WebhookSignature`, `SecureToken`, `ReplayGuard`, `DeviceSigningKey` | Device request signing, signed decisions, webhook HMAC, tokens, replay protection |
| SMS gateway | `SMSGatewayEngine`, `ConversationContext`, `GatewayEffect`, `DirectoryLookup`, `GatewayCopy` | A pure, deterministic state machine that returns the next state plus effects |
| Models / DTOs | `BusinessProfile`, `Relationship`, `ConsentGrant`, `Device`, `ConversationMessage`, `Reward`, `RewardEntry`/`RewardEligibility`, `LoyaltyAccount`, `HouseholdGrant`, `DelegationStepUpProof`/`DelegationScopePolicy`, `AcknowledgmentRecord`, `LiveActivityStatus`, `AuditEvent`, `DelegationGrant`, request/response types | Shared wire types. Always encode them with `ViadereJSON` |
| API catalog | `APIRoutes`, `Endpoint<Req, Res>`, `AuthRequirement` | One source of truth for paths, methods and the auth each route requires |

**Design rules:**
- Every public type is `Sendable`.
- Wire types are `Codable` through `ViadereJSON`: ISO-8601 UTC dates with milliseconds, sorted keys, and lowercase UUIDs.
- Library code never uses `try!` or force unwraps.

## Module responsibilities outside Core

**ViadereKit (iOS)**
- Holds a Secure Enclave `DeviceSigningKey` for each `DeviceKeyPurpose`:
  - `request`: no access-control flags.
  - `approvalUserPresence`: `.userPresence`.
  - `approvalBiometric`: `.biometryCurrentSet`.
- Provides a typed API client built on `APIRoutes` that signs each request with `RequestSigner`.
- Registers notification categories from `NotificationRendering.category`. The Notification Service Extension registers dynamic `choose` categories before display.
- Maps notification actions to `DecisionPayload`.

**Server (Vapor)**
- Registers routes from `APIRoutes.all` and enforces each route's `AuthRequirement`.
- Runs a DB-backed `ReplayGuard` (unique index on `(scope, nonce)`) and a DB-backed `DirectoryLookup`.
- Persists `ConversationContext` per phone number using compare-and-swap on `revision`.
- Executes `GatewayEffect`s in order.
- Delivers webhooks signed with `WebhookSignature` and writes audit events.
- **Channels (P4).** `ChannelAdapter` unifies SMS, RCS and the Apple Messages for Business placeholder. `ChannelRouter` owns a durable outbox: capability check per phone, RCS send, SMS fallback, receipts. RCS postbacks are opaque signed single-use tokens validated against the active menu version and TTL.
- **Platform (P5).** Server-rendered business dashboard and operator console (passkey sign-in, `__Host-` sessions, CSRF, re-authentication, roles), business onboarding (`pending → verified`, handle and code only on verification), suspension, abuse thresholds with automatic throttling, downward-only operator overrides, usage metering with an invoice preview, a server-side QR encoder, and the embeddable connect button.

- **Utility (P3).** `RewardsService` + `RewardEligibilityEvaluator` compute eligibility only on the server (recurrence in the business's time zone, per-day slots and points reserved when a single-use code is issued, released on expiry; the business consumes a code with one compare-and-swap). `WalletService` signs passes (`PassSigner`; `X509PassSigner` builds the detached PKCS#7 with swift-certificates), serves Apple's PassKit web service with per-pass tokens and pushes updates from a durable outbox. `LiveActivityService` sends ActivityKit pushes only for statuses `LiveActivityPolicy` allows. `HouseholdService` implements invitations (hashed single-use codes, attempt limits), the biometric step-up (`DelegationStepUpVerifier` in Core) and the household audit; `InteractionService` scopes a delegate to the grant's purposes and businesses and refuses delegated `authenticate`/`authorize` decisions.

**App (SwiftUI)**
- Onboarding (passkey), connected businesses, inbox and history, approvals that need a secure step-up, permissions, devices.
- Live Activities and Wallet.
- Kept intentionally small. The notification is the primary UX.

## Data flow: MFA / transaction approval

```
Business ──POST /v1/business/interactions (API key, Idempotency-Key)──▶ Server
Server: validate (InteractionValidation), check relationship + ConsentPolicy, clamp priority,
        mint ChallengeNonce, store, choose channel (Trust Engine)
Server ──APNs (NotificationRendering: category viadere.authorize[.secure])──▶ iPhone
User taps Approve
  ├─ RequiredAssurance ≤ deviceSignature  → handled in background, signed with the request/userPresence key
  └─ higher                               → action opens the app (foreground), Face ID unlocks the approvalBiometric key
App: DecisionPayload{interactionId, businessId, decision, challenge, signedAt, deviceId, assurance}
     → canonical JSON → ECDSA P-256 → SignedDecision
App ──POST /v1/interactions/{id}/decision (VIADERE-SIG-V1 + bearer)──▶ Server
Server: RequestVerifier (+ReplayGuard) → DecisionVerifier.verify(… replayGuard:) using the device key whose
        purpose = DeviceKeyPurpose.required(for: assurance) → AssurancePolicy.canSatisfy → record outcome (single use)
Server ──webhook interaction.decided (Viadere-Signature: t=…,v1=…)──▶ Business (remains authoritative)
```

Stale, replayed, wrong-device, wrong-challenge and under-assured decisions are all rejected. If the interaction is sent over SMS or RCS, `ChannelRenderer` produces a secure handoff link and never a YES/NO.

## Data flow: SMS routing

```
Provider ──POST /v1/providers/sms/inbound (provider signature)──▶ Server
Server: verify provider signature → dedup on provider message id (unique index)
        → load ConversationContext(phone) → SMSGatewayEngine.handle(inbound, context, now)
Engine (pure): idempotency → opt-out keywords → OPTED_OUT gate → HELP → session idle expiry
        → escape (\…) → MENU/BACK → per-state handling
        (menu digits only with an active, unexpired, current menu; @handle/code/name resolution
         via DirectoryLookup; explicit confirmation; verbatim forwarding in CONNECTED)
Engine → GatewayTransition{context, effects:[sendSMS, openSession, forwardToBusiness, closeSession,
                                              sendAccountLink, sendSecureHandoff, recordConsent, audit…]}
Server: CAS-persist context (revision) → execute effects in order (outbound queue keeps ordering/retries)
Business reply ──POST /v1/business/messages──▶ Server → engine.deliverBusinessMessage(…)
        → "[Business]: text" only if it belongs to the active session, otherwise holdBusinessMessage (history only)
```

States: `NEW, UNLINKED, LINK_PENDING, IDLE_MENU, RECENT_MENU, SEARCH_PENDING, DISAMBIGUATION, CONFIRM_DESTINATION, CONNECTED, SESSION_MENU, OPTED_OUT, EXPIRED`.

Key rules:
- Menus have at most 4 options, carry a version, and expire after a TTL (default 10 min). A reply received before the current menu was issued is stale. Stale, expired or invalid replies re-display the menu.
- In `CONNECTED`, text is forwarded verbatim, including numbers. A leading `@handle` of a *different* verified business asks for confirmation and is never sent to the current business.
- Unlinked numbers can browse. Routing requires an account link (`requireLinkForRouting`), and the pending destination and message survive the linking step.
- Sessions idle for 24 h become `EXPIRED`. The next message is held and routed only after the user explicitly resumes.
- Each business has its own `SessionID` and its own history. Attribution always uses the verified name captured at connect time.

## Data flow: rich channels (RCS with SMS fallback)

```
Business ──POST /v1/business/interactions (allowedChannels ∋ rcs|sms)──▶ Server
Server (one transaction): store interaction + challenge, meter usage, write a channel_outbound row
        (needs: verified phone link, not opted out, text-channel consent for non-essential purposes)
Worker (ChannelRouter.deliverDue):
   rcs preferred? → capability(phone) cached 24 h ─┬─ capable → ChannelRenderer.rcs
                                                   │     sensitive / not inline → secure handoff link (/h/{token}), no chips
                                                   │     else → suggested replies, one opaque signed single-use token each,
                                                   │            endpoint.active_menu_version += 1 (CAS), older menus revoked
                                                   │     → RCSProvider.send; transient errors retry, then fall back
                                                   └─ not capable / provider error → SMS (same interaction):
                                                         needs an answer or sensitive → handoff link; informational → plain text
Provider ──POST /v1/providers/rcs/inbound (X-RCS-Signature)──▶ Server
   postback: token well-formed (MAC) → row found → same phone → open → menu version current and unexpired
             → interaction pending, business verified, phone belongs to the interaction's consumer
             → AssurancePolicy.canSatisfy(channel: .rcs, .unauthenticatedReply) → CAS token + decision in one transaction
             → webhook interaction.decided (channel "rcs", no assurance/signature)
   text: joins the SMS gateway thread (STOP/HELP work); receipts: delivered / failed → SMS fallback for a pending interaction
```

## Data flow: business onboarding and operations

```
Organization ──/dashboard/signup (passkey)──▶ user + organization(pending) + application   (no handle, no code, no API access)
Operator ──/operator (passkey, re-auth)──▶ approve → status verified + handle + permanent code   |   decline → note, may resubmit
Business user ──/dashboard (passkey, role-gated)──▶ API keys · webhooks · templates · campaign links/QR · consent counts · audit · team · billing preview
Operator ──suspend──▶ status flips atomically → next API call 403, pending interactions cancelled, consumer decisions refused
Background ──abuse sweep──▶ complaint / opt-out rates over the window → auto-throttle (quota and API rate × factor) → auto-lift on recovery
```

## Open decisions (tracked from the spec)

- Messaging provider and number type.
- Retention windows.
- Simultaneous sessions. The engine allows one active session per thread.
- RCS provider selection and carrier launch approval (a generic RBM-style adapter ships; vendor adapters implement `RCSProvider`).
- Apple Messages for Business: blocked on Apple's written approval of multi-merchant brokerage (placeholder only).
- Business pricing and billing (metering and an invoice preview exist; no payment processor).
- Operator staffing and the account-recovery policy for business users who lose every passkey.
