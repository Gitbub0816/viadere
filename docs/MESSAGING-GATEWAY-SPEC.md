# Viadere — Messaging Gateway and Conversation Brokerage Specification

Status: Product specification / proposed architecture (2026-10-26). Not a claim of implemented features or channel approval.

## Product principle
Viadere ("A trusted way to connect") is a verified, low-friction business–consumer communications network. Customers should rarely need to open an app. Viadere presents a single customer-facing messaging identity while routing explicitly selected conversations to participating, verified businesses through its backend. Business integrations remain responsible for their own support/transaction outcomes. Keep the customer informed about which business receives each message.

## Scope and launch strategy
**Phase 1:** SMS-first (MMS optional) gateway with a Viadere-owned messaging number, numbered menus, typed replies, account-linking links, verified business discovery, sessions, message forwarding, business responses, opt-outs, and auditability. No iMessage extension or Apple approval required for this phase; messaging provider registration and consent compliance still apply.
**Phase 2:** Native Viadere app actionable notifications and secure authorizations; RCS Business Messaging with suggested replies/cards where supported.
**Phase 3:** Explore Apple Messages for Business (AMB) using an approved Messaging Service Provider, contingent on Apple's approval of Viadere's multi-business brokerage model. A single Viadere AMB identity must not be assumed to authorize routing on behalf of unrelated businesses. An ordinary phone number cannot inject arbitrary native blue-bubble iMessage extension cards from a server.

## User journeys
1. Customer texts the Viadere number (e.g. "Hi").
2. Gateway looks up the phone number and its opt-in, account-link, and conversation state. A number is a routing identifier, not proof of account ownership.
3. Unlinked users may continue limited, non-sensitive discovery. To link an account, send a short-lived, single-use HTTPS URL bound to the initiating session; require sign-in and explicit phone-number confirmation, and rotate/invalidate tokens.
4. Present up to four numbered options per SMS menu, e.g. "1. Recent businesses\n2. Find a business\n3. Account help\n4. More options".
5. Recent businesses show up to three verified names plus "4. Search by name". If a user types a name, handle, or code, resolve it, display disambiguation options, and require explicit selection.
6. Confirm destination and scope before forwarding. On connection: "Connected to [Verified Business]. Send your message normally. Reply MENU to switch."
7. While connected, forward ordinary text/media to the business via authorized API/webhook/support integration, and return business replies in the same Viadere thread, clearly attributed (e.g. "[Business]: ...").
8. "MENU" opens session controls; "BACK" returns within menu state; "HELP" gives help; "STOP" triggers channel-compliant opt-out and must not be repurposed; "START" only when permitted for re-opt-in.
9. Switching businesses closes/parks the active routing session and opens a separate scoped session. The history remains isolated by business even though SMS appears in one Viadere thread.
10. Support direct addressing: "@amazon I need help with my order" or "AF2345 Where is my package?" Resolve, confirm when necessary, and forward after the customer has authorized the destination. Unknown/ambiguous matches must never be silently routed.

## Business identity and discovery
- Verified directory with immutable internal business IDs, business verification and authorization status, and searchable public handles (e.g. @starbucks).
- Permanent, non-reassigned, six-character alphanumeric business codes (e.g. AF2345). Case-insensitive normalization; I and 1 equivalent, O and 0 equivalent, L distinct. Reject collisions under canonical normalization.
- QR codes and links (e.g. viadere.com/c/AF2345) encode a business code plus optional signed context, not a separate identity scheme.
- "Connect with Viadere" buttons may link to the native app, eligible App Clip, or secure web fallback.
- Recent businesses and discovery results must only include actual verified participating organizations; sample brand names in this spec are illustrative, not claims of integration.

## SMS conversation state machine
States: NEW, UNLINKED, LINK_PENDING, IDLE_MENU, RECENT_MENU, SEARCH_PENDING, DISAMBIGUATION, CONFIRM_DESTINATION, CONNECTED, SESSION_MENU, OPTED_OUT, EXPIRED.
- Store per-channel sender identity, state, active menu ID/version, menu option mapping, expiration, active business/session ID, consent version, and last activity.
- Parse numeric 1–4 replies **only when a valid menu is active**. Otherwise treat numbers, order numbers, and arbitrary text as normal conversation content.
- Make menus short and expire stale choices. Re-display menu on invalid or expired selection; don't route based on an old menu.
- Normalize commands case-insensitively, with safe whitespace handling. Reserve STOP/HELP and related carrier-mandated keywords globally; document behavior in all states.
- In CONNECTED state, default to forwarding user text verbatim except reserved gateway commands. Provide a documented way to escape a reserved command if it must be sent literally.
- Deduplicate inbound webhook deliveries, sequence outbound replies, handle retries, delivery failure, out-of-order events, and timeouts. Never route a message to an unintended business on uncertain state.
- Consider SMS segmentation, Unicode encoding, MMS attachment limitations, and carrier throughput.

## Structured channel-agnostic conversation engine
Backend outputs typed interaction objects independent of transport:
- `message`, `choose`, `reply`, `confirm`, `authenticate`, `authorize`, `acknowledge`, `status`, `reward`, `ticket`.
- Example choice payload: interaction_id, session_id, business_id, prompt, options [{id,label}], expiration, sensitivity, fallback, idempotency_key.
- SMS adapter renders numbered options; RCS adapter may render suggested replies/cards; AMB adapter may render permitted pickers/quick replies; native iOS uses notification actions or in-app flows.
- If a channel cannot safely express an interaction, issue a secure, short-lived app/web handoff. Do not downgrade device-bound MFA, payment approval, or sensitive authorization to a simple SMS YES/NO.
- Business APIs/webhooks: verified credentials, tenant-scoped endpoints, signed webhook events, retries, idempotency, correlation IDs, rate limits, event versioning, and delivery acknowledgments.
- Proposed implementation: C#/.NET backend on Azure, Swift/SwiftUI consumer app, APNs, optional ActivityKit/PassKit, SMS provider initially; Android/FCM later. These are architectural preferences, not deployment commitments.

## Security, privacy, and trust requirements
- Explicit consumer initiation or lawful opt-in; transactional/security/marketing consents separately scoped. Enforce carrier, TCPA/A2P, opt-out, and applicable retention rules.
- Verify businesses and require documented authorization for routing. Prevent impersonation, spoofed identities, and unsolicited messages through Viadere's shared sender.
- Clearly display the active business before and during each session; attribute business responses; allow immediate switching/disconnect.
- Strict per-tenant authorization, data isolation, access logging, retention/deletion policies, encryption in transit and at rest, and least-privilege operations.
- One-time account-linking tokens: short TTL, cryptographically random, bound to initiating channel/session, single-use, protected from replay and open redirect. A phone number/SMS is not a high-assurance authenticator.
- Maintain auditable consent, routing, and authorization records with appropriate redaction. Avoid placing sensitive message content in general telemetry.
- Abuse/fraud controls, spam prevention, per-business quotas, complaint monitoring, incident response, and transparent notification priority. Businesses cannot buy security-priority overrides.
- Sensitive approvals use Viadere secure app/passkey/biometric-backed workflows as appropriate, not unauthenticated SMS replies.

## Acceptance criteria for phase 1
1. New user can text Viadere and receive a four-option menu.
2. Replying "1" advances the active menu, but "1" in an active business conversation forwards as ordinary text.
3. User can search by name, @handle, or normalized permanent code; ambiguous matches request selection.
4. Unlinked user can complete a secure one-time account-link flow; replayed/expired links fail.
5. User can select and explicitly confirm a verified business; messages and responses route through its authorized integration.
6. User can switch businesses; prior tenant cannot access new tenant's messages.
7. MENU/BACK/HELP/STOP work appropriately; stale menus do not route messages.
8. Duplicate, delayed, and failed provider webhooks do not duplicate or misroute customer messages.
9. Business responses show sender attribution; customer can review conversation history in Viadere when authenticated.
10. Security-sensitive requests are handed off to a stronger channel.

## Later ecosystem features (not phase-1 dependencies)
Native actionable notifications (approve/deny/reply), MFA, context-rich transaction authorization, structured support, order/delivery and appointment updates, Live Activities for ongoing events, Apple Wallet loyalty/tickets, consent acknowledgments, delegated household access, and business dashboard/analytics/billing. Avoid an unnecessary social feed or standalone payments wallet.

## Apple/RCS caveats and validation
- AMB business onboarding and MSP connectivity are separate from becoming an MSP yourself. Viadere may use an approved MSP; self-MSP status is not inherently required just to broker backend messages.
- Apple's approval of a single Viadere-facing identity that routes to many independent merchants is **unconfirmed**. Obtain written policy/technical confirmation before committing to AMB integration.
- iMessage apps/extensions can support interactive experiences in compatible client contexts but cannot be used by a server-owned SMS number to push arbitrary interactive blue-bubble iMessages.
- RCS agent verification/carrier launch requirements and tariffs vary by provider/carrier; use contractual pricing, not illustrative rates, for budgeting.
- SMS is the reliable lowest-common-denominator launch channel; MMS is optional for media, not needed for numbered choices.

## Proposed initial backend objects
`Business`, `BusinessHandle`, `BusinessCode`, `BusinessVerification`, `ConsumerIdentity`, `PhoneLink`, `ConsentGrant`, `ChannelEndpoint`, `ConversationSession`, `ConversationState`, `MenuInteraction`, `MessageEnvelope`, `RoutingEvent`, `DeliveryAttempt`, `WebhookSubscription`, `AuditEvent`.

## Open decisions
Messaging provider and number type; exact SMS pricing and registration; launch geography; whether users may start unlinked; business directory verification workflow; business support integrations; retention windows; number of simultaneous business sessions; fallback when a business is offline; RCS provider; Apple policy acceptance; whether SMS messages are persisted verbatim or minimized.
