# Viadere — Complete Product Specification and Feature Register

**Status:** Consolidated product vision and decisions from the Viadere planning conversation, October 26, 2026. This is a requirements baseline, not a claim of implementation, Apple approval, partner participation, or finalized commercial terms.

## 1. Identity, brand and design
- **Name:** Viadere, pronounced **VYE-ah-DARE**.
- **Tagline:** **A trusted way to connect.**
- **Positioning:** A universal, verified, privacy-conscious business–consumer connection and interaction layer. Users should **almost never need to open the app**.
- **Selected visual direction:** neutral **charcoal / ivory / champagne** palette; flowing interconnected **via** ribbon-and-dot mark; lowercase `viadere` wordmark with **via** emphasized in heavier weight. Avoid generic shield icons or blue-first substitutions. Design language: understated, Apple-like, minimal, not crowded.
- Brand/domain clearance and trademark review remain outstanding.

## 2. Core product principles
1. Connect a consumer to a **verified business once**, then let them interact with minimal friction.
2. Use a **single identity and permissions layer** across channels: native push, app, SMS/MMS, RCS, web, and potentially Apple Messages for Business.
3. Default to **compact actionable notifications**; only open a richer surface when the task requires it.
4. Make business identity, request purpose, urgency, amount/location/context (when relevant), and the requested action unambiguous.
5. Separate authentication, transaction authorization, customer support, transactional notices, and marketing permissions.
6. Give consumers granular control, revocation, history, and device management.
7. Keep channels interchangeable through typed structured interactions and adapters.
8. Do not create a social feed, marketplace, replacement email client, or separate payment wallet merely to increase engagement.

## 3. Permanent business connection and identification methods
**All three are required:**
- **Public business handles**, e.g. `@starbucks`, `@amazon`, searchable and suitable for spoken/radio/print discovery. Handles resolve to verified internal business IDs.
- **Permanent six-character alphanumeric business codes**, e.g. `AF2345`; never reassign a retired code to another business. Case-insensitive. **I and 1 normalize together; O and 0 normalize together; L remains distinct.** Enforce uniqueness after normalization, including collisions caused by those equivalences. Provide user-friendly code entry and validation.
- **Embeddable “Connect with Viadere” buttons** for ecommerce sites, apps, checkout/account portals and other business surfaces, with deep-link to installed app, eligible App Clip, or web fallback.

**QR codes are a fourth entry path, not a separate identifier.** Encode the same permanent code in a URL (illustrative: `viadere.com/c/AF2345`) and optionally signed campaign/action context. Support links and NFC where platform rules allow. Business handles, codes, QR, and buttons converge on the same business record and permission flow.

## 4. Consumer onboarding and relationship management
- Create/link Viadere account, register trusted devices, and link verified phone numbers.
- Search directory by name, handle or permanent code; resolve ambiguous names with verified matches.
- Connect to businesses intentionally, view relationship and permission status, and disconnect/revoke.
- Permissions are **purpose-scoped**: security/MFA, account service, transactional, customer support, marketing, rewards, and sensitive actions as appropriate.
- Present clear consent records and changes; marketing opt-in must not be conflated with essential service/security messages.
- Support recent businesses and fast re-entry without overwhelming the UI.
- Global preference: **only interrupt when action is required**; respect platform notification controls, Focus, and user choices.

## 5. Interaction types and protocol
Canonical structured request types (extendable, versioned):
- `authenticate`: login challenge, sign-in verification, device/session context, approve/deny.
- `authorize`: purchase, financial transaction, account change, high-impact request.
- `confirm`: booking, pickup, reservation, order or other confirmation.
- `choose`: select one or more options.
- `acknowledge`: receipt, policy/consent/estimate acknowledgment.
- `reply`: short text response or structured answer.
- `status`: progress and event updates.
- `reward`: loyalty, offer, redemption, benefit.
- `ticket`: ticket, pass, admission, travel document.
- `message`: conversation/customer support.

Every interaction should carry a verified business identity, stable interaction ID, account/relationship scope, purpose, requested actions, relevant contextual data, creation/expiration, priority, sensitivity, allowed channels, and audit/correlation identifiers. Define idempotency and replay resistance.

## 6. Authentication and security approvals (Duo-like)
- Businesses request a login/MFA challenge through Viadere; user approves or denies in a native notification or secure app flow where appropriate.
- Show meaningful context: business, sign-in device/browser, approximate location, time, and risk indicators when reliable.
- Support expiration, cancellation, denied/unrecognized attempt reporting, rate limits, replay prevention, device binding, and secure step-up authentication.
- Biometric/passkey-backed verification where supported; distinguish basic push approval from **phishing-resistant** authentication. Do not claim simple Yes/No push is inherently phishing-resistant.
- Record outcome and notify requesting business through signed API/webhook. Business remains authoritative for granting access.
- Design for rapid, one-tap action without a routine app launch; require stronger UI where security dictates.

## 7. Transaction and intent authorization
- Example: “Someone is trying to spend **$285.28 at Walmart in or near Mesa, Arizona. Is this you?**” with **Yes / No**.
- Generalize beyond banking: purchases, transfers, changes to account/security settings, service estimates, access requests, reservations, cancellations and industry-specific approvals.
- Clearly present merchant/requester, amount/currency, location if known, action, risk context, expiration, and effect of approval.
- Sensitive approvals require integrity checks, strong identity/session binding, fraud/abuse controls, and optional step-up. Viadere transmits authorization decisions; the originating business processes the transaction.
- Do not treat SMS YES/NO as a sufficient high-assurance substitute.

## 8. Native iOS interaction model
- **Actionable notifications:** `UNNotificationCategory`, `UNNotificationAction`, `UNTextInputNotificationAction`; approve, deny, confirm, select supported actions, or reply without opening app where permitted.
- Compact notification banner is the primary UX, **not** an arbitrary persistent system overlay. iOS determines delivery, banner appearance, Focus handling and permissions.
- **Live Activities / Dynamic Island** for genuinely ongoing events (delivery, trip, flight, active order, appointment status); not arbitrary promotional or permanent controls.
- **Apple Watch** notification actions and compact companion interactions where practical.
- **App Clips** invoked via eligible QR/link/NFC/app-clip invocation for quick onboarding or richer flows when full app isn't installed. App Clips cannot arbitrarily overlay other apps; not necessary for every basic notification action.
- Native app serves as fallback for full inbox, search, account setup, permissions, history, security settings and complex workflows.
- App should feel intentionally small, fast, and not overloaded.

## 9. Business–consumer messaging and structured service
- Verified bidirectional messages: business-to-consumer and consumer-to-business.
- Transactional messages, customer support, and separately consented marketing.
- Rich structured choices, short free-text answers, escalation to a full conversation, attachments where supported, and channel-appropriate fallbacks.
- Unified conversation history in Viadere with clear business identity and consent boundaries.
- Preserve support context when transferring from a quick action to a richer channel; avoid duplicate messages.
- Customers can initiate via business handle, permanent code, search, Connect button, or shared Viadere phone number.

## 10. Loyalty, rewards and Apple Wallet
- Loyalty enrollment and account linking, points/status, coupons, perks, promotional rewards, and redemption.
- Recurring eligibility examples (e.g. a free coffee on Tuesdays), with backend eligibility and redemption enforcement.
- Issue/update eligible **Apple Wallet** passes: loyalty cards, coupons, event tickets, reservations and similar passes.
- Wallet pass updates are not a guaranteed mechanism for scheduled marketing notifications; use permitted communication channels and consent.
- Support one-tap claim/redeem, business validation, and fraud prevention.

## 11. Orders, deliveries, appointments, travel and events
- **Orders/commerce:** purchase confirmation, payment/fulfillment status, shipment tracking, pickup ready, delivery instructions, return/refund updates, service follow-up.
- **Appointments:** reminders, confirm/cancel, reschedule, check-in, waitlist/status, relevant follow-up.
- **Travel:** flight changes, delays, rebooking prompts, boarding/status, hotel check-in, itinerary changes, travel assistance.
- **Events:** tickets, entry passes, schedule changes, venue information, parking and active-event updates.
- Use Live Activities for eligible ongoing statuses and Wallet for passes where supported.

## 12. Consent, signatures, delegation and trust
- Explicit acknowledgments of terms, policies, estimates, data sharing and business requests; timestamped provenance/audit trail.
- Acknowledgment is not automatically a legally sufficient signature; formal e-signature workflows require appropriate legal/identity controls.
- Future **household/delegated access**: scoped roles, expiration, revocation, and full auditability; never silently inherit sensitive permissions.
- **Trust Engine**: prioritize genuine security/urgent actions over low-priority notices, choose appropriate channel, limit interruption, detect abuse and business misuse. Businesses cannot pay to override security priority.
- Verified business registry, suspicious-request reporting, fraud signals, rate limiting, consent enforcement and device/session management.

## 13. Viadere universal SMS/MMS gateway — initial launch
- Obtain a Viadere-owned messaging number through an approved provider and complete applicable U.S. A2P/10DLC or toll-free verification, consent and opt-out obligations.
- **SMS alone is sufficient** for the first iteration; MMS optional for media.
- Customer texts Viadere. If not linked, send a secure **one-time account-link URL** with short TTL and explicit confirmation; allow only safe limited discovery before verification.
- Display **numbered menus with up to four choices**, e.g. `1. Recent businesses / 2. Find a business / 3. Account help / 4. More options`. For recent: three businesses plus `4. Search by name`.
- Accept `1`–`4` **only while an unexpired menu is active**; when connected to a business, numeric replies/order numbers must forward as ordinary messages.
- Accept typed business names, `@handles`, permanent codes, and direct-addressed messages (e.g. `@amazon I need help with my order`). Disambiguate and confirm before routing.
- Once selected, establish a business-scoped session and forward customer messages via authorized business API/integration. Deliver replies back in the same Viadere phone-number thread, **clearly attributed to the business**.
- `MENU` switches to controls; `BACK`, `HELP`, `STOP` and opt-in/resume keywords handled consistently and in compliance with carrier rules. Support ending/switching sessions.
- Maintain state machine: NEW, UNLINKED, LINK_PENDING, IDLE_MENU, RECENT_MENU, SEARCH_PENDING, DISAMBIGUATION, CONFIRM_DESTINATION, CONNECTED, SESSION_MENU, OPTED_OUT, EXPIRED.
- Enforce menu version/TTL, session binding, inbound deduplication, outbound ordering, retries, failed delivery, webhook authenticity, rate limits and no cross-business leakage.
- An SMS sender number alone is not high-assurance identity. Secure account/financial/MFA actions hand off to Viadere's stronger native/web experience.
- The consumer's single SMS thread can switch businesses; backend maintains separate business conversation histories and access control.

## 14. iMessage, Apple Messages for Business and RCS
### Ordinary iMessage / Messages extensions
- iMessage apps/extensions can offer interactive experiences within compatible Messages clients, including supported message layouts and extension UI.
- They **cannot** register Viadere `@handles` as native Apple Messages recipients, read arbitrary message history, silently send iMessages, or enable a server-controlled phone number to inject arbitrary interactive blue-bubble cards.
- An optional Viadere iMessage extension could help discover businesses/share content inside existing conversations, but it is **not** the primary universal broker.

### Apple Messages for Business (AMB)
- Potential future rich Apple-native business conversation channel with supported quick replies, list/time pickers, forms/authentication and payment-related flows subject to Apple's current capabilities.
- **Proposed architecture:** consumer converses with **Viadere as the visible Apple-facing business**; Viadere backend brokers to separately verified participating merchants. This is distinct from requiring every merchant to own a separate Apple conversation.
- Apple requires an approved **Messaging Service Provider (MSP) connection** for AMB delivery. Viadere need **not necessarily become an MSP itself** if it uses an approved MSP.
- **Critical policy dependency:** Apple has **not approved or confirmed** a single Viadere AMB identity as a switchboard for unrelated companies. Demonstrate transparent routing, consent, verification, isolation, opt-outs and legitimate consumer purpose; seek explicit written permission before treating this as available.
- AMB is not simply a regular iMessage phone number and is generally consumer-initiated; no assumption of unsolicited outreach.
- Apple transport may have no Apple per-message fee, but provider, engineering and operational costs must be priced separately.

### RCS Business Messaging
- Potential rich channel for verified sender identity, suggested replies, cards, carousels and supported interactive actions; carrier/device/provider support varies.
- Requires provider/agent onboarding, verification and carrier launch approval; price depends on carrier, content, provider and direction. Do not assume one universal price.
- Translate the **same** structured `choose` object into SMS numbered options, RCS suggested replies, AMB picker (where allowed), or native action controls.
- Fallback to SMS/web when rich features are unavailable; never silently downgrade a sensitive authorization.

## 15. Business platform and developer ecosystem
- Verified business enrollment, organizational ownership/identity proof, merchant profile, handles/codes, relationship management, scopes and consent.
- **API / SDKs / webhooks** for issuing structured requests, receiving customer decisions, routing conversations, updating statuses, issuing rewards/passes, and event delivery.
- Business dashboard for integration setup, message queues, support routing, customer consent status, templates, API keys, audit events, campaign QR/links, analytics and billing.
- Webhook signing, tenant isolation, API authentication, idempotency, retry/dead-letter handling, quotas, versioning, delivery receipts, operational telemetry and abuse monitoring.
- Business-side routing to customer-support platforms, CRM, internal services or human agents; do not imply integrations with named brands unless contracted.
- **Commercial model:** free for consumers, paid businesses/platform access; final pricing and metering undecided. Separate platform fees from SMS/RCS/MSP transport charges.

## 16. Suggested technical architecture
- **Consumer:** Swift/SwiftUI iOS app; UserNotifications, APNs, AuthenticationServices/passkeys as appropriate, ActivityKit, PassKit, App Clips, optional Watch experience.
- **Backend:** C#/.NET services hosted on Azure (proposed); business registry, identity/consent, relationship graph, interaction orchestration, message broker, channel adapters, audit and trust/risk engine.
- **Channels:** APNs native, SMS/MMS provider, RCS provider, optional approved AMB MSP, web fallback, future Android/FCM.
- **Data models:** Business, BusinessVerification, BusinessHandle, BusinessCode, ConsumerIdentity, Device, PhoneLink, ConsentGrant, Relationship, ChannelEndpoint, Interaction, ConversationSession, ConversationState, MenuInteraction, MessageEnvelope, RoutingEvent, DeliveryAttempt, WebhookSubscription, WalletPass, Reward, AuditEvent.
- Event-driven processing, transactional idempotency, reliable queues, encrypted storage, retention controls, observability and safe failure modes. Exact deployment design TBD.

## 17. Delivery phases and acceptance
**P0 — Product and trust foundation:** verify brand, define typed interaction schema, business verification, handle/code registry and normalization, identity/consent model, threat model.

**P1 — Demonstrable SMS broker:** live number, A2P compliance, 1–4 menus, name/handle/code discovery, secure account link, explicit business selection, bidirectional routing, attributed replies, session switching, STOP/HELP, tenant isolation, audit and retries. Test malformed, duplicate, delayed and stale replies.

**P2 — Native minimal experience:** app onboarding, connected businesses, actionable notifications, messaging/history, MFA and sensitive approvals with secure step-up, permissions and account/device controls.

**P3 — Utility expansion:** Wallet/rewards, commerce/orders, appointments, travel/events, Live Activities, structured customer service, delegated access where justified.

**P4 — Rich external channels:** RCS agent/provider verification and integration; explore AMB business enrollment/MSP integration only after policy approval of multi-merchant brokerage. Preserve SMS fallback.

**P5 — Platform scale:** developer SDKs, self-service merchant dashboard, analytics/billing, partner integrations, compliance and trust operations.

## 18. Non-goals, unknowns and external dependencies
- No unsupported iOS persistent overlay, guaranteed notification banner, or forced Dynamic Island placement.
- No guarantee of universal native iMessage routing, arbitrary iMessage bubble buttons from a server, or automatic AMB approval.
- No guarantee that Apple permits brokerage across unrelated companies via one AMB identity.
- No claims that Amazon, Starbucks, airlines, banks or any other named illustrative company is a Viadere customer.
- No high-risk authorizations solely via unauthenticated SMS.
- Not yet finalized: company/brand legal clearance, carrier/provider selection, phone number type, launch regions, business onboarding and verification policy, pricing, data retention, fraud thresholds, legal-signature scope, Apple/RCS approvals, and implementation status.

## 19. Product test scenarios
1. A consumer connects through `@handle`, permanent code, QR and Connect button; all resolve to the same verified business.
2. Codes `IO3456` and `103456` normalize equivalently; codes differing only in `L` remain distinguishable; issuance collision checks work.
3. A login request appears as a contextual approve/deny action; stale/replayed approvals fail.
4. A $285.28 transaction at a merchant near Mesa, Arizona presents accurate business-provided details and secure decision handling.
5. A customer receives a delivery update and can perform a quick supported action without opening the app.
6. An eligible active delivery or flight uses Live Activity; unrelated marketing does not.
7. A loyalty pass can be issued and redeemed with backend eligibility enforcement.
8. SMS menu option `4` triggers search, while an order number `4` during a connected session forwards unchanged.
9. A customer switches from airline to hotel in one Viadere phone-number thread without leaking tenant history.
10. A customer can revoke marketing consent without unintentionally disabling essential security notices.
11. Rich-channel unavailability falls back safely to SMS/web without weakening authentication.
12. A merchant cannot impersonate another merchant or gain priority by paying.

---
**Related focused specification:** [Messaging Gateway and Conversation Brokerage](MESSAGING-GATEWAY-SPEC.md). This document is the broader, cross-feature product baseline; keep both aligned as decisions evolve.
