<!-- Source: Viadere_Integrated_Feature_Expansion_v4_1.docx (product owner, 30 October 2026). Text extracted verbatim; tables rendered as Markdown. -->

# Viadere

**Loops • Brand Kits • Organization**

_Integrated Feature Expansion & Architecture Specification | v4.0 | 29 October 2026_

Engineering review perspectives: Principal Software Architecture; Application Security; Native Mobile Platforms; Distributed Systems; Product/UX and Accessibility. These are disciplinary review lenses, not claims of named external engineer authorship.

Status: design specification. Distinguishes user-approved product direction from proposed engineering controls and open decisions.

# Executive decision and scope

Viadere comprises three independent subsystems: (A) Loops: optional business-authored interactive workflows; (B) Brand Kits: optional presentation styling for Viadere-owned business pages and widgets; (C) Organization: the customer and business information architecture that keeps many tenants understandable. The first-party feature catalog (messaging, approvals, verification, coupons, rewards, business information, activity) is available independently of Loops and Brand Kits.

| System | Owns | Does NOT own |
|---|---|---|
| Loops | Business-authored declarative forms, steps, approved actions, workflow state | Native component code, universal app navigation, brand identity system |
| Brand Kits | Business-specific visual assets and permitted style tokens for pages/widgets | Workflow execution, actions, permissions, UX control |
| Organization | Business compartments, global views, filtering, navigation, preferences | Individual business workflow implementation |

# 1. Product invariants

- Core Viadere messaging, MFA, identity/age verification, standard approvals, coupons, and business connection must work with no Loop and no Brand Kit.
- A business may publish a branded Viadere page/widget containing only standard Viadere modules; a Loop is optional content within the page/widget, never its foundation.
- A business may create a Loop without creating a Brand Kit; it renders using the standard Viadere UI and must still disclose the third-party author clearly.
- Business input is declarative data and validated media only. No partner-provided executable code, HTML, JavaScript, native libraries, or arbitrary URLs execute on consumer devices.
- Viadere controls all native components, security-critical language, permission prompts, trust indicators, navigation rules, and action semantics.
- Organization must scale from one business to fifty or more without presenting fifty apps or forcing every business to become a top-level tab.
- Business data and staff access are isolated by tenant; customers can choose a business context or cross-business All view.
- Never represent notification delivery as guaranteed or imply an external business outcome merely because Viadere successfully sent an action.

# SPECIFICATION A — LOOPS

# A1. Definition and separation

A Loop is an optional, business-authored interaction assembled in Loop Studio using Viadere-owned components and approved actions. Business-authored means the business configures the experience, not that it must supply a visual design. A Loop may use the standard, unmodified Viadere UI, a permitted business Brand Kit, or a Viadere-approved themed presentation. Appearance is independent of authorship, ownership, and action permissions. A Loop may be opened from a business page, widget, message, alert, or other authorized entry point.

Examples: florist pickup scheduling; repair estimate approval; appointment arrival acknowledgment; parcel pickup request. Businesses choose approved fields, steps, outcomes, and routing. Viadere owns rendering and interaction execution.

# A2. Three execution modes

Hosted: Viadere stores the request, manages state and routes work to a business inbox; no business backend required. Connected: an authenticated, explicitly configured business endpoint receives verified action events. Integrated: a vetted connector exchanges data with a supported external platform (e.g., Shopify, scheduling tools), subject to scope and policy. A single Loop may combine modes step by step.

| Mode | Example | Dependency | Business experience |
|---|---|---|---|
| Hosted | Doctor office check-in | Browser + verified business account | Staff sees request, accepts/rejects, customer receives outcome |
| Connected | Enterprise check-in | Approved API + webhook endpoint | Business system performs external workflow |
| Integrated | Store pickup | Authorized platform integration | Connector creates or reads supported objects |

# A3. Hosted business operations

Provide a responsive web-based Business Inbox usable on common Windows/macOS browsers, without a locally installed desktop app. Optional browser notifications require user permission and are not guaranteed; use in-console queues, unread badges, and configurable email alerts as fallback.

Define per-business staff roles (owner, admin, operator, viewer), queues, assignment, read receipts, handoff, action audit, operating hours, retention, and export. An action may remain pending until a staff member confirms it; customer status must reflect that distinction.

For regulated or sensitive information, use data minimization and policy-gated templates; do not treat ordinary email as an appropriate channel for protected medical details.

# A4. Approved action registry

Action types are registered by Viadere with schema, risk class, allowed inputs, policy checks, confirmation wording, idempotency, timeout, permitted routing, and audit requirements. Businesses can bind a button to a registered action and select allowed labels; they cannot define arbitrary operations through a string parameter.

| Initial action | Risk | Hosted support |
|---|---|---|
| Acknowledge / confirm attendance | Low | Yes |
| Request callback / submit inquiry | Low | Yes |
| Appointment check-in / arrival | Medium | Yes, with confirmation and minimal data |
| Select option / pickup time | Medium | Yes, inventory and scheduling constraints |
| Approve estimate / authorize change | High | Only with explicit terms, amount, and stronger confirmation |
| Identity / age attestation | High | Only first-party verification module, not business-authored logic |
| Payment / order | High | Approved payment provider and separate commerce controls |

# A5. Loop Studio and publishing

Guided templates first; drag-and-drop or form-based arrangement of approved fields and native components; an optional AI assistant may draft declarative definitions but never directly publish them. Advanced mode can expose schema editing and integration mappings, never executable client code.

Lifecycle: draft → preview → validation → policy review (risk-dependent) → signed/versioned publication → staged rollout → revoke/retire. Existing in-flight instances pin to a version. Business-authored wording is constrained in sensitive flows.

A studio simulator built in React can mirror native views but must be verified with screenshot parity tests on SwiftUI and Jetpack Compose; the React simulator is not the production renderer.

# A6. Customer consent and trust boundary

Loops are disabled for customers by default. This does not disable core Viadere features, business pages, or standard modules. At first enablement, provide concise accessible, non-skippable education about third-party-authored experiences, comprehension checks, and an explicit agreement. Each business is separately authorized.

A Loop must identify its creator and the downstream recipient of information. Viadere remains accountable for its own platform security, accurate presentation, routing, and data practices; businesses remain accountable for their external operations. Legal disclosures must not falsely disclaim nonwaivable obligations.

# A6a. Authorship disclosure and first-party distinction

MANDATORY REQUIREMENT — Every business-authored Loop, including one rendered entirely with default Viadere components and colors, must visibly identify its creator. Example: “Built by [Verified Business Name]” or “Created by [Verified Business Name]”. This is separate from the verified-business badge and from any “Secured by Viadere” statement.

Disclosure must appear at the Loop entry point and persist in the Loop's primary view or accessible, consistently placed attribution area. It must not be hidden behind a menu, rely on color alone, or be removable by a business or its Brand Kit. For consequential actions, the confirmation view must identify the business responsible for the downstream action.

Viadere-authored first-party features must not carry a misleading “Built by” label. The platform must derive authorship from a server-controlled immutable publisher identity and signed publication metadata—not business-editable copy, uploaded artwork, or client-provided claims.

Suggested manifest fields: publisher_type = viadere | business; publisher_business_id; published_definition_id; revision; attribution_policy_version. The native renderer must enforce attribution regardless of theme and reject or fall back safely when required publisher metadata is absent.

Acceptance tests: (1) business Loop with default Viadere styling shows “Built by [business]”; (2) business Loop with a Brand Kit shows the same attribution; (3) first-party Viadere module is not mislabeled; (4) attempts to conceal or spoof attribution fail; (5) accessibility services announce authorship; (6) notifications and compact surfaces use a concise business-origin indicator where full wording cannot fit.

# A7. Action protocol and security

Create a server-side interaction instance with tenant, business, customer pseudonymous identity, action schema version, nonce, expiration, and authorization scope. On tap, the backend checks authenticated customer/device, connection authorization, Loop publication status, allowed action and current state.

Record an idempotent, immutable action event with correlation ID. Deliver to hosted queue or signed webhook using retry/backoff and dead-letter handling. Require outcome acknowledgment and model accepted, rejected, pending, timed out, and unknown outcomes separately.

Webhook signing, replay protection, secret rotation, rate limits, allowlisted destinations, tenant-scoped authorization, schema validation, audit trails, abuse controls, and least-privilege connectors are mandatory. Signing a published definition proves integrity, not downstream business safety.

# A8. Integrations and commerce

Shopify or other commerce connectors are future candidates, not automatic support. Use provider OAuth/approved permissions and server-side APIs; avoid collecting raw payment card data. Catalog sync, availability, order creation, refunds, taxes, shipping, fraud and disputes require distinct designs and merchant-of-record decisions.

Healthcare workflows require legal/privacy assessment before production, including HIPAA applicability, business associate agreements where required, restricted PHI fields, and appropriate notification content.

# SPECIFICATION B — BRAND KITS & VIADERE BUSINESS SURFACES

# B1. Scope and independence

Brand Kits are business-owned appearance configurations, not business-authored workflows. A Brand Kit may style a Viadere business page or widget regardless of whether it contains only standard features or includes a Loop. A Loop may be displayed in a neutral page, a branded page, or an approved compact widget.

Pages and widgets are Viadere-owned native surfaces with a module registry: messages, coupons, rewards, business details, approvals, recent activity, verification requests, and Loops where customer-enabled. Businesses may select from Viadere-approved modules and presentation arrangements; they do not gain control of Viadere navigation or security-critical UX.

# B2. Brand Kit schema and assets

Brand Kit contains tenant ID, kit ID/version, display name, approved logo variants, optional background/decorative images, primary/secondary/accent tokens, contrast-safe foreground choices, approved typography scale, decorative border/radius settings, and optional Viadere frame ID.

Uploaded assets must be normalized to approved formats and sizes, stripped of metadata, scanned, bounded in dimensions/byte size, and served from a dedicated asset domain. SVG/HTML should not be accepted as executable render content; rasterize or sanitize to a strict non-scripted format at ingestion.

Kit data never changes button meaning, risk disclosures, permissions, verified-business indicator, destination, component behavior, or critical text. Viadere may override styles for accessibility, legibility, safety, and platform constraints.

# B3. Brand Kit Studio

Business console includes logo/art uploads, color pickers, contrast warnings, crop/safe-area previews, selectable Viadere frames, business page/widget previews, and phone form-factor simulation. Preview standard messages, coupons, approvals, activity and Loop modules using the same kit.

Business can create multiple named kits; schedule effective date/time windows in a specified timezone, assign a fallback default, and optionally randomize among eligible standard kits. Validate overlapping priorities; deterministically select and pin a kit for an active interaction to prevent mid-flow appearance changes.

Seasonal Viadere frames (for example decorative snow) remain first-party controlled. A business may select only frames offered by Viadere; a business may independently schedule seasonal brand art.

# B4. Native rendering and performance

Compile one approved SwiftUI/ActivityKit renderer on iOS and one Jetpack Compose renderer on Android. The server distributes small, versioned presentation data and asset references, never Swift/Kotlin source or dynamically executable UI.

Download only relevant businesses’ kits on demand or upon connection. Use manifest/ETag version checks and prefetch upcoming scheduled kits opportunistically. Enforce cache budget, LRU eviction, offline fallback and atomic updates. The earlier 50–150 KB per kit and 25 MB cache are planning targets, not guaranteed sizes.

The UI must render immediately with neutral Viadere defaults if an asset is missing or stale. Never block approval or authentication on a branding download.

# B5. Surface-specific limitations

Standard push banners are system-controlled; Viadere can supply content, approved actions, and supported attachments, but cannot replace the system banner with a custom quarter-screen overlay while backgrounded.

Live Activities are for genuinely ongoing states and are rendered through app-provided ActivityKit views; system controls presentation, limits, and update delivery. Do not treat them as guaranteed instant approval alerts. Actionable push notifications handle many approval/deny scenarios, subject to authentication and platform restrictions.

App Clips are separate constrained iOS app experiences, not a general notification replacement; design for download/launch restrictions and entitlement requirements. Android notification UI and background execution also require OS-specific policies.

# B6. Page/widget composition contract

Every module exposes fixed input schema, supported display sizes, interaction permissions, accessibility contract, risk classification and platform capability matrix. Page templates can arrange approved modules; widgets use constrained slots.

Brand Kit styling is optional and applied only after layout validation. Loop definitions are resolved as content modules only if enabled and authorized. A Loop may use standard Viadere styling or an eligible Brand Kit, independently of the containing page/widget. Neutral Viadere styling must never be used to imply a business-authored Loop is first-party.

# SPECIFICATION C — ORGANIZATION & INFORMATION ARCHITECTURE

# C1. Primary principle

The customer sees one Viadere, not fifty nested apps. Business separation is strong at the data and authorization layer, but cross-business views remain useful and understandable. A global All context aggregates only user-authorized, relevant items; choosing a business changes context without losing the primary navigation.

The top-level IA should be stable: Messages, Alerts, Benefits (Coupons & Rewards), and Businesses; Activity and Settings may be dedicated tabs or secondary destinations after usability validation. A single contextual business selector, with All as default, filters the applicable sections consistently.

# C2. Navigation model

| Destination | All businesses | Selected business |
|---|---|---|
| Messages | Unified thread list grouped by business, search and unread | One business’s threads, messages and reply actions |
| Alerts | Cross-business actionable requests, urgency and status | Only this business’s approvals, requests and notices |
| Benefits | Eligible coupons, rewards, wallet passes and expiration | This business’s offers, redemption and rewards |
| Businesses | Directory of connected businesses, search, add (+), favorites | Business home/page, details, settings, optional Loop entry points |
| Activity | Auditable recent interactions and status changes | Timeline limited to this business |
| Settings | Global privacy, notifications, connected accounts, Loop enablement | Per-business permissions, marketing, mute, remove, data controls |

# C3. Business compartments and adding a business

Businesses are not separate installed applications. Each connected business has an identity card, verified name/status, category, optional logo, recent activity, and a consistent home page with Viadere-owned modules.

Provide prominent Add Business (+) in the Businesses directory and a discoverable action near the business selector; connection methods include QR, verified handle, or approved code. Search and favorites support large directories. Do not assume a connected business has a Loop or Brand Kit.

Selecting a business must persist as a clearly labeled context until changed, with an obvious return to All. Never silently switch context during a security-sensitive action.

# C4. Messaging pane

Separate threads by business with sender identity and verification status; no cross-tenant merging of message histories. In All view, list threads with business names, previews, unread counts, and filters.

Support reply, attachments only where approved, search, archiving, mute, and marketing-vs-transactional distinctions. Business-owned branding may decorate the business page or message card but must not obscure verified sender identity.

# C5. Alerts pane

Alerts are distinct from messages: approvals, MFA challenges, age/identity requests, time-sensitive business actions, Loop tasks, and system notices. Present urgency, issuer, action requested, expiry, status, and trust indicators.

All view supports unread, pending, completed, expired, and business filters; selected-business view narrows scope. Expired items must never appear actionable. Dedupe repeated pushes by server event ID. High-risk actions require an appropriate confirmation or device authentication, independent of visual branding.

An alert inbox is the durable source of truth; push delivery is a best-effort attention mechanism. A notification that was not delivered must not erase the pending alert.

# C6. Benefits and business home

Coupons and rewards need their own clear destination rather than being buried in messages. Provide available, saved, redeemed, expired, and eligible filters with expiration and terms visible. Wallet passes may be linked where supported.

Business home is a configurable composition of standard Viadere modules: verified profile, message/contact, offers, rewards, recent activity, standard approvals and, only where enabled, Loops. Brand Kits can style this composition but cannot redefine core navigation.

# C7. Settings and consent

Global settings: account/device security, notification preferences, privacy, connected businesses, Loop opt-in/out, data export and deletion where applicable, accessibility. Per-business settings: transactional alerts, marketing permission, rewards, notification priority/mute, connected status, available Loops, remove/block, and permission history.

Disabling Loops must not remove core messaging or standard features; hide or disable Loop entry points, preserve legally required history and cancel/expire active requests according to policy. Disconnecting a business must revoke scoped tokens and stop new deliveries.

# C8. Anti-clutter and scalability

Do not create one permanent tab per business. Use progressive disclosure, pinned/favorite businesses, search, contextual shortcuts and sensible notification grouping. Show actionable items before promotional content, but avoid an opaque algorithm that hides urgent requests.

Provide empty states for zero businesses and for businesses without messages, benefits or Loops. No duplicate modules, no empty promotional placeholders, no unrequested promotional surfaces.

Cross-business search must respect privacy and authorization boundaries. Sorting/filter state should be understandable and reversible.

# C9. UX acceptance scenarios

One business: user can locate message, approval, coupon, and settings without learning a new navigation system. Fifty businesses: user can find a specific business via search and view only its alerts within a few interactions.

Business without a Brand Kit: uses neutral Viadere appearance. Business without a Loop: standard modules work. Business with a Loop but no API: hosted inbox receives requests. Business with a Brand Kit but no Loop: branded standard pages/widgets work.

A user receiving MFA from one business while browsing another must see the verified source and have a safe, clear way to act without accidental cross-business context confusion.

# SHARED PLATFORM ARCHITECTURE

# D1. Service boundaries

Proposed logical services: Tenant & Connection Registry; Identity/Verification; Messaging; Alerts & Action Registry; Benefits; Business Surface Registry; Brand Kit Service; Loop Definition/Runtime; Hosted Business Inbox; Integration Gateway; Audit/Event Store; Notification Orchestrator; Consumer Organization API. These may initially deploy as modules in fewer services; logical boundaries matter more than microservice count.

Data ownership: Loop Runtime owns workflow state; Brand Kit Service owns style manifests and media; Organization owns user context, business ordering, filters and preferences; core first-party modules own their business data. A shared policy engine evaluates permissions across all three.

# D2. Minimal domain model

| Entity | Important fields |
|---|---|
| Business | business_id, verified_identity, status, category |
| CustomerBusinessConnection | customer_id, business_id, scopes, preferences, created_at |
| BusinessSurface | surface_id, business_id, module_layout, publication_version |
| BrandKit | kit_id, business_id, version, assets, tokens, schedule, frame_id |
| LoopDefinition | loop_id, business_id, schema_version, action_bindings, publication_state |
| LoopInstance | instance_id, loop_version, customer_scope, status, expiry |
| Alert | alert_id, business_id, category, action_ref, urgency, status |
| MessageThread | thread_id, business_id, participants, unread_state |
| Benefit | benefit_id, business_id, type, eligibility, expiry |
| BusinessPreference | customer_id, business_id, marketing, mute, favorites |

# D3. Security boundaries and review

Every request enforces tenant ID from trusted authorization context, never merely a client-provided parameter. Apply row-level/partition authorization, object-level checks, business verification, rate limiting, anti-spam and content moderation.

Keep branding, workflow and organization metadata separately versioned. Signed publication manifests and authenticated transport protect integrity; encrypted storage and narrowly scoped access protect confidentiality.

Test cross-tenant leakage in All views, unauthorized business selector manipulation, forged Loop actions, misleading branded approvals, malicious asset uploads, consent bypass, stale cache, revoked businesses and staff privilege escalation.

# D4. Performance and offline behavior

Target instantaneous local navigation and cached page rendering under ordinary conditions. Organization lists should paginate and incrementally sync. Brand Kit manifests should be small and cached. Workflow submission requires authoritative server acknowledgment; never present offline actions as completed.

A neutral page and alert list must remain readable without branding assets. Offline message drafts may be retained locally where appropriate, but security-sensitive approvals must not be queued silently for later execution.

# D5. Delivery plan and engineering gates

Phase 0: freeze domain model, trust boundary, design system, platform constraints, and user-tested IA prototypes. Phase 1: Organization core (Businesses, Messages, Alerts, Benefits, All/business filter) plus neutral business surfaces. Phase 2: Brand Kit Studio, manifest service, native renderers, caching and schedules. Phase 3: Hosted Loop Studio/runtime/business inbox with consent. Phase 4: connected APIs, approved integrations, AI drafting and advanced commerce.

Each phase requires native iOS/Android accessibility QA, threat modeling, cross-tenant tests, load and cache tests, legal review for regulated use cases, rollback controls and observable failure states.

# D6. Open decisions

Confirm top-level tab arrangement through usability testing, particularly whether Activity belongs in the bottom navigation or under Alerts. Define business-side notification delivery channels and operating-hour semantics. Set exact Brand Kit asset limits and cache budget after device profiling.

Decide pricing and entitlement boundaries for Brand Kits and Loops independently. Define supported commerce connectors and merchant-of-record responsibilities before payment features. Confirm customer-facing terminology for enabling Loops and formal disclosure copy with counsel.

The name “Loops” is a strong working product choice, subject to trademark and marketplace clearance.

# Final architecture statement

A business connects to Viadere, receives a standard business home, messaging, alerts and other eligible first-party modules, optionally applies a Brand Kit, and optionally publishes one or more Loops. The customer sees a single coherent, compartmentalized Viadere app with global views and explicit per-business context. No business gains execution rights inside Viadere’s native code or authority over Viadere’s trust-critical interface.
