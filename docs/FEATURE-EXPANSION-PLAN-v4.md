# Feature expansion plan v4: Loops, Brand Kits, Organization

Maps [`FEATURE-EXPANSION-v4.md`](FEATURE-EXPANSION-v4.md) (product owner, 2026-10-29, "the spec") onto the build as it stands on branch `claude/inspiring-cannon-t5hxfw`. Status: **draft for product-owner review**, 2026-10-30. Docs only; no code changes.

Every work package follows [`../CLAUDE.md`](../CLAUDE.md): Swift end to end, **no Node.js or PHP anywhere** (browser JavaScript only as plain dependency-free files with no Node build step), current stable versions (checked against upstream before any dependency is added), shared logic in `ViadereCore`, security fixes start with a failing test, no control in [`SECURITY.md`](SECURITY.md) is weakened, brand rules (custom design-system components, charcoal/ivory/champagne, no shield imagery). New wire formats are added to `SECURITY.md` §2 in the same change as the code.

Milestones B (Azure adapters, Service Bus, WP-B3) and C (link sessions WP-C1, approval hardening WP-C2, configurable link domain WP-C3) of [`IMPLEMENTATION-PLAN-v3.md`](IMPLEMENTATION-PLAN-v3.md) are being built by other agents. Neither exists in the tree yet (`Server/Sources/ViadereServerKit/Queue` and `.../Link` are absent). This plan treats them as dependencies and names the exact point where each is needed.

## 0. Product-owner decisions already taken (binding for this plan)

| # | Decision | Effect |
|---|---|---|
| FX-1 | The Loop Studio simulator is **not React**. The owner wants a Swift renderer/simulator for the web studio. | Definition, Brand Kit manifest, module registry, layout and attribution rules live in `ViadereCore`; **one Swift presentation model** feeds two renderers: SwiftUI (production, iOS) and a Swift web renderer (studio preview only). Section 5.3 evaluates server-side HTML versus Swift-to-WebAssembly and recommends. |
| FX-2 | **Android: specify only.** | Every contract is platform-neutral with conformance vectors. The Jetpack Compose renderer, Play Integrity and FCM pieces are written as specs (section 4.10). No Android build work in any phase until the owner says so. |
| FX-3 | **Every Loop is reviewed by Viadere before publication**, always, not only risk-dependent ones. | Pipeline: automated policy validation as a hard gate, then human operator review (two-person for high-risk actions), then signed publication; re-review on every revision; post-publication monitoring, customer reports, operator kill switch per Loop and per business. Locked templates are the fast path but still pass review (sections 4.3, 4.12, WP-3.2). Business roles can submit, never publish. |
| FX-4 | **Healthcare is banned entirely**: no healthcare-provider use cases and no collection of health information through Loops or any business-authored content. | Enforced in layers: business verification category, Loop review rules, the field-type allowlist, the Acceptable Use Policy and Business Services Agreement, marketing copy (section 4.13, WP-0.6, WP-1.9, WP-3.2). Replaces the spec's HIPAA-gated path (A8.4); all examples in this plan are non-health. |
| FX-5 | **Commerce is Shopify only; Viadere never takes payments and is never merchant of record.** | A business connects its own Shopify store; Viadere shows catalog and order status and hands the customer to Shopify's hosted checkout. Payment, refunds, taxes, shipping and disputes stay with the merchant. No other connector, no Viadere checkout (section 4.11, WP-4.5, WP-4.6). "Approve estimate" stays separate from payment. |

## 1. Summary

The spec describes three independent subsystems and eight product invariants.

| Subsystem | Owns | Builds on what exists |
|---|---|---|
| **C. Organization** (Phase 1) | One coherent app across many businesses: context selector with All, Messages, Alerts, Benefits, Businesses, per-business settings | `AppTab` has five tabs, none of them the spec's IA (`Packages/ViadereKit/Sources/ViadereKit/Stores/AppModel.swift:7`; bar built in `App/Viadere/Features/MainShell.swift:29-66`). Per-business threads (`ConversationSummary.business`, `Packages/ViadereCore/Sources/ViadereCore/Models/Messaging.swift:70`), a durable server-side request list that never returns expired items (`Server/Sources/ViadereServerKit/Services/InteractionService.swift:295-307`), deterministic security-first ranking (`HomeContent.rank`, `Packages/ViadereKit/Sources/ViadereKit/Stores/HomeContent.swift`), rewards and Wallet (`Packages/ViadereCore/Sources/ViadereCore/Models/Rewards.swift:59`), per-purpose consent (`ConsentGrantRecord`, `Server/Sources/ViadereServerKit/Models/RelationshipModels.swift:37`) |
| **B. Brand Kits** (Phase 2) | Business-owned appearance for Viadere-owned pages and widgets | Only a bare `brand_color` and a free-text `logo_url` per business (`Server/Sources/ViadereServerKit/Models/BusinessModels.swift:16-17`, `Packages/ViadereCore/Sources/ViadereCore/Models/Business.swift:62-63`); neither is read by the app (no match in `App/` or `Packages/ViadereKit`). Design tokens (`App/Shared/DesignSystem/ViadereDesignSystem.swift:23-42`), the hash-pinned console CSP (`Server/Sources/ViadereServerKit/Dashboard/DashboardUI.swift:79-84`) |
| **A. Loops** (Phase 3 hosted; Phase 4 connected/integrated) | Business-authored declarative workflows | Typed, strictly validated declarative interactions (`Packages/ViadereCore/Sources/ViadereCore/Interaction/Interaction.swift:27-60`, `InteractionValidation.swift:190`, `DisplayTextSanitizer.swift:20`, `SECURITY.md` §2.19), a typed capability catalog (`Policy/CapabilityDefinition.swift:237`) and policy engine (`Policy/PolicyEngine.swift:205`, `Server/.../Policy/PolicyService.swift:136`), single-shot decision CAS (`InteractionService.swift:320`), signed webhooks with retry, rotation, ownership proof and DNS-pinned public-IP delivery (`Services/WebhookService.swift:110,239`, `WebhookTransport.swift:32,108`, `SECURITY.md` §2.6, §2.56, §2.73), JWS signing pattern (`Approve/ApprovalResult.swift:99`), nine-role console permissions (`Dashboard/DashboardRoles.swift:9,98`) |

**Product invariants and where they are enforced in this plan.**

| Invariant | Mechanism |
|---|---|
| Core features work with no Loop and no Brand Kit | Standing regression suite "core without extensions" (WP-0.5), run in every phase |
| Business input is declarative data and validated media only | Closed JSON schema in Core (section 4.3), asset re-encoding (section 4.6), reject unknown fields; no URL fields except Viadere-resolved asset refs |
| Viadere owns native components, security language, trust indicators, action semantics | The presentation model has no slot for business-supplied security copy; renderers draw attribution and confirmation chrome themselves (section 4.4) |
| Scale 1 to 50+ businesses without per-business tabs | Single selector, directory with search and favorites (WP-1.4, WP-1.6) |
| Tenant isolation; user picks a context or All | Tenant derived from the authenticated principal only; the `business_id` filter is validated against the caller's relationships (section 4.8) |
| Never imply guaranteed delivery or an external outcome | Outcome state machine with `pending`, `timed_out`, `unknown` (section 4.5); copy lint in the Site and app strings |

**What the spec assumes that is not true today.** The console has no inbox ("Inbox and agent assignment are not offered yet", `Server/Sources/ViadereServerKit/Dashboard/ConsoleSections.swift:96`). There is no object storage or image code anywhere in the server (the only blob store is the audit-head sink planned in WP-B2, `IMPLEMENTATION-PLAN-v3.md:313`). The console roles are nine (`OrgRole`), not the spec's owner/admin/operator/viewer. The app has no Android counterpart.

## 2. Gap table

Status: **Done** (exists and meets the statement), **Partial** (some of it exists), **Gap** (absent), **Conflicts** (the statement conflicts with a repo rule or an owner decision; resolved in section 3), **Later** (deliberately deferred or spec-only). Phase `P0`..`P4`; `P4+` means gated beyond Phase 4 build start.

### 2.1 Product invariants

| ID | Statement | Current state | Status | Phase |
|---|---|---|---|---|
| INV-1 | Messaging, MFA, verification, approvals, coupons, connection work with no Loop/Brand Kit | All of it exists and nothing depends on either (`App/Viadere/Features/*`, `Server/.../Services/*`). Needs a standing test so it stays true | Done | P0 (WP-0.5 guard) |
| INV-2 | A branded page/widget may contain only standard modules; a Loop is optional content | Business page is a fixed native screen (`App/Viadere/Features/Business/BusinessDetailView.swift`); no module registry, no branding | Gap | P1 neutral, P2 branded |
| INV-3 | A Loop works without a Brand Kit and still discloses its author | No Loops | Gap | P3 |
| INV-4 | Business input is declarative data and validated media only; no code, HTML, JS or arbitrary URLs on devices | Interactions are declarative and validated (§2.19). But `logo_url` is a free string (`BusinessModels.swift:17`, passed through at `Services/DirectoryService.swift:36`) | Partial | P2 (replace with asset refs) |
| INV-5 | Viadere controls native components, security language, trust indicators, navigation, action semantics | All native; actions are a closed `ActionRole` enum (`InteractionEnums.swift:145`); display text sanitized | Done | all (kept by tests) |
| INV-6 | Scales 1 to 50+ businesses; not 50 apps or tabs | No per-business tabs, but Home shows only 6 recent businesses (`HomeContent.build recentLimit`), no directory, search or favorites | Partial | P1 |
| INV-7 | Tenant isolation; customer picks a business context or All | Tenant from principal everywhere (`Security/Principals.swift:7,16`); no context selector | Partial | P1 |
| INV-8 | Never imply guaranteed delivery or an external outcome | `DeliveryStatus` queued/sent/delivered/read/failed (`Messaging.swift`), push documented best-effort; no outcome model for business actions | Partial | P3 |

### 2.2 Specification A: Loops

| ID | Statement | Current state | Status | Phase |
|---|---|---|---|---|
| A1.1 | Loop = optional business-authored interaction from Viadere components and approved actions; appearance independent of authorship | Nothing | Gap | P3 |
| A1.2 | Opened from page, widget, message, alert or other authorized entry point | `Interaction.interactionId` links messages to interactions (`Messaging.swift`); no Loop entry model | Gap | P3 |
| A2.1 | Hosted mode: Viadere stores request, manages state, routes to a business inbox | No inbox (`ConsoleSections.swift:96`) | Gap | P3 |
| A2.2 | Connected mode: authenticated, configured endpoint receives verified action events | Webhooks with signing, 300 s replay window, rotation overlap, ownership proof, pause, DLQ-like `dead` state exist (`WebhookService.swift:239`, §2.73). No Loop event types, no outcome ack | Partial | P4 |
| A2.3 | Integrated mode: vetted connector to external platform | Nothing | Later | P4+ |
| A2.4 | One Loop may combine modes step by step | Nothing | Later | P4 |
| A3.1 | Responsive web Business Inbox on common browsers, no desktop app | Console is server-rendered Swift HTML (`Dashboard/DashboardUI.swift`); inbox absent | Gap | P3 |
| A3.2a | In-console queues, unread badges, configurable email alerts | Email sender exists (`Email/EmailSender.swift`); no queues or badges | Gap | P3 |
| A3.2b | Optional browser notifications | Needs service worker, Web Push and CSP changes on the credentialed console | Conflicts | Later |
| A3.3 | Roles owner/admin/operator/viewer, queues, assignment, read receipts, handoff, action audit, hours, retention, export | Nine roles with a single permission matrix (`DashboardRoles.swift:9,98`, `docs/ops/CONSOLE-ROLES.md`), audit chain (`Services/AuditService.swift:76`), retention (`Operations/Retention.swift`), tenant export (`Operations/TenantRights.swift`). No queues, assignment, hours | Partial | P3 |
| A3.4 | An action may stay pending until staff confirm; customer status reflects it | `InteractionStatus` has no staff-pending state (`API/ConsumerDTOs.swift:88`) | Gap | P3 |
| A3.5 | Sensitive data: minimization, policy-gated templates, no ordinary email for protected medical details | Email notices carry no content by design; `Sensitivity` levels. **Superseded by FX-4**: health information is not collected at all, so the rule becomes "no health data, enforced by allowlist and review" (section 4.13); content-free email alerts remain | Conflicts | P3 |
| A4.1 | Registry with schema, risk class, inputs, policy checks, confirmation wording, idempotency, timeout, routing, audit | `CapabilityCatalog` has typed params, sensitivity, consent, UX, audit fields, revocation, but models API capabilities, not button actions; `RequestedAction.id/label` are free strings (`InteractionEnums.swift:150`) | Partial | P3 |
| A4.2 | Bind a button to a registered action; choose from allowed labels only | Roles are a closed enum, labels are free text up to 32 chars | Partial | P3 |
| A4.3a | Acknowledge, confirm attendance, request callback, submit inquiry (low) | `acknowledge` and `reply` kinds (`Payloads.swift:96,115`) | Partial | P3 |
| A4.3b | Check-in/arrival, select option/pickup time (medium) | `choose` kind and `ChoiceOption` (`Payloads.swift:69,82`); no scheduling constraints | Partial | P3 |
| A4.3c | Approve estimate/authorize change (high): terms, amount, stronger confirmation | `authorize` with `MoneyAmount`, assurance policy, Approve v2 signed approvals. Stays separate from payment (FX-5, section 4.11.6) | Partial | P3 (read-only reference), P4 (binding) |
| A4.3d | Identity/age attestation only via the first-party module | Verify module with tier V entitlement and per-request receipts (§2.28, §2.60) | Done | P3 (registry must never offer them; test) |
| A4.3e | Payment/order via approved provider and commerce controls | Nothing. Viadere never takes payments (FX-5): replaced by Shopify checkout handoff (section 4.11); `payment.*` and `order.*` actions stay rejected | Conflicts | P4 (handoff only) |
| A5.1a | Guided templates first; form-based arrangement of approved fields | Message templates only (`ConsoleSections.swift:96`) | Gap | P3 |
| A5.1b | Optional AI assistant drafts declarative definitions, never publishes | Nothing | Later | P4 |
| A5.1c | Advanced mode: schema editing and mappings, never executable client code | Nothing | Later | P4 |
| A5.2 | Lifecycle draft, preview, validation, policy review, signed publication, staged rollout, revoke/retire; in-flight instances pin a version | **FX-3: review is mandatory for every Loop and every revision**, human review by operators, two-person for high risk. Building blocks exist: operator console and passkey step-up (`Dashboard/OperatorRoutes.swift`), two-person approvals (`Dashboard/TwoPerson.swift`), kill switches (`Policy/PolicyOperatorRoutes.swift`). No Loop lifecycle | Gap | P3 |
| A5.2b | (FX-3) Post-publication monitoring, customer reporting, operator kill switch per Loop and per business | Customer `report` role and `reported` status exist for interactions (`InteractionEnums.swift:146`, `ConsumerDTOs.swift:88`); capability switches have global and business scope (§2.29). No Loop-level switch, monitoring or report queue | Gap | P3 |
| A5.3 | Business wording constrained in sensitive flows | `DisplayTextSanitizer`, `InteractionValidation` with impersonation checks (§2.19) reusable | Partial | P3 |
| A5.4 | Studio simulator built in React | React needs a Node build | Conflicts | P3 (resolved by FX-1) |
| A5.5 | Screenshot parity tests on SwiftUI and Compose | No Android; no snapshot tests for a web preview | Later | P3 SwiftUI parity, Android spec-only |
| A6.1 | Loops disabled for customers by default; core unaffected | Nothing | Gap | P3 |
| A6.2 | First enablement: accessible non-skippable education, comprehension checks, explicit agreement; each business authorized separately | Versioned consent grants (`ConsentGrantRecord.version/policy_version`), acknowledgments with document digest (`AcknowledgmentRecord`), onboarding consent step (`Stores/OnboardingViewModel.swift`) are reusable; no Loop consent | Gap | P3 |
| A6.3 | A Loop identifies its creator and the downstream recipient of information | Nothing | Gap | P3 |
| A6.4 | Legal disclosures must not falsely disclaim nonwaivable obligations | Needs counsel copy | Gap | P0 (copy), P3 |
| A6a.1 | Every business Loop, even default-styled, visibly says "Built by [verified name]"; separate from verified badge and "Secured by Viadere" | Verified status exists (`BusinessSummary.verificationStatus`); attribution does not | Gap | P3 |
| A6a.2 | Disclosure at entry point and persistent in primary view; not in a menu, not color-only, not removable by business or Brand Kit; consequential confirmation names the responsible business | Nothing | Gap | P3 |
| A6a.3 | First-party features never carry a misleading "Built by"; authorship from server-controlled immutable publisher identity and signed metadata | Same principle already exists for messages: `MessageAttribution.SenderType.viadere` (`Messaging.swift:11`) | Gap | P3 |
| A6a.4 | Manifest fields `publisher_type`, `publisher_business_id`, `published_definition_id`, `revision`, `attribution_policy_version` | No manifest | Gap | P3 |
| A6a.5 | Renderer enforces attribution regardless of theme; rejects or falls back safely when metadata is absent | Nothing | Gap | P3 |
| A6a.T1 | Test: default-styled business Loop shows "Built by [business]" | | Gap | P3 |
| A6a.T2 | Test: same attribution with a Brand Kit | | Gap | P3 |
| A6a.T3 | Test: first-party module not mislabeled | | Gap | P3 |
| A6a.T4 | Test: concealing or spoofing attribution fails | | Gap | P3 |
| A6a.T5 | Test: accessibility services announce authorship | | Gap | P3 |
| A6a.T6 | Test: notifications and compact surfaces carry a concise business-origin indicator | Notification enrichment is in `Notifications/NotificationEnricher.swift`; titles use the sanitized business name | Gap | P3 |
| A7.1 | Server-side instance with tenant, business, pseudonymous customer, schema version, nonce, expiry, scope | `Interaction` already carries all of these (`Interaction.swift:27-60`, `RelationshipScope.subjectRef`) | Partial | P3 |
| A7.2 | On tap check device, connection, publication status, allowed action, state | `decide` checks device, delegation, business verified, pending, expiry (`InteractionService.swift:320-360`); no publication status | Partial | P3 |
| A7.3 | Idempotent immutable action event with correlation id | Business `idempotencyKey`/`correlationId`, append-only audit; no action-event table | Partial | P3 |
| A7.4 | Deliver to hosted queue or signed webhook with retry/backoff and DLQ | Webhook backoff 30 s to 24 h then dead (§2.73); queue transport is WP-B3 (in progress) | Partial | P3 hosted, P4 connected |
| A7.5 | Outcome ack; accepted, rejected, pending, timed out, unknown modeled separately | Nothing | Gap | P3 |
| A7.6 | Webhook signing, replay protection, rotation, rate limits, allowlisted destinations, tenant-scoped authz, schema validation, audit, abuse controls, least-privilege connectors | Signing, replay, rotation, ownership proof, public-IP DNS pinning, per-endpoint pause, API key scopes all exist; Loop-specific scopes and schema do not | Partial | P4 |
| A7.7 | Signing a definition proves integrity, not downstream safety | Needs console and consent wording | Gap | P3 |
| A8.1 | Shopify/commerce connectors are future candidates | **Shopify only** (FX-5); no other connector | Later | P4 |
| A8.2 | Provider OAuth, server-side APIs, no raw card data | Shopify OAuth (authorization code grant), server-side calls, no card or payment fields exist in the field allowlist (section 4.11) | Later | P4 |
| A8.3 | Catalog sync, orders, refunds, tax, shipping, fraud, disputes need separate designs and merchant-of-record decisions | Decided (FX-5): all of it stays with the merchant on Shopify; Viadere is never merchant of record. Viadere reads catalog and order status only | Conflicts | P4 (superseded) |
| A8.4 | Healthcare workflows need HIPAA assessment, BAA, restricted PHI fields, notification content rules | **Banned (FX-4)** instead of gated. Existing hooks: `BusinessCategory.healthcare` (`Business.swift:24`), enhanced onboarding review for the category (`SECURITY.md` §2.70), `LEG-ID-004` (`SECURITY-TRUST-PLATFORM-SPEC.md:280`) are repurposed for refusal | Conflicts | P0 legal, P1 onboarding, P3 review rules |

### 2.3 Specification B: Brand Kits and business surfaces

| ID | Statement | Current state | Status | Phase |
|---|---|---|---|---|
| B1.1 | Brand Kits are appearance only, usable with or without a Loop | Nothing beyond `brand_color`/`logo_url` | Gap | P2 |
| B1.2 | Pages and widgets are Viadere-owned native surfaces with a module registry (messages, coupons, rewards, details, approvals, recent activity, verification requests, Loops) | `BusinessDetailView` is fixed; `ViadereWidgets` target exists | Partial | P1 |
| B1.3 | Businesses pick modules and arrangements; no control of navigation or security UX | Nothing to control today | Gap | P1 |
| B2.1 | Kit contents: tenant, kit id/version, name, logos, art, tokens, contrast-safe foregrounds, type scale, borders/radius, frame id | Two columns only | Partial | P2 |
| B2.2 | Assets normalized, metadata-stripped, scanned, bounded, served from a dedicated asset domain | No upload path, no object store, no image code; console CSP is `img-src 'self' data:` | Gap | P2 |
| B2.3 | SVG/HTML never accepted as executable render content | No image pipeline; Linux has no ImageIO | Conflicts | P2 |
| B2.4 | Kit never changes button meaning, risk text, permissions, verified indicator, destination, behavior, critical text; Viadere may override for accessibility | Nothing | Gap | P2 |
| B3.1 | Studio: uploads, color pickers, contrast warnings, crop/safe-area, frames, page/widget previews, phone simulation, same-kit previews of messages, coupons, approvals, activity, Loops | Nothing | Gap | P2 |
| B3.2 | Multiple named kits, scheduled windows with timezone, fallback default, optional randomization, overlap validation, deterministic selection, pinning per active interaction | Nothing | Gap | P2 |
| B3.3 | Seasonal Viadere frames are first-party; business selects only offered frames; may schedule seasonal brand art independently | Nothing | Gap | P2 |
| B4.1a | One approved SwiftUI/ActivityKit renderer on iOS | Live Activity views exist (`App/` LiveActivity target); no kit renderer | Gap | P2 |
| B4.1b | One Jetpack Compose renderer on Android | No Android app (FX-2) | Later | spec-only |
| B4.2 | Server distributes small versioned presentation data and asset refs, never code | Nothing | Gap | P2 |
| B4.3 | On-demand/at-connect download, ETag, prefetch, cache budget, LRU, offline fallback, atomic update (sizes are targets) | `ViadereKit/Storage` has preferences and secrets only | Gap | P2 |
| B4.4 | Render neutral immediately if asset missing; never block approval or sign-in on branding | Approval path has no asset fetch today | Gap | P2 (test-first) |
| B5.1 | Push banners are system-controlled | Actionable notifications via service/content extensions | Done | all |
| B5.2 | Live Activities only for genuinely ongoing states | `LiveActivityPolicy` (`Models/LiveActivity.swift:138`), `ActivityLiveEligibility` | Done | all |
| B5.3 | App Clips are constrained, not a notification replacement | Clip creates a request-key-only D0 account | Done | all |
| B5.4 | Android notification and background policies | No Android | Later | spec-only |
| B6.1 | Each module exposes input schema, sizes, interaction permissions, accessibility contract, risk class, platform matrix | Nothing | Gap | P1 |
| B6.2 | Page templates arrange modules; widgets use constrained slots | Nothing | Gap | P1 pages, P2 widgets |
| B6.3 | Kit applied after layout validation; Loop modules resolved only if enabled and authorized | Nothing | Gap | P2 / P3 |
| B6.4 | Neutral styling never implies a business Loop is first-party | Covered by A6a | Gap | P3 |

### 2.4 Specification C: Organization

| ID | Statement | Current state | Status | Phase |
|---|---|---|---|---|
| C1.1 | One Viadere; strong data separation; All aggregates only authorized items; selecting a business keeps primary nav | Separation yes; no selector | Partial | P1 |
| C1.2 | Stable IA: Messages, Alerts, Benefits, Businesses; Activity and Settings as tabs or secondary after usability validation; one selector, All default | Tabs are home, activity, connect, messages, settings (`AppModel.swift:7`) | Gap | P0 test, P1 build |
| C2.1 | Messages: All = unified list grouped by business, search, unread; selected = one business | One flat list, no grouping/search/filter (`Stores/MessagesViewModels.swift:11`) | Partial | P1 |
| C2.2 | Alerts: All = cross-business actionable list with urgency and status; selected = that business | Home pending list (`HomeViewModel.swift:30`), Activity "needs you" phase, Approve v2 (`Stores/ApproveController.swift`), verification requests, security notices live in separate stores | Partial | P1 |
| C2.3 | Benefits: All = coupons, rewards, passes, expirations; selected = that business | `RewardsView`, `BusinessRewardsView`, Wallet; reached only from Home and business detail | Partial | P1 |
| C2.4 | Businesses: directory, search, add (+), favorites; selected = business home | Connect tab is the add flow (`Features/Connect/ConnectView.swift:7`); recents on Home; `BusinessDetailView` | Partial | P1 |
| C2.5 | Activity: auditable recent interactions; selected = that business | `ActivityFeed` with category chips (`Activity/ActivityModels.swift:33,140`), no business filter | Partial | P1 |
| C2.6 | Settings: global privacy, notifications, accounts, Loop enablement; per-business permissions, marketing, mute, remove, data | Global `SettingsView` and per-business consents exist; no mute, no Loop toggle | Partial | P1, P3 |
| C3.1 | Businesses are compartments with identity card, verified status, category, logo, recent activity, consistent home | `BusinessDetailView`; logo never rendered | Partial | P1 |
| C3.2 | Prominent Add Business (+) in the directory and near the selector; QR, handle, code | All three methods work in Connect (`ConnectSource`, `QRScannerScreen`) | Partial | P1 |
| C3.3 | Search and favorites for large directories | None | Gap | P1 |
| C3.4 | Do not assume a Loop or Brand Kit | Nothing assumes either | Done | P1/P2 tests |
| C3.5 | Selected business persists as a labeled context with obvious return to All; never switch silently during a sensitive action | None | Gap | P1 |
| C4.1 | Per-business threads with sender identity and verification; no cross-tenant merging | `ConversationSummary.business: BusinessSummary`; sessions per business (`Services/ConversationService.swift`) | Done | all |
| C4.2 | All view lists threads with business names, previews, unread, filters | Names, previews, unread yes; filters no | Partial | P1 |
| C4.3a | Reply | `ConversationViewModel.send` | Done | all |
| C4.3b | Attachments only where approved | None | Later | P4 |
| C4.3c | Search, archive, mute, marketing-vs-transactional distinction | None. Message bodies are field-encrypted (`Services/ConversationService.swift:120`), so search must be on-device | Gap | P1 |
| C4.4 | Branding must not obscure verified sender identity | Nothing | Gap | P2 (renderer invariant) |
| C5.1 | Alerts distinct from messages with urgency, issuer, action, expiry, status, trust indicators | Pieces exist in separate stores | Partial | P1 |
| C5.2 | All-view filters unread, pending, completed, expired, business | Server list filters status only; offset cursor (`InteractionService.swift:295-307`) | Gap | P1 |
| C5.3 | Expired items never actionable | Server filter `expiresAt > now` (`InteractionService.swift:303`), `decide` returns 410 on expiry, client `isExpired` (`HomeContent.swift`) | Done | all |
| C5.4 | Dedupe repeated pushes by server event id | Thread identifiers per business and "already handled" state (`NotificationEnricher.swift:126`); no event-id dedupe | Partial | P1 |
| C5.5 | High-risk actions need confirmation or device authentication independent of branding | Assurance policy, signed decisions, D0/D1/D2 tiers (`Services/DeviceTrust.swift:17`) | Done | all |
| C5.6 | Alert inbox is the durable source of truth; push is best-effort; an undelivered push never erases a pending alert | Interactions are server rows loaded on launch/refresh; Approve v2 and verification use other stores | Partial | P1 |
| C6.1 | Benefits destination with available, saved, redeemed, expired, eligible filters, expiry and terms; Wallet links | `Reward.Status` available/redeemed/expired/revoked; server `RewardEligibility.swift`; no "saved" | Partial | P1 |
| C6.2 | Business home = configurable composition of standard modules | Fixed screen | Gap | P1 |
| C6.3 | Brand Kits style but cannot redefine navigation | | Gap | P2 |
| C7.1 | Global settings: security, notifications, privacy, connected businesses, Loop opt-in/out, export and deletion, accessibility | All but Loop opt-in and a connected-businesses list exist (`Settings/SettingsView.swift`, `DataExportView.swift`) | Partial | P1, P3 |
| C7.2 | Per-business: transactional alerts, marketing, rewards, priority/mute, status, available Loops, remove/block, permission history | Purpose consents, disconnect, history (`BusinessDetailViewModel.swift`, `ConsentHistoryView`); no mute, priority, block, Loops | Partial | P1, P3 |
| C7.3 | Disabling Loops keeps core; hides entry points; preserves required history; cancels/expires active requests per policy | | Gap | P3 |
| C7.4 | Disconnecting revokes scoped tokens and stops new deliveries | Relationship disconnect with `cancelsPending` revocation in the catalog; needs All-view and Loop tests | Partial | P1, P3 |
| C8.1 | No tab per business; progressive disclosure, favorites, search, shortcuts, grouping | No per-business tabs; the rest absent | Partial | P1 |
| C8.2 | Actionable before promotional; no opaque ranking that hides urgent items | Deterministic rank, security first, marketing never actionable (`HomeContent.rank`, `isActionable`) | Done | all |
| C8.3 | Empty states for zero businesses and businesses with no messages, benefits or Loops; no duplicate modules or placeholders | `ViadereEmptyState` on Home only | Partial | P1 |
| C8.4 | Cross-business search respects boundaries | None | Gap | P1 |
| C8.5 | Sort/filter state understandable and reversible | None | Gap | P1 |
| C9.1 | One business: find message, approval, coupon, settings without learning new nav | Not validated | Gap | P0 test |
| C9.2 | Fifty businesses: find one by search and see only its alerts within a few interactions | | Gap | P0 test, P1 |
| C9.3 | No Brand Kit: neutral appearance | By absence | Done | P2 test |
| C9.4 | No Loop: standard modules work | By absence | Done | P3 test |
| C9.5 | Loop without API: hosted inbox receives requests | | Gap | P3 |
| C9.6 | Brand Kit without Loop: branded standard pages work | | Gap | P2 |
| C9.7 | MFA from business A while browsing B: verified source shown, safe clear action, no context confusion | `AppModel.presentedApproval` is a global modal showing the issuing business (`Stores/AppModel.swift`, `Approval/ApprovalSheet.swift`) | Partial | P1 |

### 2.5 Shared platform (D)

| ID | Statement | Current state | Status | Phase |
|---|---|---|---|---|
| D1.1 | Thirteen logical services | Existing modules cover Tenant/Connection (`RelationshipService`), Identity/Verification (`Verify/*`), Messaging, Benefits (`RewardsService`, `Wallet/*`), Audit, Integration Gateway (partial: webhooks), Notification Orchestrator (partial: `Push/*`, `Channels/*`). New: Surface Registry, Brand Kit, Loop Definition/Runtime, Hosted Inbox, Organization API, Action Registry | Partial | P0 map (section 4.1) |
| D1.2 | Modular monolith; logical boundaries over service count | ADR-0010 single image with api/worker roles | Done | P0 (formalize as SwiftPM targets) |
| D1.3 | Data ownership per service; shared policy engine across all three | `PolicyEngine` is pure Core; extend inputs | Partial | P0, P3 |
| D2.1 | Business | `BusinessRecord` | Done | n/a |
| D2.2 | CustomerBusinessConnection with scopes, preferences | `RelationshipRecord` + `ConsentGrantRecord`; preferences missing | Partial | P1 |
| D2.3 | BusinessSurface | | Gap | P1 |
| D2.4 | BrandKit | | Gap | P2 |
| D2.5 | LoopDefinition | | Gap | P3 |
| D2.6 | LoopInstance | | Gap | P3 |
| D2.7 | Alert | Derived from `InteractionRecord`, approve requests, verification requests, security notices; no unified type | Partial | P1 |
| D2.8 | MessageThread | `conversation_sessions`, unread state | Done | n/a |
| D2.9 | Benefit | `Reward`, Wallet passes; no unified type | Partial | P1 |
| D2.10 | BusinessPreference | Marketing is a consent; favorites and mute absent | Partial | P1 |
| D3.1 | Tenant from trusted context; object-level checks; verification; rate limits; anti-spam; moderation | Principals, `IPRateLimitMiddleware`, `Platform/AbuseService.swift`; content moderation of Loop text absent | Partial | P0 harness, each WP |
| D3.2 | Separately versioned branding/workflow/organization metadata; signed manifests; encrypted storage | `FieldCipher` for sensitive columns; no manifests | Gap | P2, P3 |
| D3.T1 | Test: cross-tenant leakage in All views | | Gap | P1 |
| D3.T2 | Test: selector manipulation | | Gap | P1 |
| D3.T3 | Test: forged Loop actions | | Gap | P3 |
| D3.T4 | Test: misleading branded approvals | | Gap | P2 |
| D3.T5 | Test: malicious asset uploads | | Gap | P2 |
| D3.T6 | Test: consent bypass | | Gap | P3 |
| D3.T7 | Test: stale cache | | Gap | P2 |
| D3.T8 | Test: revoked businesses | Verified-business check at decide (`InteractionService.swift:348`); no All-view or kit cases | Partial | P1 |
| D3.T9 | Test: staff privilege escalation | Role grant policy and matrix tests exist (`DashboardRoles.swift`, `WP6RolesTests`); inbox permissions new | Partial | P3 |
| D4.1 | Instant local navigation; paginated, incrementally synced lists | Offset cursors only | Gap | P1 |
| D4.2 | Workflow submission needs authoritative server ack; offline never shown as complete | Decisions require the server response | Partial | P3 |
| D4.3 | Neutral page and alert list readable without branding assets | | Gap | P2 |
| D4.4 | Offline drafts allowed; sensitive approvals never queued silently | Draft is in memory; approvals never queue | Partial | P1 |
| D5.1 | Phases 0 to 4 | This document | Gap | P0 |
| D5.2 | Per-phase gates: accessibility QA, threat model, cross-tenant tests, load/cache tests, legal review, rollback, observable failures | Kill switches (`Operations/PlatformFlags.swift`, `docs/ops/KILL-SWITCHES.md`) and metrics (`Operations/Metrics.swift`) exist; Android QA spec-only | Partial | each |
| D6.1 | Tab arrangement and Activity placement by usability test | | Gap | P0 |
| D6.2 | Business delivery channels and operating-hour semantics | | Gap | P0, P3 |
| D6.3 | Asset limits and cache budget after device profiling | | Gap | P2 |
| D6.4 | Independent pricing and entitlements for Brand Kits and Loops | `EntitlementService` grants tiers and capabilities with justification (`Policy/EntitlementService.swift`) | Partial | P0 decision |
| D6.5 | Commerce connectors and merchant-of-record | Decided (FX-5): Shopify only, merchant is the seller, Viadere never merchant of record | Later | P4 |
| D6.6 | Customer-facing Loop terminology and disclosure copy with counsel | | Gap | P0 |
| D6.7 | "Loops" trademark and marketplace clearance | | Conflicts | P0 |

**Counts by status:** Done 15, Partial 48, Gap 75, Conflicts 8, Later 11 (total 157)

## 3. Conflicts and resolutions

| # | Spec statement | Conflicts with | Resolution (recommended) |
|---|---|---|---|
| K1 | A5: studio simulator "built in React" | CLAUDE.md rule 4 (no Node anywhere, including build tooling and design tooling); owner decision FX-1 | Swift presentation model in Core; web preview rendered by the server from that model (section 5.3). Swift-to-WebAssembly is a gated spike, not the baseline |
| K2 | B4/A5: Jetpack Compose renderer and Compose screenshot parity | FX-2 (no Android build) | Spec only. Manifest, render tree and attribution rules are platform-neutral with conformance vectors under `docs/protocol/vectors/`, so a later Compose renderer can pass the same tests |
| K3 | A8/A3: healthcare/HIPAA path and the spec's own examples (a doctor's office check-in, A2 table) | FX-4 (banned); `LEG-ID-004` | Replace "gate" with "ban", enforced in five layers (section 4.13): verification category, review rules, field allowlist, AUP/BSA, marketing. The spec example is replaced in all plan material by a salon or repair-shop appointment check-in. The spec's HIPAA/BAA language becomes dead text; ask the owner to amend the spec at the next revision |
| K4 | A8: commerce and payment actions; merchant of record | FX-5 | Viadere is never merchant of record and takes no payment. Shopify-only wrapper with checkout handoff (section 4.11). Registry keeps `payment.*` and `order.*` rejected. The spec's "separate designs for refunds, taxes, shipping, fraud, disputes" are not built: they stay with the merchant |
| K5 | D6: name "Loops" | Unresolved trademark clearance | Use the codename **Loops** in repo and docs only; all customer copy goes through a single string catalog so a rename is one change. Counsel runs clearance in Phase 0; Phase 3 cannot ship customer copy before it returns |
| K6 | B2: SVG ingestion ("rasterize or sanitize") | A safe image pipeline; Linux Swift has no ImageIO | Accept **PNG and JPEG only** in Phase 2. Decode with a memory-safe Swift decoder, re-encode to a fresh PNG (drops metadata, ICC and trailing data), bound dimensions and bytes. SVG is refused with a clear message. A restricted-subset SVG-to-raster path is optional WP-2.9 behind a decision. Library choice (pure-Swift PNG/JPEG decoders versus a sandboxed C codec container) is verified against upstream at build time, per CLAUDE.md rule 1, with a fuzz corpus as an acceptance gate |
| K7 | A3: optional browser notifications | Console CSP is `default-src 'none'` plus one hash-pinned script (`DashboardUI.swift:79-84`); Web Push needs a service worker, push-service connections and carries content to third-party push services | Phase 3 ships queues, unread badges, email alerts and an in-console polling indicator. Browser notifications are Later, built (if at all) as separate plain JS and service worker files on a payload-free ping ("new request"), with a CSP delta reviewed in its own ADR |
| K8 | B2/B4: dedicated asset domain | AASA and universal links are served by the API origin (`Web/WebRoutes.swift:41`); API sets `Cross-Origin-Resource-Policy: same-origin` and CSP `default-src 'none'` (`Security/Middleware.swift:17-20`); console and Site CSP allow images from `'self'` only (`DashboardUI.swift:80`, `Site/Sources/SiteKit/Layout.swift:28`) | Separate registrable host, e.g. `assets.viadere.example` configured like `LINK_DOMAIN` (WP-C3); Cloudflare in front of an Azure Blob container through a cache rule; **never** cookie-bearing, never in AASA. Only the console Studio preview and the preview iframe gain `img-src` for that host. The app fetches assets with a pinned URLSession (existing `PinningSessionDelegate`) by content hash, so a stale or hostile URL cannot change content. Response headers: `nosniff`, `Content-Type: image/png`, `CORP: cross-origin`, immutable cache by hash |
| K9 | A3: roles owner/admin/operator/viewer | Existing nine-role matrix, doc generated from code | Do not add roles. Add permissions `viewInbox`, `manageInbox`, `manageLoops` (draft and **submit** for review), `manageBrandKits`. There is **no business `publishLoops` permission**: publication is done only by Viadere operators after review (FX-3). Mapping: owner and Organization Admin `manageLoops`; Messaging Operator `viewInbox`/`manageInbox`; Auditor and Analyst `viewInbox` read-only. Matrix test keeps `CONSOLE-ROLES.md` in sync |
| K10 | A2.3/A8: integrations "subject to scope and policy" | Webhook delivery is public-IP-pinned but a connector holds outbound credentials | One connector only (Shopify, FX-5). Shopify app secrets in Key Vault; per-shop access tokens encrypted with `FieldCipher` (one KMS-wrapped data key, not one vault secret per shop); never logged (`Security/LogRedaction.swift`) |
| K11 | A6/D6: disclosure copy | Cannot be written by engineering | Copy is a counsel deliverable in Phase 0; the app ships it as versioned consent text with a digest (reuse the acknowledgment document-digest mechanism) |
| K12 | Toolchain note | CLAUDE.md lists Swift 6.4.1 as current, while swift.org's Wasm guide fetched 2026-10-30 uses `swift-6.4.2-RELEASE_wasm` | The versions table is behind by one patch release. Not changed here (docs-only scope for this plan); bump in the next dependency refresh, which WP-2.x and the Wasm spike depend on anyway (SDK and toolchain must match exactly) |
| K13 | FX-5 and Apple App Review | Guideline 3.1.3(e) permits non-IAP payment for physical goods and for services consumed outside the app, and 3.1.1 requires IAP for unlocking in-app functionality (checked 2026-10-30 at developer.apple.com/app-store/review/guidelines) | Shopify handoff only for physical goods and out-of-app services; the Shopify review rule rejects digital/in-app products. Open the hosted checkout in the system browser sheet, not an embedded web view. App Review notes explain the merchant relationship. Risk and mitigation in section 4.11.5 |

## 4. Architecture

### 4.1 Logical services onto the modular monolith (D1)

All new code is Swift in the existing targets. No new deployable: the API and worker roles from WP-B2 (`ROLE=api|worker`) host everything. New server source folders (each an internal module boundary with its own tests and its own Fluent models; cross-module access goes through a small service protocol, never another module's models):

| D1 service | Home in the repo | Notes |
|---|---|---|
| Tenant & Connection Registry | existing `Services/RelationshipService.swift`, `Models/RelationshipModels.swift` | WP-C1 adds link-session columns here; Phase 1 adds nothing to this table, it adds `business_preferences` beside it |
| Identity/Verification | existing `Verify/*`, `Approve/*` | Unchanged; Loops reference, never reimplement |
| Messaging | existing `Services/ConversationService.swift`, `SMS/*`, `Channels/*` | Phase 1 adds `conversation_state` (archive/mute) |
| Alerts & Action Registry | new `Alerts/` (consumer inbox read model) and Core `Actions/` (registry, section 4.9) | Alerts read model is a query layer over existing durable rows |
| Benefits | existing `Services/RewardsService.swift`, `Wallet/*` | New thin `Benefits/BenefitsQuery.swift` for the unified list |
| Business Surface Registry | new `Surfaces/` | Module layout per business, publication version |
| Brand Kit Service | new `BrandKits/` + `Assets/` | Kits, schedules, manifest signing, asset ingestion |
| Loop Definition/Runtime | new `Loops/` | Definitions, publications, instances, action events |
| Hosted Business Inbox | new `Dashboard/ConsoleInbox*.swift` over `Loops/` tables | Server-rendered HTML like the rest of the console |
| Integration Gateway | existing `Services/WebhookService.swift` plus new `Loops/LoopWebhooks.swift` | Phase 4 |
| Audit/Event Store | existing `Services/AuditService.swift` | Every state change below writes an event; new event types listed in each WP |
| Notification Orchestrator | existing `Push/*`, `Channels/*`, queue push from WP-B3 | Loop tasks and alert updates use the same `push` queue |
| Consumer Organization API | new `Routes/OrganizationRoutes.swift` | Thin; routes declared in Core `API/APIRoutes.swift` per the route-catalog rule |

Core gains four folders: `Organization/` (context, filters, alert and benefit DTOs), `Surfaces/` (module registry, layout validation), `BrandKits/` (manifest, tokens, schedule selection, contrast rules), `Loops/` (definition schema, validator, action registry, render tree, attribution rules). All are pure and tested on Linux (CLAUDE.md: shared logic in Core).

### 4.2 Data model (D2) and migrations

Existing tables are extended only additively and forward-only, as in `DeviceFirstAccounts.v1`. SQLite (tests) and PostgreSQL must both pass.

| Entity | Mapping | Migration |
|---|---|---|
| Business | `BusinessRecord`; `logo_url` retired in favor of asset refs after `BrandKits.v1` (column kept, no longer served) | n/a |
| CustomerBusinessConnection | `RelationshipRecord` + `ConsentGrantRecord`; scopes = consents and approved capabilities | n/a |
| BusinessPreference | new `business_preferences (consumer_id, business_id, favorite BOOL, favorite_rank INT NULL, mute_level TEXT {none, promotional, all_non_essential}, mute_until TIMESTAMP NULL, updated_at; PK (consumer_id, business_id))`. **Mute never applies to purposes `security` and `accountService`**: server rule from `InteractionPurpose.isRevocable` (`InteractionEnums.swift`) | `Organization.v1` |
| (conversation state) | `conversation_state (consumer_id, session_id, archived_at NULL, muted BOOL; PK (consumer_id, session_id))` | `Organization.v1` |
| Alert | not a table. A read model `AlertItem {alert_id = "{source}:{id}", source: interaction|approve_request|verification|security_notice|loop_task, business, category, urgency, status, expires_at, action_ref}` assembled from durable rows. Seen state: `alert_seen (consumer_id, alert_id, seen_at; PK both)` (per viewer, because household delegates see others' items, `InteractionService.swift:281`) | `Organization.v1` |
| Benefit | read model over `Reward`, loyalty accounts and Wallet passes; `saved` stored as `benefit_saved (consumer_id, reward_id)` | `Organization.v1` |
| BusinessSurface | `business_surfaces (id, business_id, version INT, status {draft, published}, layout_json, published_at, published_by)`; unique `(business_id, version)`; one published row per business | `Surfaces.v1` |
| BrandKit | `brand_kits (id, business_id, name, version, status, tokens_json, frame_id NULL, created_by, updated_at)`, `brand_assets (id, business_id, sha256, kind {logo, mark, background, art}, width, height, bytes, state {pending, ready, rejected}, created_at)`, `brand_kit_assets (kit_id, asset_id, slot)`, `brand_kit_schedules (id, business_id, kit_id, timezone, starts_at, ends_at NULL, priority INT, weight INT NULL, is_default BOOL)`, `brand_manifests (business_id, version, manifest_json, signature, key_ref, created_at)` | `BrandKits.v1` |
| LoopDefinition | `loop_definitions (id, business_id, key, created_by)`, `loop_revisions (id, definition_id, revision INT, schema_version, definition_json, definition_hash, state {draft, validating, validation_failed, in_review, changes_requested, approved, published, suspended, revoked, retired}, risk_class, created_by, submitted_at NULL, published_at NULL)`; unique `(definition_id, revision)`; revisions past `draft` are immutable (DB trigger in PostgreSQL, CAS guard in tests); any edit creates a new revision that starts the pipeline again. `loop_reviews (id, revision_id, stage {automated, reviewer_1, reviewer_2}, reviewer_id NULL, decision {pass, fail, approve, reject, request_changes}, rule_hits_json, notes (field-encrypted), at)`, `loop_reports (id, publication_id, consumer_id, reason, at, state)` and `loop_switches` are described in section 4.12 | `Loops.v1` |
| Publication | `loop_publications (published_definition_id, revision_id, manifest_json, signature, key_ref, rollout_percent, rollout_started_at, suspended_at NULL, revoked_at NULL, attribution_policy_version)` | `Loops.v1` |
| LoopInstance | `loop_instances (id, publication_id, revision pinned, business_id, consumer_id, subject_ref, entry_point, state, nonce_hash, expires_at, created_at)` | `Loops.v1` |
| Action event | `loop_action_events (id, instance_id, step_id, action_type, action_schema_version, input_json (field-encrypted), idempotency_key, correlation_id, outcome {accepted, rejected, pending, timed_out, unknown}, outcome_at, created_at)`; **append-only** (no UPDATE grant, same technique as `audit_events`, `Migrations/RuntimeRoleGrants.swift:30-31`); outcomes are new rows in `loop_action_outcomes (event_id, outcome, reason, source {staff, webhook, system}, at)` | `Loops.v1` |
| Inbox | `inbox_items (id, business_id, instance_id, event_id, queue_id, assignee NULL, state {new, open, handed_off, closed}, first_read_at, ...)`, `inbox_queues (id, business_id, name, hours_json, timezone)`, `inbox_reads (item_id, staff_id, read_at)`, `inbox_notes` (field-encrypted) | `Inbox.v1` |
| Loop consent | `loop_consents (consumer_id, business_id NULL for global, text_version, text_digest, comprehension_passed_at, granted_at, revoked_at NULL)`; global row required before any per-business row | `Loops.v1` |
| Entitlements | `EntitlementService` gains kinds `brand_kits` and `loops` (independent, per D6.4) | no schema change if kinds are strings; verify in WP-0.1 |

Rules shared by all new tables: every row carries `business_id` (or `consumer_id`), every query is built from the authenticated principal, not from a request field; payloads that can hold customer text use `ctx.cipher.seal(..., context:, rowId:)` like webhook bodies (`WebhookService.swift:131`); retention entries are added to `docs/ops/DATA-INVENTORY.md` in the same change.

### 4.3 Declarative Loop definition (JSON schema sketch)

The definition is closed data. Unknown members are rejected on validation (not ignored). All strings pass `DisplayTextSanitizer` and the impersonation checks in §2.19, with length limits and a per-risk-class allowlist of free-text slots. No URL-valued field exists except `asset_ref`, which only names an asset already owned by the same business.

```jsonc
{
  "schema_version": 1,
  "key": "pickup-scheduling",
  "title": "Schedule your pickup",                 // <= 60, sanitized
  "risk_class": "medium",                          // derived by the validator, never trusted from input
  "entry_points": ["business_page", "message", "alert"],
  "appearance": { "mode": "standard" },            // "standard" | { "mode": "brand_kit", "kit": "<kit key>" }
  "steps": [
    { "id": "s1", "type": "form",
      "fields": [
        { "id": "slot", "type": "single_choice", "label_key": "choose_time",
          "options_from": { "source": "static", "values": [ { "id": "am", "label": "Morning" }, { "id": "pm", "label": "Afternoon" } ] },
          "required": true } ],
      "actions": [ { "id": "confirm", "action": "select_option", "label": "continue", "next": "s2" } ] },
    { "id": "s2", "type": "summary",
      "actions": [ { "id": "submit", "action": "acknowledge", "label": "send_request", "routing": { "mode": "hosted", "queue": "pickups" }, "next": "done" } ] },
    { "id": "done", "type": "result", "show_outcome": true }
  ],
  "limits": { "expires_in_seconds": 86400, "max_steps": 8, "max_fields_per_step": 6 }
}
```

Rules enforced by `LoopDefinitionValidator` (Core, tested on Linux): step graph is acyclic and reachable; every `action` is a registered action type (section 4.9) and its `label` is a `label_key` from that action's allowed-label set (the business picks among Viadere-written labels; custom label text is allowed only for `low` risk actions and still sanitized); field types come from a fixed set (`single_choice`, `multi_choice`, `short_text`, `date`, `time_slot`, `yes_no`, `acknowledgement`); sensitive free text is refused in `high` risk and in the `medical`-like categories; the field-type allowlist contains **no** field for secrets, payment card or bank data, government ids or any medical or health information, so such data cannot be expressed (FX-4, FX-5; pattern and keyword checks on labels and titles are an extra tripwire, never the control); `routing.mode` is `hosted` in Phase 3, `connected` in Phase 4; unknown keys fail. The validator output is a `LoopValidationReport` (errors, warnings, derived risk class, required review level) used by Studio and by the publish gate. The same definition is the input to the presentation model (section 4.4).

### 4.4 Presentation model, renderer contract and attribution (FX-1)

One platform-neutral value type in Core, **`PresentationTree`**: a closed set of nodes (`Screen`, `Header`, `AttributionBar`, `Text`, `FieldGroup`, `Choice`, `ActionBar`, `ConfirmationPanel`, `OutcomeStatus`, `ModuleSlot`, `Notice`) with semantic style roles (`primary`, `secondary`, `danger`, `surface`), not colors or fonts. It is produced by pure functions:

`PresentationBuilder.build(publication manifest, step, instance state, brand tokens?, context) -> PresentationTree`

Two renderers consume it and nothing else:

| Renderer | Where | Role |
|---|---|---|
| SwiftUI `PresentationView` | `App/Shared/` using design-system components (`ViadereHeader`, `ViadereNotice`, `ViadereChip`, ...) | **Production** on iOS |
| Swift web renderer | `Server` (baseline) | **Preview only**, labeled "Preview, not exactly what customers see" |

Contract points, all enforced by the builder or the renderers, never by business data:

1. `AttributionBar` is inserted by the builder from the signed manifest (`publisher_type = business` gives "Built by {verified business name}" with the name taken from the verified business record at render time, not from the definition). It is the first node of every Loop screen, cannot be omitted by the definition, has fixed role `primary` contrast, and is exempt from Brand Kit overrides. `publisher_type = viadere` gives no "Built by" node.
2. If the manifest is missing, unsigned, fails verification against the pinned Viadere publication key, has an unknown `attribution_policy_version`, or its `publisher_business_id` differs from the business the instance belongs to, the renderer shows a neutral "This request can't be shown" state and offers only Close/Report. It never renders the body.
3. Confirmation panels for consequential actions are generated by the builder from the action registry (section 4.9): they name the responsible business, the exact effect and any amount; the definition supplies only registered parameters.
4. Accessibility: `AttributionBar` has an accessibility label "Built by {name}, a business on Viadere" read first (A6a.T5); compact surfaces (notification titles, Live Activity, widget) use the concise origin indicator from `PresentationBuilder.compactOrigin(...)` (A6a.T6).
5. Brand tokens are applied by renderers after layout validation and clamped by Core (`ContrastPolicy`: minimum contrast ratio checked per role against the surface; failing tokens are replaced by neutral ones, B2.4 "Viadere may override").

**Signed publication manifest** (JWS ES256 over canonical JSON, same pattern as `ApprovalResultJWS`, `Approve/ApprovalResult.swift:99`, signed with a dedicated KMS key `loop-publication` via the `KeyManagementService` from WP-B2; the key has no other use):

```json
{ "v": 1, "publisher_type": "business", "publisher_business_id": "…", "published_definition_id": "…",
  "revision": 3, "attribution_policy_version": 1, "definition_hash": "sha256:…",
  "rollout": {"percent": 100}, "valid_from": "…", "not_after": "…", "kid": "loop-publication-v1" }
```

The device pins the public key set (served with the key directory, `KeyDirectory/*`, so rotation and transparency apply). `not_after` plus server-side revocation (instance start and every action call check `revoked_at`) bounds the life of a leaked or retired definition. First-party Viadere modules never go through this path.

**A6a acceptance tests** become Core tests over `PresentationBuilder` (no UI needed) plus SwiftUI snapshot/accessibility tests on a macOS runner: T1 default style, T2 with kit, T3 first-party module, T4 a definition containing `"Built by Viadere"`-like text or a Brand Kit that sets the bar's color to the background (clamp and impersonation check hold), T5 accessibility tree order and label, T6 compact origin string.

### 4.5 Loop action events, queues and outcomes (rides on WP-B3)

Flow (hosted, Phase 3):

1. Customer taps. `POST /v1/loops/instances/{id}/actions` with `action_id`, inputs, `idempotency_key`, device-signed request (`VIADERE-SIG-V1`); high-risk actions additionally carry a signed decision built exactly like `DecisionPayload` (existing verifier, `InteractionService.decide`).
2. Server checks, in this order and each audited on denial: authenticated device and tier; relationship active and business verified (`DirectoryService.verified`); Loop consent for this business; publication not revoked and instance pinned revision valid; action allowed in the current step; instance not expired; input matches the registered schema; rate limits.
3. In **one transaction**: insert `loop_action_events` (unique on `(instance_id, idempotency_key)`; replay returns the stored result), advance instance state with CAS, insert `inbox_items` (hosted) or an outbox row for the webhook (connected), insert the `outbox_messages` row for pushes/emails. This is the outbox from WP-B3 (`IMPLEMENTATION-PLAN-v3.md:322`).
4. Consumers (idempotent via `processed_messages`) send the staff email alert, the customer push, and for connected mode the webhook. Messages are versioned ids-only envelopes: `{"v":1,"type":"loop.action.deliver","id":"<outbox>","ref":"<event id>"}`. Unknown `type`/`v` is dead-lettered, never executed (same rule as ADR-0014). New queues: `loop-delivery` (maxDelivery 8) and `loop-timeout` (scheduled message at `expires_at`/response deadline; also swept by the maintenance job).
5. Outcomes are separate states and the customer UI maps them to distinct, non-promissory wording:

| Outcome | Meaning | Customer wording (example) |
|---|---|---|
| `accepted` | Business confirmed | "{Business} confirmed" |
| `rejected` | Business declined | "{Business} couldn't do this" |
| `pending` | Received by Viadere, not yet confirmed by the business | "Sent to {Business}. Waiting for them to confirm." |
| `timed_out` | No answer by the deadline | "{Business} hasn't answered. You can contact them." |
| `unknown` | Delivery to the business could not be confirmed (connected mode failure, DLQ) | "We couldn't confirm that {Business} received this." |

Delivered-to-Viadere is never described as delivered-to-business. `pending` is the only state set at submission. Staff `accept`/`reject` calls and connected-mode outcome callbacks are themselves idempotent events.

Connected mode (Phase 4) reuses the v2 opaque webhook envelope (`SECURITY.md` §2.56): events `loop.action.submitted` and `loop.instance.expired` carry ids only; the business fetches `GET /v1/business/loops/events/{ref}` (scope `loops:read`) and answers with `POST .../outcome` (scope `loops:write`, idempotent). Signing, replay window, `Viadere-Delivery-Id`, key id rotation overlap, ownership proof, public-IP DNS pinning and pause all come from the existing implementation unchanged; DLQ on a Loop delivery marks affected events `unknown` and pauses the endpoint through the existing path.

### 4.6 Brand Kit manifest and asset pipeline

**Manifest** (what a device downloads per business; small, versioned, signed with KMS key `brand-manifest`; `ETag` = manifest hash):

```json
{ "v": 1, "business_id": "…", "version": 14, "kits": [
    { "kit_id": "…", "name": "Spring", "tokens": { "primary": "#8C7550", "accent": "#…", "surface": "#…", "on_primary": "auto",
        "radius": "medium", "border": "hairline", "type_scale": "standard" },
      "frame_id": "viadere.frame.snow.v1",
      "assets": { "logo": {"sha256": "…", "w": 512, "h": 512, "bytes": 18432}, "background": {…} } } ],
  "schedule": { "timezone": "America/Phoenix", "default_kit": "…",
    "windows": [ { "kit": "…", "starts_at": "…", "ends_at": "…", "priority": 10, "weight": null } ],
    "random_pool": [] },
  "issued_at": "…", "not_after": "…" }
```

Tokens are an enumerated schema: colors (validated hex), enumerated radius, border, type-scale and frame ids. There is no field for text, links, button labels or layout. Contrast-safe foregrounds are computed, not supplied (`on_primary: auto`).

**Selection and pinning (Core, pure):** `BrandKitSelector.select(schedule, now, pinned) -> KitID`. Order: pinned kit for an active interaction/instance (stored in `loop_instances.kit_id` and an `interaction_kit_pin` column or side table at creation); else windows active at `now` in the schedule timezone, highest `priority`; equal priority means ambiguity and is a **publish-time validation error** (overlap validator in Studio and server); else the random pool if enabled, chosen by `HMAC(consumer_id ‖ business_id ‖ day)` so it is stable across a day and devices and not user-trackable across businesses; else the default; else neutral. Daylight-saving gaps and overlaps are covered by tests using fixed `IANA` fixtures.

**Asset ingestion (server, worker role, WP-2.2):** upload through the console is size-capped before read (initial cap proposal 2 MB, to be set after profiling, D6.3); `Content-Type` and magic bytes must agree; decode with bounded memory and a dimension ceiling (decompression-bomb guard: reject if `w*h` exceeds a limit before allocating); re-encode to a fresh PNG, which drops EXIF, ICC profiles, text chunks and trailing bytes; resize to the slot's maximum (logo 512 px, background 1600 px initially); compute SHA-256 of the output; store in the private container as `brand/{business}/{sha256}.png`; state `ready` only after all steps pass; failures record a reason code and the original is deleted. Optional AV scan (a ClamAV container, not Node) is defense in depth, decision open. Uploads need `manageBrandKits` plus fresh authentication (step-up, as for API keys). Rate limits per business and per day. Moderation: new kits and assets are `pending` for operator review in Phase 2 for businesses below a trust threshold (decision open), with the review queue in the operator console.

**Serving:** `ObjectStore` protocol (Core-free, Server) with `AzureBlobObjectStore` (managed identity, Storage Blob Data Reader for the serving path, Contributor only for the worker; same Blob adapter family as `AzureBlobHeadSink` from WP-B2) and a filesystem implementation for tests. Public path is `https://{ASSET_DOMAIN}/b/{sha256}.png` through Cloudflare; the origin container is private and reachable only by the Cloudflare rule/tunnel (as for the API, `IMPLEMENTATION-PLAN-v3.md` §5.4). Because names are hashes, assets are immutable and cacheable for a year; a replaced asset is a new URL. No directory listing, no cookies, no query parameters.

**Device cache (Kit, Linux-testable logic, Apple storage adapter):** `BrandKitStore` fetches `GET /v1/businesses/{id}/brand` only for connected businesses on demand, opening the business home, at connect, and opportunistically before a scheduled window starts; uses `If-None-Match`; verifies the manifest signature and each asset hash before use; writes atomically (stage, verify, swap); LRU eviction under a byte budget; any miss or failure renders neutral immediately; no approval, sign-in or alert flow awaits it (B4.4). The 50 to 150 KB per kit and 25 MB figures stay planning targets until measured (D6.3).

### 4.7 Frames and surfaces

Frames are Viadere-authored SwiftUI decorations registered by id in Core (`FrameRegistry`, with `available_from/until` for seasonal ones, including time-boxed Viadere control); the manifest names only an id the registry knows and currently allows, else no frame. Frames decorate page and widget backgrounds and never draw over the attribution bar, verified badge, action bars or confirmation panels (those nodes carry `z: protected` in the presentation tree).

**Module registry** (Core `Surfaces/ModuleRegistry`): each module declares `{id, input_schema, sizes, interaction_permissions, accessibility_contract, risk_class, platforms}`. Initial modules: `profile`, `message`, `offers`, `rewards`, `recent_activity`, `approvals`, `verification_requests`, `loops` (inactive until Phase 3). `BusinessSurface.layout_json` selects modules from a fixed set of page templates; the validator rejects unknown modules, duplicates, and a layout without `profile`. Widgets (WidgetKit target `App/ViadereWidgets`) use constrained slots from the same registry in Phase 2.

### 4.8 Organization: information architecture and navigation

**Context.** `OrganizationContext { all | business(BusinessID) }` is client state (persisted locally for convenience), included only as a *filter* in requests. The server never trusts it: `business_id` is accepted only if the caller has an active relationship (or delegation grant) with that business, else `404` (no existence leak); omitted means All and returns only the caller's items. Context never changes silently during a sensitive action: the approval sheet, verification sheet and any push-opened item always show their own issuing business, and a notification or deep link for business B while context is A shows a one-line "Showing {B}" banner and an explicit "Back to all" control; it does not rewrite the user's saved context (C9.7).

**Tabs.** Recommended arrangement to test in Phase 0 (D6.1):

| Variant | Bar | Activity | Settings |
|---|---|---|---|
| **A (recommended default)** | Messages, Alerts, Benefits, Businesses | Segment inside Alerts ("Needs you", "History") | Account button in the top bar of each tab |
| B | Messages, Alerts, Benefits, Businesses, Activity | Own tab | In the top bar |
| C | As A with five tabs and Settings as the fifth | In Alerts | Own tab |

Current to target mapping: `home` (pending list, status, rewards, recent, authenticator) splits into Alerts (pending, status), Benefits (rewards), Businesses (recent) and the Authenticator entry moves to Businesses/Settings; `activity` becomes the history segment of Alerts (or a tab in B); `connect` becomes the "+" in Businesses and next to the selector; `messages` stays; `settings` moves to the top bar (A, B). The tab bar is the existing `ViadereTabBar` (`App/Shared/DesignSystem/ViadereComponents.swift:166`); new design-system components are `ViadereContextBar` (selector, All default, "Add business" shortcut), `ViadereBusinessCard`, `ViadereFilterBar`. Badges: Alerts = pending actionable count (from the server read model), Messages = unread, not both for the same event.

**Screens.**

| Destination | All | Business selected | Server endpoint (new, Core route catalog) |
|---|---|---|---|
| Messages | Threads grouped by business, on-device search over cached threads (bodies are encrypted at rest on the server, so no server-side search), archive, mute | One business | `GET /v1/conversations?business_id=` (extends existing) |
| Alerts | `GET /v1/alerts?status=pending\|completed\|expired&unread=1&business_id=&since=<cursor>` | Filtered | new; stable cursor (`(updated_at, id)` keyset), `since` for incremental sync |
| Benefits | `GET /v1/benefits?filter=available\|saved\|redeemed\|expired\|eligible&business_id=` | Filtered | new |
| Businesses | `GET /v1/relationships` (existing) merged with `business_preferences`; favorites first, then recent activity; local search | Business home from the module layout | extends existing |
| Settings | Global; Loop toggle appears in Phase 3 | Per-business: purposes, mute, priority, remove/block, history, Loops | `PUT /v1/businesses/{id}/preferences` |

Alert ordering stays the deterministic rule already in `HomeContent.rank` (security first, then clamped priority, then earliest expiry); no learned ranking (C8.2). Expired items are filtered server-side and rechecked on the client. Push dedupe: the push payload carries the stable `alert_id`; the client keeps a bounded seen-set and the notification `threadIdentifier` stays per business. If a push is missed, the next foreground load or `since` sync restores the alert; the notification is never the source of truth (C5.6).

**Per-business settings.** Mute cannot suppress `security`, `accountService` or any action-required alert; it only affects `marketing`, `rewards`, `support` and low-priority `transactional` notifications' interruption level, never their presence in the Alerts list. Disconnect keeps the existing revocation semantics; block adds `blocked_at` to the relationship preferences and refuses new `connect` attempts from that business for the customer. Permission history is the existing consent history.

### 4.9 Action registry (A4), generalized from the capability catalog

The registry is a Core value `LoopActionDefinition` in the same style as `CapabilityDefinition` (`Policy/CapabilityDefinition.swift`), with: `actionType`, `title`, `riskClass` (low, medium, high), typed `inputs` (reusing `CapabilityParameter` and its strict validation, including unknown-parameter rejection), `allowedLabelKeys`, `confirmation` (wording template with named holes for business name, amount, effect), `requiredEvidence` and `minimumTier` (reusing `RequiredEvidence`, `BusinessRiskTier`), `consent` (reusing `ConsentRequirement`), `idempotency` (scope and window), `timeoutSeconds`, `routing` (`hosted`, `connected`), `auditFields`, `revocation` (reusing `RevocationBehavior`), `available` (feature flag), `phase`.

Initial entries: `acknowledge`, `confirm_attendance`, `request_callback`, `submit_inquiry` (low); `check_in`, `select_option`, `select_pickup_time` (medium); `review_estimate` (high, read-only in Phase 3: shows terms and amount and sends an acknowledgment, **no binding authorization**); `approve_estimate` (high, binds through Approve v2 signed approval, Phase 4; its confirmation panel states "This approves the estimate. It does not charge you." and the registry forbids pairing it with any payment step, section 4.11.6); reserved and rejected by the validator: `verify_identity`, `verify_age` (first-party module only, A4.3d), `payment.*`, `order.*` (Viadere takes no payments, FX-5), any health-data field (FX-4). Shopify checkout is not an action type: it is a native `shop` module with its own handoff (section 4.11).

Policy: the existing `PolicyEngine` gains a `loops.use` capability family in `Capability` (new known capabilities `loop.publish`, `loop.action.hosted`, `loop.action.connected`) so entitlement, key scope, operator kill switches (`capability_switches`), jurisdiction rules and per-request consent all come from the machinery in `SECURITY.md` §2.29 instead of a parallel one. Milestone C introduces the link-session capabilities (`message.send`, `auth.challenge`, `transaction.approve` in `IMPLEMENTATION-PLAN-v3.md:334`); WP-3.1 must be written after WP-C1 lands so the `Capability` enum and `SECURITY.md` §2.28 table change once, not twice. The Loop runtime reuses the action *routing* of existing capabilities: a `review_estimate`/`approve_estimate` is just an `authorize` interaction created by the runtime on the business's behalf with the same assurance rules.

### 4.10 Android: specification only (FX-2)

No Android code, build, CI or store work. The deliverable is documentation in `docs/protocol/` and vectors:

* Contract files used by any client: `PresentationTree` JSON, manifest and publication JWS, `LoopDefinition` schema, brand manifest, alert/benefit DTOs. Each has fixtures under `docs/protocol/vectors/` generated by Core tests (Core is Linux-testable, so generation does not need Apple tooling).
* A short spec page per Android piece, marked "not scheduled": Jetpack Compose renderer (node-by-node mapping table, semantics/TalkBack rules, attribution bar requirements identical to section 4.4), Play Integrity verdict handling (already stubbed server-side in `IMPLEMENTATION-PLAN-v3.md` WP-E1), FCM sender behind the `PushProvider` protocol (WP-E2), Android notification channel policy.
* The acceptance criterion for "ready for Android" is that a hypothetical client passes the vectors; nothing else.

### 4.11 Commerce: Shopify only, no Viadere checkout (FX-5)

Viadere is never merchant of record and never accepts or processes payment. A business connects its own Shopify store. Viadere shows the catalog, shows order status and hands the customer to the store's own Shopify checkout. Payment, refunds, taxes, shipping and disputes stay with the merchant on Shopify. Facts below were checked against shopify.dev and developer.apple.com on 2026-10-30 and are re-verified when WP-4.5 starts.

1. **App type and review.** Shopify offers *public distribution* (many stores; Shopify App Store review, one-time registration fee, certain data must sync with Shopify) and *custom distribution* (one store or one Plus organization; no review; cannot use Shopify billing). The choice cannot be changed after creation, and admin-created custom apps are no longer available for new apps. Plan: a **custom-distribution app** for design-partner merchants during the pilot, then a **separate public app** for general availability (accepting a second review and install flow). The app is *not embedded* in Shopify admin (the merchant connects from the Viadere console, which is server-rendered Swift with no App Bridge), so OAuth uses the **authorization code grant**. Whether Shopify's App Store review accepts a non-embedded app for a given listing is an open item to verify with Shopify before the public app is created (O18). Compliance webhooks required of public apps (customer data request, customer redact, shop redact) are implemented in WP-4.5.
2. **Scopes, least privilege.** Request only `read_orders` on the Admin API (order and fulfillment status; recent-orders window only, never `read_all_orders`) and the Storefront API unauthenticated read scopes for products (and inventory only if the merchant opts to show availability) plus the cart/checkout scopes needed to create a cart. No write scopes on the Admin API, no `read_customers`, no discounts, payments or fulfillment writes. Exact scope names are copied from the current Admin and Storefront API references at build time and reviewed in the connector ADR.
3. **Protected customer data.** Orders, customer data and order webhooks are protected customer data. Viadere requests **Level 1 only** (no name, address, phone or email fields): minimum necessary, merchants told what is processed and why (DPA addendum in `Site/content/legal/`), retention set (order status 90 days after completion by default), encryption at rest (`FieldCipher`) and in transit, honoring consent and opt-outs. Fields Shopify does not approve arrive as null; the ingestion layer **drops every personal field from webhook payloads before storing** and keeps only: order reference, status, fulfillment status, line titles, tracking carrier and number, timestamps. Level 2 (name/email/phone) is not requested; if ever needed it also requires the Level 2 controls (staff access restriction, access logs, encrypted backups, test/production separation), which the operator console and `docs/ops/` already largely have, and a data protection review.
4. **Storefront versus Admin API.** Storefront API (server-side, from the worker): product and collection listings, variants and prices for display, `cartCreate` which returns the cart's `checkoutUrl`. Admin API: order reads for reconciliation and webhook subscription management. The **device never talks to Shopify**: the server fetches and caches catalog data, rejects unexpected fields, passes product images through the asset pipeline (re-encoded, hashed, served from the asset domain, so INV-4 "no arbitrary URLs" holds) and serves a small `ShopModule` payload (title, price string with currency, availability, image ref). Prices are displayed from Shopify and labeled "Price set by {Merchant}; confirmed at checkout".
5. **Checkout handoff on iOS.** Tapping Checkout calls `POST /v1/shop/{business}/carts` (server creates a Shopify cart with an opaque Viadere order reference as a cart attribute) and returns the `checkoutUrl`. The app shows a fixed Viadere interstitial: "You're leaving Viadere to pay {Merchant} on Shopify. Viadere doesn't see or process your payment." Then it opens the URL in the **system browser sheet** (not a custom web view, so the user sees the real address bar and Apple Pay/autofill work as in Safari). The URL host must match the shop's stored checkout domains (the `*.myshopify.com` domain or the merchant's verified domain), else the app refuses. **Apple App Review**: Guideline 3.1.3(e) allows methods other than In-App Purchase for physical goods and for services consumed outside the app, while 3.1.1 requires IAP for digital content or functionality unlocked in the app; so the review rules reject digital/in-app products and the module is only enabled for physical goods and out-of-app services. App Review notes describe the merchant-of-record relationship. Risk: reviewer pushback; mitigation is the interstitial, no in-app payment UI, and no Viadere branding on the payment page.
6. **Order status via webhooks.** A public HTTPS endpoint receives Shopify webhooks (topics: orders create, updated, cancelled; fulfillments; `app/uninstalled`; the compliance topics). Verification: `X-Shopify-Hmac-SHA256` is the base64 HMAC-SHA256 of the **raw body** using the app client secret, compared in constant time (Core `ConstantTime`), before any parsing; during secret rotation both secrets are accepted (Shopify says the new digest can take up to an hour to take effect). Dedupe on `X-Shopify-Webhook-Id` through `processed_messages`; `X-Shopify-Event-Id` is for correlation only. Shopify times out at 5 seconds total (1 second to connect) and retries 8 times over about 4 hours, then deletes the subscription: the endpoint only verifies, writes an outbox row and answers 200; processing happens in the worker; a **reconciliation job** polls recent orders to heal missed events and re-creates deleted subscriptions. The shop in each request is matched against connected shops (header `X-Shopify-Shop-Domain` checked against the stored domain), unknown shops get 401. Orders are matched to a Viadere customer only through the opaque cart attribute, never through personal data. Customer status uses the honest ladder: "Sent to {Merchant}'s checkout" (never "ordered") until a webhook shows the merchant created the order (INV-8).
7. **"Approve estimate" stays separate from payment.** `approve_estimate` (section 4.9) records an approval of terms through Approve v2. It never opens checkout, never collects or moves money and its confirmation says so. A Loop definition cannot link an approval step to a checkout step; the validator rejects a definition that contains both an amount-bearing approval and a `shop` handoff in one flow.
8. **Not built:** catalog sync into Viadere tables beyond a cache, order creation, refunds, taxes, shipping rates, fraud checks, disputes, wallets or stored payment methods, any other commerce platform.

### 4.12 Loop review pipeline (FX-3)

No Loop reaches a customer without passing all of: 

| Stage | Who | What | Failure behavior |
|---|---|---|---|
| 1. Automated policy validation (hard gate) | `LoopPolicyValidator` in Core, run on submit and again on publish | registered actions only; field-type allowlist; prohibited categories (health, adult, gambling, weapons, etc. per AUP) by business category, definition text and linked metadata; prohibited-content and impersonation rules (§2.19 plus "Viadere", "government", "bank" claims); wording constraints per risk class; attribution metadata present and consistent with the publisher; no URLs; limits | Revision moves to `validation_failed` with rule-coded messages; a human cannot override a hard rule (only the rule set, via a code change and ADR) |
| 2. Human review | Viadere operator with a `loop_reviewer` permission (operator console, fresh passkey, reason) | checks the rendered preview against intent, wording, data collected, downstream recipient disclosure, prohibited uses the validator cannot see | `changes_requested` or `rejected`; author sees reasons |
| 3. Second person | A different operator, **required for high-risk actions** (`approve_estimate`, anything touching amounts, any definition marked high by the validator) | same checklist; cannot be the author's reviewer | Same |
| 4. Signed publication | Server, KMS key `loop-publication` | signs the manifest over the exact `definition_hash` that was reviewed; allow-list rollout | n/a |

Rules: re-review on every revision (a revision is immutable; edits create a new one); locked templates are the fast path (a template-only revision with unchanged structure and only allowed-label/field changes skips nothing, but the validator pre-fills the checklist and the reviewer can approve in minutes); reviewers see the same preview customers will see, rendered by the web renderer, plus a diff to the previous published revision. **Monitoring and response:** every published Loop has dashboards in the operator console (instances, outcome states, abandonment, report counts); customers can report a Loop from its screen (existing `report` role / `reported` status pattern), reports above a threshold auto-suspend the publication pending review; **operator kill switch per Loop** (`loop_publications.suspended_at`, effective on the next instance start and action call) **and per business** (`capability_switches` scope business for `loop.*`, §2.29); suspension shows customers a neutral "paused" state, cancels no data, and notifies the business. All stage transitions are audit events (`loop.submitted`, `loop.validation_failed`, `loop.review_decision`, `loop.published`, `loop.suspended`, `loop.revoked`).

### 4.13 Healthcare ban: layered enforcement (FX-4)

Banned: healthcare-provider use cases, and collection of health information through Loops or any other business-authored content. Layers (each independently tested, so one failure does not open the path):

1. **Business verification category.** `BusinessCategory.healthcare` (`Packages/ViadereCore/Sources/ViadereCore/Models/Business.swift:24`) businesses cannot hold the `loops` entitlement (`EntitlementService` refuses to grant it; `PolicyEngine` returns `category_blocked` for `loop.*` even if a row exists) and cannot publish; the onboarding state machine (`Platform/Onboarding.swift`, §2.70) stops routing the category into "enhanced review" and rejects it with a plain reason. A business that self-attests another category but whose legal-entity record or domain indicates a provider is caught by the reviewer checklist (layer 2) and by the operator action "reclassify" that revokes entitlements and suspends all its Loops.
2. **Loop review rules.** The checklist and the automated rules list health services, symptoms, diagnosis, treatment, prescriptions, insurance, appointments with clinicians and similar as prohibited topics; keyword/pattern hits raise a mandatory second reviewer and cannot be waived by a single reviewer.
3. **Field-type allowlist.** There is no field type, action type or template for medical or health data, and free text is limited to short, sanitized, low-risk slots (so a customer can still type anything into a short-text field: therefore also the AUP and the customer-facing prompt "Don't share health details here", and a report path).
4. **Legal documents (WP-0.6).** Acceptable Use Policy and Business Services Agreement drafts in `Site/content/legal/acceptable-use-policy` and `Site/content/legal/business-services-agreement` gain: prohibition of healthcare-provider use and of collecting health information through any Viadere feature; right to suspend; indemnity wording is counsel's. Related: `data-processing-addendum` (Viadere is not a business associate and does not accept PHI), `privacy-notice`, `mfa-approval-services-addendum` and `messaging-consent-content-policy-addendum` get cross-references.
5. **Marketing copy.** No healthcare use cases, examples or imagery in the Site, store listing, Studio templates, docs or demos; the Site lint (planned in WP-F2 of the v3 plan for risky claims) adds the terms (health, medical, patient, clinic, HIPAA, doctor) as failing for pages that describe Loops.

Scope question for the owner (O19): the ban as stated covers any business-authored content, so it also reaches ordinary messaging and approvals by healthcare providers. This plan assumes a **platform-wide** refusal of the `healthcare` category (existing healthcare businesses, if any, are offboarded), implemented in Phase 1 (WP-1.9); the narrower reading (Loops only) would keep today's enhanced-review path for messaging.

## 5. Phases and work packages

Size: S up to 1 week, M 1 to 3 weeks, L 3 to 6 weeks of one engineer. "Tests first" lists security tests that must exist and fail before the change (CLAUDE.md). "A11y" lists the accessibility checks that are part of acceptance: VoiceOver order and labels, Dynamic Type at the largest accessibility size, contrast in light and dark, 44 pt targets, Reduce Motion, no information by color alone. D5 gates (threat model update, cross-tenant tests, load/cache tests, legal review where regulated, rollback controls, observable failures) apply at each phase exit and are listed once in 5.6.

### 5.1 Dependencies on Milestones B and C

| Needed from | By | Used for |
|---|---|---|
| WP-C3 configurable link domain | P1 start (small) | Same injection mechanism for `ASSET_DOMAIN` (P2) |
| WP-C1 link sessions (relationship columns, `Capability` changes) | before WP-1.1 merges (migration ordering) and before WP-3.1 | Avoid two migrations/enum edits to `relationships` and `Capability`; Phase 1 reads `relationships` only |
| WP-B2 `KeyManagementService`, Blob adapter, Entra identity | P2 (manifest signing, `ObjectStore`) | Not needed in P1 |
| WP-B3 outbox, `processed_messages`, queues, DLQ | P3 (Loop events, inbox emails) | Not needed in P1 or P2 |
| WP-B1 landing zone | P2 (asset container, Cloudflare rule, new key vault keys) | |
| WP-C2 approval hardening | P3 (`approve_estimate` in P4) | |

**Phase 1 is buildable immediately after Milestones B and C** (and in practice can start earlier on the Kit/App/read-model work, since it touches only reads and two small tables): its only hard coupling is migration ordering with WP-C1.

### Phase 0: freeze (about 4 to 6 weeks, mostly decisions)

* **WP-0.1 Domain-model freeze, ADRs, threat model (S).** ADR-0015 (modular boundaries and Core folders), ADR-0016 (presentation model, renderers, preview strategy, FX-1), ADR-0017 (asset domain and image pipeline), ADR-0018 (Loop runtime, outcomes, action registry). `SECURITY.md` §1 threat rows: cross-tenant aggregation, selector manipulation, forged/replayed Loop actions, attribution spoofing, malicious asset upload, stale or poisoned manifest, consent bypass, staff escalation via inbox, branded phishing look-alike. Normative sections drafted: §2.92 presentation tree and publication manifest, §2.93 brand manifest and asset serving, §2.94 loop action events. Files: `docs/SECURITY.md`, `docs/ops/adr/*`, `docs/ops/RISK-REGISTER.md`.
* **WP-0.2 Counsel and clearance packet (S, owner-led).** Trademark and marketplace clearance for "Loops" (D6.7), disclosure and consent copy (D6.6, A6.4), Shopify merchant/Viadere responsibility statement (FX-5), review-process terms for business-authored content (FX-3). HIPAA/BAA work is no longer needed (FX-4: banned).
* **WP-0.3 IA prototypes and usability test (M, product owner).** SwiftUI prototypes (extend `PreviewData`) of tab variants A, B, C (section 4.8); tasks from C9.1, C9.2, C9.7; 8 to 12 participants including screen-reader users; produces the decision for D6.1.
* **WP-0.4 Contracts and vectors (M).** JSON schemas and Core types (no behavior) for `LoopDefinition`, `PresentationTree`, publication manifest, brand manifest, module registry; fixtures in `docs/protocol/vectors/`. Tests first: vectors fail if encoding drifts. This is also the Android spec deliverable.
* **WP-0.5 Multi-tenant test harness and "core without extensions" suite (M).** Shared fixtures: N businesses, M consumers, delegates, revoked and suspended businesses; helpers asserting no row of tenant X in any response for principal Y; All-view leakage matrix generated per endpoint; suite proving INV-1 with no Loop/kit/surface rows. Everything later adds endpoints to the matrix.
* **WP-0.6 Legal documents and marketing rules (M, counsel + owner).** Update the drafts in `Site/content/legal/`: `acceptable-use-policy` and `business-services-agreement` (healthcare ban, prohibited categories, Viadere review and suspension rights, business accountability for Loop content, no payment processing by Viadere), `data-processing-addendum` (no PHI; Shopify order-status processing as a subprocess relationship), `privacy-notice`, `consumer-terms` (Loops are third-party-authored; Shopify checkout is the merchant's sale), `mfa-approval-services-addendum`/`messaging-consent-content-policy-addendum` cross-references; Site copy lint extended with health terms and "Viadere checkout/secure payment" claims; template and doc review for health examples. Tests: the Site lint test fails on the listed terms in Loop-related pages. Gate: no Phase 3 customer-facing build ships before these are published.
* Exit: ADRs accepted by the owner, D6.1 decided, counsel engaged, legal drafts and lint rules merged, harness merged.

### Phase 1: Organization core and neutral business surfaces (after B and C)

* **WP-1.1 Organization data and read models (L).** Migration `Organization.v1` (`business_preferences`, `conversation_state`, `alert_seen`, `benefit_saved`); `AlertService` assembling `AlertItem` from interactions, Approve v2 requests, verification requests, security notices; `BenefitsQuery`; keyset pagination and `since`; `business_id` validation helper `OrganizationScope.authorize(principal, businessID)` used by every new route. Core: `Organization/*` DTOs, routes in `API/APIRoutes.swift`. Files: `Server/Sources/ViadereServerKit/Alerts/*`, `Benefits/*`, `Routes/OrganizationRoutes.swift`, `Migrations/OrganizationSchema.swift`. Tests first: principal A requests B's `business_id` and gets 404 (D3.T2); All view returns zero rows of an unconnected or disconnected business (D3.T1); revoked/suspended business items are not actionable (D3.T8); expired never returned as pending; mute cannot hide `security` items; delegate sees only granted purposes. A11y: n/a (server).
* **WP-1.2 Kit: context, view models, sync (M).** `OrganizationContext`, `AlertsViewModel`, `BenefitsViewModel`, `BusinessesViewModel` (favorites, local search, grouping), filters on `MessagesViewModel`, incremental sync with a seen-set and bounded cache; `AppTab` redefined; badges. Files: `Packages/ViadereKit/Sources/ViadereKit/Stores/*`, `Organization/*`. Tests (Linux): context switch never mutates an in-flight approval; stale cache never shows an expired item as actionable (D3.T7 partial); offline shows cached but disables actions; 50 businesses fixture search under budget. 
* **WP-1.3 Design-system components (S).** `ViadereContextBar`, `ViadereBusinessCard`, `ViadereFilterBar`, empty states, in `App/Shared/DesignSystem/`. Brand rules: charcoal/ivory/champagne, no shield imagery. A11y: selector is one adjustable element announcing "Showing all businesses" / "Showing {name}"; filters expose selected state in text.
* **WP-1.4 App IA shell (L).** New tab arrangement per the Phase 0 decision; migrate Home/Activity/Connect content into Alerts/Benefits/Businesses; Add Business (+) in two places; settings entry point; `swiftc -parse` on touched app files. Files: `App/Viadere/Features/MainShell.swift`, `Home/`, `Activity/`, `Connect/`, `Messages/`, `Rewards/`. A11y: tab order and badges announced once; Dynamic Type at AX5 keeps the selector usable; VoiceOver rotor for filters.
* **WP-1.5 Per-business settings (M).** Preferences screen (mute, priority, favorite, block, purposes, history) extending `BusinessDetailView`/`BusinessDetailViewModel`; server `PUT /v1/businesses/{id}/preferences`; block enforcement in `connect`. Tests first: mute and block cannot suppress security/account notices; block refuses reconnect; disconnect stops new deliveries (C7.4).
* **WP-1.6 Neutral business surfaces and module registry (L).** Core `ModuleRegistry` and page templates; migration `Surfaces.v1`; native `BusinessHomeView` composed from modules (profile, message, offers, rewards, recent activity, approvals, verification requests); console page "Your Viadere page" to choose modules and order (permission `manageOrganization`); `Loops` slot present but inactive. Tests first: unknown module rejected; layout without `profile` rejected; a module cannot be placed twice; business cannot influence navigation. A11y: each module's accessibility contract is a registry field checked by a snapshot test.
* **WP-1.7 Sensitive-flow context safety (S).** Approval, verification and push-open entry points always render issuer; "Showing {B}" banner; explicit return to All. Tests first (C9.7): MFA for B while browsing A shows B's verified name and acts without changing saved context; deep link cannot select a business the user is not connected to.
* **WP-1.8 Usability validation and phase gate (S).** Task study on the built shell (C9.1, C9.2), cross-tenant matrix run, load test of `GET /v1/alerts` at 50 businesses x 500 items, TalkBack-equivalent review spec only (FX-2).
* **WP-1.9 Healthcare category refusal in onboarding (S).** `BusinessCategory.healthcare` is no longer an "enhanced review" path but a refusal with a plain reason; existing records handled by the offboarding runbook (`docs/ops/RUNBOOKS.md` addition); `EntitlementService` refuses `loops` for the category; operator "reclassify" action revokes entitlements. Files: `Server/.../Platform/Onboarding.swift`, `Platform/BusinessOnboarding.swift`, `Policy/EntitlementService.swift`. Tests first (FX-4 layer 1): a healthcare-category application cannot reach go-live; a category change after approval suspends Loop entitlements; the state machine cannot skip the refusal. Subject to the owner's answer to O19.
* Exit: spec scenarios C9.1, C9.2, C9.7 pass; no Loops or Brand Kit code in the release.

### Phase 2: Brand Kits

* **WP-2.1 Asset domain, `ObjectStore`, signing key (M; needs B1, B2).** Azure Blob container, Cloudflare hostname/cache rule, `ASSET_DOMAIN` config (like `LINK_DOMAIN`), CSP deltas scoped to Studio and preview, `brand-manifest` and `loop-publication` KMS keys, OpenTofu changes in `Infra/azure` with the policy check updated (no public container). Tests first: container not publicly listable; serving host never sets cookies; AASA unaffected.
* **WP-2.2 Asset ingestion (L).** Pipeline of section 4.6; library selection verified against upstream; fuzz corpus (truncated, polyglot, decompression-bomb, EXIF/GPS, ICC, animated, mislabeled MIME, SVG, HTML-as-PNG). Tests first (D3.T5): each corpus file is rejected or re-encoded to a clean PNG with no metadata; oversize/dimension rejected before allocation; script-bearing file never served with a script-capable type; unauthenticated or wrong-tenant upload rejected.
* **WP-2.3 Brand Kit model, API and manifest (M).** Migration `BrandKits.v1`; kit CRUD with versioning; token schema validation; contrast policy; frame registry; manifest builder and signer; `GET /v1/businesses/{id}/brand` (authorized by relationship). Tests first: tokens with extra keys or text/URL values rejected; low-contrast tokens replaced; manifest for business A never served to a non-connected user; tampered manifest fails device verification.
* **WP-2.4 Scheduling, selection, pinning (M).** `BrandKitSelector` in Core, overlap validator, timezone/DST fixtures, pin storage on interactions. Tests first: overlapping equal-priority windows rejected at publish; a pinned interaction keeps its kit when the window changes; random pool stable per day and not linkable across businesses.
* **WP-2.5 Brand Kit Studio, console (L).** Server-rendered Swift pages (permission `manageBrandKits`): uploads, color inputs with contrast warnings, crop/safe-area guides (plain CSS), frame picker, schedule editor, previews of message, coupon, approval, activity and (later) Loop modules, phone-frame simulation. Previews are produced by the web renderer of FX-1 inside a sandboxed iframe (section 5.3). Minimal plain JS only for crop handles and live color updates, as a dependency-free file with no build step, under its own hash-pinned CSP. A11y: Studio itself keyboard-operable; contrast warnings are text, not color only.
* **WP-2.6 iOS kit renderer and cache (L).** `BrandKitStore` (section 4.6), design-system application of tokens, frames, branded business home and message-card decoration that keeps sender identity unobscured (C4.4); nothing in approval/auth paths awaits the store. Files: `Packages/ViadereKit/.../BrandKits/*`, `App/Shared/DesignSystem/BrandStyle.swift`, `App/Viadere/Features/Business/*`. Tests first (D3.T4, D3.T7): a kit cannot change an approval sheet's text, buttons, risk chip, verified badge (snapshot with hostile tokens); stale or expired manifest falls back to neutral; asset hash mismatch rejected; branding download failure does not delay approval (timing test with a hung server).
* **WP-2.7 Surfaces beyond the app (S).** Notification attachment policy (approved logo only, no business art on security requests), widget slots, Live Activity accent restricted to the allowed token (B5). 
* **WP-2.8 Operator review and abuse controls (M).** Operator queue for new kits/assets, takedown, per-business limits, audit events `brandkit.*`.
* **WP-2.9 (optional, decision) restricted SVG logo path (M).** Only if the owner wants SVG; strict-subset parser and rasterizer, same fuzz gate.
* Exit: C9.3 and C9.6 pass; performance measurements fill in D6.3; kit pricing decision implemented through the `brand_kits` entitlement.

### Phase 3: Hosted Loops (needs B3, C1, C2)

* **WP-3.1 Core: definition, validator, action registry, presentation builder (L).** Section 4.3, 4.4, 4.9 types; `Capability` additions after WP-C1; vectors from WP-0.4 become executable. Tests first: all A6a tests that need no UI; unknown member, unregistered action, cyclic graph, forbidden field type (secret, card, health), `payment.*`, `verify_age` all rejected; label outside the allowed set rejected; high-risk definition cannot omit the confirmation panel.
* **WP-3.2 Publication service and mandatory review (L).** Migration `Loops.v1` (definitions, revisions, reviews, publications, reports, switches); the pipeline of section 4.12 for **every Loop and every revision**: `LoopPolicyValidator` hard gate, operator review queue in the operator console (new permission `loop_reviewer`, fresh passkey, reason), second reviewer required for high-risk actions (reuse `TwoPerson.swift`), signing with `loop-publication` only after approval of the exact `definition_hash`; locked-template fast path (pre-filled checklist, still reviewed); allow-list rollout; customer report intake and auto-suspend threshold; kill switch per Loop (`suspended_at`) and per business (`capability_switches`); monitoring pages; revoke/retire with instance handling; healthcare refusal layers 1 to 3 (section 4.13). Tests first (D3.T3, D3.T9): a revision that skipped any stage cannot be signed; a single reviewer cannot approve a high-risk revision; an author cannot review their own revision; a new revision of a published Loop is not served until it passes the pipeline and the old revision keeps serving until then (or is suspended); editing a reviewed revision in place is impossible; business roles have no publish path; revoked or suspended publication refuses new instances and actions; a healthcare-category business cannot submit; definitions with prohibited fields or categories fail the hard gate and a human cannot override it.
* **WP-3.3 Runtime and consumer API (L; needs WP-B3).** Instances, action events, outcomes, outbox integration, queues `loop-delivery`, `loop-timeout`; routes `POST /v1/loops/instances`, `.../actions`, `GET .../{id}`. Tests first (D3.T3): forged action from another device/consumer, replayed `idempotency_key` returns the same result with one event, action on a retired step, action after expiry, action on a revoked publication, action by a customer without Loop consent, cross-business instance id — all refused and audited; message delivered twice yields one inbox item; DLQ marks `unknown`.
* **WP-3.4 Hosted business inbox (L).** Console inbox pages: queues, unread badges, assignment, read receipts, handoff, notes, accept/reject/ask-for-info, audit, operating hours (D6.2 semantics), export (`TenantRights` extension), retention; email alerts via `EmailSender` carrying no customer content. Permissions `viewInbox`, `manageInbox`. Tests first (D3.T9): operator cannot read another tenant's items, viewer cannot act, role downgrade takes effect immediately, export excludes other tenants. A11y: full keyboard operation, live-region announcements for new items (plain JS, optional, degrades to page refresh).
* **WP-3.5 Customer Loop consent (M).** Global enablement flow with non-skippable, accessible education, comprehension checks and explicit agreement; separate per-business authorization; Settings toggles; disable semantics (hide entry points, cancel/expire active instances per policy, preserve required history). Text comes from the counsel-approved catalog with digest recorded. Tests first (D3.T6): no instance can be created, resumed or acted on without both consents; revoking cancels pending instances; consent text version bump forces re-consent; core messaging works with Loops off. A11y: comprehension checks usable with VoiceOver and Switch Control, no timing pressure.
* **WP-3.6 iOS Loop renderer and attribution (L).** SwiftUI `PresentationView`, entry points (business page, message, alert), compact origin in notifications, outcome presentation with the five states, A6a.T1 to T6 as snapshot and accessibility tests. Tests first: missing/invalid manifest yields the safe fallback; attribution cannot be hidden by hostile tokens; confirmation names the responsible business.
* **WP-3.7 Loop Studio v1 (L).** Template gallery (acknowledge, callback, salon or repair-shop appointment check-in, pickup time), form-based editor over the validated schema, live validation report, preview via the web renderer, **submit for Viadere review** (status tracker for the 4 stages, reviewer messages); no AI, no schema mode, no publish button. A11y: Studio keyboard-operable; preview is labeled.
  *Status 2026-10-31: built.* `/dashboard/loops/studio` (`ConsoleLoopStudio`, `LoopStudioService`, migration `LoopStudio.v1`; SECURITY.md §2.99): five locked templates in Core (`LoopTemplateCatalog`: acknowledge, callback request, salon check-in, repair-shop drop-off, pickup time), script-free form editor whose structure comes from the stored draft, live `LoopPolicyValidator` report with plain messages, preview by `LoopWebRenderer` (option (a)) in a sandboxed iframe with its own CSP and placeholders for system chrome, submission through `LoopPublicationService.submit`, a four-stage tracker with reviewer messages, drafts per business with audit events. New read-only permission `viewLoops`; the raw-JSON submission form on `/dashboard/loops` is gone. Loop validation now receives the business's own approved Brand Kit keys (submission, publish gate, Studio), so `brand_kit` appearances work and can never name another tenant's kit. The operator review shows the same renderer in the same sandbox. Open: whether saves or submissions should need a fresh passkey (they do not today), and an "edit from a published revision" path for Loops submitted before Studio.
* **WP-3.8 Web renderer parity harness (M).** Section 5.3: fixtures rendered by SwiftUI (macOS runner) and by the web renderer, compared on the presentation tree and on a tolerance-based snapshot.
  *Status 2026-10-31: part 1 (tree level) built.* 17 fixtures (every node kind, Brand Kit, hostile tokens, foreign kit, maximum-length and RTL text, bidi override, fallbacks, paused, first party) as canonical JSON goldens with `PresentationLandmarks` in `Packages/ViadereCore/Tests/ViadereCoreTests/Golden/presentation-trees` (`PresentationParityTests`, Linux); the server suite renders every golden with the web renderer and checks node order, text order, attribution presence and position, action count and protected nodes. Part 2 (SwiftUI snapshots and the pixel-tolerance diff in headless Chromium) needs a macOS runner: CI follow-up under O14.
* **WP-3.9 Alerts integration and phase gate (M).** Loop tasks appear in Alerts with urgency/expiry; push for outcome changes; red-team session on forged actions and attribution; load test of inbox and runtime; rollback by kill switch rehearsed.
* Exit: C9.5 passes with a business that has no API; all A6a tests green; counsel sign-off on copy; every published Loop has a recorded automated pass, a human approval (two for high risk) and a signed manifest over the reviewed hash; kill switches rehearsed per Loop and per business.

### Phase 4: connected APIs, Shopify, AI drafting, binding approvals

* **WP-4.1 Connected mode (L).** `loop.action.submitted`/`instance.expired` opaque events, event fetch and outcome callback endpoints, SDK support in `Packages/ViadereBusinessSDK`, console endpoint binding per Loop with the existing ownership proof; scopes `loops:read|write`. Tests first: forged callback (wrong key, replay, other tenant's event) rejected; outcome callback idempotent; endpoint pause produces `unknown`, not `accepted`.
* **WP-4.2 Connector framework, Shopify only (M).** Minimal interface shared by the Shopify code (credential storage, webhook ingress, reconciliation job, kill switch per shop); no second connector is planned (FX-5). Per-connector ADR and threat model (ADR-0019 Shopify).
* **WP-4.3 AI drafting assistant (M).** Drafts a `LoopDefinition` that must pass the validator, appears only in Studio as an unsaved draft, never calls publish, sends no customer data, vendor and data-processing decision first.
* **WP-4.4 Binding `approve_estimate` (M).** Through Approve v2 signed approval with amount and terms; stronger confirmation; explicit "does not charge you" wording; validator rule that forbids pairing it with a `shop` handoff (section 4.11.7). Tests first: an approval can never trigger a checkout URL.
* **WP-4.5 Shopify connector (L; calendar time includes Shopify review).** Section 4.11: custom-distribution app for pilot merchants, then public app; OAuth authorization code grant, `read_orders` plus Storefront read/cart scopes, protected customer data Level 1 request, compliance webhooks, HMAC-verified webhook ingress with outbox, shop connection and disconnect/uninstall handling, reconciliation job, encrypted per-shop tokens, console page "Connect your Shopify store". Files: new `Server/.../Commerce/Shopify*`, `Routes/ShopifyWebhookRoutes.swift`, migration `Shopify.v1` (`shopify_shops`, `shopify_orders_status`, `shopify_webhook_seen` via `processed_messages`). Tests first: webhook with a bad/absent HMAC, wrong shop domain, replayed webhook id, stale timestamp-equivalent (orders older than the window), or a body altered after signing is rejected; personal fields in a payload are never persisted; uninstall revokes the token and stops deliveries; compliance redact removes stored order status; token never appears in logs.
* **WP-4.6 Shop module and checkout handoff (L).** Native `shop` module in the registry (physical goods and out-of-app services only), catalog cache through the asset pipeline, cart creation, interstitial, system-browser handoff, host allow-list for `checkoutUrl`, order-status presentation and alerts (honest ladder, section 4.11.6), digital-product rejection, App Review notes. A11y: prices and currency read correctly, interstitial is a blocking step with clear Cancel. Tests first: a `checkoutUrl` on a non-allowed host is never opened; no Viadere UI collects any payment data; digital products never listed; order status text never claims an order before a verified webhook.
* **WP-4.7 Advanced Studio mode (M).** Schema editor and integration mappings, still data only and still through the full review pipeline.
* Healthcare use cases: none, permanently (FX-4); not a deferred item.
* Android items remain specifications (section 4.10).

### 5.2 Order and critical path

`WP-0.1 .. 0.6` -> `WP-1.1 -> 1.2 -> 1.3/1.4/1.5/1.6 -> 1.7 -> 1.8/1.9` -> (`WP-2.1 -> 2.2 -> 2.3 -> 2.4`) -> `2.5 ∥ 2.6 -> 2.7/2.8` -> `WP-3.1 -> 3.2 -> 3.3 -> 3.4 ∥ 3.5 ∥ 3.6 ∥ 3.7 -> 3.8 -> 3.9` -> Phase 4: `4.1 -> 4.2 -> 4.5 -> 4.6` (Shopify) in parallel with `4.3`, `4.4`, `4.7`. Critical path in bold terms: 0.4 -> 3.1 -> 3.3 -> 3.6. Phase 1 can overlap Phase 0 once 0.5 exists, provided variant A/B/C is chosen before WP-1.4.

### 5.3 Studio preview: evaluation and recommendation (FX-1)

State checked 2026-10-30: the official Swift SDK for WebAssembly ships with the toolchain distribution (guide at <https://www.swift.org/documentation/articles/wasm-getting-started.html>, SDK ids `swift-6.4.2-RELEASE_wasm` and `-wasm-embedded`; the SDK must match the installed toolchain exactly). A secondhand report says Swift 6.4 made JavaScriptKit bridging much faster; this was not confirmed from an upstream page and is not relied on. The guide says nothing about Foundation or binary sizes, so both are unverified for our use.

| | (a) Server-side Swift to HTML/CSS | (b) Swift compiled to WebAssembly + plain JS shim |
|---|---|---|
| Parity with iOS | Shared `PresentationBuilder` and tree; renderer is separate code | Same: also separate renderer, but runs the **same builder code** client-side |
| Node/build rule | No JS framework, no build step; only plain CSS (and optional tiny JS) | Allowed if the shim is a plain dependency-free file; toolchain is Swift. Needs a Wasm SDK in CI and exact toolchain match (K12) |
| Console CSP | Strict CSP unchanged; previews in a sandboxed iframe served as static HTML | Needs `'wasm-unsafe-eval'` (or equivalent) on a page next to credentialed console UI; must be isolated in a separate origin/iframe, and CSP review |
| Latency / interactivity | Round trip per edit, fine for forms with debounce | Instant local updates |
| Payload and supply chain | Nothing shipped to the browser | Wasm module of unknown size, loader shim, versioned artifact pipeline and signing |
| Maturity risk | Low; same stack as the rest of the console | Moderate: Foundation subset on Wasm, JS bridging; needs a spike |
| Test | HTML string/DOM snapshots in plain `swift test` on Linux | Needs a headless browser in CI (Python Playwright is allowed; `Server/Tests/browser` already uses Python) |

**Recommendation: (a) for Phases 2 and 3.** It keeps the console's strict CSP, adds no browser-side execution surface and no new artifact pipeline, and is testable on Linux. Add **(b) as a time-boxed spike (S) after Phase 3** only if Studio feedback shows the round trip hurts authoring; the spike must prove Foundation-free presentation code, module size and a sandboxed-origin deployment before any commitment. Both paths use the same `PresentationTree`, so switching renderers does not touch definitions.

Parity testing: (1) tree-level — for every fixture definition, the builder output is serialized and compared across Linux (`swift test`) and macOS runs; (2) SwiftUI snapshot tests (`swift-snapshot-testing` is a dependency decision to check against upstream; or Xcode's own image comparison) on a macOS runner render each fixture, and the web renderer's HTML is rendered in headless Chromium by a Python test; the check compares layout landmarks (node order, text, attribution bar presence, action count) and a tolerance-based pixel diff on tokens-neutral fixtures; (3) a fixture set that includes hostile tokens, long text, Dynamic Type equivalents, RTL. The preview is labeled as a preview, never as the production renderer, and the Studio shows the production-only chrome (system banners, Face ID) as placeholders. CI has only `ubuntu-24.04` runners today (`.github/workflows/*`), so adding a GitHub-hosted macOS job for snapshots is a CI decision (it also covers the existing "app built in current Xcode" step in CLAUDE.md rule 6).

### 5.4 Security tests that must exist before their code (D3 mapping)

| D3 test | First WP that must carry it |
|---|---|
| Cross-tenant leakage in All views | WP-0.5 harness, WP-1.1 |
| Unauthorized selector manipulation | WP-1.1, WP-1.7 |
| Forged Loop actions | WP-3.3 (and WP-4.1) |
| Misleading branded approvals | WP-2.6 |
| Malicious asset uploads | WP-2.2 |
| Consent bypass | WP-3.5, WP-3.3 |
| Stale cache | WP-1.2, WP-2.6 |
| Revoked businesses | WP-1.1, WP-3.2 |
| Staff privilege escalation | WP-3.2, WP-3.4 |
| Review bypass (unreviewed revision, single reviewer on high risk, self-review) | WP-3.2 |
| Prohibited category or health field reaching a customer | WP-1.9, WP-3.1, WP-3.2 |
| Forged or replayed Shopify webhook; checkout URL redirect to a foreign host | WP-4.5, WP-4.6 |

### 5.5 Rollback and observability

Each phase ships dark behind `platform_flags` kill switches (`Operations/PlatformFlags.swift`): `organization_v2` (app falls back to the old tabs by client flag fetched at launch), `brand_kits` (serve no manifests; every client renders neutral), `loops` (no new instances; existing ones show "paused" and nothing is actionable). Metrics added to `Operations/Metrics.swift`: alert list latency, sync lag, asset ingestion rejects by reason, manifest verification failures, Loop action outcomes by state, inbox age of oldest `new` item, DLQ depth for `loop-delivery`. Failure states are visible in the console (inbox banner "deliveries delayed") and to customers (outcome `unknown`).

### 5.6 Phase exit gates (D5)

Threat model delta merged in `SECURITY.md`; the phase's rows of the D3 matrix green on SQLite and PostgreSQL; accessibility acceptance per WP; load/cache test results recorded; legal/counsel sign-off where listed; rollback rehearsed; no new warnings; Package.resolved and CLAUDE.md versions table updated for any new dependency.

## 6. Open decisions

| # | Decision | Recommended default | Who decides |
|---|---|---|---|
| O1 | Top-level tabs and where Activity lives (D6.1) | Variant A (4 tabs, Activity under Alerts, Settings in top bar), confirmed by WP-0.3 | Product owner, after usability test |
| O2 | Pricing and entitlements for Brand Kits and Loops, independently (D6.4) | Two independent entitlement kinds; Brand Kits low-friction, Loops require tier plus review; free tier: neutral only | Product owner |
| O3 | Business notification channels and operating-hour semantics (D6.2) | Inbox + email alert (content-free) at launch; hours only affect staff-facing SLA text and auto "we'll respond" copy, never block submission | Product owner |
| O4 | Asset limits and cache budget (D6.3) | Start 2 MB upload, logo 512 px, background 1600 px, 10 MB device budget; revisit after profiling | Engineering, after device profiling |
| O5 | "Loops" name and customer-facing terms (D6.6, D6.7) | Codename only until counsel clears; string catalog for one-step rename | Product owner and counsel |
| O6 | Disclosure and consent copy | Drafted by counsel in Phase 0; Viadere does not disclaim nonwaivable obligations | Counsel, product owner |
| O7 | Merchant of record and commerce connectors (D6.5) | Decided by the owner: Shopify only, merchant of record is always the merchant (FX-5). Remaining: Shopify distribution path (O18) | Product owner |
| O8 | Preview renderer | Server-side HTML (a); Wasm spike only after Phase 3 | Product owner (recommendation in 5.3) |
| O9 | Image formats | PNG and JPEG only; SVG refused; optional WP-2.9 | Product owner |
| O10 | Anti-abuse and review capacity | Every Loop reviewed (FX-3); size the operator review team and SLA before Phase 3 launch; assets reviewed for businesses below a trust threshold | Product owner, operations |
| O11 | AV scanning of uploads | Re-encoding is the control; ClamAV sidecar optional | Security lead |
| O12 | Browser notifications for the inbox | Not in Phase 3 (K7) | Product owner |
| O13 | Console permission mapping for the spec's four roles (K9) | New permissions on existing roles; no new roles | Product owner |
| O14 | macOS CI runner for snapshot parity (5.3) | Add a GitHub-hosted macOS job, pinned by SHA like the other actions | Engineering, product owner (cost) |
| O15 | Toolchain patch bump to 6.4.2 (K12) | Bump in the next dependency refresh | Engineering |
| O16 | Whether the stage "staged rollout" for Loops is percentage-based or allow-list | Allow-list first (internal businesses), percentage later | Product owner |
| O17 | Loop retention of action inputs and inbox items | 90 days default, configurable per business up to 400, aligned with capability retention (§2.28) | Counsel, product owner |
| O18 | Shopify distribution: custom app for pilot then separate public app; whether a non-embedded public app is acceptable to Shopify's listing review | Pilot with custom distribution; ask Shopify before creating the public app (the choice cannot be changed later) | Product owner, engineering |
| O19 | Scope of the healthcare ban: all Viadere features (platform-wide refusal of the category) versus Loops only | Platform-wide refusal (matches "no healthcare-provider use cases") | Product owner |
| O20 | Review-rule ownership: who writes and maintains the prohibited-category and wording rules, and the SLA for review | Policy owner named by the product owner; rules versioned in Core with an ADR per change; target 2 business days | Product owner |
