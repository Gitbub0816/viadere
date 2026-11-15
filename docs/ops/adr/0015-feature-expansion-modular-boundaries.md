# ADR-0015: Modular boundaries and Core folders for Loops, Brand Kits and Organization

- **Status:** proposed (2026-10-30)
- **Plan reference:** `docs/FEATURE-EXPANSION-PLAN-v4.md` sections 4.1, 4.2, WP-0.1, WP-0.4; spec `docs/FEATURE-EXPANSION-v4.md` D1
- **Related:** ADR-0010 (single image, api/worker roles), ADR-0016, ADR-0017, ADR-0018, `SECURITY.md` §2.92 to §2.94
- **Review:** at each phase gate of the feature expansion; when a module needs its own deployable

## Context

The spec names thirteen logical services (D1) and asks for logical boundaries over service count. The repository is a modular monolith: one Swift server image with API and worker roles (ADR-0010), one shared contract package (`ViadereCore`, Linux and Apple), app logic in `ViadereKit`. CLAUDE.md requires shared logic in Core and forbids duplicating it in the server or app. The new subsystems are business-facing input surfaces (definitions, tokens, layouts) whose validation must be identical on the server (publish gate), in the Studio preview (server-side renderer) and on the device (defense in depth), and later on Android (FX-2, spec only). Two other work streams (Milestones B and C) are editing the server and the `Capability` enum at the same time.

## Decision

1. **New Core folders, pure and Linux-tested**, each owning one contract:
   - `ContractSupport/`: strict JSON reading (closed objects; unknown members are errors), contract hashing (`sha256:` over canonical JSON, §2.2), the shared manifest JWS helper.
   - `Loops/`: `LoopDefinition` (schema v1), `LoopActionRegistry`, `LoopContentRules`, `LoopCategoryPolicy`, `LoopPolicyValidator` (hard gate), `LoopPublicationGate` (review), outcome state machine, submission digest and idempotency, queue envelope, `LoopAccessPolicy` (consent and status gate).
   - `Presentation/`: `PresentationTree`, `PresentationBuilder`, `LoopPublicationManifest`, the customer string catalog (`LoopStringCatalog`).
   - `BrandKits/`: `BrandTokens`, `ContrastPolicy`, `FrameRegistry`, `BrandManifest`, `BrandKitSelector`, `BrandAssetPolicy`.
   - `Surfaces/`: `ModuleRegistry`, page templates, `SurfaceLayout` validation.
   - `Organization/`: `OrganizationContext` and its state rules, alert actionability, mute policy, push dedupe.
2. **Additive only.** No existing Core type is edited. Loop identifiers use their own phantom tags (`LoopIDTag`), not `IDTag`. The Loop action registry references policy capabilities by **string id** (`capabilityId`: `loop.action.hosted`, `loop.action.connected`, `transaction.approve`); the `Capability` enum gains `loop.*` cases only after WP-C1 lands, so it changes once (plan 4.9). Until then those strings decode as `Capability.unknown`, which the policy engine never allows.
3. **Server folders** (later WPs) mirror Core: `Surfaces/`, `BrandKits/` + `Assets/`, `Loops/`, `Alerts/`, `Benefits/`, `Routes/OrganizationRoutes.swift`. Each owns its Fluent models; cross-module access goes through a small service protocol, never another module's models. Every query derives the tenant from the authenticated principal.
4. **Contracts are closed data with conformance vectors.** Each contract has a JSON Schema (documentation, `docs/protocol/schemas/`) and vectors in `docs/protocol/vectors/` generated and re-checked by `FeatureExpansionVectorTests`. The vectors are the Android acceptance criterion (FX-2).
5. **What stays out of Core:** persistence, signing with KMS keys (the server passes a `DeviceSigningKey`-shaped KMS adapter from WP-B2), image decoding and re-encoding, HTTP routes, SwiftUI. Organization view models (`AlertsViewModel`, `BusinessesViewModel`, sync and caches) are Phase 1 Kit work (WP-1.2); only the pure rules they need live in Core.

## Consequences

- One implementation of each rule; the server publish gate, the Studio preview and the device re-validation cannot disagree.
- Core grows by about 3,000 lines with no new dependency (swift-crypto only, as today).
- A rule change (content terms, registry entries, limits) is a Core change with tests, vectors and, for policy rules, an ADR (plan O20).
- Integration points for later phases are named in the types (string capability ids, `KeyManagementService` adapter, `ObjectStore`), so Milestones B and C can merge without touching these folders.
