# ADR-0016: One presentation model, two renderers, server-side preview

- **Status:** proposed (2026-10-30)
- **Plan reference:** `docs/FEATURE-EXPANSION-PLAN-v4.md` decision FX-1, FX-2, sections 4.4, 5.3, conflicts K1, K2; spec A5, A6a, B4, B6
- **Related:** ADR-0015, `SECURITY.md` §2.92, `Packages/ViadereCore/Sources/ViadereCore/Presentation/*`
- **Review:** after Phase 3 Studio feedback (Wasm spike decision, O8); when an Android renderer is scheduled

## Context

Loops and Brand Kits need business-configured screens that Viadere still fully controls: native components, security wording, attribution and action semantics (INV-4, INV-5). The spec suggested a React simulator, which CLAUDE.md rule 4 forbids (no Node), and the product owner decided on a Swift renderer for the Studio (FX-1). Android is specification only (FX-2). The attribution requirements (A6a) must hold whatever the theme, and must be testable without UI.

## Decision

1. **`PresentationTree`** (Core) is the only thing renderers consume: a closed, recursive set of nodes (`screen`, `header`, `attribution_bar`, `text`, `field_group`, `choice`, `input`, `action_bar`, `confirmation_panel`, `outcome_status`, `module_slot`, `notice`) with semantic roles (`primary`, `secondary`, `danger`, `surface`), never colors or fonts. Child order is reading order. The tree is `Equatable` and canonically encodable, so tree equality is a plain `swift test` on Linux.
2. **`PresentationBuilder`** (Core, pure) is the only producer. It verifies the publication manifest, re-validates the definition with `LoopPolicyValidator`, inserts the attribution bar from the signed manifest and the verified directory record, generates confirmation panels from the action registry, and applies clamped Brand Kit styling. Invariants it enforces (tests T1 to T6 and D3.T4 in `PresentationBuilderTests`):
   - a business Loop's first node is a protected `attribution_bar` ("Built by {verified name}", accessibility label "Built by {name}, a business on Viadere");
   - first-party trees (`origin: viadere`) never contain one;
   - missing or invalid publisher metadata yields the neutral fallback (notice plus Close and Report, no body);
   - protected nodes (attribution, confirmation, outcome, notices, confirmation and fallback action bars) ignore Brand Kit styling and frames; renderers draw them with `ProtectedPalette`;
   - compact surfaces use `compactOrigin` ("By {name}").
3. **Renderers.** SwiftUI `PresentationView` in `App/Shared/` (production, iOS, WP-3.6) maps each node to design-system components. The Studio preview is a **server-side Swift renderer to HTML/CSS** (WP-2.5/3.7), served in a sandboxed iframe under the console's existing strict CSP, labeled "Preview, not exactly what customers see". It renders the same tree; no JavaScript framework and no build step. A Swift-to-WebAssembly preview is a time-boxed spike after Phase 3 only (plan 5.3).
4. **Unknown node kinds fail closed.** A renderer that meets a node kind it does not know shows the fallback, never a partial screen.
5. **Parity testing:** tree-level equality across platforms through the vectors (`presentation-tree-v1.json`), plus SwiftUI snapshot and accessibility tests on a macOS runner and HTML landmark checks for the web renderer (WP-3.8). A future Compose renderer must reproduce the same vectors.

## Consequences

- Business data can never add, remove or restyle trust chrome: there is no field for it in the definition, the tokens or the layout, and the builder is the only producer.
- The preview is a second renderer and can drift visually; it is labeled as a preview and parity is tested on the tree, not on pixels alone.
- Wire detail: a notice's own kind is encoded as `notice_kind` because `kind` is the node discriminator.
