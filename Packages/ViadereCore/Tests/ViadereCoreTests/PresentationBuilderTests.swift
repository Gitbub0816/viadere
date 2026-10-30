import Foundation
import Testing
@testable import ViadereCore

/// Spec A6a acceptance tests T1–T6 at model level, the safe fallback, confirmation panels and D3.T4 (misleading branded approvals).
@Suite("Presentation builder and attribution")
struct PresentationBuilderTests {
    func build(_ definition: LoopDefinition = FX.pickup, manifest: String?, phase: PresentationPhase = .step("s1"),
               publisher: VerifiedBusinessRecord? = FX.salon, brand: BrandKitPresentation? = nil, status: LoopPublicationStatus = .active) -> PresentationTree {
        PresentationBuilder.build(FX.presentation(definition, manifest: manifest, publisher: publisher, brand: brand, status: status), phase: phase)
    }

    func attribution(_ tree: PresentationTree) -> AttributionNode? {
        for node in tree.nodes { if case .attributionBar(let a) = node { return a } }
        return nil
    }

    func firstChild(_ tree: PresentationTree) -> PresentationNode? { tree.root.children.first }

    var spring: BrandKitPresentation { BrandKitPresentation(businessId: FX.business, kitId: "spring", tokens: FX.springTokens, frameId: "viadere.frame.hairline.v1") }

    // T1: default styling shows "Built by {business}".
    @Test func t1DefaultStyledBusinessLoopShowsBuiltBy() async throws {
        let tree = build(manifest: try await FX.manifest(for: FX.pickup))
        #expect(tree.origin == .business)
        guard case .attributionBar(let bar)? = firstChild(tree) else { Issue.record("attribution bar is not first"); return }
        #expect(bar.text == "Built by Juniper Salon")
        #expect(bar.businessId == FX.business)
        #expect(bar.protected && bar.verified)
        #expect(bar.verifiedLabel == "Verified business")
        #expect(tree.style == .neutral)
        // Present on every step and on the confirmation view.
        for phase: PresentationPhase in [.step("s2"), .step("done", outcome: .pending)] {
            #expect(attribution(build(manifest: try await FX.manifest(for: FX.pickup), phase: phase))?.text == "Built by Juniper Salon")
        }
    }

    // T2: the same attribution with a Brand Kit; tokens never reach protected nodes.
    @Test func t2BrandKitKeepsTheSameAttribution() async throws {
        let definition = FX.estimate
        let manifest = try await FX.manifest(for: definition)
        let branded = build(definition, manifest: manifest, phase: .step("review"), brand: spring)
        let neutral = build(definition, manifest: manifest, phase: .step("review"), brand: nil)
        #expect(branded.style.source == .brandKit && branded.style.kitId == "spring")
        #expect(neutral.style.source == .neutral)
        #expect(attribution(branded) == attribution(neutral))
        // Only the style differs: the node tree (text, order, actions, protected flags) is identical.
        #expect(branded.root == neutral.root)
    }

    // T3: first-party surfaces are never labeled "Built by".
    @Test func t3FirstPartyIsNotMislabeled() async throws {
        let home = PresentationBuilder.firstPartyScreen(id: "business_home", title: "Juniper Salon",
                                                        modules: [ModulePlacement(module: "profile", size: .regular), ModulePlacement(module: "offers", size: .compact)])
        #expect(home.origin == .viadere)
        #expect(attribution(home) == nil)
        #expect(home.compactOrigin == nil)
        // A first-party Loop publication (publisher_type viadere) renders without "Built by".
        let manifest = try await FX.manifest(for: FX.pickup, publisher: .viadere, business: nil)
        let tree = build(manifest: manifest)
        #expect(tree.origin == .viadere)
        #expect(attribution(tree) == nil)
        #expect(!(try String(decoding: tree.canonicalJSON(), as: UTF8.self)).contains("Built by"))
    }

    // T4: concealing or spoofing attribution fails.
    @Test func t4SpoofedAttributionInTheDefinitionIsNeverRendered() async throws {
        for title in ["Built by Viadere", "Created by Viadere Security", "Secured by Viadere", "Verified by Juniper Salon"] {
            var d = FX.pickup
            d.title = title
            // Even if a (compromised) server signed it, the device re-validation refuses to render it.
            let tree = build(d, manifest: try await FX.manifest(for: d))
            #expect(tree.origin == .unavailable, "\(title)")
            #expect(tree.fallbackReason == PresentationFallbackReason.definitionRejected.rawValue)
            #expect(!(try String(decoding: tree.canonicalJSON(), as: UTF8.self)).contains(title))
        }
    }

    @Test func t4ManifestForgeryAndMismatchFallBackSafely() async throws {
        let good = try await FX.manifest(for: FX.pickup)
        // Missing, garbage, wrong key, wrong kid, other business, unknown policy version, expired, wrong definition, tampered payload.
        let otherKey = FX.key("attacker")
        var other = FX.pickup
        other.title = "Schedule a delivery"
        let parts = good.split(separator: ".").map(String.init)
        var tampered: String {
            var payload = String(decoding: Base64URL.decode(parts[1])!, as: UTF8.self)
            payload = payload.replacingOccurrences(of: FX.business.description, with: FX.otherBusiness.description)
            return parts[0] + "." + Base64URL.encode(Data(payload.utf8)) + "." + parts[2]
        }
        let headerNone = Base64URL.encode(Data(#"{"alg":"none","kid":"loop-publication-v1","typ":"viadere-loop-publication+jws"}"#.utf8))
        let cases: [(String?, PresentationFallbackReason)] = [
            (nil, .manifestMissing),
            ("not.a.jws", .manifestInvalid),
            (try await FX.manifest(for: FX.pickup, key: otherKey), .manifestInvalid),
            (try await FX.manifest(for: FX.pickup, kid: "unknown-kid"), .manifestInvalid),
            (try await FX.manifest(for: FX.pickup, business: FX.otherBusiness), .publisherMismatch),
            (try await FX.manifest(for: FX.pickup, policy: 2), .attributionPolicyUnknown),
            (try await FX.manifest(for: FX.pickup, validFrom: FX.now.addingTimeInterval(-40 * 86400)), .manifestInvalid),
            (try await FX.manifest(for: FX.pickup, validFrom: FX.now.addingTimeInterval(3600)), .manifestInvalid),
            (try await FX.manifest(for: FX.pickup, lifetime: 400 * 86400), .manifestInvalid),
            (try await FX.manifest(for: other), .definitionHashMismatch),
            (tampered, .manifestInvalid),
            (headerNone + "." + parts[1] + "." + parts[2], .manifestInvalid),
            (good + "x", .manifestInvalid),
        ]
        for (manifest, reason) in cases {
            let tree = build(manifest: manifest)
            #expect(tree.origin == .unavailable)
            #expect(tree.fallbackReason == reason.rawValue, "\(String(describing: manifest?.prefix(20))) → \(String(describing: tree.fallbackReason))")
            assertSafeFallback(tree)
        }
        // A viadere-typed manifest claiming a business is refused; a business manifest for a business that is not verified, unknown,
        // or whose directory name impersonates Viadere falls back as well.
        #expect(build(manifest: good, publisher: nil).fallbackReason == PresentationFallbackReason.publisherUnknown.rawValue)
        #expect(build(manifest: good, publisher: VerifiedBusinessRecord(id: FX.business, displayName: "Juniper Salon", verificationStatus: .suspended)).fallbackReason
            == PresentationFallbackReason.publisherNotVerified.rawValue)
        #expect(build(manifest: good, publisher: VerifiedBusinessRecord(id: FX.otherBusiness, displayName: "Juniper Salon", verificationStatus: .verified)).fallbackReason
            == PresentationFallbackReason.publisherMismatch.rawValue)
        #expect(build(manifest: good, publisher: VerifiedBusinessRecord(id: FX.business, displayName: "Viadere Support", verificationStatus: .verified)).fallbackReason
            == PresentationFallbackReason.publisherNameInvalid.rawValue)
        #expect(build(manifest: good, publisher: VerifiedBusinessRecord(id: FX.business, displayName: "\u{202E}\u{200B}", verificationStatus: .verified)).fallbackReason
            == PresentationFallbackReason.publisherNameInvalid.rawValue)
        #expect(build(manifest: good, status: .revoked).fallbackReason == PresentationFallbackReason.publicationNotActive.rawValue)
        let paused = build(manifest: good, status: .suspended)
        #expect(paused.origin == .unavailable && paused.fallbackReason == "publication_suspended")
        #expect(build(manifest: good, phase: .step("nope")).fallbackReason == PresentationFallbackReason.unknownStep.rawValue)
        #expect(build(manifest: good, phase: .confirm(stepId: "s1", actionId: "confirm")).fallbackReason == PresentationFallbackReason.unknownAction.rawValue)
    }

    func assertSafeFallback(_ tree: PresentationTree) {
        #expect(tree.style == .neutral)
        #expect(tree.compactOrigin == nil)
        // Only the notice and Close/Report: no business text, fields or business actions.
        let kinds = tree.nodes.map(\.kind)
        #expect(kinds == ["screen", "notice", "action_bar"])
        guard case .actionBar(let bar)? = tree.root.children.last else { return }
        #expect(bar.actions.map(\.actionType) == ["viadere.close", "viadere.report"])
        #expect(bar.actions.allSatisfy(\.system) && bar.protected)
    }

    @Test func hostileTokensCannotHideAttributionOrRestyleProtectedNodes() async throws {
        // D3.T4: a kit that sets everything to the surface color (to make the bar vanish) or to unreadable values.
        let hostile = BrandTokens(primary: BrandColor("#FCFBF8")!, secondary: BrandColor("#FCFBF8")!, accent: BrandColor("#FFFFFF")!,
                                  surface: BrandColor("#FCFBF8")!)
        let definition = FX.estimate
        let manifest = try await FX.manifest(for: definition)
        let tree = build(definition, manifest: manifest, phase: .confirm(stepId: "review", actionId: "ack"),
                         brand: BrandKitPresentation(businessId: FX.business, kitId: "spring", tokens: hostile))
        let reference = build(definition, manifest: manifest, phase: .confirm(stepId: "review", actionId: "ack"))
        // Text, order, actions and protection flags are identical with and without the hostile kit.
        #expect(tree.root == reference.root)
        // The clamp replaced every failing role.
        #expect(tree.style.palette.overriddenLight == [.primary, .secondary, .accent])
        #expect(tree.style.palette.light.primary == NeutralPalette.palette(.light).primary)
        // Protected nodes are flagged; renderers draw them with the neutral protected palette.
        let protectedKinds = tree.nodes.filter(\.isProtected).map(\.kind)
        #expect(protectedKinds == ["attribution_bar", "confirmation_panel", "action_bar"])
        #expect(ProtectedPalette.palette(.light) == NeutralPalette.palette(.light))
    }

    @Test func kitsOfOtherBusinessesOrUnrequestedKitsAreIgnored() async throws {
        let definition = FX.estimate
        let manifest = try await FX.manifest(for: definition)
        let foreign = BrandKitPresentation(businessId: FX.otherBusiness, kitId: "spring", tokens: FX.springTokens)
        #expect(build(definition, manifest: manifest, phase: .step("review"), brand: foreign).style == .neutral)
        let wrongKit = BrandKitPresentation(businessId: FX.business, kitId: "winter", tokens: FX.springTokens)
        #expect(build(definition, manifest: manifest, phase: .step("review"), brand: wrongKit).style == .neutral)
        // A standard-appearance Loop stays neutral even when the business has a kit (appearance is independent, B6.3).
        #expect(build(manifest: try await FX.manifest(for: FX.pickup), brand: spring).style == .neutral)
        // An unknown or out-of-season frame is dropped.
        var seasonal = spring
        seasonal.frameId = "viadere.frame.snow.v1"
        #expect(build(definition, manifest: manifest, phase: .step("review"), brand: seasonal).style.frameId == nil)
        seasonal.frameId = "business.frame.fake"
        #expect(build(definition, manifest: manifest, phase: .step("review"), brand: seasonal).style.frameId == nil)
        #expect(build(definition, manifest: manifest, phase: .step("review"), brand: spring).style.frameId == "viadere.frame.hairline.v1")
    }

    // Confirmation panels: generated from the registry, naming the responsible business and the effect.
    @Test func confirmationNamesTheResponsibleBusinessAndEffect() async throws {
        let definition = FX.estimate
        let tree = build(definition, manifest: try await FX.manifest(for: definition), phase: .confirm(stepId: "review", actionId: "ack"))
        guard case .attributionBar? = tree.root.children.first, case .confirmationPanel(let panel)? = tree.root.children.dropFirst().first else {
            Issue.record("expected attribution bar then confirmation panel: \(tree.nodes.map(\.kind))")
            return
        }
        #expect(panel.responsibleBusinessId == FX.business)
        #expect(panel.responsibleBusinessName == "Juniper Salon")
        #expect(panel.title == "Estimate from Juniper Salon")
        #expect(panel.statement == "Juniper Salon sent you an estimate of $285.28.")
        #expect(panel.effect.contains("doesn't approve or charge anything"))
        #expect(panel.amount == "$285.28")
        #expect(panel.accessibilityLabel.contains("Responsible business: Juniper Salon"))
        #expect(panel.protected)
        guard case .actionBar(let bar)? = tree.root.children.last else { return }
        #expect(bar.protected)
        #expect(bar.actions.map(\.label) == ["Send acknowledgment", "Cancel"])
        // In the step view the consequential action is marked as needing confirmation.
        let step = build(definition, manifest: try await FX.manifest(for: definition), phase: .step("review"))
        guard case .actionBar(let stepBar)? = step.root.children.last else { return }
        #expect(stepBar.actions.first?.requiresConfirmation == true)
    }

    // T5: accessibility announces authorship first.
    @Test func t5AttributionIsFirstInReadingOrderWithAnExplicitLabel() async throws {
        let tree = build(manifest: try await FX.manifest(for: FX.pickup))
        let order = tree.nodes.map(\.kind)
        #expect(order.first == "screen")
        #expect(order.dropFirst().first == "attribution_bar")
        #expect(attribution(tree)?.accessibilityLabel == "Built by Juniper Salon, a business on Viadere")
    }

    // T6: compact surfaces carry a concise business-origin indicator.
    @Test func t6CompactOrigin() async throws {
        #expect(build(manifest: try await FX.manifest(for: FX.pickup)).compactOrigin == "By Juniper Salon")
        #expect(PresentationBuilder.compactOrigin("Juniper Salon and Day Spa of North Phoenix")?.count ?? 99 <= PresentationBuilder.compactOriginMaxCharacters)
        #expect(PresentationBuilder.compactOrigin("Juniper Salon and Day Spa of North Phoenix")?.hasPrefix("By Juniper") == true)
        #expect(PresentationBuilder.compactOrigin("Viadere") == nil)
        #expect(PresentationBuilder.compactOrigin("") == nil)
    }

    @Test func freeTextStepsCarryTheHealthPrivacyNotice() async throws {
        var d = FX.pickup
        d.steps[0].fields.append(LoopField(id: "note", type: .shortText, label: "Note for the florist", maxLength: 80))
        let tree = build(d, manifest: try await FX.manifest(for: d))
        #expect(tree.nodes.contains { if case .notice(let n) = $0 { n.kind == .healthPrivacy && n.text == "Don't share health details here." } else { false } })
        #expect(!build(manifest: try await FX.manifest(for: FX.pickup)).nodes.contains { if case .notice = $0 { true } else { false } })
    }

    @Test func outcomeStatusAndFieldNodes() async throws {
        let manifest = try await FX.manifest(for: FX.pickup)
        let result = build(manifest: manifest, phase: .step("done", outcome: .unknown))
        #expect(result.nodes.contains { if case .outcomeStatus(let o) = $0 { o.outcome == .unknown && o.text == "We couldn't confirm that Juniper Salon received this." && o.protected } else { false } })
        let form = build(manifest: manifest)
        #expect(form.nodes.map(\.kind) == ["screen", "attribution_bar", "header", "field_group", "choice", "action_bar"])
        guard case .actionBar(let bar)? = form.root.children.last else { return }
        #expect(bar.actions.map(\.label) == ["Continue"])
        #expect(!bar.protected)
    }

    @Test func treeEncodingRoundTrips() async throws {
        let tree = build(FX.estimate, manifest: try await FX.manifest(for: FX.estimate), phase: .confirm(stepId: "review", actionId: "ack"), brand: spring)
        let data = try tree.canonicalJSON()
        #expect(try JSONDecoder().decode(PresentationTree.self, from: data) == tree)
        #expect(throws: (any Error).self) { try JSONDecoder().decode(PresentationNode.self, from: Data(#"{"kind":"web_view","url":"https://x"}"#.utf8)) }
    }
}
