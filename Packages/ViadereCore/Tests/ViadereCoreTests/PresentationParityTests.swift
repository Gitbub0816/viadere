import Foundation
import Testing
@testable import ViadereCore

/// WP-3.8 part 1, tree-level parity (plan section 5.3 (1) and (3)). For every fixture, `PresentationBuilder` output is serialized to canonical
/// JSON and compared byte for byte with a golden file in `Tests/ViadereCoreTests/Golden/presentation-trees/`. Each golden also carries the
/// tree's `PresentationLandmarks`, so any renderer (the server's web renderer here on Linux; the SwiftUI renderer on a macOS runner, a CI
/// follow-up) can be checked against the same files without running the builder.
///
/// `VIADERE_WRITE_GOLDENS=1 swift test --filter PresentationParityTests` rewrites the goldens (review the diff: a changed golden is a changed
/// customer-visible screen). Without the variable the files are only read.
@Suite("Presentation tree parity goldens")
struct PresentationParityTests {
    static var writing: Bool { ProcessInfo.processInfo.environment["VIADERE_WRITE_GOLDENS"] == "1" }

    static var directory: URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Golden/presentation-trees", isDirectory: true)
    }

    struct Fixture: Sendable {
        var name: String
        var description: String
        var build: @Sendable () async throws -> PresentationTree
    }

    // MARK: Fixture definitions

    /// Exactly `count` characters of plain words (no content-rule hits), ending in a letter.
    static func filler(_ count: Int, seed: String = "Bring the receipt and wait near the counter until we call your name") -> String {
        var out = ""
        while out.count < count { out += (out.isEmpty ? "" : " ") + seed }
        var cut = String(out.prefix(count))
        while cut.last == " " { cut.removeLast(); cut += "x" }
        return cut
    }

    static var longText: LoopDefinition {
        LoopDefinition(key: "long-text", title: filler(LoopLimits.titleLength), description: filler(LoopLimits.descriptionLength),
                       entryPoints: [.businessPage],
                       steps: [
                        LoopStep(id: "s1", type: .form, title: filler(LoopLimits.stepTitleLength, seed: "Choose what suits you best today"),
                                 body: filler(LoopLimits.bodyLength), fields: [
                                    LoopField(id: "pick", type: .singleChoice, label: filler(LoopLimits.fieldLabelLength, seed: "Which option works for your visit"),
                                              required: true, options: (1...LoopLimits.maxOptions).map {
                                                  LoopOption(id: "o\($0)", label: filler(LoopLimits.optionLabelLength, seed: "Option number \($0) with extra words"))
                                              }),
                                 ], actions: [LoopActionBinding(id: "send", action: "acknowledge", label: "send_request",
                                                                customLabel: filler(LoopLimits.customLabelLength, seed: "Send this to the shop now"), next: "done",
                                                                routing: LoopRouting(mode: .hosted))]),
                        LoopStep(id: "done", type: .result, showOutcome: true),
                       ], limits: LoopLimits(expiresInSeconds: 86_400))
    }

    static var rtl: LoopDefinition {
        LoopDefinition(key: "rtl-pickup", title: "اختر وقت الاستلام", entryPoints: [.message],
                       steps: [
                        LoopStep(id: "s1", type: .form, title: "בחרו שעה", body: "Order 1042 · الطلب جاهز", fields: [
                            LoopField(id: "slot", type: .timeSlot, label: "وقت الاستلام", required: true,
                                      options: [LoopOption(id: "am", label: "صباحا"), LoopOption(id: "pm", label: "אחר הצהריים")]),
                        ], actions: [LoopActionBinding(id: "next", action: "select_pickup_time", label: "choose_time", next: "s2")]),
                        LoopStep(id: "s2", type: .summary, title: "שליחה",
                                 actions: [LoopActionBinding(id: "send", action: "acknowledge", label: "send_request", next: "done",
                                                             routing: LoopRouting(mode: .hosted, queue: "pickups"))]),
                        LoopStep(id: "done", type: .result, showOutcome: true),
                       ], limits: LoopLimits(expiresInSeconds: 86_400))
    }

    /// Every input control: six fields on the first step, a time slot on the second.
    static var allInputs: LoopDefinition {
        LoopDefinition(key: "all-inputs", title: "Plan your visit", entryPoints: [.businessPage],
                       steps: [
                        LoopStep(id: "s1", type: .form, title: "A few details", body: "Answer what applies.", fields: [
                            LoopField(id: "service", type: .singleChoice, label: "Service", required: true,
                                      options: [LoopOption(id: "cut", label: "Haircut"), LoopOption(id: "color", label: "Color")]),
                            LoopField(id: "extras", type: .multiChoice, label: "Extras",
                                      options: [LoopOption(id: "wash", label: "Wash"), LoopOption(id: "style", label: "Styling")]),
                            LoopField(id: "name", type: .shortText, label: "Name for the booking", required: true, maxLength: 40),
                            LoopField(id: "day", type: .date, label: "Preferred day"),
                            LoopField(id: "first", type: .yesNo, label: "First visit?"),
                            LoopField(id: "policy", type: .acknowledgement, label: "I read the cancellation policy", required: true),
                        ], actions: [LoopActionBinding(id: "next", action: "select_option", label: "next", next: "s2"),
                                     LoopActionBinding(id: "later", action: "submit_inquiry", label: "send_inquiry", next: "done",
                                                       routing: LoopRouting(mode: .hosted, queue: "bookings"))]),
                        LoopStep(id: "s2", type: .form, title: "Pick a time", fields: [
                            LoopField(id: "slot", type: .timeSlot, label: "Time", required: true,
                                      options: [LoopOption(id: "t10", label: "10:00"), LoopOption(id: "t14", label: "14:00")]),
                        ], actions: [LoopActionBinding(id: "send", action: "acknowledge", label: "send_request", next: "done",
                                                       routing: LoopRouting(mode: .hosted, queue: "bookings"))]),
                        LoopStep(id: "done", type: .result, showOutcome: true),
                       ], limits: LoopLimits(expiresInSeconds: 86_400))
    }

    /// Tokens that fail every contrast check: the builder clamps them, and protected nodes never see them.
    static let hostileTokens = BrandTokens(primary: BrandColor("#FFFF00")!, secondary: BrandColor("#FFFFFE")!, accent: BrandColor("#FEFEFE")!,
                                           surface: BrandColor("#FFFF66")!, radius: .large, border: .regular, typeScale: .large)

    static func tree(_ definition: LoopDefinition, _ phase: PresentationPhase, brand: BrandKitPresentation? = nil,
                     status: LoopPublicationStatus = .active, manifest: Bool = true) async throws -> PresentationTree {
        let signed = manifest ? try await FX.manifest(for: definition) : nil
        return PresentationBuilder.build(FX.presentation(definition, manifest: signed, brand: brand, status: status), phase: phase)
    }

    static let fixtures: [Fixture] = [
        Fixture(name: "pickup-form", description: "Plan 4.3 pickup example, form step: attribution first, choice field, one action") {
            try await tree(FX.pickup, .step("s1"))
        },
        Fixture(name: "pickup-summary", description: "Pickup example, summary step with a delivering action") {
            try await tree(FX.pickup, .step("s2"))
        },
        Fixture(name: "pickup-result-pending", description: "Pickup example, result step with the pending outcome (protected)") {
            try await tree(FX.pickup, .step("done", outcome: .pending))
        },
        Fixture(name: "pickup-result-accepted", description: "Pickup example, result step with the accepted outcome") {
            try await tree(FX.pickup, .step("done", outcome: .accepted))
        },
        Fixture(name: "estimate-review-branded", description: "High-risk estimate review with the business's own Brand Kit (style only)") {
            try await tree(FX.estimate, .step("review"), brand: BrandKitPresentation(businessId: FX.business, kitId: "spring", tokens: FX.springTokens,
                                                                                    frameId: "viadere.frame.hairline.v1"))
        },
        Fixture(name: "estimate-confirmation", description: "Registry-generated confirmation panel naming the responsible business and amount") {
            try await tree(FX.estimate, .confirm(stepId: "review", actionId: "ack"))
        },
        Fixture(name: "hostile-tokens", description: "Brand tokens failing every contrast check: clamped to neutral roles; tree identical to neutral") {
            try await tree(FX.estimate, .step("review"), brand: BrandKitPresentation(businessId: FX.business, kitId: "spring", tokens: hostileTokens))
        },
        Fixture(name: "foreign-kit-ignored", description: "A kit of another business is ignored: neutral style") {
            try await tree(FX.estimate, .step("review"), brand: BrandKitPresentation(businessId: FX.otherBusiness, kitId: "spring", tokens: FX.springTokens))
        },
        Fixture(name: "long-text", description: "Every text slot at its maximum length, ten options, a custom label") {
            try await tree(longText, .step("s1"))
        },
        Fixture(name: "rtl-text", description: "Arabic and Hebrew text with mixed Latin digits") {
            try await tree(rtl, .step("s1"))
        },
        Fixture(name: "all-inputs", description: "Every input control, the health-privacy notice (short text) and two actions") {
            try await tree(allInputs, .step("s1"))
        },
        Fixture(name: "time-slot", description: "Time slot control") {
            try await tree(allInputs, .step("s2"))
        },
        Fixture(name: "check-in-confirmation", description: "Medium-risk check-in confirmation from a locked template") {
            let definition = LoopTemplateCatalog.template("salon_check_in")!.definition
            return try await tree(definition, .confirm(stepId: "s2", actionId: "arrive"))
        },
        Fixture(name: "first-party-home", description: "First-party screen of module slots: no attribution bar") {
            PresentationBuilder.firstPartyScreen(id: "business_home", title: "Juniper Salon",
                                                 modules: [ModulePlacement(module: "profile", size: .regular), ModulePlacement(module: "offers", size: .compact)])
        },
        Fixture(name: "fallback-manifest-missing", description: "Safe fallback: no manifest, no business content, Close and Report only") {
            try await tree(FX.pickup, .step("s1"), manifest: false)
        },
        Fixture(name: "fallback-hostile-bidi", description: "A bidi override in the title fails device re-validation: fallback, title never shown") {
            var definition = FX.pickup
            definition.title = "Schedule \u{202E}pickup"
            return try await tree(definition, .step("s1"))
        },
        Fixture(name: "paused", description: "Suspended publication: neutral paused notice, Close only") {
            try await tree(FX.pickup, .step("s1"), status: .suspended)
        },
    ]

    // MARK: Goldens

    static func goldenValue(_ fixture: Fixture, _ tree: PresentationTree) throws -> JSONValue {
        .object(["name": .string(fixture.name), "description": .string(fixture.description), "tree": try JSONValue.encoding(tree),
                 "landmarks": try JSONValue.encoding(PresentationLandmarks(tree))])
    }

    @Test func goldenTreesMatchTheBuilder() async throws {
        if Self.writing { try FileManager.default.createDirectory(at: Self.directory, withIntermediateDirectories: true) }
        for fixture in Self.fixtures {
            let tree = try await fixture.build()
            let bytes = try CanonicalJSON.serialize(try Self.goldenValue(fixture, tree)) + Data("\n".utf8)
            let url = Self.directory.appendingPathComponent("\(fixture.name).json")
            if Self.writing { try bytes.write(to: url) }
            let stored = try Data(contentsOf: url)
            #expect(stored == bytes, "\(fixture.name): builder output differs from the golden (VIADERE_WRITE_GOLDENS=1 to regenerate, then review the diff)")
            // The stored tree decodes back to the same value (any renderer can start from the file).
            let decoded = try JSONDecoder().decode(Golden.self, from: stored)
            #expect(decoded.tree == tree, "\(fixture.name)")
            #expect(decoded.landmarks == PresentationLandmarks(tree), "\(fixture.name)")
        }
        // No stray goldens: every file belongs to a fixture.
        let files = try FileManager.default.contentsOfDirectory(atPath: Self.directory.path).filter { $0.hasSuffix(".json") }.sorted()
        #expect(files == Self.fixtures.map { "\($0.name).json" }.sorted())
    }

    struct Golden: Decodable {
        var name: String
        var tree: PresentationTree
        var landmarks: PresentationLandmarks
    }

    @Test func fixturesCoverEveryNodeKindAndTheParityRisks() async throws {
        var kinds = Set<String>()
        var landmarks: [String: PresentationLandmarks] = [:]
        var trees: [String: PresentationTree] = [:]
        for fixture in Self.fixtures {
            let tree = try await fixture.build()
            trees[fixture.name] = tree
            landmarks[fixture.name] = PresentationLandmarks(tree)
            kinds.formUnion(tree.nodes.map(\.kind))
        }
        #expect(kinds == ["screen", "header", "attribution_bar", "text", "field_group", "choice", "input", "action_bar", "confirmation_panel",
                          "outcome_status", "module_slot", "notice"])
        // Every business Loop screen reads the attribution first; first-party and fallback trees have none.
        for (name, l) in landmarks {
            let origin = trees[name]!.origin
            #expect(l.attributionBar == (origin == .business), "\(name)")
            #expect(l.attributionFirst == (origin == .business), "\(name)")
        }
        // Hostile tokens are clamped and change nothing but style; a foreign kit changes nothing at all.
        let hostile = trees["hostile-tokens"]!, branded = trees["estimate-review-branded"]!, foreign = trees["foreign-kit-ignored"]!
        #expect(hostile.root == branded.root)
        #expect(hostile.style.palette.light.primary != Self.hostileTokens.primary)
        #expect(hostile.style.palette.overriddenLight.contains(.primary) && hostile.style.palette.overriddenLight.contains(.accent))
        #expect(foreign.style == .neutral)
        // Text survives verbatim at its limits and in right-to-left scripts.
        #expect(landmarks["long-text"]!.texts.contains(Self.filler(LoopLimits.bodyLength)))
        #expect(landmarks["rtl-text"]!.texts.contains("وقت الاستلام"))
        #expect(landmarks["fallback-hostile-bidi"]!.texts.allSatisfy { !$0.contains("pickup") })
        #expect(landmarks["fallback-manifest-missing"]!.actionCount == 2)
        #expect(landmarks["paused"]!.actionCount == 1)
        #expect(landmarks["estimate-confirmation"]!.protectedKinds == ["attribution_bar", "confirmation_panel", "action_bar"])
    }

    @Test func landmarksFollowReadingOrder() async throws {
        let tree = try await Self.tree(FX.pickup, .step("s1"))
        let l = PresentationLandmarks(tree)
        #expect(l.nodeKinds == ["screen", "attribution_bar", "header", "field_group", "choice", "action_bar"])
        #expect(l.texts == ["Schedule your pickup", "Built by Juniper Salon", "Verified business", "Schedule your pickup", "Pickup time", "Morning",
                            "Afternoon", "Continue"])
        #expect(l.attributionBar && l.attributionFirst)
        #expect(l.actionCount == 1)
        #expect(l.protectedKinds == ["attribution_bar"])
    }
}
