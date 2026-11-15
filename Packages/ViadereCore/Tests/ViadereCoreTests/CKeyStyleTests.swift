import Crypto
import Foundation
import Testing
@testable import ViadereCore

/// Custom CKey styles against the reference core (`docs/protocol/vectors/ckey-style-v1.json`, made by clearkeysolutions/ckey
/// v0.1.0-build.85): the same verdict and message for every style in the table, and the same SVG byte for byte for every accepted one.
/// Then the rules Viadere adds for a business's own code (`BusinessCodeStyle`, docs/SECURITY.md §2.105).
@Suite struct CKeyStyleTests {
    struct Vectors: Decodable {
        struct Check: Decodable { let name: String, style: CKeyStyleSpec, accepted: Bool, message: String }
        struct Render: Decodable { let name: String, style: CKeyStyleSpec, payload: String, requested_version: Int, level: Int, svg_sha256: String }
        let checks: [Check], renders: [Render]
    }

    static func load() throws -> Vectors {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { url.deleteLastPathComponent() }
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url.appendingPathComponent("docs/protocol/vectors/ckey-style-v1.json")))
    }

    static func color(_ hex: String) -> BrandColor { BrandColor(hex)! }

    // MARK: The reference's check

    @Test func everyReferenceVerdictIsReproduced() throws {
        let checks = try Self.load().checks
        #expect(checks.count >= 30)
        var refused = 0, advised = 0
        for check in checks {
            let verdict = CKeyStyleCheck.evaluate(check.style)
            switch verdict {
            case .refused:
                refused += 1
                #expect(!check.accepted, "\(check.name)")
                #expect(throws: CKeyStyleCheck.Refusal.self, "\(check.name)") { try CKeyStyle(validating: check.style) }
            case .advice:
                advised += 1
                #expect(check.accepted, "\(check.name)")
                #expect(check.message.hasPrefix("style OK, but "), "\(check.name)")
            case .ok:
                #expect(check.accepted, "\(check.name)")
                #expect(check.message.hasPrefix("style OK: "), "\(check.name)")
            }
            // The reference's diagnostics hold 95 characters. The ratio is printed from `pow`; see the note on the SVG test.
            #if os(Linux)
            #expect(String(verdict.referenceMessage.prefix(95)) == check.message, "\(check.name)")
            #endif
        }
        #expect(refused >= 10 && advised >= 8)
    }

    @Test func theFloorsSitWhereTheReferencePutsThem() {
        let white = Self.color("#FFFFFF")
        // #D2D2D2 on white is the last grey above 1.5:1, #D3D3D3 the first below; #949494 and #959595 straddle 3:1.
        #expect(CKeyStyleCheck.evaluate(CKeyStyleSpec(background: white, ink: Self.color("#D3D3D3"))) == .refused(.tooFaint(ink: "#d3d3d3", background: "#ffffff", ratio: CKeyStyleCheck.contrastRatio(Self.color("#D3D3D3"), white))))
        if case .advice(.lowContrast, _) = CKeyStyleCheck.evaluate(CKeyStyleSpec(background: white, ink: Self.color("#D2D2D2"))) {} else { Issue.record("1.5:1 is advice") }
        if case .advice(.lowContrast, _) = CKeyStyleCheck.evaluate(CKeyStyleSpec(background: white, ink: Self.color("#959595"))) {} else { Issue.record("just under 3:1 is advice") }
        if case .ok = CKeyStyleCheck.evaluate(CKeyStyleSpec(background: white, ink: Self.color("#949494"))) {} else { Issue.record("3:1 passes") }
        #expect(CKeyStyleCheck.isLightOnDark(.concept) == true)
        #expect(CKeyStyleCheck.isLightOnDark(.plain) == false)
        #expect(CKeyStyleCheck.isLightOnDark(CKeyStyleSpec(background: Self.color("#808080"), ink: white, inkShade: Self.color("#000000"))) == nil)
    }

    // MARK: Rendering

    @Test func thePresetSpecsAreThePresets() throws {
        #expect(try CKeyStyle(validating: .plain) == .plain)
        #expect(try CKeyStyle(validating: .concept) == .concept)
    }

    // Coordinates and filter amounts are printed to four decimals; see `CKeySymbolTests` on why the hash is checked on Linux only.
    #if os(Linux)
    @Test func everyReferenceStyleRendersTheSameSVG() throws {
        let renders = try Self.load().renders
        #expect(renders.count >= 45)
        #expect(Set(renders.map(\.style.modules)).count == 4 && Set(renders.map(\.style.rings)).count == 2 && Set(renders.map(\.style.rays)).count == 2)
        for render in renders {
            let symbol = try CKeySymbol.encode(bytes: CKeySymbolTests.bytes(render.payload), level: CKeySymbol.Level(rawValue: render.level)!, version: render.requested_version)
            let svg = symbol.svg(style: try CKeyStyle(validating: render.style))
            #expect(CKeySymbolTests.sha256(svg) == render.svg_sha256, "\(render.name)")
        }
    }
    #endif

    @Test func styleNeverChangesThePayloadOrWhereMarksSit() throws {
        let link = "https://viadere.com/c/AF2345"
        let symbol = try CKeySymbol.encode(link)
        // The codeword is made before any style exists; a flat custom style draws the plain geometry in other colours.
        let forest = try BusinessCodeStyle(custom: CKeyStyleSpec(background: Self.color("#FFF5D6"), ink: Self.color("#2F5D50")))
        let styled = symbol.svg(style: try #require(forest.ckeyStyle))
        let plain = symbol.svg(style: .plain)
        #expect(styled.replacingOccurrences(of: "#fff5d6", with: "#ffffff").replacingOccurrences(of: "#2f5d50", with: "#000000") == plain)
        // Shapes change the drawing of a mark, never the count of marks or their centres.
        func count(_ needle: String, in text: String) -> Int { text.components(separatedBy: needle).count - 1 }
        let diamonds = symbol.svg(style: try CKeyStyle(validating: CKeyStyleSpec(background: Self.color("#FFFFFF"), ink: Self.color("#000000"), modules: .diamond)))
        #expect(count("<polygon", in: diamonds) == count("<rect", in: plain) - 2)  // all but the field and the frame
        #expect(!styled.contains("AF2345") && !diamonds.contains("AF2345"))
        for svg in [styled, diamonds] { #expect(!svg.contains("<script") && !svg.contains("href") && !svg.contains("<image")) }
    }

    // MARK: Business styles

    @Test func aBusinessStyleNeedsTheCheckToPassWithoutAWarning() throws {
        let white = Self.color("#FFFFFF"), black = Self.color("#000000")
        func refusal(_ spec: CKeyStyleSpec) -> BusinessCodeStyle.Refusal? {
            do { _ = try BusinessCodeStyle(custom: spec); return nil } catch { return error as? BusinessCodeStyle.Refusal }
        }
        // Near-invisible, inverted mixes and malformed amounts: the reference's refusals.
        if case .unsafe(.tooFaint)? = refusal(CKeyStyleSpec(background: white, ink: Self.color("#F0F0F0"))) {} else { Issue.record("too faint") }
        #expect(refusal(CKeyStyleSpec(background: Self.color("#808080"), ink: white, inkShade: black)) == .unsafe(.mixedPolarity))
        #expect(refusal(CKeyStyleSpec(background: white, ink: black, accents: Array(repeating: black, count: 5), accentPercent: 10)) == .unsafe(.accentLimits))
        #expect(refusal(CKeyStyleSpec(background: white, ink: black, accentPercent: 101)) == .unsafe(.accentLimits))
        #expect(refusal(CKeyStyleSpec(background: white, ink: black, texture: -1)) == .unsafe(.effectRange))
        // Between 1.5:1 and 3:1 the reference asks for certification. Viadere has none, so that is a refusal here.
        if case .uncertified(.lowContrast)? = refusal(CKeyStyleSpec(background: white, ink: Self.color("#959595"))) {} else { Issue.record("under 3:1") }
        if case .uncertified(.lowContrast)? = refusal(CKeyStyleSpec(background: white, ink: black, accents: [Self.color("#959595")], accentPercent: 5)) {} else { Issue.record("accent under 3:1") }
        #expect(refusal(CKeyStyleSpec(background: white, ink: black, shadow: 41)) == .uncertified(.strongShadowOnLight))
        #expect(refusal(CKeyStyleSpec(background: white, ink: black, bevel: 51)) == .uncertified(.strongBevelOnLight))
        // Exactly 3:1, in both polarities: accepted.
        #expect(refusal(CKeyStyleSpec(background: white, ink: Self.color("#949494"))) == nil)
        #expect(refusal(CKeyStyleSpec(background: black, ink: Self.color("#5A5A5A"))) == nil)
        // Materials stay within the concept preset's amounts.
        #expect(refusal(CKeyStyleSpec(background: black, ink: white, bevel: 60, shadow: 50, texture: 40)) == nil)
        #expect(refusal(CKeyStyleSpec(background: black, ink: white, bevel: 61)) == .materialsTooStrong)
        #expect(refusal(CKeyStyleSpec(background: black, ink: white, shadow: 51)) == .materialsTooStrong)
        #expect(refusal(CKeyStyleSpec(background: black, ink: white, texture: 41)) == .materialsTooStrong)
        // The Viadere code's own colours are not a "custom" style, whatever else is changed.
        #expect(refusal(.concept) == .reservedForViadere)
        var disguised = CKeyStyleSpec.concept
        disguised.accents = []
        disguised.modules = .circle
        #expect(refusal(disguised) == .reservedForViadere)
        disguised.ink = Self.color("#F6EEE1")
        #expect(refusal(disguised) == nil)
        for refusal in [BusinessCodeStyle.Refusal.unsafe(.mixedPolarity), .uncertified(.strongShadowOnLight), .materialsTooStrong, .reservedForViadere, .qr(.inverted),
                        .qr(.lowContrast(ratioTimes100: 312)), .qr(.lowLuminanceDifference), .unsafe(.tooFaint(ink: "#f0f0f0", background: "#ffffff", ratio: 1.1))] {
            #expect(refusal.message.count > 20 && !refusal.message.contains("<"))
        }
        #expect(BusinessCodeStyle.Refusal.qr(.lowContrast(ratioTimes100: 312)).message.contains("3.12:1"))
    }

    @Test func qrColoursAreDarkOnLightWithRealContrast() throws {
        func refusal(_ dark: String, _ light: String) -> QRCodeColorPolicy.Refusal? { QRCodeColorPolicy.check(dark: Self.color(dark), light: Self.color(light)) }
        #expect(refusal("#1F1E1C", "#FFFFFF") == nil)
        #expect(refusal("#2F5D50", "#FFF5D6") == nil)
        // Light on dark, and equal colours.
        #expect(refusal("#FFFFFF", "#000000") == .inverted)
        #expect(refusal("#777777", "#777777") == .inverted)
        // #777777 on white is 4.47:1, #767676 is 4.54:1.
        #expect(refusal("#777777", "#FFFFFF") == .lowContrast(ratioTimes100: 447))
        #expect(refusal("#767676", "#FFFFFF") == nil)
        #expect(refusal("#FFD400", "#FFFFFF") == .lowContrast(ratioTimes100: 143))
        // Black on a mid grey reaches 4.5:1 but the background reflects far too little.
        #expect(refusal("#000000", "#777777") == .lowLuminanceDifference)
        #expect(refusal("#000000", "#AAAAAA") == nil)  // luminance 0.40
        #expect(refusal("#000000", "#A9A9A9") == .lowLuminanceDifference)
        #expect(throws: BusinessCodeStyle.Refusal.qr(.inverted)) { try BusinessCodeStyle(qrDark: Self.color("#FFFFFF"), light: Self.color("#000000")) }
        let qr = try BusinessCodeStyle(qrDark: Self.color("#2F5D50"), light: Self.color("#FFF5D6"))
        #expect(qr.symbology == .qr && qr.ckeyStyle == nil && qr.qrColors?.dark.hex == "#2F5D50")
        #expect(QRCodeColorPolicy.quietZoneModules == 4)
    }

    @Test func theStoredFormIsVersionedAndValidatedWhenRead() throws {
        #expect(BusinessCodeStyle.standard.choice == .ckeyPreset(.concept))
        #expect(BusinessCodeStyle.standard.ckeyStyle == .concept)
        let custom = try BusinessCodeStyle(custom: CKeyStyleSpec(background: Self.color("#2F5D50"), backgroundEdge: Self.color("#1D3B33"), ink: Self.color("#FFF5D6"),
                                                                 inkShade: Self.color("#E8D9A8"), accents: [Self.color("#F0B060")], accentPercent: 12, modules: .circle,
                                                                 rings: .dots, rays: .flat, bevel: 30, shadow: 20, texture: 10))
        for style in [BusinessCodeStyle.standard, BusinessCodeStyle(preset: .plain), custom, try BusinessCodeStyle(qrDark: Self.color("#1F1E1C"), light: Self.color("#FFFFFF"))] {
            let data = try CanonicalJSON.serialize(try JSONDecoder().decode(JSONValue.self, from: JSONEncoder().encode(style)))
            #expect(try JSONDecoder().decode(BusinessCodeStyle.self, from: data) == style)
        }
        #expect(String(decoding: try CanonicalJSON.serialize(try JSONDecoder().decode(JSONValue.self, from: JSONEncoder().encode(BusinessCodeStyle.standard))), as: UTF8.self)
            == ##"{"preset":"concept","symbology":"ckey","v":1}"##)
        // A stored style is data like any other: one that no longer passes is refused when read, never drawn.
        for bad in [##"{"v":1,"symbology":"ckey","custom":{"background":"#FFFFFF","ink":"#F0F0F0"}}"##,
                    ##"{"v":1,"symbology":"ckey","custom":{"background":"#FFFFFF","ink":"#959595"}}"##,
                    ##"{"v":1,"symbology":"ckey","custom":{"background":"#FFFFFF","ink":"red"}}"##,
                    ##"{"v":1,"symbology":"ckey","custom":{"background":"#FFFFFF","ink":"#000000","modules":"star"}}"##,
                    ##"{"v":1,"symbology":"ckey","preset":"concept","custom":{"background":"#FFFFFF","ink":"#000000"}}"##,
                    ##"{"v":1,"symbology":"ckey","preset":"viadere-signin"}"##,
                    ##"{"v":1,"symbology":"qr","dark":"#FFFFFF","light":"#000000"}"##,
                    ##"{"v":1,"symbology":"qr","dark":"#000000"}"##,
                    ##"{"v":1,"symbology":"aztec"}"##,
                    ##"{"v":2,"symbology":"ckey","preset":"concept"}"##,
                    ##"{"symbology":"ckey","preset":"concept"}"##] {
            #expect(throws: (any Error).self, "\(bad)") { try JSONDecoder().decode(BusinessCodeStyle.self, from: Data(bad.utf8)) }
        }
    }

    @Test func suggestionsFromBrandTokensAlwaysPassTheValidator() throws {
        let table: [BrandTokens?] = [
            nil,
            BrandTokens(primary: Self.color("#2F5D50")),
            BrandTokens(primary: Self.color("#2F5D50"), secondary: Self.color("#6B675F"), accent: Self.color("#B5683A"), surface: Self.color("#FFF5D6")),
            BrandTokens(primary: Self.color("#FFF5D6")),                                   // a primary too light for white
            BrandTokens(primary: Self.color("#FFFFFF"), surface: Self.color("#FFFFFF")),   // nothing usable
            BrandTokens(primary: Self.color("#808080"), accent: Self.color("#818181"), surface: Self.color("#7F7F7F")),
            BrandTokens(primary: Self.color("#F6EEE0"), surface: Self.color("#14161E")),   // the Viadere code's base colours
            BrandTokens(primary: Self.color("#FFD400"), accent: Self.color("#FFFFFF"), surface: Self.color("#000000")),
        ]
        for tokens in table {
            let spec = BusinessCodeStyle.suggestedCustom(from: tokens)
            #expect(BusinessCodeStyle.refusal(for: spec) == nil, "\(String(describing: tokens))")
            let qr = BusinessCodeStyle.suggestedQR(from: tokens)
            #expect(QRCodeColorPolicy.check(dark: qr.dark, light: qr.light) == nil)
        }
        #expect(BusinessCodeStyle.suggestedCustom(from: table[2]).accents.map(\.hex) == ["#B5683A", "#6B675F"])
        #expect(BusinessCodeStyle.suggestedCustom(from: table[4]) == .plain)
        #expect(BusinessCodeStyle.suggestedQR(from: table[3]).dark == QRCodeColorPolicy.defaultDark)
    }

    // MARK: Campaign actions

    @Test func campaignActionsAreAClosedList() {
        #expect(Set(CampaignAction.allCases.map(\.rawValue)) == ["enroll_rewards", "open_messages", "open_benefits"])
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        #expect(CampaignAction(verified: ConnectContext(campaign: "c", action: "open_messages", issuedAt: now)) == .openMessages)
        for other in ["connect", "approve", "OPEN_MESSAGES", "open_messages ", "", "https://evil.example", "grant_marketing"] {
            #expect(CampaignAction(verified: ConnectContext(campaign: "c", action: other, issuedAt: now)) == nil)
        }
        #expect(CampaignAction(verified: ConnectContext(campaign: "c", issuedAt: now)) == nil)
        #expect(CampaignAction(verified: nil) == nil)
        #expect(CampaignAction.enrollRewards.destination == .benefits && CampaignAction.openMessages.destination == .messages)
    }
}
