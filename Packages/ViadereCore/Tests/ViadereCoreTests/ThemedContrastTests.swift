import Foundation
import Testing
@testable import ViadereCore

/// The theme-aware Brand Kit clamp (`ContrastPolicy.resolve(_:over:)`): same integer arithmetic as the classic clamp, derived variants
/// bounded, and every color it keeps meets the base's minimums on every ground it is drawn on.
@Suite("Brand Kits over appearance themes")
struct ThemedContrastTests {
    static let black = BrandColor("#000000")!
    static let midnightBase = ThemedBrandBase(
        palette: .make(primary: BrandColor("#D4BE94")!, onPrimary: black, secondary: BrandColor("#A39D93")!, accent: BrandColor("#D4BE94")!,
                       surface: BrandColor("#0C0C0B")!, onSurface: BrandColor("#EDE8DF")!),
        foregrounds: [BrandColor("#EDE8DF")!, black], acceptsBrandSurface: false, minimums: .aa, isDark: true, grounds: [black])

    @Test("mix is exact integer interpolation")
    func mix() {
        #expect(ContrastPolicy.mix(Self.black, toward: BrandColor("#FFFFFF")!, step: 10, of: 20).hex == "#808080")
        #expect(ContrastPolicy.mix(BrandColor("#227470")!, toward: BrandColor("#227470")!, step: 7, of: 20).hex == "#227470")
        #expect(ContrastPolicy.mix(BrandColor("#102030")!, toward: Self.black, step: 20, of: 20) == Self.black)
    }

    @Test("a deep brand color is lightened on a black base until it reads, within the derivation bound")
    func deepColorsAreDerived() {
        let navy = BrandTokens(primary: BrandColor("#0B1F3A")!, accent: BrandColor("#1E3A8A")!)
        let result = ContrastPolicy.resolve(navy, over: Self.midnightBase)
        #expect(result.derived.contains(.primary) && result.derived.contains(.accent))
        #expect(result.overridden.isEmpty)
        for ground in [BrandColor("#0C0C0B")!, Self.black] {
            #expect(ContrastPolicy.meets(result.palette.primary, ground, minimumTimes10: 30))
            #expect(ContrastPolicy.meets(result.palette.accent, ground, minimumTimes10: 30))
        }
        #expect(ContrastPolicy.meets(result.palette.onPrimary, result.palette.primary, minimumTimes10: 45))
        // Without derivation the same kit falls back to the base.
        let strict = ContrastPolicy.resolve(navy, over: Self.midnightBase, derive: false)
        #expect(strict.overridden == [.primary, .accent])
        #expect(strict.palette.primary == Self.midnightBase.palette.primary)
    }

    @Test("derivation is bounded: past 12/20 toward white or black the base color is used instead")
    func derivationIsBounded() {
        // Black on a black base becomes a dark grey (8/20 toward white, where both it and its ink read): still the brand's black, now visible.
        let result = ContrastPolicy.resolve(BrandTokens(primary: Self.black), over: Self.midnightBase)
        #expect(result.derived == [.primary])
        #expect(result.palette.primary.hex == "#666666")
        // Nothing within the bound passes: no variant.
        #expect(ContrastPolicy.derive(Self.black, lighten: true, accepts: { _ in false }) == nil)
        var tried: [BrandColor] = []
        _ = ContrastPolicy.derive(BrandColor("#204060")!, lighten: false, accepts: { tried.append($0); return false })
        #expect(tried.count == ContrastPolicy.maximumDerivationSteps + 1)
        #expect(tried.last == ContrastPolicy.mix(BrandColor("#204060")!, toward: Self.black, step: 12, of: 20))
    }

    @Test("the neutral bases without derivation reproduce the classic clamp exactly")
    func classicEquivalence() {
        let kits = [
            BrandTokens(primary: BrandColor("#227470")!, accent: BrandColor("#A88545")!, surface: BrandColor("#FAF7F0")!),
            BrandTokens(primary: BrandColor("#F5F2EC")!, secondary: BrandColor("#F0F0F0")!, accent: BrandColor("#FFFFFF")!, surface: BrandColor("#777777")!),
            BrandTokens(primary: BrandColor("#39FF14")!, accent: BrandColor("#FF00FF")!, surface: Self.black),
        ]
        for tokens in kits {
            let classic = ContrastPolicy.resolve(tokens)
            for appearance in BrandAppearance.allCases {
                let themed = ContrastPolicy.resolve(tokens, over: .neutral(appearance), derive: false)
                #expect(themed.palette == classic.palette(appearance))
                #expect(themed.overridden == (appearance == .light ? classic.overriddenLight : classic.overriddenDark))
            }
        }
    }

    @Test("a clamped resolution gives back the kit's surviving tokens")
    func keptTokens() {
        let tokens = BrandTokens(primary: BrandColor("#227470")!, secondary: BrandColor("#3B4A5E")!, accent: BrandColor("#A88545")!,
                                 surface: BrandColor("#FAF7F0")!)
        let kept = ContrastPolicy.resolve(tokens).keptTokens
        #expect(kept?.primary == tokens.primary && kept?.accent == tokens.accent && kept?.surface == tokens.surface)
        #expect(BrandStyleResolution.neutral.keptTokens == nil)
    }
}
