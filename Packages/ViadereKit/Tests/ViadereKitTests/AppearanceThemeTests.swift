import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

@Suite("Appearance themes: contrast, pairings, persistence, brand over themes")
struct AppearanceThemeTests {
    // MARK: Contrast

    @Test("every theme meets WCAG AA (high-contrast themes AAA) for every role on every ground")
    func everyThemeMeetsItsContrastLevel() {
        for theme in AppearanceTheme.all {
            let failures = AppearanceThemeAudit.failures(theme)
            #expect(failures.isEmpty, "\(failures)")
            #expect(AppearanceThemeAudit.checks(theme).count >= 30)
        }
    }

    @Test("high contrast means 7:1 text on every ground")
    func highContrastThemesAreAAA() {
        for theme in AppearanceTheme.all where theme.contrast == .high {
            for check in AppearanceThemeAudit.checks(theme) where check.name.hasPrefix("text") && !check.name.contains("Tertiary") {
                #expect(check.minimumTimes10 == 70)
                #expect(check.passes, "\(check)")
            }
        }
        #expect(AppearanceTheme.beacon.contrast == .high && AppearanceTheme.lantern.contrast == .high)
    }

    @Test("the audit catches a palette that fails")
    func auditCatchesFailures() {
        var theme = AppearanceTheme.daybreak
        theme.palette.textSecondary = ThemeSwatch("#C9C4BB")
        theme.palette.accent = ThemeSwatch("#E8DCC8")
        let names = Set(AppearanceThemeAudit.failures(theme).map(\.name))
        #expect(names.contains("textSecondary on background"))
        #expect(names.contains("accent on accentSoft"))
    }

    @Test("Midnight is true black with champagne accents; Daybreak and Nightfall keep the brand hexes")
    func signatureColors() {
        #expect(AppearanceTheme.midnight.palette.background.color.hex == "#000000")
        #expect(AppearanceTheme.midnight.palette.primaryFill.color == AppearanceTheme.midnight.palette.accent.color)
        #expect(AppearanceTheme.daybreak.palette.background.color.hex == "#F5F2EC")
        #expect(AppearanceTheme.daybreak.palette.textPrimary.color.hex == "#1F1E1C")
        #expect(AppearanceTheme.nightfall.palette.background.color.hex == "#121211")
        #expect(AppearanceTheme.nightfall.palette.accent.color.hex == "#CDB993")
        // Names are real names, never "Light", "Dark" or "Paper"; ids and names are unique.
        let names = AppearanceTheme.all.map(\.name) + AppearancePairing.all.map(\.name)
        #expect(Set(names).count == names.count)
        for name in names { #expect(!["light", "dark", "paper", "default"].contains(name.lowercased())) }
        #expect(AppearanceTheme.all(.light).count == 4 && AppearanceTheme.all(.dark).count == 4)
    }

    @Test("compositing matches the screen: 10% charcoal over ivory")
    func compositing() {
        let swatch = ThemeSwatch("#1F1E1C", opacity: 0.10)
        #expect(swatch.composited(over: BrandColor("#F5F2EC")!).hex == "#E0DDD7")
        #expect(ThemeSwatch("#123456").composited(over: BrandColor("#FFFFFF")!).hex == "#123456")
    }

    // MARK: Pairings

    @Test("a pairing follows the system, or locks one side; Increase Contrast swaps in Beacon / Lantern")
    func pairingResolution() {
        let reading = AppearancePairing.readingRoom.selection
        #expect(reading.resolvedTheme(systemIsDark: false).id == .folio)
        #expect(reading.resolvedTheme(systemIsDark: true).id == .nightfall)
        var locked = reading
        locked.follow = .alwaysDark
        #expect(locked.resolvedTheme(systemIsDark: false).id == .nightfall)
        locked.follow = .alwaysLight
        #expect(locked.resolvedTheme(systemIsDark: true).id == .folio)
        #expect(reading.resolvedTheme(systemIsDark: false, increaseContrast: true).id == .beacon)
        #expect(reading.resolvedTheme(systemIsDark: true, increaseContrast: true).id == .lantern)
        var ignore = reading
        ignore.honorsIncreaseContrast = false
        #expect(ignore.resolvedTheme(systemIsDark: true, increaseContrast: true).id == .nightfall)
        #expect(reading.pairing == .readingRoom)
        #expect(AppearanceSelection(light: .sage, dark: .lantern).pairing == nil)
        for pairing in AppearancePairing.all {
            #expect(AppearanceTheme.theme(pairing.light).side == .light && AppearanceTheme.theme(pairing.dark).side == .dark, "\(pairing.id)")
        }
    }

    @Test("a theme on the wrong side falls back to that side's signature theme")
    func sidesAreEnforced() {
        let wrong = AppearanceSelection(light: .midnight, dark: .folio)
        #expect(wrong.light == .daybreak && wrong.dark == .nightfall)
    }

    @Test("render keys round-trip every selection and are never 0")
    func renderKeys() {
        var seen = Set<Int>()
        for light in AppearanceTheme.all(.light) {
            for dark in AppearanceTheme.all(.dark) {
                for follow in AppearanceFollow.allCases {
                    for contrast in [true, false] {
                        let s = AppearanceSelection(light: light.id, dark: dark.id, follow: follow, honorsIncreaseContrast: contrast)
                        #expect(s.renderKey > 0)
                        #expect(AppearanceSelection(renderKey: s.renderKey) == s)
                        seen.insert(s.renderKey)
                    }
                }
            }
        }
        #expect(seen.count == 4 * 4 * 3 * 2)
        #expect(AppearanceSelection(renderKey: 0) == nil)
    }

    // MARK: Persistence

    @Test("the choice persists, applies at once and reads back in another process (extensions)")
    @MainActor
    func persistence() throws {
        let store = InMemoryAppearancePersistence()
        let model = AppearanceModel(persistence: store)
        #expect(model.selection == .default)
        var applied: [AppearanceSelection] = []
        model.onChange = { applied.append($0) }
        model.select(.lamplight)
        model.setFollow(.alwaysDark)
        model.setTheme(.ember)
        #expect(model.selection == AppearanceSelection(light: .folio, dark: .ember, follow: .alwaysDark))
        #expect(applied.count == 3)
        model.setTheme(.ember)
        #expect(applied.count == 3, "no change, no re-apply")
        #expect(AppearanceModel.read(store) == model.selection)
        #expect(AppearanceModel(persistence: store).selection == model.selection)
    }

    @Test("unreadable or foreign stored values fall back to the defaults")
    func lenientDecoding() throws {
        #expect(AppearanceModel.read(InMemoryAppearancePersistence(Data("garbage".utf8))) == .default)
        let future = Data(#"{"light":"aurora","dark":"midnight","follow":"sometimes"}"#.utf8)
        #expect(AppearanceModel.read(InMemoryAppearancePersistence(future)) == AppearanceSelection(light: .daybreak, dark: .midnight))
        let encoded = try JSONEncoder().encode(AppearanceSelection(light: .beacon, dark: .lantern, follow: .alwaysLight, honorsIncreaseContrast: false))
        #expect(try JSONDecoder().decode(AppearanceSelection.self, from: encoded)
                == AppearanceSelection(light: .beacon, dark: .lantern, follow: .alwaysLight, honorsIncreaseContrast: false))
    }

    @Test("UserDefaults persistence in a suite")
    func userDefaultsPersistence() {
        let suite = "test.appearance.\(UUID().uuidString)"
        let a = UserDefaultsAppearancePersistence(suiteName: suite)
        a.save(Data("x".utf8))
        #expect(UserDefaultsAppearancePersistence(suiteName: suite).load() == Data("x".utf8))
        UserDefaults(suiteName: suite)?.removePersistentDomain(forName: suite)
    }

    // MARK: Brand Kits over themes

    static let kits: [(String, BrandTokens)] = [
        ("atlas", BrandTokens(primary: BrandColor("#227470")!, accent: BrandColor("#A88545")!, surface: BrandColor("#FAF7F0")!)),
        ("good", BK.good),
        ("hostile", BK.hostile),
        ("navy", BrandTokens(primary: BrandColor("#0B1F3A")!, secondary: BrandColor("#3B4A5E")!, accent: BrandColor("#1E3A8A")!)),
        ("neon", BrandTokens(primary: BrandColor("#39FF14")!, accent: BrandColor("#FF00FF")!, surface: BrandColor("#000000")!)),
        ("white", BrandTokens(primary: BrandColor("#FFFFFF")!, secondary: BrandColor("#FFFFFF")!, accent: BrandColor("#FFFFFF")!,
                              surface: BrandColor("#FFFFFF")!)),
        ("black", BrandTokens(primary: BrandColor("#000000")!, secondary: BrandColor("#000000")!, accent: BrandColor("#000000")!,
                              surface: BrandColor("#000000")!)),
    ]

    @Test("every kit, clamped over every theme, keeps every brand role and the tinted grounds legible")
    func brandOverEveryTheme() {
        for theme in AppearanceTheme.all {
            for (name, tokens) in Self.kits {
                let brand = ThemedBrandPalette.resolve(tokens, theme: theme)
                let failures = AppearanceThemeAudit.brandFailures(brand, theme: theme)
                #expect(failures.isEmpty, "\(name) over \(theme.id): \(failures)")
                #expect(brand.isBranded)
            }
        }
    }

    @Test("Atlas teal keeps its hue in every standard theme, and tints the whole space")
    func atlasInEveryTheme() {
        let atlas = Self.kits[0].1
        for theme in AppearanceTheme.all where theme.contrast == .standard {
            let brand = ThemedBrandPalette.resolve(atlas, theme: theme)
            #expect(!brand.overridden.contains(.primary), "\(theme.id)")
            #expect(brand.primary == atlas.primary || (theme.isDark && brand.derived.contains(.primary)), "\(theme.id): \(brand.primary.hex)")
            #expect(brand.canvas != theme.palette.background.color, "the whole space is tinted in \(theme.id): \(brand)")
            #expect(brand.card != theme.palette.surface.color, "cards are tinted in \(theme.id): \(brand)")
        }
    }

    @Test("a deep navy kit is lightened (derived), not dropped, on dark themes")
    func deepColorsAreDerivedOnDarkThemes() {
        let navy = Self.kits[3].1
        for theme in AppearanceTheme.all where theme.isDark && theme.contrast == .standard {
            let brand = ThemedBrandPalette.resolve(navy, theme: theme)
            #expect(brand.derived.contains(.primary), "\(theme.id): \(brand.primary.hex)")
            #expect(ContrastPolicy.luminance(brand.primary) > ContrastPolicy.luminance(navy.primary))
            #expect(ContrastPolicy.meets(brand.primary, theme.palette.surface.color, minimumTimes10: 30))
        }
        // On light themes navy is used as is.
        #expect(ThemedBrandPalette.resolve(navy, theme: .daybreak).primary == navy.primary)
    }

    @Test("the classic clamp is unchanged: the neutral base without derivation equals ContrastPolicy.resolve")
    func classicClampUnchanged() {
        for (_, tokens) in Self.kits {
            let classic = ContrastPolicy.resolve(tokens)
            for appearance in BrandAppearance.allCases {
                let themed = ContrastPolicy.resolve(tokens, over: .neutral(appearance), derive: false)
                #expect(themed.palette == classic.palette(appearance))
                #expect(themed.overridden == (appearance == .light ? classic.overriddenLight : classic.overriddenDark))
                #expect(themed.derived.isEmpty)
            }
        }
    }

    @Test("high-contrast themes are never tinted and hold brand colors to AAA")
    func highContrastBrand() {
        for theme in AppearanceTheme.all where theme.contrast == .high {
            let brand = ThemedBrandPalette.resolve(Self.kits[0].1, theme: theme)
            #expect(brand.canvas == theme.palette.background.color)
            #expect(brand.card == theme.palette.surface.color)
            if !brand.overridden.contains(.primary) {
                #expect(ContrastPolicy.meets(brand.onPrimary, brand.primary, minimumTimes10: 70))
            }
        }
    }

    @Test("protected colors are the theme's own, whatever the kit")
    func protectedPaletteIgnoresKits() {
        for theme in AppearanceTheme.all {
            let protected = ThemedBrandPalette.protected(for: theme)
            #expect(!protected.isBranded)
            #expect(protected.primary == theme.palette.primaryFill.color)
            #expect(protected.accent == theme.palette.accent.color)
            #expect(protected.canvas == theme.palette.background.color)
        }
        // A neutral style resolves to the theme palette.
        #expect(BrandAppearanceStyle.neutral.palette(in: .midnight) == ThemedBrandPalette.protected(for: .midnight))
    }

    @Test("a Loop tree's clamped palette re-resolves to the kit's surviving tokens")
    func loopTreeTokens() {
        let atlas = Self.kits[0].1
        let resolution = ContrastPolicy.resolve(atlas)
        let kept = try! #require(resolution.keptTokens)
        #expect(kept.primary == atlas.primary && kept.accent == atlas.accent && kept.surface == atlas.surface)
        #expect(BrandStyleResolution.neutral.keptTokens == nil)
        let style = BrandAppearanceStyle(source: .brandKit, kitId: "atlas", palette: resolution, frameId: nil, radius: .medium, border: .hairline,
                                         typeScale: .standard)
        #expect(style.palette(in: .daybreak).primary == atlas.primary)
    }
}
