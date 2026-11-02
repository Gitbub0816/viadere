//
//  ViadereThemes.swift
//  Viadere: appearance themes at run time.
//
//  Every design-system color (`ViadereColor`) is a dynamic color that resolves against the current appearance theme
//  (ViadereKit `AppearanceTheme`, chosen per device through `AppearanceModel`) and the system light/dark appearance. A change applies at
//  once: the choice travels as a UIKit trait bridged to the SwiftUI environment (`viadereAppearanceKey`), so every view and every hosted
//  UIKit view re-resolves its colors; processes without the root modifier (notification extensions, widgets) read the same choice from
//  the app group when they start.
//
//  Brand Kit colors (`BrandStyle`) are resolved over the same theme, so a business's space follows the person's theme too.
//

import SwiftUI
import ViadereCore
import ViadereKit
#if canImport(UIKit)
import UIKit
#endif

/// The process-wide appearance choice that dynamic colors read when no trait carries one.
public final class ViadereThemeRuntime: @unchecked Sendable {
    public static let shared = ViadereThemeRuntime()

    /// The app group shared with the extensions (Info.plist `ViadereAppGroupID`, else the default group); empty = standard defaults.
    public static var appGroupID: String {
        (Bundle.main.object(forInfoDictionaryKey: "ViadereAppGroupID") as? String) ?? "group.com.viadere.shared"
    }

    public static func persistence() -> any AppearancePersistence { UserDefaultsAppearancePersistence(suiteName: appGroupID) }

    private let lock = NSLock()
    private var selection: AppearanceSelection
    private var brandCache: [BrandCacheKey: ThemedBrandPalette] = [:]

    private struct BrandCacheKey: Hashable {
        var tokens: BrandTokens?
        var theme: AppearanceTheme.ID
    }

    init() { selection = AppearanceModel.read(Self.persistence()) }

    /// Re-reads the stored choice (for long-lived extension processes that may have started before the person changed theme).
    @discardableResult
    public func reloadFromStore() -> AppearanceSelection {
        let stored = AppearanceModel.read(Self.persistence())
        current = stored
        return stored
    }

    public var current: AppearanceSelection {
        get { lock.withLock { selection } }
        set { lock.withLock { selection = newValue } }
    }

    /// The theme for a light/dark appearance; `renderKey` (from the trait) wins over the process-wide value when set.
    public func theme(dark: Bool, increaseContrast: Bool, renderKey: Int = 0) -> AppearanceTheme {
        let selection = AppearanceSelection(renderKey: renderKey) ?? current
        #if os(watchOS)
        // The watch has no light appearance: it always draws the night side of the choice synced from the phone.
        return selection.watchTheme
        #else
        return selection.resolvedTheme(systemIsDark: dark, increaseContrast: increaseContrast)
        #endif
    }

    /// A kit over a theme, memoized (dynamic colors resolve often).
    public func brand(_ tokens: BrandTokens?, theme: AppearanceTheme) -> ThemedBrandPalette {
        let key = BrandCacheKey(tokens: tokens, theme: theme.id)
        if let hit = lock.withLock({ brandCache[key] }) { return hit }
        let value = ThemedBrandPalette.resolve(tokens, theme: theme)
        lock.withLock {
            if brandCache.count > 256 { brandCache.removeAll() }
            brandCache[key] = value
        }
        return value
    }

    /// The app's appearance model (Settings → Appearance and the root `.viadereAppearance(_:)`), created on first use.
    @MainActor public static let model: AppearanceModel = makeModel()

    /// A model wired to this runtime (`model` is the app's one).
    @MainActor
    public static func makeModel() -> AppearanceModel {
        let model = AppearanceModel(persistence: persistence())
        shared.current = model.selection
        model.onChange = { shared.current = $0 }
        return model
    }
}

#if canImport(UIKit) && !os(watchOS)

/// The appearance choice as a UIKit trait (iOS 17 custom traits): changing it re-resolves every dynamic color in the window.
public struct ViadereAppearanceTrait: UITraitDefinition {
    public static let defaultValue = 0
    public static let identifier = "com.viadere.appearance"
    public static let name = "ViadereAppearance"
    public static let affectsColorAppearance = true
}

extension UITraitCollection {
    public var viadereAppearanceKey: Int { self[ViadereAppearanceTrait.self] }

    /// The theme these traits draw.
    public var viadereTheme: AppearanceTheme {
        ViadereThemeRuntime.shared.theme(dark: userInterfaceStyle == .dark, increaseContrast: accessibilityContrast == .high,
                                         renderKey: viadereAppearanceKey)
    }
}

extension UIMutableTraits {
    public var viadereAppearanceKey: Int {
        get { self[ViadereAppearanceTrait.self] }
        set { self[ViadereAppearanceTrait.self] = newValue }
    }
}

private struct ViadereAppearanceEnvironmentKey: EnvironmentKey {
    static let defaultValue = 0
}

extension ViadereAppearanceEnvironmentKey: UITraitBridgedEnvironmentKey {
    static func read(from traitCollection: UITraitCollection) -> Int { traitCollection.viadereAppearanceKey }
    static func write(to mutableTraits: inout UIMutableTraits, value: Int) { mutableTraits.viadereAppearanceKey = value }
}

extension UIColor {
    convenience init(viadereSwatch swatch: ThemeSwatch) {
        self.init(viadereHex: swatch.rgbValue, alpha: swatch.opacity)
    }
}

#else

private struct ViadereAppearanceEnvironmentKey: EnvironmentKey {
    static let defaultValue = 0
}

#endif

extension EnvironmentValues {
    /// `AppearanceSelection.renderKey` of the choice on screen (0 = the process-wide choice).
    public var viadereAppearanceKey: Int {
        get { self[ViadereAppearanceEnvironmentKey.self] }
        set { self[ViadereAppearanceEnvironmentKey.self] = newValue }
    }
}

extension Color {
    /// A design-system role in the current theme.
    public static func viadere(_ role: ThemeRole) -> Color {
        viadereDynamic { $0.palette[role] }
    }

    /// A color computed from the current theme at resolve time.
    public static func viadereDynamic(_ resolve: @escaping @Sendable (AppearanceTheme) -> ThemeSwatch) -> Color {
        #if canImport(UIKit) && !os(watchOS)
        return Color(uiColor: UIColor { traits in UIColor(viadereSwatch: resolve(traits.viadereTheme)) })
        #else
        // watchOS has no light appearance: the night theme of the choice.
        let swatch = resolve(ViadereThemeRuntime.shared.theme(dark: true, increaseContrast: false))
        return Color(viadereHex: swatch.rgbValue, opacity: swatch.opacity)
        #endif
    }
}

/// The current theme for views that need more than a color (e.g. shadows, previews).
public struct ViadereThemeReader<Content: View>: View {
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.viadereAppearanceKey) private var key
    private let content: (AppearanceTheme) -> Content

    public init(@ViewBuilder content: @escaping (AppearanceTheme) -> Content) { self.content = content }

    public var body: some View {
        content(ViadereThemeRuntime.shared.theme(dark: colorScheme == .dark, increaseContrast: contrast == .increased, renderKey: key))
    }
}

// MARK: - Root

/// Applies the person's appearance choice to everything below: the theme (through the environment/trait bridge), the locked
/// light/dark side (`preferredColorScheme`) and the champagne tint. Put it once on the root view of each scene.
public struct ViadereAppearanceModifier: ViewModifier {
    let model: AppearanceModel

    public func body(content: Content) -> some View {
        let selection = model.selection
        content
            .environment(\.viadereAppearanceKey, selection.renderKey)
            .preferredColorScheme(selection.lockedSide.map { $0 == .dark ? ColorScheme.dark : ColorScheme.light })
            .tint(ViadereColor.accent)
            .onChange(of: selection, initial: true) { _, next in ViadereThemeRuntime.shared.current = next }
    }
}

extension View {
    /// `.viadereAppearance(model)` on the root view: themes follow the person's choice and change instantly.
    public func viadereAppearance(_ model: AppearanceModel) -> some View { modifier(ViadereAppearanceModifier(model: model)) }

    /// Marks a security surface (approval, sign-in, payment, verification, profile request): no Brand Kit style reaches anything inside,
    /// whatever an enclosing business space set. The theme still applies (it is Viadere's own palette).
    /// `nonisolated` (like SwiftUI's own modifiers) so widget and Live Activity builders, which are not main-actor isolated, can use it.
    nonisolated public func viadereProtectedSurface() -> some View { environment(\.brandStyle, .neutral) }

    /// Draws the night side of the person's chosen theme whatever light/dark side they follow. For surfaces the system always paints
    /// dark (the Dynamic Island), where a light theme's dark text would vanish.
    nonisolated public func viadereNightSurface() -> some View { modifier(ViadereNightSurfaceModifier()) }
}

/// See `View.viadereNightSurface()`.
struct ViadereNightSurfaceModifier: ViewModifier {
    nonisolated init() {}

    func body(content: Content) -> some View {
        let chosen = ViadereThemeRuntime.shared.current
        let night = AppearanceSelection(light: chosen.light, dark: chosen.dark, follow: .alwaysDark,
                                        honorsIncreaseContrast: chosen.honorsIncreaseContrast)
        content
            .environment(\.viadereAppearanceKey, night.renderKey)
            .environment(\.colorScheme, .dark)
    }
}
