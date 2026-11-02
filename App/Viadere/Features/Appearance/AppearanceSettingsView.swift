import SwiftUI
import ViadereCore
import ViadereKit

/// Settings → Appearance: the person's themes on this device (ViadereKit `AppearanceModel`). Pairings are shown as cards with live
/// previews of both sides; below them the day and night themes can be chosen one by one, and the pairing can follow the system or keep
/// one side. Every change applies at once and reaches the notification extensions through the app group.
///
/// Wiring: the app's model is `ViadereThemeRuntime.model` (already applied on the root view by `ViadereApp` with
/// `.viadereAppearance(_:)`); Settings pushes `AppearanceSettingsView(model: ViadereThemeRuntime.model)`.
struct AppearanceSettingsView: View {
    let model: AppearanceModel
    @Environment(\.dismiss) private var dismiss

    private var selection: AppearanceSelection { model.selection }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: ViadereSpace.l) {
                ViadereBackButton("Settings") { dismiss() }
                VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                    Text("Appearance")
                        .font(ViadereType.display)
                        .foregroundStyle(ViadereColor.textPrimary)
                        .accessibilityAddTraits(.isHeader)
                    Text("Choose how Viadere looks by day and by night on this device.")
                        .font(ViadereType.subhead)
                        .foregroundStyle(ViadereColor.textSecondary)
                }

                VStack(alignment: .leading, spacing: ViadereSpace.s) {
                    ViadereSectionHeader("Pairings")
                    LazyVGrid(columns: [GridItem(.flexible(), spacing: ViadereSpace.s), GridItem(.flexible(), spacing: ViadereSpace.s)],
                              spacing: ViadereSpace.s) {
                        ForEach(AppearancePairing.all) { pairing in
                            PairingCard(pairing: pairing, isSelected: selection.pairing == pairing, follow: selection.follow) {
                                withAnimation(ViadereMotion.standard) { model.select(pairing) }
                            }
                        }
                    }
                    if selection.pairing == nil {
                        Text("Your own pairing: \(AppearanceTheme.theme(selection.light).name) by day, \(AppearanceTheme.theme(selection.dark).name) by night.")
                            .font(ViadereType.footnote)
                            .foregroundStyle(ViadereColor.textSecondary)
                    }
                }

                VStack(alignment: .leading, spacing: ViadereSpace.s) {
                    ViadereSectionHeader("Show")
                    ViadereSegmented(selection: Binding(get: { selection.follow }, set: { next in
                        withAnimation(ViadereMotion.standard) { model.setFollow(next) }
                    }), options: AppearanceFollow.allCases, title: \.title)
                    Text(followCaption)
                        .font(ViadereType.footnote)
                        .foregroundStyle(ViadereColor.textSecondary)
                }

                themeRow(.light, title: "By day")
                themeRow(.dark, title: "By night")

                ViadereCard(padding: ViadereSpace.m) {
                    Toggle(isOn: Binding(get: { selection.honorsIncreaseContrast }, set: { model.setHonorsIncreaseContrast($0) })) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Follow Increase Contrast")
                                .font(ViadereType.body)
                                .foregroundStyle(ViadereColor.textPrimary)
                            Text("When it's on in iOS Settings, Viadere uses Beacon and Lantern.")
                                .font(ViadereType.footnote)
                                .foregroundStyle(ViadereColor.textSecondary)
                        }
                    }
                    .toggleStyle(.viadere)
                }

                Text("Approvals, sign-in requests, payments and verification always keep Viadere's own look, in every theme and on every business's page.")
                    .font(ViadereType.footnote)
                    .foregroundStyle(ViadereColor.textSecondary)
            }
            .padding(.horizontal, ViadereSpace.screen)
            .padding(.bottom, ViadereSpace.xl)
        }
        .scrollIndicators(.hidden)
        .viadereScreenBackground()
        .toolbar(.hidden, for: .navigationBar)
    }

    private var followCaption: String {
        switch selection.follow {
        case .system: "Switches with your iPhone's light and dark appearance."
        case .alwaysLight: "Always shows \(AppearanceTheme.theme(selection.light).name)."
        case .alwaysDark: "Always shows \(AppearanceTheme.theme(selection.dark).name)."
        }
    }

    private func themeRow(_ side: ThemeSide, title: String) -> some View {
        VStack(alignment: .leading, spacing: ViadereSpace.s) {
            ViadereSectionHeader(title)
            ScrollView(.horizontal) {
                HStack(spacing: ViadereSpace.s) {
                    ForEach(AppearanceTheme.all(side)) { theme in
                        ThemeCard(theme: theme, isSelected: (side == .light ? selection.light : selection.dark) == theme.id) {
                            withAnimation(ViadereMotion.standard) { model.setTheme(theme.id) }
                        }
                    }
                }
                .padding(.vertical, 2)
            }
            .scrollIndicators(.hidden)
        }
    }
}

// MARK: - Cards

/// One theme: a live miniature of a Viadere screen in that theme's palette, its name and line.
private struct ThemeCard: View {
    let theme: AppearanceTheme
    let isSelected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                ThemeMiniature(theme: theme)
                    .frame(width: 132, height: 168)
                    .clipShape(RoundedRectangle(cornerRadius: ViadereRadius.control, style: .continuous))
                    .overlay(SelectionRing(isSelected: isSelected, radius: ViadereRadius.control))
                HStack(spacing: 4) {
                    Text(theme.name)
                        .font(ViadereType.subhead.weight(.semibold))
                        .foregroundStyle(ViadereColor.textPrimary)
                    if theme.contrast == .high {
                        Text("AAA").font(ViadereType.caption).foregroundStyle(ViadereColor.textSecondary)
                    }
                }
                Text(theme.tagline)
                    .font(ViadereType.caption)
                    .foregroundStyle(ViadereColor.textSecondary)
                    .lineLimit(2, reservesSpace: true)
                    .frame(width: 132, alignment: .leading)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("\(theme.name). \(theme.tagline)"))
        .accessibilityAddTraits(isSelected ? [.isButton, .isSelected] : .isButton)
    }
}

/// A pairing: its day theme and night theme side by side, the side not shown dimmed when the pairing keeps one side.
private struct PairingCard: View {
    let pairing: AppearancePairing
    let isSelected: Bool
    let follow: AppearanceFollow
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                HStack(spacing: 0) {
                    ThemeMiniature(theme: .theme(pairing.light), compact: true)
                        .opacity(follow == .alwaysDark ? 0.35 : 1)
                    ThemeMiniature(theme: .theme(pairing.dark), compact: true)
                        .opacity(follow == .alwaysLight ? 0.35 : 1)
                }
                .frame(height: 112)
                .clipShape(RoundedRectangle(cornerRadius: ViadereRadius.control, style: .continuous))
                .overlay(SelectionRing(isSelected: isSelected, radius: ViadereRadius.control))
                Text(pairing.name)
                    .font(ViadereType.subhead.weight(.semibold))
                    .foregroundStyle(ViadereColor.textPrimary)
                Text(pairing.tagline)
                    .font(ViadereType.caption)
                    .foregroundStyle(ViadereColor.textSecondary)
                    .lineLimit(2, reservesSpace: true)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("\(pairing.name). \(pairing.tagline)"))
        .accessibilityAddTraits(isSelected ? [.isButton, .isSelected] : .isButton)
    }
}

/// The selected card's champagne ring with a small check (no shield imagery).
private struct SelectionRing: View {
    let isSelected: Bool
    let radius: CGFloat

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: radius, style: .continuous)
        ZStack(alignment: .topTrailing) {
            shape.strokeBorder(isSelected ? ViadereColor.accent : ViadereColor.hairline, lineWidth: isSelected ? 2 : 1)
            if isSelected {
                Image(systemName: "checkmark.circle.fill")
                    .font(.system(size: 18, weight: .semibold))
                    .foregroundStyle(ViadereColor.onPrimary, ViadereColor.accent)
                    .padding(6)
                    .transition(.scale.combined(with: .opacity))
            }
        }
        .accessibilityHidden(true)
    }
}

/// A miniature Viadere screen drawn in one theme's palette (fixed colors, independent of the theme on screen): page, a card with a
/// title and a line of text, a verified badge in the accent, a primary button, a hairline and a switch.
struct ThemeMiniature: View {
    let theme: AppearanceTheme
    var compact = false

    private func color(_ swatch: ThemeSwatch) -> Color { Color(viadereHex: swatch.rgbValue, opacity: swatch.opacity) }

    var body: some View {
        let p = theme.palette
        GeometryReader { proxy in
            let w = proxy.size.width
            let unit = max(4, w / 18)
            ZStack(alignment: .topLeading) {
                color(p.background)
                VStack(alignment: .leading, spacing: unit * 0.8) {
                    Capsule().fill(color(p.textPrimary)).frame(width: w * 0.46, height: unit * 0.9)
                    VStack(alignment: .leading, spacing: unit * 0.6) {
                        HStack(spacing: unit * 0.5) {
                            Circle().fill(color(p.surfaceRaised)).overlay(Circle().strokeBorder(color(p.hairline), lineWidth: 1))
                                .frame(width: unit * 2, height: unit * 2)
                            VStack(alignment: .leading, spacing: unit * 0.35) {
                                Capsule().fill(color(p.textPrimary)).frame(width: w * 0.32, height: unit * 0.6)
                                Capsule().fill(color(p.textSecondary)).frame(width: w * 0.24, height: unit * 0.5)
                            }
                        }
                        Capsule().fill(color(p.accentSoft)).overlay(Capsule().fill(color(p.accent)).frame(width: w * 0.16, height: unit * 0.35))
                            .frame(width: w * 0.3, height: unit * 0.9)
                        if !compact {
                            Rectangle().fill(color(p.hairline)).frame(height: 1)
                            HStack {
                                Capsule().fill(color(p.textSecondary)).frame(width: w * 0.22, height: unit * 0.5)
                                Spacer()
                                Capsule().fill(color(p.switchOn)).frame(width: unit * 2.4, height: unit * 1.4)
                                    .overlay(alignment: .trailing) {
                                        Circle().fill(color(p.knob)).padding(unit * 0.2)
                                    }
                            }
                        }
                    }
                    .padding(unit * 0.8)
                    .background(RoundedRectangle(cornerRadius: unit, style: .continuous).fill(color(p.surface)))
                    .overlay(RoundedRectangle(cornerRadius: unit, style: .continuous).strokeBorder(color(p.hairline), lineWidth: 1))
                    Spacer(minLength: 0)
                    Capsule().fill(color(p.primaryFill))
                        .overlay(Capsule().fill(color(p.onPrimary)).frame(width: w * 0.24, height: unit * 0.5))
                        .frame(height: unit * 2.2)
                }
                .padding(unit)
            }
        }
        .accessibilityHidden(true)
    }
}

#if DEBUG
#Preview("Appearance") {
    NavigationStack {
        AppearanceSettingsView(model: AppearanceModel(persistence: InMemoryAppearancePersistence()))
    }
}
#endif
