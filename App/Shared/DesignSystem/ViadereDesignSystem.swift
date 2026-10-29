//
//  ViadereDesignSystem.swift
//  Viadere: brand-faithful custom SwiftUI components and tokens.
//
//  Principles (see Design/brand-guide.html → "Components"):
//   • Custom controls, not stock chrome: no .borderedProminent, no default Toggle/Picker looks.
//   • Charcoal / ivory / champagne. Champagne is an accent, used sparingly (verification, focus, links).
//   • Hairlines instead of borders: 1 px at 10–12% opacity. Very soft shadows in light mode only.
//   • A tight type scale on SF Pro with Dynamic Type; generous whitespace; one primary action per screen.
//   • Restrained motion: short ease-outs and critically damped springs; honours Reduce Motion.
//
//  Requires iOS 17+. Depends on ViadereMark.swift (ViadereBrand, ViadereMark, Color(viadereHex:)).
//  Colours mirror App/Resources/Assets.xcassets/Colors so either source can be used.
//

import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

// MARK: - Colour tokens (appearance-aware)

public enum ViadereColor {
    public static let background     = Color(viadereLight: 0xF5F2EC, dark: 0x121211)
    public static let surface        = Color(viadereLight: 0xFCFBF8, dark: 0x1C1B1A)
    public static let surfaceRaised  = Color(viadereLight: 0xFFFFFF, dark: 0x262523)
    /// Recessed fill for tracks (segmented control, slider, switch off).
    public static let track          = Color(viadereLight: 0xEAE6DF, dark: 0x2A2927)
    public static let textPrimary    = Color(viadereLight: 0x1F1E1C, dark: 0xF3F0EA)
    public static let textSecondary  = Color(viadereLight: 0x6B675F, dark: 0xA29D94)
    public static let textTertiary   = Color(viadereLight: 0x9A958C, dark: 0x6F6B64)
    /// Champagne accent. Deeper in light mode so text stays readable on ivory.
    public static let accent         = Color(viadereLight: 0x8C7550, dark: 0xCDB993)
    public static let accentSoft     = Color(viadereLight: 0xC2AE8E, dark: 0xCDB993, lightOpacity: 0.16, darkOpacity: 0.14)
    /// Primary action fill: charcoal on light, ivory on dark.
    public static let primaryFill    = Color(viadereLight: 0x1F1E1C, dark: 0xF3F0EA)
    public static let onPrimary      = Color(viadereLight: 0xF5F2EC, dark: 0x1F1E1C)
    public static let danger         = Color(viadereLight: 0xA3412E, dark: 0xE08068)
    public static let success        = Color(viadereLight: 0x4C7458, dark: 0x8DBB98)
    public static let hairline       = Color(viadereLight: 0x1F1E1C, dark: 0xF3F0EA, lightOpacity: 0.10, darkOpacity: 0.12)
    public static let switchOn       = Color(viadereLight: 0x1F1E1C, dark: 0xCDB993)
    public static let knob           = Color(viadereLight: 0xFFFFFF, dark: 0xF5F2EC)
}

extension Color {
    /// Dynamic colour that resolves per light / dark appearance.
    init(viadereLight light: UInt32, dark: UInt32, lightOpacity: Double = 1, darkOpacity: Double = 1) {
        #if canImport(UIKit) && !os(watchOS)
        self.init(uiColor: UIColor { traits in
            traits.userInterfaceStyle == .dark
                ? UIColor(viadereHex: dark, alpha: darkOpacity)
                : UIColor(viadereHex: light, alpha: lightOpacity)
        })
        #else
        // watchOS has no light appearance, so use the dark palette directly.
        self.init(viadereHex: dark, opacity: darkOpacity)
        #endif
    }
}

#if canImport(UIKit) && !os(watchOS)
extension UIColor {
    convenience init(viadereHex hex: UInt32, alpha: Double = 1) {
        self.init(red: CGFloat((hex >> 16) & 0xFF) / 255,
                  green: CGFloat((hex >> 8) & 0xFF) / 255,
                  blue: CGFloat(hex & 0xFF) / 255,
                  alpha: CGFloat(alpha))
    }
}
#endif

// MARK: - Typography, spacing, radius, motion

/// A tight scale on SF Pro; every style follows Dynamic Type.
public enum ViadereType {
    public static let display  = Font.system(.largeTitle, design: .default, weight: .semibold) // 34
    public static let title    = Font.system(.title2, design: .default, weight: .semibold)     // 22
    public static let headline = Font.system(.headline, design: .default, weight: .semibold)   // 17
    public static let body     = Font.system(.body, design: .default, weight: .regular)        // 17
    public static let subhead  = Font.system(.subheadline, design: .default, weight: .regular) // 15
    public static let footnote = Font.system(.footnote, design: .default, weight: .regular)    // 13
    public static let caption  = Font.system(.caption, design: .default, weight: .medium)      // 12
    public static let code     = Font.system(.body, design: .monospaced, weight: .medium)      // one-time codes
}

/// 4-pt rhythm. Prefer the larger steps: whitespace is part of the brand.
public enum ViadereSpace {
    public static let xxs: CGFloat = 4
    public static let xs: CGFloat = 8
    public static let s: CGFloat = 12
    public static let m: CGFloat = 16
    public static let l: CGFloat = 24
    public static let xl: CGFloat = 32
    public static let xxl: CGFloat = 48
    /// Standard screen side margin.
    public static let screen: CGFloat = 24
}

public enum ViadereRadius {
    public static let chip: CGFloat = 8
    public static let control: CGFloat = 12
    public static let button: CGFloat = 14
    public static let card: CGFloat = 20
    public static let sheet: CGFloat = 28
}

public enum ViadereMotion {
    /// Press feedback, focus rings.
    public static let quick = Animation.easeOut(duration: 0.16)
    /// Selection changes, toggles, sliding pills.
    public static let standard = Animation.spring(response: 0.32, dampingFraction: 0.9)
    /// Content appearing / disappearing.
    public static let gentle = Animation.easeInOut(duration: 0.28)
}

// MARK: - Hairline

/// A 1-pixel rule in the hairline colour.
public struct ViadereHairline: View {
    @Environment(\.displayScale) private var displayScale
    private let inset: CGFloat

    public init(inset: CGFloat = 0) { self.inset = inset }

    public var body: some View {
        Rectangle()
            .fill(ViadereColor.hairline)
            .frame(height: 1 / max(displayScale, 1))
            .padding(.leading, inset)
            .accessibilityHidden(true)
    }
}

// MARK: - Buttons

public struct ViadereButtonStyle: ButtonStyle {
    public enum Kind {
        /// Charcoal (light) / ivory (dark) fill. One per screen.
        case primary
        /// Surface fill with a hairline.
        case secondary
        /// Quiet danger: tinted fill, danger text. Used for Deny / Remove.
        case destructive
        /// Text only, for tertiary actions.
        case quiet
    }

    let kind: Kind
    let fullWidth: Bool

    public init(_ kind: Kind = .primary, fullWidth: Bool = true) {
        self.kind = kind
        self.fullWidth = fullWidth
    }

    public func makeBody(configuration: Configuration) -> some View {
        ViadereButtonBody(configuration: configuration, kind: kind, fullWidth: fullWidth)
    }
}

extension ButtonStyle where Self == ViadereButtonStyle {
    /// `.buttonStyle(.viadere(.primary))`
    public static func viadere(_ kind: ViadereButtonStyle.Kind = .primary, fullWidth: Bool = true) -> ViadereButtonStyle {
        ViadereButtonStyle(kind, fullWidth: fullWidth)
    }
}

private struct ViadereButtonBody: View {
    let configuration: ButtonStyleConfiguration
    let kind: ViadereButtonStyle.Kind
    let fullWidth: Bool
    @Environment(\.isEnabled) private var isEnabled

    private var shape: RoundedRectangle { RoundedRectangle(cornerRadius: ViadereRadius.button, style: .continuous) }

    var body: some View {
        let pressed = configuration.isPressed
        configuration.label
            .font(kind == .quiet ? ViadereType.subhead.weight(.medium) : ViadereType.headline)
            .foregroundStyle(foreground)
            .lineLimit(1)
            .padding(.horizontal, kind == .quiet ? ViadereSpace.xs : 22)
            .frame(maxWidth: fullWidth ? .infinity : nil, minHeight: kind == .quiet ? 44 : 52)
            .background { shape.fill(fill).opacity(pressed ? 0.86 : 1) }
            .overlay { shape.strokeBorder(border, lineWidth: 1) }
            .contentShape(shape)
            .opacity(isEnabled ? (kind == .quiet && pressed ? 0.6 : 1) : 0.38)
            .scaleEffect(pressed && kind != .quiet ? 0.985 : 1)
            .animation(ViadereMotion.quick, value: pressed)
    }

    private var foreground: Color {
        switch kind {
        case .primary: return ViadereColor.onPrimary
        case .secondary: return ViadereColor.textPrimary
        case .destructive: return ViadereColor.danger
        case .quiet: return ViadereColor.textSecondary
        }
    }

    private var fill: Color {
        switch kind {
        case .primary: return ViadereColor.primaryFill
        case .secondary: return ViadereColor.surface
        case .destructive: return ViadereColor.danger.opacity(0.08)
        case .quiet: return .clear
        }
    }

    private var border: Color {
        switch kind {
        case .primary, .quiet: return .clear
        case .secondary: return ViadereColor.hairline
        case .destructive: return ViadereColor.danger.opacity(0.22)
        }
    }
}

// MARK: - Text field

/// Label above, quiet surface field, hairline that warms to champagne on focus.
public struct ViadereTextField: View {
    private let title: String
    @Binding private var text: String
    private let prompt: String
    private let isSecure: Bool
    private let message: String?
    private let isError: Bool
    @FocusState private var focused: Bool

    public init(_ title: String, text: Binding<String>, prompt: String = "", isSecure: Bool = false,
                message: String? = nil, isError: Bool = false) {
        self.title = title
        self._text = text
        self.prompt = prompt
        self.isSecure = isSecure
        self.message = message
        self.isError = isError
    }

    private var shape: RoundedRectangle { RoundedRectangle(cornerRadius: ViadereRadius.control, style: .continuous) }

    private var borderColor: Color {
        if isError { return ViadereColor.danger }
        return focused ? ViadereColor.accent : ViadereColor.hairline
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.xs) {
            Text(title)
                .font(ViadereType.footnote.weight(.medium))
                .foregroundStyle(ViadereColor.textSecondary)
            field
                .textFieldStyle(.plain)
                .font(ViadereType.body)
                .foregroundStyle(ViadereColor.textPrimary)
                .tint(ViadereColor.accent)
                .focused($focused)
                .padding(.horizontal, ViadereSpace.m)
                .frame(minHeight: 52)
                .background(shape.fill(ViadereColor.surface))
                .overlay(shape.strokeBorder(borderColor, lineWidth: focused || isError ? 1.5 : 1))
                .animation(ViadereMotion.quick, value: focused)
            if let message {
                Text(message)
                    .font(ViadereType.footnote)
                    .foregroundStyle(isError ? ViadereColor.danger : ViadereColor.textSecondary)
            }
        }
    }

    @ViewBuilder private var field: some View {
        let placeholder = Text(prompt).foregroundStyle(ViadereColor.textTertiary)
        if isSecure {
            SecureField(title, text: $text, prompt: placeholder)
        } else {
            TextField(title, text: $text, prompt: placeholder)
        }
    }
}

// MARK: - Surface & card

public struct ViadereSurfaceModifier: ViewModifier {
    let radius: CGFloat
    @Environment(\.colorScheme) private var colorScheme

    public func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: radius, style: .continuous)
        content
            .background(
                shape.fill(ViadereColor.surface)
                    .shadow(color: .black.opacity(colorScheme == .dark ? 0 : 0.045), radius: 14, x: 0, y: 6)
            )
            .overlay(shape.strokeBorder(ViadereColor.hairline, lineWidth: 1))
    }
}

extension View {
    /// Surface fill + hairline + (light mode) a barely-there shadow.
    public func viadereSurface(radius: CGFloat = ViadereRadius.card) -> some View {
        modifier(ViadereSurfaceModifier(radius: radius))
    }

    /// Ivory / near-black screen background, edge to edge.
    public func viadereScreenBackground() -> some View {
        background(ViadereColor.background.ignoresSafeArea())
    }
}

public struct ViadereCard<Content: View>: View {
    private let padding: CGFloat
    private let content: Content

    public init(padding: CGFloat = ViadereSpace.l, @ViewBuilder content: () -> Content) {
        self.padding = padding
        self.content = content()
    }

    public var body: some View {
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .viadereSurface()
    }
}

// MARK: - List row

public struct ViadereChevron: View {
    public init() {}
    public var body: some View {
        Image(systemName: "chevron.right")
            .font(.system(size: 13, weight: .semibold))
            .foregroundStyle(ViadereColor.textTertiary)
            .accessibilityHidden(true)
    }
}

/// 36-pt rounded tile holding an SF Symbol: the standard row leading element.
public struct ViadereIconTile: View {
    private let systemName: String
    public init(systemName: String) { self.systemName = systemName }
    public var body: some View {
        let shape = RoundedRectangle(cornerRadius: 10, style: .continuous)
        Image(systemName: systemName)
            .font(.system(size: 15, weight: .medium))
            .foregroundStyle(ViadereColor.textPrimary)
            .frame(width: 36, height: 36)
            .background(shape.fill(ViadereColor.surfaceRaised))
            .overlay(shape.strokeBorder(ViadereColor.hairline, lineWidth: 1))
            .accessibilityHidden(true)
    }
}

public struct ViadereRow<Leading: View, Trailing: View>: View {
    private let title: String
    private let subtitle: String?
    private let leading: Leading
    private let trailing: Trailing

    public init(_ title: String, subtitle: String? = nil,
                @ViewBuilder leading: () -> Leading, @ViewBuilder trailing: () -> Trailing) {
        self.title = title
        self.subtitle = subtitle
        self.leading = leading()
        self.trailing = trailing()
    }

    public var body: some View {
        HStack(spacing: 14) {
            leading
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(ViadereType.body)
                    .foregroundStyle(ViadereColor.textPrimary)
                if let subtitle {
                    Text(subtitle)
                        .font(ViadereType.subhead)
                        .foregroundStyle(ViadereColor.textSecondary)
                }
            }
            Spacer(minLength: ViadereSpace.xs)
            trailing
        }
        .padding(.vertical, ViadereSpace.s)
        .frame(minHeight: 56)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }
}

extension ViadereRow where Leading == EmptyView, Trailing == ViadereChevron {
    public init(_ title: String, subtitle: String? = nil) {
        self.init(title, subtitle: subtitle, leading: { EmptyView() }, trailing: { ViadereChevron() })
    }
}

extension ViadereRow where Trailing == ViadereChevron {
    public init(_ title: String, subtitle: String? = nil, @ViewBuilder leading: () -> Leading) {
        self.init(title, subtitle: subtitle, leading: leading, trailing: { ViadereChevron() })
    }
}

// MARK: - Toggle

/// `Toggle("Face ID", isOn: $on).toggleStyle(.viadere)`
public struct ViadereToggleStyle: ToggleStyle {
    public init() {}

    public func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: ViadereSpace.s) {
            configuration.label
                .font(ViadereType.body)
                .foregroundStyle(ViadereColor.textPrimary)
            Spacer(minLength: ViadereSpace.s)
            ViadereSwitchTrack(isOn: configuration.isOn)
        }
        .frame(minHeight: 44)
        .contentShape(Rectangle())
        .onTapGesture { configuration.isOn.toggle() }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isToggle)
        .accessibilityValue(Text(configuration.isOn ? "On" : "Off"))
        .accessibilityAction { configuration.isOn.toggle() }
    }
}

extension ToggleStyle where Self == ViadereToggleStyle {
    public static var viadere: ViadereToggleStyle { ViadereToggleStyle() }
}

private struct ViadereSwitchTrack: View {
    let isOn: Bool
    @Environment(\.isEnabled) private var isEnabled

    var body: some View {
        ZStack(alignment: isOn ? .trailing : .leading) {
            Capsule()
                .fill(isOn ? ViadereColor.switchOn : ViadereColor.track)
                .overlay(Capsule().strokeBorder(ViadereColor.hairline, lineWidth: isOn ? 0 : 1))
            Circle()
                .fill(ViadereColor.knob)
                .shadow(color: .black.opacity(0.14), radius: 2, x: 0, y: 1)
                .padding(3)
        }
        .frame(width: 50, height: 30)
        .opacity(isEnabled ? 1 : 0.4)
        .animation(ViadereMotion.standard, value: isOn)
        .sensoryFeedback(.selection, trigger: isOn)
        .accessibilityHidden(true)
    }
}

// MARK: - Segmented selector

/// Recessed track with a sliding raised pill.
public struct ViadereSegmented<Value: Hashable>: View {
    @Binding private var selection: Value
    private let options: [Value]
    private let title: (Value) -> String
    @Namespace private var namespace

    public init(selection: Binding<Value>, options: [Value], title: @escaping (Value) -> String) {
        self._selection = selection
        self.options = options
        self.title = title
    }

    public var body: some View {
        HStack(spacing: 2) {
            ForEach(options, id: \.self) { option in
                let selected = option == selection
                Button {
                    withAnimation(ViadereMotion.standard) { selection = option }
                } label: {
                    Text(title(option))
                        .font(ViadereType.subhead.weight(selected ? .semibold : .regular))
                        .foregroundStyle(selected ? ViadereColor.textPrimary : ViadereColor.textSecondary)
                        .lineLimit(1)
                        .frame(maxWidth: .infinity, minHeight: 36)
                        .background {
                            if selected {
                                RoundedRectangle(cornerRadius: 9, style: .continuous)
                                    .fill(ViadereColor.surfaceRaised)
                                    .shadow(color: .black.opacity(0.06), radius: 3, x: 0, y: 1)
                                    .matchedGeometryEffect(id: "pill", in: namespace)
                            }
                        }
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(selected ? .isSelected : [])
            }
        }
        .padding(3)
        .background(RoundedRectangle(cornerRadius: ViadereRadius.control, style: .continuous).fill(ViadereColor.track))
        .sensoryFeedback(.selection, trigger: selection)
    }
}

// MARK: - Badge / verification chip

public struct ViadereBadge: View {
    public enum Kind { case verified, neutral, pending, success, danger }

    private let text: String
    private let kind: Kind

    public init(_ text: String, kind: Kind = .neutral) {
        self.text = text
        self.kind = kind
    }

    public var body: some View {
        HStack(spacing: 5) {
            if let icon {
                Image(systemName: icon).font(.system(size: 10, weight: .bold))
            }
            Text(text).font(ViadereType.caption)
        }
        .foregroundStyle(tint)
        .padding(.horizontal, 9)
        .padding(.vertical, 4)
        .background(Capsule().fill(fill))
        .overlay(Capsule().strokeBorder(tint.opacity(0.18), lineWidth: 1))
        .accessibilityElement(children: .combine)
    }

    private var icon: String? {
        switch kind {
        case .verified: return "checkmark.seal.fill"
        case .pending: return "clock"
        case .success: return "checkmark"
        case .danger: return "exclamationmark"
        case .neutral: return nil
        }
    }

    private var tint: Color {
        switch kind {
        case .verified: return ViadereColor.accent
        case .neutral, .pending: return ViadereColor.textSecondary
        case .success: return ViadereColor.success
        case .danger: return ViadereColor.danger
        }
    }

    private var fill: Color {
        switch kind {
        case .verified: return ViadereColor.accentSoft
        case .neutral, .pending: return ViadereColor.track
        case .success: return ViadereColor.success.opacity(0.10)
        case .danger: return ViadereColor.danger.opacity(0.08)
        }
    }
}

// MARK: - Section header

public struct ViadereSectionHeader: View {
    private let title: String
    private let actionTitle: String?
    private let action: (() -> Void)?

    public init(_ title: String, actionTitle: String? = nil, action: (() -> Void)? = nil) {
        self.title = title
        self.actionTitle = actionTitle
        self.action = action
    }

    public var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(title)
                .font(ViadereType.caption)
                .tracking(1.1)
                .textCase(.uppercase)
                .foregroundStyle(ViadereColor.textSecondary)
                .accessibilityAddTraits(.isHeader)
            Spacer()
            if let actionTitle, let action {
                Button(actionTitle, action: action)
                    .buttonStyle(.plain)
                    .font(ViadereType.footnote.weight(.medium))
                    .foregroundStyle(ViadereColor.accent)
            }
        }
        .padding(.horizontal, ViadereSpace.xxs)
        .padding(.top, ViadereSpace.l)
        .padding(.bottom, ViadereSpace.xs)
    }
}

// MARK: - Sensitive approvals

/// Slide-to-approve for high-assurance actions (payments, sign-ins, signatures).
/// Deliberate by design: requires a full drag; VoiceOver users activate it with a double tap.
public struct ViadereSlideToConfirm: View {
    private let title: String
    private let confirmedTitle: String
    private let onConfirm: () -> Void

    @State private var offset: CGFloat = 0
    @State private var confirmed = false

    private let knob: CGFloat = 52
    private let inset: CGFloat = 4

    public init(_ title: String = "Slide to approve", confirmedTitle: String = "Approved", onConfirm: @escaping () -> Void) {
        self.title = title
        self.confirmedTitle = confirmedTitle
        self.onConfirm = onConfirm
    }

    public var body: some View {
        GeometryReader { proxy in
            let maxOffset = max(0, proxy.size.width - knob - inset * 2)
            let progress = maxOffset > 0 ? offset / maxOffset : 0
            ZStack(alignment: .leading) {
                Capsule().fill(ViadereColor.track)
                    .overlay(Capsule().strokeBorder(ViadereColor.hairline, lineWidth: 1))
                Capsule().fill(ViadereColor.accentSoft)
                    .frame(width: offset + knob + inset * 2)
                Text(confirmed ? confirmedTitle : title)
                    .font(ViadereType.subhead.weight(.medium))
                    .foregroundStyle(ViadereColor.textSecondary)
                    .frame(maxWidth: .infinity)
                    .padding(.leading, knob * 0.6)
                    .opacity(confirmed ? 1 : max(0, 1 - progress * 1.6))
                Circle()
                    .fill(ViadereColor.primaryFill)
                    .frame(width: knob, height: knob)
                    .overlay(
                        Image(systemName: confirmed ? "checkmark" : "arrow.right")
                            .font(.system(size: 17, weight: .semibold))
                            .foregroundStyle(ViadereColor.onPrimary)
                    )
                    .offset(x: inset + offset)
                    .gesture(
                        DragGesture(minimumDistance: 2)
                            .onChanged { value in
                                guard !confirmed else { return }
                                offset = min(max(0, value.translation.width), maxOffset)
                            }
                            .onEnded { _ in
                                guard !confirmed else { return }
                                if offset >= maxOffset * 0.88 {
                                    withAnimation(ViadereMotion.standard) { offset = maxOffset }
                                    confirm()
                                } else {
                                    withAnimation(ViadereMotion.standard) { offset = 0 }
                                }
                            }
                    )
            }
        }
        .frame(height: knob + inset * 2)
        .sensoryFeedback(.success, trigger: confirmed)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(confirmed ? confirmedTitle : title))
        .accessibilityAddTraits(.isButton)
        .accessibilityAction { confirm() }
    }

    private func confirm() {
        guard !confirmed else { return }
        confirmed = true
        onConfirm()
    }
}

/// Deny / Approve pair: equal weight, deny on the left, approve (primary) on the right.
public struct ViadereApprovalButtons: View {
    private let approveTitle: String
    private let denyTitle: String
    private let onApprove: () -> Void
    private let onDeny: () -> Void

    public init(approveTitle: String = "Approve", denyTitle: String = "Deny",
                onApprove: @escaping () -> Void, onDeny: @escaping () -> Void) {
        self.approveTitle = approveTitle
        self.denyTitle = denyTitle
        self.onApprove = onApprove
        self.onDeny = onDeny
    }

    public var body: some View {
        HStack(spacing: ViadereSpace.s) {
            Button(denyTitle, action: onDeny).buttonStyle(.viadere(.destructive))
            Button(approveTitle, action: onApprove).buttonStyle(.viadere(.primary))
        }
    }
}

public struct ViadereDetail: Identifiable, Hashable {
    public let id = UUID()
    public let label: String
    public let value: String
    public init(_ label: String, _ value: String) {
        self.label = label
        self.value = value
    }
}

/// The approval sheet body: who is asking, what for, the facts, then the decision.
public struct ViadereApprovalCard: View {
    public enum Mode { case slide, buttons }

    private let requester: String
    private let isVerified: Bool
    private let title: String
    private let details: [ViadereDetail]
    private let mode: Mode
    private let onApprove: () -> Void
    private let onDeny: () -> Void

    public init(requester: String, isVerified: Bool = true, title: String, details: [ViadereDetail],
                mode: Mode = .buttons, onApprove: @escaping () -> Void, onDeny: @escaping () -> Void) {
        self.requester = requester
        self.isVerified = isVerified
        self.title = title
        self.details = details
        self.mode = mode
        self.onApprove = onApprove
        self.onDeny = onDeny
    }

    public var body: some View {
        ViadereCard {
            VStack(alignment: .leading, spacing: ViadereSpace.l) {
                VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                    HStack(spacing: ViadereSpace.xs) {
                        Text(requester)
                            .font(ViadereType.subhead.weight(.medium))
                            .foregroundStyle(ViadereColor.textSecondary)
                        if isVerified { ViadereBadge("Verified", kind: .verified) }
                    }
                    Text(title)
                        .font(ViadereType.title)
                        .foregroundStyle(ViadereColor.textPrimary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                VStack(spacing: 0) {
                    ForEach(details) { detail in
                        HStack(alignment: .firstTextBaseline) {
                            Text(detail.label).foregroundStyle(ViadereColor.textSecondary)
                            Spacer(minLength: ViadereSpace.m)
                            Text(detail.value)
                                .foregroundStyle(ViadereColor.textPrimary)
                                .multilineTextAlignment(.trailing)
                        }
                        .font(ViadereType.subhead)
                        .padding(.vertical, 10)
                        if detail.id != details.last?.id { ViadereHairline() }
                    }
                }
                switch mode {
                case .slide:
                    VStack(spacing: ViadereSpace.xs) {
                        ViadereSlideToConfirm(onConfirm: onApprove)
                        Button("Deny", action: onDeny).buttonStyle(.viadere(.quiet))
                    }
                case .buttons:
                    ViadereApprovalButtons(onApprove: onApprove, onDeny: onDeny)
                }
            }
        }
    }
}

// MARK: - Empty state

public struct ViadereEmptyState: View {
    private let title: String
    private let message: String
    private let actionTitle: String?
    private let action: (() -> Void)?

    public init(_ title: String, message: String, actionTitle: String? = nil, action: (() -> Void)? = nil) {
        self.title = title
        self.message = message
        self.actionTitle = actionTitle
        self.action = action
    }

    public var body: some View {
        VStack(spacing: ViadereSpace.s) {
            ViadereMark.monochrome(ViadereColor.textTertiary)
                .frame(height: 36)
                .opacity(0.55)
                .padding(.bottom, ViadereSpace.s)
            Text(title)
                .font(ViadereType.title)
                .foregroundStyle(ViadereColor.textPrimary)
                .multilineTextAlignment(.center)
            Text(message)
                .font(ViadereType.body)
                .foregroundStyle(ViadereColor.textSecondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 300)
            if let actionTitle, let action {
                Button(actionTitle, action: action)
                    .buttonStyle(.viadere(.secondary, fullWidth: false))
                    .padding(.top, ViadereSpace.s)
            }
        }
        .padding(ViadereSpace.xl)
        .frame(maxWidth: .infinity)
    }
}

// MARK: - Gallery (previews / QA)

/// Every component on one screen. Useful for previews, snapshot tests and design QA.
public struct ViadereDesignSystemGallery: View {
    @State private var email = ""
    @State private var faceID = true
    @State private var alerts = false
    @State private var scope = "All"

    public init() {}

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: ViadereSpace.l) {
                ViadereLockup(.horizontal, ribbonHeight: 28)
                    .padding(.top, ViadereSpace.l)

                Text("A trusted way to connect.")
                    .font(ViadereType.display)
                    .foregroundStyle(ViadereColor.textPrimary)

                ViadereSegmented(selection: $scope, options: ["All", "Businesses", "Requests"]) { $0 }

                ViadereSectionHeader("Connections", actionTitle: "See all") {}
                ViadereCard(padding: ViadereSpace.m) {
                    VStack(spacing: 0) {
                        ViadereRow("Harbor Bank", subtitle: "Connected · verified") {
                            ViadereIconTile(systemName: "building.columns")
                        }
                        ViadereHairline(inset: 50)
                        ViadereRow("Northside Clinic", subtitle: "Appointments") {
                            ViadereIconTile(systemName: "calendar")
                        }
                    }
                }

                ViadereApprovalCard(
                    requester: "Harbor Bank",
                    title: "Approve sign-in on a new Mac?",
                    details: [ViadereDetail("Location", "Lisbon, PT"), ViadereDetail("Device", "MacBook Air"), ViadereDetail("Time", "Just now")],
                    mode: .slide,
                    onApprove: {}, onDeny: {})

                ViadereSectionHeader("Settings")
                ViadereCard(padding: ViadereSpace.m) {
                    VStack(spacing: 0) {
                        Toggle("Face ID for approvals", isOn: $faceID).toggleStyle(.viadere)
                        ViadereHairline()
                        Toggle("Marketing messages", isOn: $alerts).toggleStyle(.viadere)
                    }
                }

                ViadereTextField("Email", text: $email, prompt: "name@example.com",
                                 message: "We'll send a one-time code.")

                HStack(spacing: ViadereSpace.xs) {
                    ViadereBadge("Verified", kind: .verified)
                    ViadereBadge("Pending", kind: .pending)
                    ViadereBadge("Active", kind: .success)
                    ViadereBadge("Revoked", kind: .danger)
                }

                VStack(spacing: ViadereSpace.s) {
                    Button("Continue") {}.buttonStyle(.viadere(.primary))
                    Button("Not now") {}.buttonStyle(.viadere(.secondary))
                    Button("Remove connection") {}.buttonStyle(.viadere(.destructive))
                }

                ViadereEmptyState("No requests", message: "When a business asks for something, it appears here.",
                                  actionTitle: "Connect a business") {}
            }
            .padding(.horizontal, ViadereSpace.screen)
            .padding(.bottom, ViadereSpace.xxl)
        }
        .viadereScreenBackground()
    }
}

#Preview("Light") {
    ViadereDesignSystemGallery()
        .preferredColorScheme(.light)
}

#Preview("Dark") {
    ViadereDesignSystemGallery()
        .preferredColorScheme(.dark)
}
