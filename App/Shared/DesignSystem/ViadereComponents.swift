//
//  ViadereComponents.swift
//  App-level custom components built on the Viadere design tokens (ViadereDesignSystem.swift).
//
//  Everything here is hand-drawn from tokens: no stock tab bar, no grouped List/Form chrome, no tinted
//  system controls. Stock UI appears only where the OS owns the surface (passkey sheet, camera, Face ID,
//  the notification itself).
//

import SwiftUI

// MARK: - Layout

/// Wraps children onto new lines (choice chips, risk badges).
public struct ViadereFlowLayout: Layout {
    public var spacing: CGFloat

    public init(spacing: CGFloat = ViadereSpace.xs) { self.spacing = spacing }

    public func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let maxWidth = proposal.width ?? .infinity
        var x: CGFloat = 0
        var y: CGFloat = 0
        var rowHeight: CGFloat = 0
        var usedWidth: CGFloat = 0
        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x > 0, x + size.width > maxWidth {
                x = 0
                y += rowHeight + spacing
                rowHeight = 0
            }
            x += size.width + spacing
            usedWidth = max(usedWidth, x - spacing)
            rowHeight = max(rowHeight, size.height)
        }
        return CGSize(width: proposal.width ?? usedWidth, height: y + rowHeight)
    }

    public func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX
        var y = bounds.minY
        var rowHeight: CGFloat = 0
        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x > bounds.minX, x + size.width > bounds.maxX {
                x = bounds.minX
                y += rowHeight + spacing
                rowHeight = 0
            }
            subview.place(at: CGPoint(x: x, y: y), anchor: .topLeading, proposal: ProposedViewSize(size))
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
    }
}

// MARK: - Headers and navigation

/// Large calm title with an optional trailing control. Replaces the system navigation bar.
public struct ViadereHeader<Trailing: View>: View {
    private let title: String
    private let subtitle: String?
    private let trailing: Trailing

    public init(_ title: String, subtitle: String? = nil, @ViewBuilder trailing: () -> Trailing) {
        self.title = title
        self.subtitle = subtitle
        self.trailing = trailing()
    }

    public var body: some View {
        HStack(alignment: .top, spacing: ViadereSpace.m) {
            VStack(alignment: .leading, spacing: ViadereSpace.xxs) {
                Text(title)
                    .font(ViadereType.display)
                    .foregroundStyle(ViadereColor.textPrimary)
                    .accessibilityAddTraits(.isHeader)
                if let subtitle {
                    Text(subtitle)
                        .font(ViadereType.subhead)
                        .foregroundStyle(ViadereColor.textSecondary)
                }
            }
            Spacer(minLength: 0)
            trailing
        }
        .padding(.top, ViadereSpace.l)
        .padding(.bottom, ViadereSpace.s)
    }
}

extension ViadereHeader where Trailing == EmptyView {
    public init(_ title: String, subtitle: String? = nil) {
        self.init(title, subtitle: subtitle) { EmptyView() }
    }
}

/// A round 44-pt icon button with a hairline.
public struct ViadereIconButton: View {
    private let systemName: String
    private let label: String
    private let action: () -> Void

    public init(systemName: String, label: String, action: @escaping () -> Void) {
        self.systemName = systemName
        self.label = label
        self.action = action
    }

    public var body: some View {
        Button(action: action) {
            Image(systemName: systemName)
                .font(.system(size: 17, weight: .medium))
                .foregroundStyle(ViadereColor.textPrimary)
                .frame(width: 44, height: 44)
                .background(Circle().fill(ViadereColor.surface))
                .overlay(Circle().strokeBorder(ViadereColor.hairline, lineWidth: 1))
                .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(Text(label))
    }
}

/// "‹ Back" for pushed screens (the system bar is hidden).
public struct ViadereBackButton: View {
    private let title: String
    private let action: () -> Void

    public init(_ title: String = "Back", action: @escaping () -> Void) {
        self.title = title
        self.action = action
    }

    public var body: some View {
        Button(action: action) {
            HStack(spacing: 4) {
                Image(systemName: "chevron.left").font(.system(size: 15, weight: .semibold))
                Text(title).font(ViadereType.subhead.weight(.medium))
            }
            .foregroundStyle(ViadereColor.textSecondary)
            .frame(minHeight: 44)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

/// Small grabber at the top of a custom sheet.
public struct ViadereGrabber: View {
    public init() {}
    public var body: some View {
        Capsule()
            .fill(ViadereColor.textTertiary.opacity(0.5))
            .frame(width: 36, height: 4)
            .frame(maxWidth: .infinity)
            .padding(.top, ViadereSpace.xs)
            .accessibilityHidden(true)
    }
}

// MARK: - Tab bar

/// A hand-built bottom bar: hairline on top, quiet icons, champagne only on the selected item.
public struct ViadereTabBar<Tab: Hashable>: View {
    public struct Item: Identifiable {
        public var id: Tab { tab }
        public let tab: Tab
        public let title: String
        public let symbol: String
        public let badge: Int
        public init(tab: Tab, title: String, symbol: String, badge: Int = 0) {
            self.tab = tab
            self.title = title
            self.symbol = symbol
            self.badge = badge
        }
    }

    @Binding private var selection: Tab
    private let items: [Item]

    public init(selection: Binding<Tab>, items: [Item]) {
        self._selection = selection
        self.items = items
    }

    public var body: some View {
        VStack(spacing: 0) {
            ViadereHairline()
            HStack(spacing: 0) {
                ForEach(items) { item in
                    let selected = item.tab == selection
                    Button {
                        selection = item.tab
                    } label: {
                        VStack(spacing: 3) {
                            ZStack(alignment: .topTrailing) {
                                Image(systemName: item.symbol)
                                    .font(.system(size: 20, weight: selected ? .semibold : .regular))
                                if item.badge > 0 {
                                    Circle()
                                        .fill(ViadereColor.accent)
                                        .frame(width: 8, height: 8)
                                        .offset(x: 5, y: -2)
                                }
                            }
                            Text(item.title)
                                .font(.system(size: 11, weight: selected ? .semibold : .regular))
                        }
                        .foregroundStyle(selected ? ViadereColor.textPrimary : ViadereColor.textTertiary)
                        .frame(maxWidth: .infinity, minHeight: 52)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(Text(item.badge > 0 ? "\(item.title), \(item.badge) new" : item.title))
                    .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
                }
            }
            .padding(.horizontal, ViadereSpace.s)
            .sensoryFeedback(.selection, trigger: selection)
        }
        .background(ViadereColor.background.opacity(0.96).ignoresSafeArea(edges: .bottom))
    }
}

// MARK: - Chips

/// A choice chip: answers a structured `choose` request or filters a list. 44-pt hit target.
public struct ViadereChip: View {
    private let title: String
    private let isSelected: Bool
    private let action: () -> Void

    public init(_ title: String, isSelected: Bool = false, action: @escaping () -> Void) {
        self.title = title
        self.isSelected = isSelected
        self.action = action
    }

    public var body: some View {
        Button(action: action) {
            Text(title)
                .font(ViadereType.subhead.weight(.medium))
                .foregroundStyle(isSelected ? ViadereColor.onPrimary : ViadereColor.textPrimary)
                .padding(.horizontal, ViadereSpace.m)
                .frame(minHeight: 44)
                .background(Capsule().fill(isSelected ? ViadereColor.primaryFill : ViadereColor.surface))
                .overlay(Capsule().strokeBorder(ViadereColor.hairline, lineWidth: isSelected ? 0 : 1))
                .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }
}

// MARK: - Identity

/// A business monogram tile. Never a logo from a third party: identity comes from the verified name.
public struct ViadereAvatar: View {
    private let name: String
    private let size: CGFloat
    private let isVerified: Bool

    public init(name: String, size: CGFloat = 44, isVerified: Bool = false) {
        self.name = name
        self.size = size
        self.isVerified = isVerified
    }

    private var initials: String {
        let words = name.split(separator: " ").prefix(2)
        let letters = words.compactMap { $0.first.map(String.init) }.joined()
        return letters.isEmpty ? "·" : letters.uppercased()
    }

    public var body: some View {
        let shape = RoundedRectangle(cornerRadius: size * 0.3, style: .continuous)
        ZStack(alignment: .bottomTrailing) {
            Text(initials)
                .font(.system(size: size * 0.38, weight: .semibold))
                .foregroundStyle(ViadereColor.textPrimary)
                .frame(width: size, height: size)
                .background(shape.fill(ViadereColor.surfaceRaised))
                .overlay(shape.strokeBorder(ViadereColor.hairline, lineWidth: 1))
            if isVerified {
                Image(systemName: "checkmark.seal.fill")
                    .font(.system(size: size * 0.3, weight: .bold))
                    .foregroundStyle(ViadereColor.accent)
                    .padding(2)
                    .background(Circle().fill(ViadereColor.background))
                    .offset(x: size * 0.1, y: size * 0.1)
            }
        }
        .accessibilityHidden(true)
    }
}

// MARK: - Notices

public struct ViadereNotice: View {
    public enum Kind { case info, warning, danger }

    private let kind: Kind
    private let text: String

    public init(_ text: String, kind: Kind = .info) {
        self.text = text
        self.kind = kind
    }

    private var tint: Color {
        switch kind {
        case .info: return ViadereColor.textSecondary
        case .warning: return ViadereColor.accent
        case .danger: return ViadereColor.danger
        }
    }

    private var symbol: String {
        switch kind {
        case .info: return "info.circle"
        case .warning: return "exclamationmark.circle"
        case .danger: return "exclamationmark.triangle"
        }
    }

    public var body: some View {
        HStack(alignment: .top, spacing: ViadereSpace.s) {
            Image(systemName: symbol)
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(tint)
                .padding(.top, 2)
            Text(text)
                .font(ViadereType.subhead)
                .foregroundStyle(ViadereColor.textPrimary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(ViadereSpace.m)
        .background(RoundedRectangle(cornerRadius: ViadereRadius.control, style: .continuous).fill(tint.opacity(0.08)))
        .overlay(RoundedRectangle(cornerRadius: ViadereRadius.control, style: .continuous).strokeBorder(tint.opacity(0.2), lineWidth: 1))
        .accessibilityElement(children: .combine)
    }
}

/// A transient confirmation at the bottom of the screen.
public struct ViadereToast: View {
    private let text: String
    public init(_ text: String) { self.text = text }

    public var body: some View {
        Text(text)
            .font(ViadereType.subhead.weight(.medium))
            .foregroundStyle(ViadereColor.onPrimary)
            .padding(.horizontal, ViadereSpace.l)
            .padding(.vertical, ViadereSpace.s)
            .background(Capsule().fill(ViadereColor.primaryFill))
            .padding(.bottom, ViadereSpace.l)
            .accessibilityAddTraits(.isStaticText)
    }
}

/// A risk indicator shown on approval requests. Severity changes tint, never alarm-red wallpaper.
public struct ViadereRiskChip: View {
    private let label: String
    private let severity: String

    public init(label: String, severity: String) {
        self.label = label
        self.severity = severity
    }

    private var tint: Color { severity == "high" ? ViadereColor.danger : (severity == "warning" ? ViadereColor.accent : ViadereColor.textSecondary) }

    public var body: some View {
        HStack(spacing: 6) {
            Circle().fill(tint).frame(width: 6, height: 6)
            Text(label).font(ViadereType.footnote.weight(.medium)).foregroundStyle(ViadereColor.textPrimary)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(Capsule().fill(tint.opacity(0.10)))
        .accessibilityElement(children: .combine)
        .accessibilityLabel(Text(severity == "info" ? label : "Warning: \(label)"))
    }
}

// MARK: - Countdown

/// Time-left ring: full when fresh, empty at expiry. Reads "4:32" to VoiceOver as "Expires in 4:32".
public struct ViadereCountdownRing: View {
    private let progress: Double
    private let label: String
    private let spokenLabel: String

    public init(progress: Double, label: String, spokenLabel: String) {
        self.progress = min(max(progress, 0), 1)
        self.label = label
        self.spokenLabel = spokenLabel
    }

    public var body: some View {
        ZStack {
            Circle().stroke(ViadereColor.track, lineWidth: 3)
            Circle()
                .trim(from: 0, to: progress)
                .stroke(progress < 0.2 ? ViadereColor.danger : ViadereColor.accent, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.linear(duration: 1), value: progress)
            Text(label)
                .font(.system(size: 11, weight: .semibold, design: .rounded))
                .monospacedDigit()
                .foregroundStyle(ViadereColor.textPrimary)
        }
        .frame(width: 48, height: 48)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(spokenLabel))
    }
}

// MARK: - Progress

/// A quiet progress track: a champagne fill that ends in a small dot, echoing the via mark. Used by Activity rows,
/// Live Activities and the Dynamic Island. Reads "Progress, 55 percent" to VoiceOver.
public struct ViadereProgressBar: View {
    private let progress: Double
    private let height: CGFloat
    private let label: String

    public init(progress: Double, height: CGFloat = 5, label: String = "Progress") {
        self.progress = min(max(progress, 0), 1)
        self.height = height
        self.label = label
    }

    public var body: some View {
        GeometryReader { proxy in
            let dot = height + 3
            let fill = max(height, proxy.size.width * progress)
            ZStack(alignment: .leading) {
                Capsule().fill(ViadereColor.track)
                Capsule().fill(ViadereColor.accent).frame(width: fill)
                if progress > 0, progress < 1 {
                    Circle()
                        .fill(ViadereColor.accent)
                        .frame(width: dot, height: dot)
                        .offset(x: min(max(0, fill - dot * 0.5), proxy.size.width - dot))
                }
            }
            .frame(maxHeight: .infinity)
        }
        .frame(height: height + 4)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(label))
        .accessibilityValue(Text("\(Int(progress * 100)) percent"))
    }
}

// MARK: - Input fields

/// The unified connect field: one quiet, large field for a handle, a code, a link or a business name.
public struct ViadereEntryField: View {
    public enum Status: Equatable { case none, valid, invalid }

    private let placeholder: String
    @Binding private var text: String
    private let status: Status
    private let hint: String?
    private let monospaced: Bool
    private let onSubmit: () -> Void
    @FocusState private var focused: Bool

    public init(placeholder: String, text: Binding<String>, status: Status = .none, hint: String? = nil,
                monospaced: Bool = false, onSubmit: @escaping () -> Void = {}) {
        self.placeholder = placeholder
        self._text = text
        self.status = status
        self.hint = hint
        self.monospaced = monospaced
        self.onSubmit = onSubmit
    }

    private var border: Color {
        switch status {
        case .invalid: return ViadereColor.danger
        case .valid: return ViadereColor.accent
        case .none: return focused ? ViadereColor.accent.opacity(0.7) : ViadereColor.hairline
        }
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.xs) {
            HStack(spacing: ViadereSpace.s) {
                TextField("", text: $text, prompt: Text(placeholder).foregroundStyle(ViadereColor.textTertiary))
                    .font(monospaced ? ViadereType.code : .system(size: 20, weight: .regular))
                    .foregroundStyle(ViadereColor.textPrimary)
                    .tint(ViadereColor.accent)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.asciiCapable)
                    .submitLabel(.go)
                    .focused($focused)
                    .onSubmit(onSubmit)
                    .accessibilityLabel(Text("Handle, code or business name"))
                if status == .valid {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(ViadereColor.accent)
                        .transition(.opacity)
                        .accessibilityHidden(true)
                } else if !text.isEmpty {
                    Button {
                        text = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(ViadereColor.textTertiary)
                            .frame(width: 44, height: 44)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(Text("Clear"))
                }
            }
            .padding(.leading, ViadereSpace.m)
            .padding(.trailing, text.isEmpty ? ViadereSpace.m : 0)
            .frame(minHeight: 60)
            .background(RoundedRectangle(cornerRadius: ViadereRadius.card, style: .continuous).fill(ViadereColor.surface))
            .overlay(RoundedRectangle(cornerRadius: ViadereRadius.card, style: .continuous).strokeBorder(border, lineWidth: focused || status != .none ? 1.5 : 1))
            .animation(ViadereMotion.quick, value: status)
            .animation(ViadereMotion.quick, value: focused)
            if let hint {
                Text(hint)
                    .font(ViadereType.footnote)
                    .foregroundStyle(status == .invalid ? ViadereColor.danger : ViadereColor.textSecondary)
                    .padding(.horizontal, ViadereSpace.xxs)
            }
        }
    }
}

/// Six digit boxes backed by one hidden text field (so `.oneTimeCode` autofill from Messages works).
public struct ViadereOTPField: View {
    @Binding private var code: String
    private let length: Int
    private let isError: Bool
    @FocusState private var focused: Bool

    public init(code: Binding<String>, length: Int = 6, isError: Bool = false) {
        self._code = code
        self.length = length
        self.isError = isError
    }

    public var body: some View {
        ZStack {
            TextField("", text: $code)
                .keyboardType(.numberPad)
                .textContentType(.oneTimeCode)
                .focused($focused)
                .foregroundStyle(.clear)
                .tint(.clear)
                .frame(width: 1, height: 1)
                .opacity(0.01)
                .accessibilityLabel(Text("One-time code"))
                .accessibilityValue(Text(code.isEmpty ? "Empty" : code))
            HStack(spacing: ViadereSpace.xs) {
                ForEach(0..<length, id: \.self) { index in
                    let characters = Array(code)
                    let digit = index < characters.count ? String(characters[index]) : ""
                    let isActive = focused && index == min(code.count, length - 1)
                    Text(digit)
                        .font(.system(size: 26, weight: .medium, design: .monospaced))
                        .foregroundStyle(ViadereColor.textPrimary)
                        .frame(maxWidth: .infinity, minHeight: 56)
                        .background(RoundedRectangle(cornerRadius: ViadereRadius.control, style: .continuous).fill(ViadereColor.surface))
                        .overlay(
                            RoundedRectangle(cornerRadius: ViadereRadius.control, style: .continuous)
                                .strokeBorder(isError ? ViadereColor.danger : (isActive ? ViadereColor.accent : ViadereColor.hairline),
                                              lineWidth: isActive || isError ? 1.5 : 1)
                        )
                }
            }
            .contentShape(Rectangle())
            .onTapGesture { focused = true }
            .accessibilityHidden(true)
        }
        .onAppear { focused = true }
    }
}

// MARK: - Motion

/// The ribbon mark drawing itself in, once. Honors Reduce Motion (appears immediately).
public struct ViadereAnimatedMark: View {
    private let height: CGFloat
    @State private var reveal: CGFloat = 0
    @State private var opacity: Double = 0
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    public init(height: CGFloat = 96) { self.height = height }

    public var body: some View {
        ViadereMark()
            .frame(height: height)
            .mask(alignment: .leading) {
                GeometryReader { proxy in
                    Rectangle().frame(width: proxy.size.width * reveal)
                }
            }
            .opacity(opacity)
            .onAppear {
                if reduceMotion {
                    reveal = 1
                    opacity = 1
                } else {
                    withAnimation(.easeOut(duration: 0.5)) { opacity = 1 }
                    withAnimation(.easeInOut(duration: 1.3)) { reveal = 1 }
                }
            }
    }
}

/// Quiet loading indicator: the mark breathing.
public struct ViadereLoading: View {
    private let height: CGFloat
    @State private var pulse = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    public init(height: CGFloat = 28) { self.height = height }

    public var body: some View {
        ViadereMark.monochrome(ViadereColor.textTertiary)
            .frame(height: height)
            .opacity(reduceMotion ? 0.6 : (pulse ? 0.9 : 0.35))
            .onAppear {
                guard !reduceMotion else { return }
                withAnimation(.easeInOut(duration: 1.1).repeatForever(autoreverses: true)) { pulse = true }
            }
            .accessibilityLabel(Text("Loading"))
    }
}

// MARK: - Rows & lists

/// A flat list container: surface card with hairline-separated rows, no stock List chrome.
public struct ViadereRowGroup<Content: View>: View {
    private let content: Content
    public init(@ViewBuilder content: () -> Content) { self.content = content() }

    public var body: some View {
        VStack(spacing: 0) { content }
            .padding(.horizontal, ViadereSpace.m)
            .frame(maxWidth: .infinity, alignment: .leading)
            .viadereSurface()
    }
}

/// A label/value line used in detail tables.
public struct ViadereValueRow: View {
    private let label: String
    private let value: String
    private let emphasized: Bool

    public init(_ label: String, _ value: String, emphasized: Bool = false) {
        self.label = label
        self.value = value
        self.emphasized = emphasized
    }

    public var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: ViadereSpace.m) {
            Text(label).foregroundStyle(ViadereColor.textSecondary)
            Spacer(minLength: ViadereSpace.s)
            Text(value)
                .font(emphasized ? ViadereType.subhead.weight(.semibold) : ViadereType.subhead)
                .foregroundStyle(ViadereColor.textPrimary)
                .multilineTextAlignment(.trailing)
        }
        .font(ViadereType.subhead)
        .padding(.vertical, 11)
        .accessibilityElement(children: .combine)
    }
}

/// Full-screen backdrop for focused flows.
public struct ViadereFlowScreen<Content: View>: View {
    private let content: Content
    public init(@ViewBuilder content: () -> Content) { self.content = content() }

    public var body: some View {
        content
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            .viadereScreenBackground()
    }
}

#if DEBUG
#Preview("Components") {
    ScrollView {
        VStack(alignment: .leading, spacing: ViadereSpace.l) {
            ViadereHeader("Home", subtitle: "Nothing needs you right now") {
                ViadereIconButton(systemName: "plus", label: "Connect") {}
            }
            ViadereFlowLayout {
                ViadereChip("Tue 9:00") {}
                ViadereChip("Wed 2:30", isSelected: true) {}
                ViadereChip("Fri 11:15") {}
            }
            ViadereNotice("Screen recording is on. Approvals are paused.", kind: .warning)
            HStack {
                ViadereAvatar(name: "Harbor Bank", isVerified: true)
                ViadereCountdownRing(progress: 0.6, label: "4:32", spokenLabel: "Expires in 4:32")
            }
            ViadereEntryField(placeholder: "@handle, code or name", text: .constant("AF-23"), status: .none, hint: "2 more characters", monospaced: true)
            ViadereOTPField(code: .constant("123"))
        }
        .padding(ViadereSpace.screen)
    }
    .viadereScreenBackground()
}
#endif
