//
//  ViadereControls.swift
//  Settings controls that are not switches (docs/APP-IA.md, "Controls"). Rows and rows of toggles read as a wall: every setting looks the
//  same, nothing says what it does, and most choices are not really on/off. These controls are built from the tokens only (charcoal /
//  ivory / champagne, hairlines, the tight type scale), so a theme drops in without touching them:
//
//   • ViadereChoiceCards   one of a few options, each with a sentence that says what it does (lock-screen details).
//   • ViadereLevelPicker   preset levels with a level meter (Everything / Balanced / Only what matters), plus a "Customize" drill-in.
//   • ViadereChipSet       several independent yes/no items as one tappable group (what a business may contact you about).
//   • ViadereInlineStepper a short ordered range walked with − / + (how long a business stays quiet).
//   • ViadereStateCard     a consequential state with an explicit action button (freeze approvals), never a casual flick.
//   • ViadereSummaryCard   a smart summary of a group ("Well protected · Face ID approvals · App lock on").
//   • ViadereCheckbox      an explicit affirmation ("This is my phone", "I saved my codes").
//   • ViadereFavoriteButton, ViadereSheetHandle  small pieces used across pages and sheets.
//
//  A switch stays only where one binary is genuinely the clearest (App lock, Suggest in AutoFill, a Loop's own yes/no field).
//  iPhone only: the watch, widget and extension targets that share this folder never show settings.
//

#if os(iOS)
import SwiftUI

// MARK: - Selection mark

/// The round mark of a single choice: an empty ring, or a filled charcoal disc with a check.
public struct ViadereSelectionMark: View {
    private let isSelected: Bool
    public init(isSelected: Bool) { self.isSelected = isSelected }

    public var body: some View {
        ZStack {
            Circle()
                .strokeBorder(isSelected ? ViadereColor.primaryFill : ViadereColor.textTertiary, lineWidth: 1.5)
            if isSelected {
                Circle().fill(ViadereColor.primaryFill)
                Image(systemName: "checkmark")
                    .font(.system(size: 11, weight: .bold))
                    .foregroundStyle(ViadereColor.onPrimary)
            }
        }
        .frame(width: 22, height: 22)
        .animation(ViadereMotion.quick, value: isSelected)
        .accessibilityHidden(true)
    }
}

// MARK: - Choice cards

/// One of a few options, each a card with a sentence that says what it does. The selected card warms to champagne and carries the mark.
/// VoiceOver: one labelled group; each card is a button that reads its title, its sentence and "Selected".
public struct ViadereChoiceCards<Value: Hashable>: View {
    public struct Option: Identifiable {
        public var id: Value { value }
        public let value: Value
        public let title: String
        public let detail: String?
        public let symbol: String?
        public init(_ value: Value, _ title: String, detail: String? = nil, symbol: String? = nil) {
            self.value = value
            self.title = title
            self.detail = detail
            self.symbol = symbol
        }
    }

    @Binding private var selection: Value
    private let options: [Option]
    private let label: String
    @Environment(\.isEnabled) private var isEnabled

    public init(_ label: String, selection: Binding<Value>, options: [Option]) {
        self.label = label
        self._selection = selection
        self.options = options
    }

    private var shape: RoundedRectangle { RoundedRectangle(cornerRadius: ViadereRadius.control + 2, style: .continuous) }

    public var body: some View {
        VStack(spacing: ViadereSpace.xs) {
            ForEach(options) { option in
                let selected = option.value == selection
                Button {
                    withAnimation(ViadereMotion.quick) { selection = option.value }
                } label: {
                    HStack(alignment: .top, spacing: ViadereSpace.s) {
                        if let symbol = option.symbol {
                            Image(systemName: symbol)
                                .font(.system(size: 17, weight: .medium))
                                .foregroundStyle(selected ? ViadereColor.accent : ViadereColor.textSecondary)
                                .frame(width: 28, height: 22)
                                .accessibilityHidden(true)
                        }
                        VStack(alignment: .leading, spacing: 2) {
                            Text(option.title)
                                .font(selected ? ViadereType.body.weight(.semibold) : ViadereType.body)
                                .foregroundStyle(ViadereColor.textPrimary)
                            if let detail = option.detail {
                                Text(detail)
                                    .font(ViadereType.footnote)
                                    .foregroundStyle(ViadereColor.textSecondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                        Spacer(minLength: ViadereSpace.xs)
                        ViadereSelectionMark(isSelected: selected)
                    }
                    .multilineTextAlignment(.leading)
                    .padding(ViadereSpace.m)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(shape.fill(selected ? ViadereColor.accentSoft : ViadereColor.surface))
                    .overlay(shape.strokeBorder(selected ? ViadereColor.accent : ViadereColor.hairline, lineWidth: selected ? 1.5 : 1))
                    .contentShape(shape)
                }
                .buttonStyle(.plain)
                .accessibilityElement(children: .combine)
                .accessibilityValue(Text(selected ? "Selected" : ""))
                .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
            }
        }
        .opacity(isEnabled ? 1 : 0.45)
        .sensoryFeedback(.selection, trigger: selection)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(Text(label))
    }
}

// MARK: - Level picker

/// A small level meter: `total` bars of rising height, the first `filled` drawn. Decorative; the title carries the meaning.
public struct ViadereLevelMeter: View {
    private let filled: Int
    private let total: Int
    private let emphasized: Bool

    public init(filled: Int, total: Int = 3, emphasized: Bool = false) {
        self.filled = filled
        self.total = max(total, 1)
        self.emphasized = emphasized
    }

    public var body: some View {
        HStack(alignment: .bottom, spacing: 3) {
            ForEach(0..<total, id: \.self) { index in
                Capsule()
                    .fill(index < filled ? (emphasized ? ViadereColor.accent : ViadereColor.textSecondary) : ViadereColor.track)
                    .frame(width: 5, height: CGFloat(8 + index * 5))
            }
        }
        .frame(height: CGFloat(8 + (total - 1) * 5), alignment: .bottom)
        .accessibilityHidden(true)
    }
}

/// Preset levels side by side, each with a meter (how much gets through) and a short name; the sentence below says what the chosen level
/// does. An optional "Customize" link drills into the detailed choices. One adjustable element for VoiceOver (swipe up or down).
public struct ViadereLevelPicker<Value: Hashable>: View {
    public struct Level: Identifiable {
        public var id: Value { value }
        public let value: Value
        public let title: String
        /// 1…`levels.count`: how much gets through.
        public let intensity: Int
        public init(_ value: Value, _ title: String, intensity: Int) {
            self.value = value
            self.title = title
            self.intensity = intensity
        }
    }

    @Binding private var selection: Value
    private let levels: [Level]
    private let label: String
    private let caption: String?
    private let customizeTitle: String?
    private let customize: (() -> Void)?
    @Environment(\.isEnabled) private var isEnabled

    public init(_ label: String, selection: Binding<Value>, levels: [Level], caption: String? = nil,
                customizeTitle: String? = nil, customize: (() -> Void)? = nil) {
        self.label = label
        self._selection = selection
        self.levels = levels
        self.caption = caption
        self.customizeTitle = customizeTitle
        self.customize = customize
    }

    private var shape: RoundedRectangle { RoundedRectangle(cornerRadius: ViadereRadius.control, style: .continuous) }
    private var maxIntensity: Int { levels.map(\.intensity).max() ?? 3 }
    private var selectedTitle: String { levels.first { $0.value == selection }?.title ?? "" }

    public var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.s) {
            HStack(spacing: ViadereSpace.xs) {
                ForEach(levels) { level in
                    let selected = level.value == selection
                    Button {
                        withAnimation(ViadereMotion.quick) { selection = level.value }
                    } label: {
                        VStack(spacing: ViadereSpace.xs) {
                            ViadereLevelMeter(filled: level.intensity, total: maxIntensity, emphasized: selected)
                            Text(level.title)
                                .font(ViadereType.footnote.weight(selected ? .semibold : .regular))
                                .foregroundStyle(selected ? ViadereColor.textPrimary : ViadereColor.textSecondary)
                                .multilineTextAlignment(.center)
                                .lineLimit(2)
                                .minimumScaleFactor(0.85)
                        }
                        .padding(.vertical, ViadereSpace.s)
                        .padding(.horizontal, ViadereSpace.xxs)
                        .frame(maxWidth: .infinity, minHeight: 76)
                        .background(shape.fill(selected ? ViadereColor.accentSoft : ViadereColor.surface))
                        .overlay(shape.strokeBorder(selected ? ViadereColor.accent : ViadereColor.hairline, lineWidth: selected ? 1.5 : 1))
                        .contentShape(shape)
                    }
                    .buttonStyle(.plain)
                }
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Text(label))
            .accessibilityValue(Text(selectedTitle))
            .accessibilityHint(Text("Swipe up or down to change."))
            .accessibilityAdjustableAction { direction in
                guard let index = levels.firstIndex(where: { $0.value == selection }) else { return }
                switch direction {
                case .increment: if index + 1 < levels.count { selection = levels[index + 1].value }
                case .decrement: if index > 0 { selection = levels[index - 1].value }
                @unknown default: break
                }
            }
            if let caption {
                Text(caption)
                    .font(ViadereType.footnote)
                    .foregroundStyle(ViadereColor.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .contentTransition(.opacity)
            }
            if let customizeTitle, let customize {
                Button(action: customize) {
                    HStack(spacing: 4) {
                        Text(customizeTitle)
                        Image(systemName: "chevron.right").font(.system(size: 11, weight: .semibold))
                    }
                    .font(ViadereType.footnote.weight(.medium))
                    .foregroundStyle(ViadereColor.accent)
                    .frame(minHeight: 44)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
        .opacity(isEnabled ? 1 : 0.45)
        .sensoryFeedback(.selection, trigger: selection)
    }
}

// MARK: - Chip set

/// Several independent yes/no items as one group of chips: on chips are charcoal with a check, off chips are quiet with a plus, locked
/// chips ("Always on") carry a lock and do nothing. Replaces a column of switches; the group's summary line goes below it.
public struct ViadereChipSet<Value: Hashable>: View {
    public struct Chip: Identifiable {
        public var id: Value { value }
        public let value: Value
        public let title: String
        /// Always on (or always off): shown, never changed here.
        public let isLocked: Bool
        public let isEnabled: Bool
        public let hint: String?
        public init(_ value: Value, _ title: String, isLocked: Bool = false, isEnabled: Bool = true, hint: String? = nil) {
            self.value = value
            self.title = title
            self.isLocked = isLocked
            self.isEnabled = isEnabled
            self.hint = hint
        }
    }

    private let chips: [Chip]
    private let label: String
    private let isSelected: (Value) -> Bool
    private let toggle: (Value) -> Void

    public init(_ label: String, chips: [Chip], isSelected: @escaping (Value) -> Bool, toggle: @escaping (Value) -> Void) {
        self.label = label
        self.chips = chips
        self.isSelected = isSelected
        self.toggle = toggle
    }

    public var body: some View {
        ViadereFlowLayout(spacing: ViadereSpace.xs) {
            ForEach(chips) { chip in
                ViadereToggleChip(chip.title, isOn: isSelected(chip.value), isLocked: chip.isLocked, hint: chip.hint) {
                    toggle(chip.value)
                }
                .disabled(!chip.isEnabled)
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(Text(label))
    }
}

/// One chip of a `ViadereChipSet`.
public struct ViadereToggleChip: View {
    private let title: String
    private let isOn: Bool
    private let isLocked: Bool
    private let hint: String?
    private let action: () -> Void
    @Environment(\.isEnabled) private var isEnabled

    public init(_ title: String, isOn: Bool, isLocked: Bool = false, hint: String? = nil, action: @escaping () -> Void) {
        self.title = title
        self.isOn = isOn
        self.isLocked = isLocked
        self.hint = hint
        self.action = action
    }

    private var symbol: String { isLocked ? "lock.fill" : (isOn ? "checkmark" : "plus") }

    public var body: some View {
        Button {
            guard !isLocked else { return }
            action()
        } label: {
            HStack(spacing: 6) {
                Image(systemName: symbol)
                    .font(.system(size: isLocked ? 10 : 12, weight: .bold))
                    .accessibilityHidden(true)
                Text(title)
                    .font(ViadereType.subhead.weight(.medium))
                    .lineLimit(1)
            }
            .foregroundStyle(foreground)
            .padding(.horizontal, ViadereSpace.m - 2)
            .frame(minHeight: 40)
            .background(Capsule().fill(fill))
            .overlay(Capsule().strokeBorder(ViadereColor.hairline, lineWidth: isOn && !isLocked ? 0 : 1))
            .padding(.vertical, 2)
            .contentShape(Capsule())
            .opacity(isEnabled ? 1 : 0.4)
            .animation(ViadereMotion.quick, value: isOn)
        }
        .buttonStyle(.plain)
        .sensoryFeedback(.selection, trigger: isOn)
        .accessibilityLabel(Text(title))
        .accessibilityValue(Text(isLocked ? "Always on" : (isOn ? "On" : "Off")))
        .accessibilityHint(Text(hint ?? (isLocked ? "" : "Double-tap to turn \(isOn ? "off" : "on").")))
        .accessibilityAddTraits(isOn ? [.isButton, .isSelected] : .isButton)
    }

    private var foreground: Color {
        if isLocked { return ViadereColor.textSecondary }
        return isOn ? ViadereColor.onPrimary : ViadereColor.textPrimary
    }

    private var fill: Color {
        if isLocked { return ViadereColor.track }
        return isOn ? ViadereColor.primaryFill : ViadereColor.surface
    }
}

// MARK: - Inline stepper

/// A short ordered range walked with − and + ("For 1 hour" … "Until I change it"), inline in a row. One adjustable element for VoiceOver.
public struct ViadereInlineStepper<Value: Hashable>: View {
    private let title: String
    @Binding private var value: Value
    private let values: [Value]
    private let text: (Value) -> String

    public init(_ title: String, value: Binding<Value>, values: [Value], text: @escaping (Value) -> String) {
        self.title = title
        self._value = value
        self.values = values
        self.text = text
    }

    private var index: Int { values.firstIndex(of: value) ?? 0 }

    public var body: some View {
        HStack(spacing: ViadereSpace.s) {
            Text(title)
                .font(ViadereType.body)
                .foregroundStyle(ViadereColor.textPrimary)
            Spacer(minLength: ViadereSpace.xs)
            HStack(spacing: 0) {
                step("minus", by: -1).disabled(index == 0)
                Text(text(value))
                    .font(ViadereType.subhead.weight(.semibold))
                    .foregroundStyle(ViadereColor.textPrimary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
                    .frame(minWidth: 104)
                    .contentTransition(.opacity)
                step("plus", by: 1).disabled(index >= values.count - 1)
            }
            .background(Capsule().fill(ViadereColor.track))
        }
        .frame(minHeight: 44)
        .sensoryFeedback(.selection, trigger: value)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(title))
        .accessibilityValue(Text(text(value)))
        .accessibilityAdjustableAction { direction in
            switch direction {
            case .increment: move(1)
            case .decrement: move(-1)
            @unknown default: break
            }
        }
    }

    private func step(_ symbol: String, by delta: Int) -> some View {
        StepButton(symbol: symbol) { move(delta) }
    }

    private func move(_ delta: Int) {
        let next = min(max(index + delta, 0), values.count - 1)
        guard values.indices.contains(next) else { return }
        withAnimation(ViadereMotion.quick) { value = values[next] }
    }

    private struct StepButton: View {
        let symbol: String
        let action: () -> Void
        @Environment(\.isEnabled) private var isEnabled

        var body: some View {
            Button(action: action) {
                Image(systemName: symbol)
                    .font(.system(size: 13, weight: .bold))
                    .foregroundStyle(isEnabled ? ViadereColor.textPrimary : ViadereColor.textTertiary)
                    .frame(width: 40, height: 36)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
        }
    }
}

// MARK: - State card

/// A consequential state (approvals frozen, a business allowed to send its own requests) with the current state as a badge and one explicit
/// action button. Deliberate by design: a card and a named action, never a switch that a stray tap flips.
public struct ViadereStateCard: View {
    private let title: String
    private let detail: String
    private let state: String
    private let stateKind: ViadereBadge.Kind
    private let actionTitle: String
    private let actionKind: ViadereButtonStyle.Kind
    private let action: () -> Void

    public init(_ title: String, detail: String, state: String, stateKind: ViadereBadge.Kind = .neutral, actionTitle: String,
                actionKind: ViadereButtonStyle.Kind = .secondary, action: @escaping () -> Void) {
        self.title = title
        self.detail = detail
        self.state = state
        self.stateKind = stateKind
        self.actionTitle = actionTitle
        self.actionKind = actionKind
        self.action = action
    }

    public var body: some View {
        ViadereCard(padding: ViadereSpace.m) {
            VStack(alignment: .leading, spacing: ViadereSpace.s) {
                HStack(alignment: .firstTextBaseline, spacing: ViadereSpace.s) {
                    Text(title)
                        .font(ViadereType.headline)
                        .foregroundStyle(ViadereColor.textPrimary)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: ViadereSpace.xs)
                    ViadereBadge(state, kind: stateKind)
                }
                .accessibilityElement(children: .combine)
                Text(detail)
                    .font(ViadereType.footnote)
                    .foregroundStyle(ViadereColor.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                Button(actionTitle, action: action)
                    .buttonStyle(.viadere(actionKind, fullWidth: false))
            }
        }
    }
}

// MARK: - Summary card

/// A group's state in one glance: a status dot, a short headline and the facts behind it. Used as the label of a button that opens the
/// group, or on its own.
public struct ViadereSummaryCard: View {
    public enum Status { case positive, neutral, attention }

    private let symbol: String
    private let headline: String
    private let detail: String
    private let status: Status
    private let showsChevron: Bool

    public init(symbol: String, headline: String, detail: String, status: Status = .neutral, showsChevron: Bool = false) {
        self.symbol = symbol
        self.headline = headline
        self.detail = detail
        self.status = status
        self.showsChevron = showsChevron
    }

    private var tint: Color {
        switch status {
        case .positive: ViadereColor.success
        case .neutral: ViadereColor.accent
        case .attention: ViadereColor.danger
        }
    }

    public var body: some View {
        HStack(alignment: .center, spacing: ViadereSpace.m) {
            ZStack(alignment: .topTrailing) {
                ViadereIconTile(systemName: symbol)
                Circle()
                    .fill(tint)
                    .frame(width: 10, height: 10)
                    .overlay(Circle().strokeBorder(ViadereColor.surface, lineWidth: 2))
                    .offset(x: 3, y: -3)
                    .accessibilityHidden(true)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(headline)
                    .font(ViadereType.headline)
                    .foregroundStyle(status == .attention ? ViadereColor.danger : ViadereColor.textPrimary)
                Text(detail)
                    .font(ViadereType.footnote)
                    .foregroundStyle(ViadereColor.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: ViadereSpace.xs)
            if showsChevron { ViadereChevron() }
        }
        .padding(ViadereSpace.m)
        .frame(maxWidth: .infinity, alignment: .leading)
        .viadereSurface()
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }
}

// MARK: - Checkbox

/// An explicit affirmation the person makes on purpose ("This is my phone", "I saved my recovery codes"). A square check reads as
/// "I agree to this", which a switch does not.
public struct ViadereCheckbox<Label: View>: View {
    @Binding private var isOn: Bool
    private let label: Label
    @Environment(\.isEnabled) private var isEnabled

    public init(isOn: Binding<Bool>, @ViewBuilder label: () -> Label) {
        self._isOn = isOn
        self.label = label()
    }

    public var body: some View {
        Button {
            withAnimation(ViadereMotion.quick) { isOn.toggle() }
        } label: {
            HStack(alignment: .top, spacing: ViadereSpace.s) {
                let shape = RoundedRectangle(cornerRadius: 6, style: .continuous)
                ZStack {
                    shape.fill(isOn ? ViadereColor.primaryFill : ViadereColor.surface)
                    shape.strokeBorder(isOn ? ViadereColor.primaryFill : ViadereColor.textTertiary, lineWidth: 1.5)
                    if isOn {
                        Image(systemName: "checkmark")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundStyle(ViadereColor.onPrimary)
                    }
                }
                .frame(width: 24, height: 24)
                .padding(.top, 1)
                label
                    .font(ViadereType.body)
                    .foregroundStyle(ViadereColor.textPrimary)
                    .multilineTextAlignment(.leading)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
            }
            .frame(minHeight: 44)
            .contentShape(Rectangle())
            .opacity(isEnabled ? 1 : 0.4)
        }
        .buttonStyle(.plain)
        .sensoryFeedback(.selection, trigger: isOn)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isToggle)
        .accessibilityValue(Text(isOn ? "Checked" : "Not checked"))
    }
}

// MARK: - Favorite

/// A star that marks a business as a favorite (shown first in Businesses and the selector).
public struct ViadereFavoriteButton: View {
    private let isFavorite: Bool
    private let name: String
    private let action: () -> Void

    public init(isFavorite: Bool, name: String, action: @escaping () -> Void) {
        self.isFavorite = isFavorite
        self.name = name
        self.action = action
    }

    public var body: some View {
        Button(action: action) {
            Image(systemName: isFavorite ? "star.fill" : "star")
                .font(.system(size: 17, weight: .medium))
                .foregroundStyle(isFavorite ? ViadereColor.accent : ViadereColor.textTertiary)
                .frame(width: 44, height: 44)
                .contentShape(Rectangle())
                .animation(ViadereMotion.quick, value: isFavorite)
        }
        .buttonStyle(.plain)
        .sensoryFeedback(.selection, trigger: isFavorite)
        .accessibilityLabel(Text(isFavorite ? "Remove \(name) from favorites" : "Add \(name) to favorites"))
        .accessibilityAddTraits(isFavorite ? [.isButton, .isSelected] : .isButton)
    }
}

// MARK: - Quick action

/// A round labelled action on a business page (Message, Rewards, Settings): icon in a 52-pt disc, a one-word caption under it.
public struct ViadereQuickAction: View {
    private let title: String
    private let symbol: String
    private let action: () -> Void

    public init(_ title: String, symbol: String, action: @escaping () -> Void) {
        self.title = title
        self.symbol = symbol
        self.action = action
    }

    public var body: some View {
        Button(action: action) {
            VStack(spacing: 6) {
                Image(systemName: symbol)
                    .font(.system(size: 18, weight: .medium))
                    .foregroundStyle(ViadereColor.textPrimary)
                    .frame(width: 52, height: 52)
                    .background(Circle().fill(ViadereColor.surface))
                    .overlay(Circle().strokeBorder(ViadereColor.hairline, lineWidth: 1))
                Text(title)
                    .font(ViadereType.caption)
                    .foregroundStyle(ViadereColor.textSecondary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
            }
            .frame(maxWidth: .infinity)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(Text(title))
        .accessibilityAddTraits(.isButton)
    }
}

// MARK: - Sheet handle

/// The grabber at the top of a sheet, with an optional explicit Close on the right. Sheets close with a downward pull; a sheet that must not
/// be pulled away by accident (an answer in progress) shows Close instead and asks before leaving.
public struct ViadereSheetHandle: View {
    private let closeTitle: String
    private let onClose: (() -> Void)?

    public init(closeTitle: String = "Close", onClose: (() -> Void)? = nil) {
        self.closeTitle = closeTitle
        self.onClose = onClose
    }

    public var body: some View {
        ZStack(alignment: .top) {
            ViadereGrabber()
            if let onClose {
                HStack {
                    Spacer()
                    Button(closeTitle, action: onClose)
                        .buttonStyle(.viadere(.quiet, fullWidth: false))
                }
                .padding(.horizontal, ViadereSpace.s)
            }
        }
    }
}

#if DEBUG
private struct ControlsPreview: View {
    @State private var choice = 0
    @State private var level = 2
    @State private var chips: Set<String> = ["Orders"]
    @State private var step = 1
    @State private var agreed = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: ViadereSpace.l) {
                ViadereSummaryCard(symbol: "faceid", headline: "Well protected", detail: "Face ID approvals · App lock on · 2 trusted devices",
                                   status: .positive, showsChevron: true)
                ViadereChoiceCards("Lock screen", selection: $choice, options: [
                    .init(0, "Who's asking", detail: "Only the business name.", symbol: "eye.slash"),
                    .init(1, "Who, amount and place", detail: "Faster to decide, visible to anyone holding your phone.", symbol: "eye"),
                ])
                ViadereLevelPicker("Interruptions", selection: $level, levels: [
                    .init(3, "Everything", intensity: 3), .init(2, "Balanced", intensity: 2), .init(1, "Only what matters", intensity: 1),
                ], caption: "Offers and rewards arrive quietly.", customizeTitle: "Customize") {}
                ViadereChipSet("Contact", chips: [.init("Security", "Security", isLocked: true), .init("Orders", "Orders"), .init("Offers", "Offers")],
                               isSelected: { chips.contains($0) || $0 == "Security" }) { value in
                    if chips.contains(value) { chips.remove(value) } else { chips.insert(value) }
                }
                ViadereInlineStepper("Quiet for", value: $step, values: [0, 1, 2, 3]) { ["1 hour", "1 day", "1 week", "Until I change it"][$0] }
                ViadereStateCard("Freeze approvals", detail: "No business can ask you to approve anything.", state: "Off",
                                 actionTitle: "Freeze approvals") {}
                ViadereCheckbox(isOn: $agreed) { Text("This is my phone") }
            }
            .padding(ViadereSpace.screen)
        }
        .viadereScreenBackground()
    }
}

#Preview("Controls") { ControlsPreview() }
#endif
#endif
