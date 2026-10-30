//
//  ViadereOrganizationComponents.swift
//  Organization chrome (WP-1.3): the business context bar, the "Showing {business}" banner, business cards, filter bars and the
//  search field. Hand-drawn from the tokens (charcoal / ivory / champagne), no stock navigation or segmented controls, no shield imagery.
//  iPhone only: the watch, widget and extension targets that share this folder never show the Organization views.
//

#if os(iOS)
import SwiftUI

// MARK: - Context bar

/// The top bar of every primary destination: the single business selector (All by default), Add business (+) and the account entry
/// point (Settings is secondary, never a tab).
///
/// Accessibility: the selector is **one adjustable element**. VoiceOver reads "Business, Showing all businesses" (or "Showing {name}");
/// swipe up or down moves through All and the businesses, double-tap opens the full list. At accessibility text sizes the bar stacks so the
/// selector keeps the full width and nothing truncates into "…".
public struct ViadereContextBar: View {
    private let title: String
    private let accessibilityValue: String
    private let isFiltered: Bool
    private let openSelector: () -> Void
    private let adjust: (Int) -> Void
    private let add: () -> Void
    private let account: () -> Void
    @Environment(\.dynamicTypeSize) private var typeSize

    public init(title: String, accessibilityValue: String, isFiltered: Bool, openSelector: @escaping () -> Void, adjust: @escaping (Int) -> Void,
                add: @escaping () -> Void, account: @escaping () -> Void) {
        self.title = title
        self.accessibilityValue = accessibilityValue
        self.isFiltered = isFiltered
        self.openSelector = openSelector
        self.adjust = adjust
        self.add = add
        self.account = account
    }

    public var body: some View {
        Group {
            if typeSize.isAccessibilitySize {
                VStack(alignment: .leading, spacing: ViadereSpace.s) {
                    selector
                    HStack(spacing: ViadereSpace.s) {
                        Spacer(minLength: 0)
                        addButton
                        accountButton
                    }
                }
            } else {
                HStack(spacing: ViadereSpace.s) {
                    selector
                    Spacer(minLength: ViadereSpace.xs)
                    addButton
                    accountButton
                }
            }
        }
        .padding(.top, ViadereSpace.m)
        .padding(.bottom, ViadereSpace.xs)
    }

    private var selector: some View {
        Button(action: openSelector) {
            HStack(spacing: ViadereSpace.xs) {
                Circle()
                    .fill(isFiltered ? ViadereColor.accent : ViadereColor.textTertiary)
                    .frame(width: 8, height: 8)
                Text(title)
                    .font(ViadereType.headline)
                    .foregroundStyle(ViadereColor.textPrimary)
                    .lineLimit(typeSize.isAccessibilitySize ? 3 : 1)
                    .multilineTextAlignment(.leading)
                Image(systemName: "chevron.down")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(ViadereColor.textSecondary)
            }
            .padding(.horizontal, ViadereSpace.m)
            .frame(minHeight: 44)
            .background(Capsule().fill(isFiltered ? ViadereColor.accentSoft : ViadereColor.surface))
            .overlay(Capsule().strokeBorder(isFiltered ? ViadereColor.accent.opacity(0.35) : ViadereColor.hairline, lineWidth: 1))
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("Business"))
        .accessibilityValue(Text(accessibilityValue))
        .accessibilityHint(Text("Swipe up or down to change. Double-tap for the full list."))
        .accessibilityAddTraits(.isButton)
        .accessibilityAdjustableAction { direction in
            switch direction {
            case .increment: adjust(1)
            case .decrement: adjust(-1)
            @unknown default: break
            }
        }
    }

    private var addButton: some View {
        ViadereIconButton(systemName: "plus", label: "Add business", action: add)
    }

    private var accountButton: some View {
        ViadereIconButton(systemName: "person.crop.circle", label: "Settings", action: account)
    }
}

// MARK: - Temporary context banner

/// "Showing {business}": a push, link or request for another business is on screen; the saved choice is unchanged. One line, champagne
/// edge, an explicit way back. Never red: it informs, it does not alarm.
public struct ViadereContextBanner: View {
    private let businessName: String
    private let backTitle: String
    private let back: () -> Void

    public init(businessName: String, backTitle: String = "Back to all", back: @escaping () -> Void) {
        self.businessName = businessName
        self.backTitle = backTitle
        self.back = back
    }

    public var body: some View {
        HStack(spacing: ViadereSpace.s) {
            Image(systemName: "arrow.uturn.left.circle")
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(ViadereColor.accent)
                .accessibilityHidden(true)
            Text("Showing \(businessName)")
                .font(ViadereType.subhead.weight(.medium))
                .foregroundStyle(ViadereColor.textPrimary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: ViadereSpace.xs)
            Button(backTitle, action: back)
                .buttonStyle(.plain)
                .font(ViadereType.subhead.weight(.semibold))
                .foregroundStyle(ViadereColor.accent)
                .frame(minHeight: 44)
        }
        .padding(.horizontal, ViadereSpace.m)
        .background(RoundedRectangle(cornerRadius: ViadereRadius.control, style: .continuous).fill(ViadereColor.accentSoft))
        .overlay(RoundedRectangle(cornerRadius: ViadereRadius.control, style: .continuous).strokeBorder(ViadereColor.accent.opacity(0.3), lineWidth: 1))
        .accessibilityElement(children: .contain)
    }
}

// MARK: - Business card

/// A connected business in the directory: verified identity first (monogram, name, verified badge), then what is new. Favorites carry a
/// champagne star that is a separate, labelled control.
public struct ViadereBusinessCard: View {
    private let name: String
    private let subtitle: String
    private let isVerified: Bool
    private let isFavorite: Bool
    private let badge: String?
    private let toggleFavorite: (() -> Void)?

    public init(name: String, subtitle: String, isVerified: Bool, isFavorite: Bool = false, badge: String? = nil, toggleFavorite: (() -> Void)? = nil) {
        self.name = name
        self.subtitle = subtitle
        self.isVerified = isVerified
        self.isFavorite = isFavorite
        self.badge = badge
        self.toggleFavorite = toggleFavorite
    }

    public var body: some View {
        HStack(spacing: 14) {
            HStack(spacing: 14) {
                ViadereAvatar(name: name, size: 44, isVerified: isVerified)
                VStack(alignment: .leading, spacing: 2) {
                    Text(name)
                        .font(ViadereType.body.weight(.medium))
                        .foregroundStyle(ViadereColor.textPrimary)
                        .fixedSize(horizontal: false, vertical: true)
                    Text(subtitle)
                        .font(ViadereType.subhead)
                        .foregroundStyle(ViadereColor.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: ViadereSpace.xs)
                if let badge { ViadereBadge(badge, kind: .verified) }
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Text([name, isVerified ? "verified business" : "not verified", subtitle, badge].compactMap { $0 }.joined(separator: ", ")))
            if let toggleFavorite {
                Button(action: toggleFavorite) {
                    Image(systemName: isFavorite ? "star.fill" : "star")
                        .font(.system(size: 17, weight: .medium))
                        .foregroundStyle(isFavorite ? ViadereColor.accent : ViadereColor.textTertiary)
                        .frame(width: 44, height: 44)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel(Text(isFavorite ? "Remove \(name) from favorites" : "Add \(name) to favorites"))
                .accessibilityValue(Text(isFavorite ? "Favorite" : "Not a favorite"))
            }
        }
        .padding(.vertical, ViadereSpace.s)
        .frame(minHeight: 64)
        .contentShape(Rectangle())
    }
}

// MARK: - Filter bar

/// A horizontal row of filter chips. Each chip says in text whether it is selected ("Selected"), not only by color, and the bar is one
/// labelled container so VoiceOver users know where the filters start and end.
public struct ViadereFilterBar<Value: Hashable>: View {
    public struct Option: Identifiable {
        public var id: Value { value }
        public let value: Value
        public let title: String
        public let count: Int?
        public init(_ value: Value, _ title: String, count: Int? = nil) {
            self.value = value
            self.title = title
            self.count = count
        }
    }

    @Binding private var selection: Value
    private let options: [Option]
    private let label: String

    public init(_ label: String = "Filters", selection: Binding<Value>, options: [Option]) {
        self.label = label
        self._selection = selection
        self.options = options
    }

    public var body: some View {
        ScrollView(.horizontal) {
            HStack(spacing: ViadereSpace.xs) {
                ForEach(options) { option in
                    let selected = option.value == selection
                    Button {
                        withAnimation(ViadereMotion.quick) { selection = option.value }
                    } label: {
                        HStack(spacing: 6) {
                            Text(option.title)
                            if let count = option.count, count > 0 {
                                Text("\(count)")
                                    .monospacedDigit()
                                    .foregroundStyle(selected ? ViadereColor.onPrimary.opacity(0.75) : ViadereColor.textSecondary)
                            }
                        }
                        .font(ViadereType.subhead.weight(.medium))
                        .foregroundStyle(selected ? ViadereColor.onPrimary : ViadereColor.textPrimary)
                        .padding(.horizontal, ViadereSpace.m)
                        .frame(minHeight: 44)
                        .background(Capsule().fill(selected ? ViadereColor.primaryFill : ViadereColor.surface))
                        .overlay(Capsule().strokeBorder(ViadereColor.hairline, lineWidth: selected ? 0 : 1))
                        .contentShape(Capsule())
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(Text(option.count.map { "\(option.title), \($0)" } ?? option.title))
                    .accessibilityValue(Text(selected ? "Selected" : ""))
                    .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
                }
            }
            .padding(.vertical, ViadereSpace.xs)
        }
        .scrollIndicators(.hidden)
        .sensoryFeedback(.selection, trigger: selection)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(Text(label))
    }
}

// MARK: - Search field

/// Search over the customer's own data on this device. Hairline field, magnifier, clear button; no stock search bar chrome.
public struct ViadereSearchField: View {
    private let prompt: String
    @Binding private var text: String
    @FocusState private var focused: Bool

    public init(_ prompt: String, text: Binding<String>) {
        self.prompt = prompt
        self._text = text
    }

    public var body: some View {
        HStack(spacing: ViadereSpace.xs) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(ViadereColor.textSecondary)
                .accessibilityHidden(true)
            TextField("", text: $text, prompt: Text(prompt).foregroundStyle(ViadereColor.textTertiary))
                .font(ViadereType.body)
                .foregroundStyle(ViadereColor.textPrimary)
                .tint(ViadereColor.accent)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .submitLabel(.search)
                .focused($focused)
                .accessibilityLabel(Text(prompt))
            if !text.isEmpty {
                Button { text = "" } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 15))
                        .foregroundStyle(ViadereColor.textTertiary)
                        .frame(width: 44, height: 44)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(Text("Clear search"))
            }
        }
        .padding(.leading, ViadereSpace.m)
        .frame(minHeight: 44)
        .background(RoundedRectangle(cornerRadius: ViadereRadius.control, style: .continuous).fill(ViadereColor.surface))
        .overlay(RoundedRectangle(cornerRadius: ViadereRadius.control, style: .continuous)
            .strokeBorder(focused ? ViadereColor.accent.opacity(0.6) : ViadereColor.hairline, lineWidth: 1))
    }
}
#endif
