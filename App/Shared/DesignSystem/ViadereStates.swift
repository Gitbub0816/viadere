import SwiftUI

// Viadere design system — screen states and Reduce Motion helpers.
//
// What a list screen shows before it has anything (placeholder rows), when loading failed (the reason and a way to try again) and when a
// search finds nothing; plus the two helpers every explicit animation in a screen goes through, so nothing moves when Reduce Motion is on.
// Same rules as the rest of the system: theme roles only, hairlines, one calm sentence, no stock spinner.

// MARK: - Reduce Motion

/// `withAnimation` that honors Reduce Motion: the change is applied at once, without animation, when `reduceMotion` is true.
///
///     @Environment(\.accessibilityReduceMotion) private var reduceMotion
///     Button("Show earlier") { withViadereAnimation(reduceMotion: reduceMotion) { showEarlier.toggle() } }
@discardableResult
public func withViadereAnimation<Result>(_ animation: Animation = ViadereMotion.standard, reduceMotion: Bool,
                                         _ body: () throws -> Result) rethrows -> Result {
    if reduceMotion { return try body() }
    return try withAnimation(animation, body)
}

private struct ViadereAnimationModifier<Value: Equatable>: ViewModifier {
    let animation: Animation
    let value: Value
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        content.animation(reduceMotion ? nil : animation, value: value)
    }
}

extension View {
    /// `.animation(_:value:)` that honors Reduce Motion (no animation when it is on).
    public func viadereAnimation<Value: Equatable>(_ animation: Animation = ViadereMotion.standard, value: Value) -> some View {
        modifier(ViadereAnimationModifier(animation: animation, value: value))
    }
}

// MARK: - Skeleton

/// Placeholder rows or cards shown while a list loads for the first time, in the shape of what is coming, so the screen does not jump
/// when the answer arrives. They breathe gently; with Reduce Motion they are still. VoiceOver reads one "Loading" element.
public struct ViadereSkeleton: View {
    public enum Layout: Sendable, Equatable {
        /// A row group: a round leading mark and two lines per row, hairline-separated.
        case rows(Int)
        /// Separate cards, each with a short header line and a taller title line.
        case cards(Int)
    }

    private let layout: Layout
    private let label: String
    @State private var pulse = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    /// - Parameters:
    ///   - layout: the shape of the content being loaded.
    ///   - label: what VoiceOver says, for example "Loading your businesses".
    public init(_ layout: Layout = .rows(4), label: String = "Loading") {
        self.layout = layout
        self.label = label
    }

    public var body: some View {
        Group {
            switch layout {
            case .rows(let count):
                ViadereRowGroup {
                    ForEach(0..<max(1, count), id: \.self) { index in
                        row(index)
                        if index < max(1, count) - 1 { ViadereHairline(inset: 50) }
                    }
                }
            case .cards(let count):
                VStack(spacing: ViadereSpace.s) {
                    ForEach(0..<max(1, count), id: \.self) { index in
                        card(index)
                    }
                }
            }
        }
        .opacity(reduceMotion ? 0.8 : (pulse ? 1 : 0.5))
        .onAppear {
            guard !reduceMotion else { return }
            withAnimation(.easeInOut(duration: 1.1).repeatForever(autoreverses: true)) { pulse = true }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(label))
    }

    private func bar(width: CGFloat, height: CGFloat = 10) -> some View {
        Capsule().fill(ViadereColor.track).frame(width: width, height: height)
    }

    private func row(_ index: Int) -> some View {
        HStack(spacing: 14) {
            Circle().fill(ViadereColor.track).frame(width: 36, height: 36)
            VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                bar(width: index.isMultiple(of: 2) ? 150 : 118, height: 11)
                bar(width: index.isMultiple(of: 2) ? 96 : 132, height: 9)
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, ViadereSpace.s)
        .frame(minHeight: 60)
    }

    private func card(_ index: Int) -> some View {
        VStack(alignment: .leading, spacing: ViadereSpace.s) {
            HStack(spacing: ViadereSpace.s) {
                Circle().fill(ViadereColor.track).frame(width: 36, height: 36)
                VStack(alignment: .leading, spacing: 6) {
                    bar(width: 120, height: 10)
                    bar(width: 72, height: 8)
                }
                Spacer(minLength: 0)
            }
            bar(width: index.isMultiple(of: 2) ? 210 : 170, height: 16)
            bar(width: 80, height: 10)
        }
        .padding(ViadereSpace.l)
        .frame(maxWidth: .infinity, alignment: .leading)
        .viadereSurface()
    }
}

// MARK: - Error state

/// A first load that failed: what went wrong, in the screen's own sentence, and one way to try again. Use it only when there is nothing
/// to show; when content is already on screen, keep the content and say it in a `ViadereNotice`.
public struct ViadereErrorState: View {
    private let title: String
    private let message: String
    private let retryTitle: String
    private let retry: (() async -> Void)?
    @State private var retrying = false

    /// - Parameters:
    ///   - title: a short headline ("Couldn't load your businesses").
    ///   - message: the view model's error sentence.
    ///   - retry: runs when the person taps the button; the button is disabled, and reads "Trying…", until it returns.
    public init(_ title: String, message: String, retryTitle: String = "Try again", retry: (() async -> Void)? = nil) {
        self.title = title
        self.message = message
        self.retryTitle = retryTitle
        self.retry = retry
    }

    public var body: some View {
        VStack(spacing: ViadereSpace.s) {
            Image(systemName: "exclamationmark.circle")
                .font(.system(size: 30, weight: .light))
                .foregroundStyle(ViadereColor.warning)
                .padding(.bottom, ViadereSpace.xs)
                .accessibilityHidden(true)
            Text(title)
                .font(ViadereType.title)
                .foregroundStyle(ViadereColor.textPrimary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            Text(message)
                .font(ViadereType.body)
                .foregroundStyle(ViadereColor.textSecondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 300)
            if let retry {
                Button(retrying ? "Trying\u{2026}" : retryTitle) {
                    guard !retrying else { return }
                    retrying = true
                    Task {
                        await retry()
                        retrying = false
                    }
                }
                .buttonStyle(.viadere(.secondary, fullWidth: false))
                .disabled(retrying)
                .padding(.top, ViadereSpace.s)
            }
        }
        .padding(ViadereSpace.xl)
        .frame(maxWidth: .infinity)
    }
}

// MARK: - No results

/// A search that found nothing: the sentence, and a way to clear the search. Smaller than an empty state; it sits where the rows were.
public struct ViadereNoResults: View {
    private let text: String
    private let clear: (() -> Void)?

    /// - Parameters:
    ///   - text: for example "No business matches “harbor”."
    ///   - clear: empties the search field; omit when the search cannot be cleared from here.
    public init(_ text: String, clear: (() -> Void)? = nil) {
        self.text = text
        self.clear = clear
    }

    public var body: some View {
        VStack(spacing: ViadereSpace.xs) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 22, weight: .light))
                .foregroundStyle(ViadereColor.textTertiary)
                .padding(.bottom, ViadereSpace.xxs)
                .accessibilityHidden(true)
            Text(text)
                .font(ViadereType.body)
                .foregroundStyle(ViadereColor.textSecondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            if let clear {
                Button("Clear search", action: clear)
                    .buttonStyle(.viadere(.quiet, fullWidth: false))
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, ViadereSpace.l)
    }
}

// MARK: - Local toast

private struct ViadereToastHost: ViewModifier {
    @Binding var text: String?
    let duration: Double
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        content
            .overlay(alignment: .bottom) {
                if let text {
                    ViadereToast(text)
                        .transition(reduceMotion ? .opacity : .move(edge: .bottom).combined(with: .opacity))
                        .task(id: text) {
                            AccessibilityNotification.Announcement(text).post()
                            try? await Task.sleep(for: .seconds(duration))
                            self.text = nil
                        }
                }
            }
            .animation(reduceMotion ? nil : ViadereMotion.standard, value: text)
            .sensoryFeedback(trigger: text) { _, now in
                guard now != nil else { return nil }
                return .impact(weight: .light)
            }
    }
}

extension View {
    /// Shows `text` as a toast at the bottom of this view for a few seconds, with one light haptic, and tells VoiceOver. For sheets and
    /// pushed screens that confirm a small action themselves (copy, save); the tabs use the app-wide toast instead.
    public func viadereToast(_ text: Binding<String?>, duration: Double = 2.5) -> some View {
        modifier(ViadereToastHost(text: text, duration: duration))
    }
}

#if DEBUG
#Preview("States") {
    ScrollView {
        VStack(alignment: .leading, spacing: ViadereSpace.l) {
            ViadereSkeleton(.cards(1))
            ViadereSkeleton(.rows(3))
            ViadereErrorState("Couldn't load your businesses", message: "You're offline. Try again when you're connected.") {}
            ViadereNoResults("No business matches \u{201C}harbor\u{201D}.") {}
        }
        .padding(ViadereSpace.screen)
    }
    .viadereScreenBackground()
}
#endif
