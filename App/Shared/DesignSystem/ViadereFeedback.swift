import SwiftUI

// Viadere design system — outcomes and motion.
//
// How a screen answers the person: a drawn outcome mark with one haptic, a staggered entrance for lists, and a press response for
// tappable cards. Everything here follows the brand guide's motion rule: short ease-outs and critically damped springs, subtle haptics,
// and nothing moves when Reduce Motion is on (the final state simply appears).

// MARK: - Outcome

/// The end of a flow, said once: a ring that draws itself around a check, a stop or a caution mark, and the flow's own sentence.
///
/// Use it instead of a bare line of text when something finished (approved, denied, expired, could not be verified). The haptic matches
/// the kind and fires once when the outcome appears. VoiceOver reads it as one element and is told when it appears.
public struct ViadereOutcome: View {
    public enum Kind: Sendable, Equatable {
        /// It went through (approved, connected, verified).
        case success
        /// The person said no, or it ended quietly (denied, closed). Not an error.
        case neutral
        /// It could not go through (expired, offline, stopped, could not be verified).
        case caution
    }

    private let kind: Kind
    private let text: String
    private let detail: String?
    @State private var drawn = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    /// - Parameters:
    ///   - text: what happened, in the flow's own approved copy (one or two sentences).
    ///   - detail: an optional quieter line underneath.
    public init(_ kind: Kind, _ text: String, detail: String? = nil) {
        self.kind = kind
        self.text = text
        self.detail = detail
    }

    private var tint: Color {
        switch kind {
        case .success: ViadereColor.success
        case .neutral: ViadereColor.textSecondary
        case .caution: ViadereColor.warning
        }
    }

    public var body: some View {
        VStack(spacing: ViadereSpace.m) {
            ZStack {
                Circle().stroke(ViadereColor.hairline, lineWidth: 2)
                Circle()
                    .trim(from: 0, to: drawn ? 1 : 0)
                    .stroke(tint, style: StrokeStyle(lineWidth: 2, lineCap: .round))
                    .rotationEffect(.degrees(-90))
                ViadereOutcomeGlyph(kind: kind)
                    .trim(from: 0, to: drawn ? 1 : 0)
                    .stroke(tint, style: StrokeStyle(lineWidth: 2.5, lineCap: .round, lineJoin: .round))
                    .padding(20)
            }
            .frame(width: 72, height: 72)
            .accessibilityHidden(true)
            VStack(spacing: ViadereSpace.xs) {
                Text(text)
                    .font(ViadereType.headline)
                    .foregroundStyle(ViadereColor.textPrimary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                if let detail {
                    Text(detail)
                        .font(ViadereType.subhead)
                        .foregroundStyle(ViadereColor.textSecondary)
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .opacity(drawn ? 1 : 0)
            .offset(y: drawn || reduceMotion ? 0 : 6)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, ViadereSpace.l)
        .accessibilityElement(children: .combine)
        .sensoryFeedback(trigger: drawn) { _, now in
            guard now else { return nil }
            switch kind {
            case .success: return .success
            case .neutral: return .impact(weight: .light)
            case .caution: return .warning
            }
        }
        .onAppear {
            if reduceMotion {
                drawn = true
            } else {
                withAnimation(.easeOut(duration: 0.45)) { drawn = true }
            }
            AccessibilityNotification.Announcement([text, detail].compactMap { $0 }.joined(separator: " ")).post()
        }
    }
}

/// The mark inside the ring: a check, a short bar, or an exclamation stroke with its dot.
private struct ViadereOutcomeGlyph: Shape {
    let kind: ViadereOutcome.Kind

    func path(in rect: CGRect) -> Path {
        var path = Path()
        switch kind {
        case .success:
            path.move(to: CGPoint(x: rect.minX, y: rect.midY + rect.height * 0.05))
            path.addLine(to: CGPoint(x: rect.minX + rect.width * 0.36, y: rect.maxY - rect.height * 0.12))
            path.addLine(to: CGPoint(x: rect.maxX, y: rect.minY + rect.height * 0.14))
        case .neutral:
            path.move(to: CGPoint(x: rect.minX + rect.width * 0.1, y: rect.midY))
            path.addLine(to: CGPoint(x: rect.maxX - rect.width * 0.1, y: rect.midY))
        case .caution:
            path.move(to: CGPoint(x: rect.midX, y: rect.minY))
            path.addLine(to: CGPoint(x: rect.midX, y: rect.minY + rect.height * 0.62))
            path.move(to: CGPoint(x: rect.midX, y: rect.maxY - 0.5))
            path.addLine(to: CGPoint(x: rect.midX, y: rect.maxY))
        }
        return path
    }
}

// MARK: - Loading with a caption

/// The breathing mark, centered, with a line saying what is being waited for. For sheets that fetch before they can show anything.
public struct ViadereLoadingState: View {
    private let caption: String

    public init(_ caption: String) { self.caption = caption }

    public var body: some View {
        VStack(spacing: ViadereSpace.m) {
            ViadereLoading(height: 32)
            Text(caption)
                .font(ViadereType.subhead)
                .foregroundStyle(ViadereColor.textSecondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, ViadereSpace.xxl)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(Text(caption))
    }
}

// MARK: - Entrance

private struct ViadereEntrance: ViewModifier {
    let index: Int
    @State private var shown = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        content
            .opacity(shown || reduceMotion ? 1 : 0)
            .offset(y: shown || reduceMotion ? 0 : 10)
            .onAppear {
                guard !shown else { return }
                // Only the first screenful is staggered; later rows arrive at once so scrolling never waits on animation.
                withAnimation(ViadereMotion.standard.delay(Double(min(index, 6)) * 0.04)) { shown = true }
            }
    }
}

/// A card that answers a touch: it settles slightly while pressed. For rows and cards that open something.
public struct ViaderePressableStyle: ButtonStyle {
    public init() {}

    public func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.98 : 1)
            .opacity(configuration.isPressed ? 0.92 : 1)
            .animation(ViadereMotion.quick, value: configuration.isPressed)
    }
}

extension ButtonStyle where Self == ViaderePressableStyle {
    public static var viaderePressable: ViaderePressableStyle { ViaderePressableStyle() }
}

extension View {
    /// Rises and fades in when it first appears, `index` steps after its siblings (capped). No movement with Reduce Motion.
    public func viadereEntrance(_ index: Int = 0) -> some View {
        modifier(ViadereEntrance(index: index))
    }
}
