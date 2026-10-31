import ActivityKit
import SwiftUI
import ViadereCore
import ViadereKit
import WidgetKit

/// Live Activity and Dynamic Island for genuinely ongoing events: orders, deliveries, flights, appointments.
/// Content is `LiveActivityStatus` from ViadereCore, so a server status push decodes straight into it.
///
/// Layout (brand: charcoal, ivory, champagne; the via mark is the signature):
/// - compact: the mark on the left, the ETA (a live countdown when it is close) or a status word on the right;
/// - expanded: business and what is happening, a champagne progress line ending in the via dot, and the next step;
/// - Lock Screen: the same hierarchy on the ivory/charcoal card.
/// The wording comes from `LiveActivityPresentation` in ViadereKit (unit-tested); this file only lays it out.
///
/// Decision activities (a pending confirm or choose, docs/SECURITY.md §2.16) are laid out from `LiveDecisionPresentation`: the question,
/// and buttons that run `ViadereDecisionIntent` in the app (which answers through the notification action's signed path and refuses
/// while the phone is locked). Business text appears only after the app enriched the activity on the device; until then, or if that
/// failed, the wording is Viadere's own, and Confirm is never offered without the question.
///
/// Brand Kits (WP-2.7): the only business styling is the accent (`ViadereActivityAttributes.accent`: the kit's `accent` token if the
/// contrast clamp kept it, never for security requests), on the trailing word or countdown, the keyline and the stage dot. Titles,
/// status text, alert colors and the answer buttons stay Viadere's.
struct ViadereLiveActivityWidget: Widget {
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: ViadereActivityAttributes.self) { context in
            Group {
                if case .decision(let decision) = context.state {
                    let presentation = LiveDecisionPresentation(state: decision, businessName: context.attributes.businessName)
                    DecisionLockScreenView(interactionId: context.attributes.interactionId, presentation: presentation, accent: context.attributes.accent)
                        .widgetURL(presentation.openURL)
                } else {
                    LockScreenActivityView(business: context.attributes.businessName,
                                           presentation: LiveActivityPresentation(status: context.state, businessName: context.attributes.businessName),
                                           accent: context.attributes.accent)
                }
            }
            .activityBackgroundTint(ViadereColor.background)
            .activitySystemActionForegroundColor(ViadereColor.textPrimary)
        } dynamicIsland: { context in
            if case .decision(let decision) = context.state {
                return DecisionIsland.make(interactionId: context.attributes.interactionId,
                                           presentation: LiveDecisionPresentation(state: decision, businessName: context.attributes.businessName),
                                           accent: context.attributes.accent)
            }
            let presentation = LiveActivityPresentation(status: context.state, businessName: context.attributes.businessName)
            return DynamicIsland {
                DynamicIslandExpandedRegion(.leading) {
                    ViadereMark(style: .onDark)
                        .frame(height: 24)
                        .padding(.leading, 6)
                        .padding(.top, 2)
                }
                DynamicIslandExpandedRegion(.trailing) {
                    ActivityTrailingText(trailing: presentation.trailing, isAlert: presentation.isAlert, size: 20, accent: context.attributes.accent)
                        .padding(.trailing, 6)
                        .padding(.top, 2)
                }
                DynamicIslandExpandedRegion(.center) {
                    VStack(spacing: 1) {
                        Text(context.attributes.businessName)
                            .font(.system(size: 12, weight: .medium))
                            .foregroundStyle(ViadereColor.textSecondary)
                            .lineLimit(1)
                        Text(presentation.headline)
                            .font(.system(size: 16, weight: .semibold))
                            .foregroundStyle(ViadereColor.textPrimary)
                            .lineLimit(1)
                            .minimumScaleFactor(0.8)
                    }
                }
                DynamicIslandExpandedRegion(.bottom) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(presentation.detail)
                            .font(.system(size: 14, weight: presentation.isAlert ? .semibold : .regular))
                            .foregroundStyle(presentation.isAlert ? ViadereColor.danger : ViadereColor.textPrimary)
                            .lineLimit(2)
                        if let progress = presentation.progress { ViadereProgressBar(progress: progress, height: 4) }
                        if let next = presentation.nextStep {
                            Text(next)
                                .font(.system(size: 12))
                                .foregroundStyle(ViadereColor.textSecondary)
                                .lineLimit(1)
                        }
                    }
                    .padding(.horizontal, 6)
                    .padding(.top, 6)
                }
            } compactLeading: {
                ViadereMark(style: .onDark)
                    .frame(height: 16)
                    .padding(.leading, 2)
            } compactTrailing: {
                ActivityTrailingText(trailing: presentation.trailing, isAlert: presentation.isAlert, size: 13, accent: context.attributes.accent)
                    .frame(maxWidth: 52, alignment: .trailing)
            } minimal: {
                ViadereMark(style: .onDark).frame(height: 14)
            }
            .keylineTint(context.attributes.accent)
        }
    }
}

/// The right-hand slot: a live countdown when the moment is near, otherwise a short status word.
struct ActivityTrailingText: View {
    let trailing: LiveActivityPresentation.Trailing
    let isAlert: Bool
    let size: CGFloat
    var accent: Color = ViadereColor.accent

    var body: some View {
        Group {
            switch trailing {
            case .countdown(let target):
                // `max` keeps the range valid if the moment has just passed while the activity is still on screen.
                Text(timerInterval: Date.now...max(Date.now, target), pauseTime: nil, countsDown: true, showsHours: false)
                    .monospacedDigit()
                    .multilineTextAlignment(.trailing)
            case .text(let word):
                Text(word).lineLimit(1)
            }
        }
        .font(.system(size: size, weight: .semibold, design: .rounded))
        .foregroundStyle(isAlert ? ViadereColor.danger : accent)
    }
}

/// Lock Screen / banner presentation.
struct LockScreenActivityView: View {
    let business: String
    let presentation: LiveActivityPresentation
    var accent: Color = ViadereColor.accent

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                ViadereMark().frame(height: 14)
                Text(business)
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(ViadereColor.textSecondary)
                    .lineLimit(1)
                Spacer(minLength: 8)
                ActivityTrailingText(trailing: presentation.trailing, isAlert: presentation.isAlert, size: 15, accent: accent)
            }
            Text(presentation.headline)
                .font(.system(size: 20, weight: .semibold))
                .foregroundStyle(ViadereColor.textPrimary)
                .lineLimit(2)
            Text(presentation.detail)
                .font(.system(size: 15, weight: presentation.isAlert ? .semibold : .regular))
                .foregroundStyle(presentation.isAlert ? ViadereColor.danger : ViadereColor.textSecondary)
            if let progress = presentation.progress { ViadereProgressBar(progress: progress) }
            if let next = presentation.nextStep {
                Text(next).font(.system(size: 13)).foregroundStyle(ViadereColor.textTertiary)
            }
        }
        .padding(16)
    }
}

// MARK: - Decision activities

/// Dynamic Island for a pending decision: the mark and "Decide" when compact; the question and its answers when expanded.
enum DecisionIsland {
    static func make(interactionId: String, presentation: LiveDecisionPresentation, accent: Color = ViadereColor.accent) -> DynamicIsland {
        DynamicIsland {
            DynamicIslandExpandedRegion(.leading) {
                ViadereMark(style: .onDark)
                    .frame(height: 24)
                    .padding(.leading, 6)
                    .padding(.top, 2)
            }
            DynamicIslandExpandedRegion(.trailing) {
                DecisionTrailing(presentation: presentation, size: 18, accent: accent)
                    .padding(.trailing, 6)
                    .padding(.top, 2)
            }
            DynamicIslandExpandedRegion(.center) {
                VStack(spacing: 1) {
                    Text(presentation.business)
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(ViadereColor.textSecondary)
                        .lineLimit(1)
                    Text(presentation.headline)
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundStyle(ViadereColor.textPrimary)
                        .lineLimit(2)
                        .multilineTextAlignment(.center)
                        .minimumScaleFactor(0.85)
                        .privacySensitive()
                }
            }
            DynamicIslandExpandedRegion(.bottom) {
                VStack(alignment: .leading, spacing: 8) {
                    if let detail = presentation.detail {
                        Text(detail)
                            .font(.system(size: 13))
                            .foregroundStyle(ViadereColor.textSecondary)
                            .lineLimit(1)
                            .privacySensitive()
                    }
                    DecisionActions(interactionId: interactionId, presentation: presentation, height: 36, accent: accent)
                }
                .padding(.horizontal, 6)
                .padding(.top, 4)
            }
        } compactLeading: {
            ViadereMark(style: .onDark)
                .frame(height: 16)
                .padding(.leading, 2)
        } compactTrailing: {
            Text(presentation.compact)
                .font(.system(size: 13, weight: .semibold, design: .rounded))
                .foregroundStyle(accent)
                .lineLimit(1)
                .frame(maxWidth: 56, alignment: .trailing)
        } minimal: {
            ViadereMark(style: .onDark).frame(height: 14)
        }
        .widgetURL(presentation.openURL)
        .keylineTint(accent)
    }
}

/// Lock Screen / banner presentation of a decision: who asks, what, and the answers.
struct DecisionLockScreenView: View {
    let interactionId: String
    let presentation: LiveDecisionPresentation
    var accent: Color = ViadereColor.accent

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                ViadereMark().frame(height: 14)
                Text(presentation.business)
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(ViadereColor.textSecondary)
                    .lineLimit(1)
                Spacer(minLength: 8)
                DecisionTrailing(presentation: presentation, size: 14, accent: accent)
            }
            Text(presentation.headline)
                .font(.system(size: 17, weight: .semibold))
                .foregroundStyle(ViadereColor.textPrimary)
                .lineLimit(2)
                .privacySensitive()
            if let detail = presentation.detail {
                Text(detail)
                    .font(.system(size: 14))
                    .foregroundStyle(ViadereColor.textSecondary)
                    .lineLimit(2)
                    .privacySensitive()
            }
            DecisionActions(interactionId: interactionId, presentation: presentation, height: 40, accent: accent)
                .padding(.top, 2)
        }
        .padding(16)
    }
}

/// The answers (each a `ViadereDecisionIntent`), an "Open" link when the app is the way to answer, or the final stage.
struct DecisionActions: View {
    let interactionId: String
    let presentation: LiveDecisionPresentation
    let height: CGFloat
    var accent: Color = ViadereColor.accent

    var body: some View {
        if let stage = presentation.stageText {
            HStack(spacing: 6) {
                Circle().fill(accent).frame(width: 6, height: 6)
                Text(stage)
                    .font(.system(size: 14, weight: .medium))
                    .foregroundStyle(ViadereColor.textSecondary)
            }
            .accessibilityElement(children: .combine)
        } else {
            HStack(spacing: 8) {
                ForEach(presentation.buttons) { button in
                    Button(intent: ViadereDecisionIntent(interactionId: interactionId, actionId: button.actionIdentifier)) {
                        Text(button.label)
                    }
                    .buttonStyle(DecisionButtonStyle(kind: button.isDestructive ? .destructive : (button.isPrimary ? .primary : .secondary), height: height))
                    .accessibilityLabel(button.accessibilityLabel)
                }
                if presentation.showsOpen, let url = presentation.openURL {
                    Link(destination: url) {
                        Text(LiveDecisionPresentation.openLabel)
                            .modifier(DecisionButtonLabel(kind: presentation.buttons.isEmpty ? .primary : .secondary, height: height))
                    }
                    .accessibilityLabel("Open this request in Viadere")
                }
            }
        }
    }
}

/// Time left while pending (a live countdown when it is close), otherwise the stage word.
struct DecisionTrailing: View {
    let presentation: LiveDecisionPresentation
    let size: CGFloat
    var accent: Color = ViadereColor.accent

    var body: some View {
        Group {
            if presentation.isPending, presentation.expiresAt.timeIntervalSinceNow > 0,
               presentation.expiresAt.timeIntervalSinceNow <= LiveActivityPresentation.countdownWindow {
                Text(timerInterval: Date.now...max(Date.now, presentation.expiresAt), pauseTime: nil, countsDown: true, showsHours: false)
                    .monospacedDigit()
                    .multilineTextAlignment(.trailing)
                    .accessibilityLabel("Time left to answer")
            } else {
                Text(presentation.compact).lineLimit(1)
            }
        }
        .font(.system(size: size, weight: .semibold, design: .rounded))
        .foregroundStyle(accent)
    }
}

/// A compact Lock Screen button in the brand's colors: charcoal/ivory primary, surface secondary, quiet danger for a refusal.
struct DecisionButtonStyle: ButtonStyle {
    let kind: DecisionButtonLabel.Kind
    let height: CGFloat

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .modifier(DecisionButtonLabel(kind: kind, height: height))
            .opacity(configuration.isPressed ? 0.86 : 1)
    }
}

struct DecisionButtonLabel: ViewModifier {
    enum Kind { case primary, secondary, destructive }
    let kind: Kind
    let height: CGFloat

    private var shape: RoundedRectangle { RoundedRectangle(cornerRadius: ViadereRadius.control, style: .continuous) }

    func body(content: Content) -> some View {
        content
            .font(.system(size: 15, weight: .semibold))
            .lineLimit(1)
            .minimumScaleFactor(0.8)
            .foregroundStyle(foreground)
            .padding(.horizontal, 10)
            .frame(maxWidth: .infinity, minHeight: height)
            .background { shape.fill(fill) }
            .overlay { shape.strokeBorder(border, lineWidth: 1) }
            .contentShape(shape)
    }

    private var foreground: Color {
        switch kind {
        case .primary: ViadereColor.onPrimary
        case .secondary: ViadereColor.textPrimary
        case .destructive: ViadereColor.danger
        }
    }

    private var fill: Color {
        switch kind {
        case .primary: ViadereColor.primaryFill
        case .secondary: ViadereColor.surface
        case .destructive: ViadereColor.danger.opacity(0.08)
        }
    }

    private var border: Color {
        switch kind {
        case .primary: .clear
        case .secondary: ViadereColor.hairline
        case .destructive: ViadereColor.danger.opacity(0.22)
        }
    }
}

#if DEBUG
private extension ViadereActivityAttributes {
    static let preview = ViadereActivityAttributes(businessName: "Northwind Air", businessId: "b", interactionId: "i")
}

private enum PreviewStates {
    static var flight: LiveActivityStatus {
        .flight(FlightActivityState(flightNumber: "NW 482", departureAirport: "PHX", arrivalAirport: "SEA", stage: .delayed,
                                    scheduledDeparture: Date().addingTimeInterval(7_200), estimatedDeparture: Date().addingTimeInterval(8_700), gate: "B12"))
    }
    static var order: LiveActivityStatus {
        .order(OrderActivityState(orderReference: "1042", stage: .preparing, estimatedReadyAt: Date().addingTimeInterval(8 * 60)))
    }
    static var delivery: LiveActivityStatus {
        .delivery(DeliveryActivityState(trackingReference: "NM-7731", stage: .outForDelivery, carrierName: "Northfield Delivery",
                                        estimatedDeliveryAt: Date().addingTimeInterval(25 * 60), stopsAway: 3))
    }
    static var appointment: LiveActivityStatus {
        .appointment(AppointmentActivityState(title: "Haircut with Maya", startsAt: Date().addingTimeInterval(50 * 60),
                                              location: "Suite 210", providerName: "Linden Hair Studio", stage: .checkInOpen))
    }
    /// As the server sends it: no business text.
    static var decisionNeutral: LiveActivityStatus {
        .decision(DecisionActivityState(interactionId: InteractionID(), kind: .confirm, expiresAt: Date().addingTimeInterval(20 * 60)))
    }
    /// After the app enriched it on the device.
    static var decisionConfirm: LiveActivityStatus {
        .decision(DecisionActivityState(interactionId: InteractionID(), kind: .confirm, expiresAt: Date().addingTimeInterval(20 * 60),
                                        title: "Move your seat to 14C?", detail: "Same fare, window seat"))
    }
    static var decisionChoose: LiveActivityStatus {
        .decision(DecisionActivityState(interactionId: InteractionID(), kind: .choose, expiresAt: Date().addingTimeInterval(45 * 60),
                                        title: "Which meal would you like?",
                                        options: [.init(id: "veg", label: "Vegetarian"), .init(id: "fish", label: "Fish"), .init(id: "none", label: "No meal")]))
    }
    static var decisionAnswered: LiveActivityStatus {
        .decision(DecisionActivityState(interactionId: InteractionID(), kind: .confirm, expiresAt: Date().addingTimeInterval(20 * 60), stage: .answered,
                                        title: "Move your seat to 14C?"))
    }
}

#Preview("Lock screen", as: .content, using: ViadereActivityAttributes.preview) {
    ViadereLiveActivityWidget()
} contentStates: {
    PreviewStates.flight
    PreviewStates.order
    PreviewStates.delivery
    PreviewStates.appointment
    PreviewStates.decisionNeutral
    PreviewStates.decisionConfirm
    PreviewStates.decisionChoose
    PreviewStates.decisionAnswered
}

#Preview("Dynamic Island · expanded", as: .dynamicIsland(.expanded), using: ViadereActivityAttributes.preview) {
    ViadereLiveActivityWidget()
} contentStates: {
    PreviewStates.flight
    PreviewStates.order
    PreviewStates.appointment
    PreviewStates.decisionConfirm
    PreviewStates.decisionChoose
}

#Preview("Dynamic Island · compact", as: .dynamicIsland(.compact), using: ViadereActivityAttributes.preview) {
    ViadereLiveActivityWidget()
} contentStates: {
    PreviewStates.order
    PreviewStates.flight
    PreviewStates.delivery
}

#Preview("Dynamic Island · minimal", as: .dynamicIsland(.minimal), using: ViadereActivityAttributes.preview) {
    ViadereLiveActivityWidget()
} contentStates: {
    PreviewStates.order
}
#endif
