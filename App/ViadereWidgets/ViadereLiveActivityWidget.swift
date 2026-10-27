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
struct ViadereLiveActivityWidget: Widget {
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: ViadereActivityAttributes.self) { context in
            LockScreenActivityView(business: context.attributes.businessName,
                                   presentation: LiveActivityPresentation(status: context.state, businessName: context.attributes.businessName))
                .activityBackgroundTint(ViadereColor.background)
                .activitySystemActionForegroundColor(ViadereColor.textPrimary)
        } dynamicIsland: { context in
            let presentation = LiveActivityPresentation(status: context.state, businessName: context.attributes.businessName)
            return DynamicIsland {
                DynamicIslandExpandedRegion(.leading) {
                    ViadereMark(style: .onDark)
                        .frame(height: 24)
                        .padding(.leading, 6)
                        .padding(.top, 2)
                }
                DynamicIslandExpandedRegion(.trailing) {
                    ActivityTrailingText(trailing: presentation.trailing, isAlert: presentation.isAlert, size: 20)
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
                ActivityTrailingText(trailing: presentation.trailing, isAlert: presentation.isAlert, size: 13)
                    .frame(maxWidth: 52, alignment: .trailing)
            } minimal: {
                ViadereMark(style: .onDark).frame(height: 14)
            }
            .keylineTint(ViadereColor.accent)
        }
    }
}

/// The right-hand slot: a live countdown when the moment is near, otherwise a short status word.
struct ActivityTrailingText: View {
    let trailing: LiveActivityPresentation.Trailing
    let isAlert: Bool
    let size: CGFloat

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
        .foregroundStyle(isAlert ? ViadereColor.danger : ViadereColor.accent)
    }
}

/// Lock Screen / banner presentation.
struct LockScreenActivityView: View {
    let business: String
    let presentation: LiveActivityPresentation

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                ViadereMark().frame(height: 14)
                Text(business)
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(ViadereColor.textSecondary)
                    .lineLimit(1)
                Spacer(minLength: 8)
                ActivityTrailingText(trailing: presentation.trailing, isAlert: presentation.isAlert, size: 15)
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
        .appointment(AppointmentActivityState(title: "Cleaning with Dr. Okafor", startsAt: Date().addingTimeInterval(50 * 60),
                                              location: "Suite 210", providerName: "Linden Dental", stage: .checkInOpen))
    }
}

#Preview("Lock screen", as: .content, using: ViadereActivityAttributes.preview) {
    ViadereLiveActivityWidget()
} contentStates: {
    [PreviewStates.flight, PreviewStates.order, PreviewStates.delivery, PreviewStates.appointment]
}

#Preview("Dynamic Island · expanded", as: .dynamicIsland(.expanded), using: ViadereActivityAttributes.preview) {
    ViadereLiveActivityWidget()
} contentStates: {
    [PreviewStates.flight, PreviewStates.order, PreviewStates.appointment]
}

#Preview("Dynamic Island · compact", as: .dynamicIsland(.compact), using: ViadereActivityAttributes.preview) {
    ViadereLiveActivityWidget()
} contentStates: {
    [PreviewStates.order, PreviewStates.flight, PreviewStates.delivery]
}

#Preview("Dynamic Island · minimal", as: .dynamicIsland(.minimal), using: ViadereActivityAttributes.preview) {
    ViadereLiveActivityWidget()
} contentStates: {
    [PreviewStates.order]
}
#endif
