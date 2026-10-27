import ActivityKit
import SwiftUI
import ViadereCore
import ViadereKit
import WidgetKit

/// Live Activity and Dynamic Island for genuinely ongoing events: orders, deliveries, flights, appointments.
/// Content is `LiveActivityStatus` from ViadereCore, so a server status push decodes straight into it.
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
                    Image(systemName: presentation.symbol)
                        .font(.system(size: 22, weight: .regular))
                        .foregroundStyle(ViadereColor.accent)
                        .padding(.leading, 4)
                }
                DynamicIslandExpandedRegion(.trailing) {
                    if let target = presentation.target {
                        Text(target, style: .time)
                            .font(.system(size: 17, weight: .semibold, design: .rounded))
                            .monospacedDigit()
                            .padding(.trailing, 4)
                    }
                }
                DynamicIslandExpandedRegion(.center) {
                    VStack(spacing: 2) {
                        Text(presentation.headline).font(.system(size: 15, weight: .semibold)).lineLimit(1)
                        Text(context.attributes.businessName).font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
                DynamicIslandExpandedRegion(.bottom) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(presentation.detail)
                            .font(.system(size: 14, weight: presentation.isAlert ? .semibold : .regular))
                            .foregroundStyle(presentation.isAlert ? ViadereColor.danger : .primary)
                        if let progress = presentation.progress { ActivityProgressBar(progress: progress) }
                    }
                    .padding(.top, 4)
                }
            } compactLeading: {
                Image(systemName: presentation.symbol).foregroundStyle(ViadereColor.accent)
            } compactTrailing: {
                Text(presentation.compact)
                    .font(.system(size: 13, weight: .semibold, design: .rounded))
                    .lineLimit(1)
                    .frame(maxWidth: 56)
            } minimal: {
                Image(systemName: presentation.symbol).foregroundStyle(ViadereColor.accent)
            }
            .keylineTint(ViadereColor.accent)
        }
    }
}

/// Lock Screen / banner presentation.
struct LockScreenActivityView: View {
    let business: String
    let presentation: LiveActivityPresentation

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                ViadereMark.monochrome(ViadereColor.textSecondary).frame(height: 14)
                Text(business).font(.system(size: 13, weight: .medium)).foregroundStyle(ViadereColor.textSecondary)
                Spacer()
                if let target = presentation.target {
                    Text(target, style: .time).font(.system(size: 13, weight: .semibold, design: .rounded)).monospacedDigit()
                        .foregroundStyle(ViadereColor.textPrimary)
                }
            }
            Text(presentation.headline)
                .font(.system(size: 20, weight: .semibold))
                .foregroundStyle(ViadereColor.textPrimary)
            Text(presentation.detail)
                .font(.system(size: 15))
                .foregroundStyle(presentation.isAlert ? ViadereColor.danger : ViadereColor.textSecondary)
            if let progress = presentation.progress { ActivityProgressBar(progress: progress) }
        }
        .padding(16)
    }
}

struct ActivityProgressBar: View {
    let progress: Double

    var body: some View {
        GeometryReader { proxy in
            ZStack(alignment: .leading) {
                Capsule().fill(ViadereColor.track)
                Capsule().fill(ViadereColor.accent).frame(width: proxy.size.width * min(max(progress, 0), 1))
            }
        }
        .frame(height: 5)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("Progress"))
        .accessibilityValue(Text("\(Int(progress * 100)) percent"))
    }
}

#if DEBUG
#Preview("Lock screen", as: .content, using: ViadereActivityAttributes(businessName: "Juniper Air", businessId: "b", interactionId: "i")) {
    ViadereLiveActivityWidget()
} contentStates: {
    [LiveActivityStatus.flight(FlightActivityState(flightNumber: "JA 482", departureAirport: "PHX", arrivalAirport: "SEA",
                                                   stage: .delayed, scheduledDeparture: Date().addingTimeInterval(7_200),
                                                   estimatedDeparture: Date().addingTimeInterval(8_700), gate: "B12"))]
}
#endif
