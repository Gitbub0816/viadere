import SwiftUI
import ViadereKit

/// Compact approval card: who, what, the facts, and when it expires.
struct NotificationCardView: View {
    let card: NotificationCard?
    let fallbackTitle: String
    let fallbackBody: String

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.s) {
            if let card {
                HStack(spacing: ViadereSpace.xs) {
                    ViadereAvatar(name: card.business, size: 32, isVerified: true)
                    VStack(alignment: .leading, spacing: 0) {
                        Text(card.business).font(ViadereType.subhead.weight(.semibold)).foregroundStyle(ViadereColor.textPrimary)
                        Text(card.kindLabel).font(ViadereType.caption).foregroundStyle(ViadereColor.textSecondary)
                    }
                    Spacer()
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        Text(InteractionPresentation.countdown(until: card.expiresAt, now: context.date))
                            .font(ViadereType.caption).monospacedDigit().foregroundStyle(ViadereColor.accent)
                    }
                }
                Text(card.question)
                    .font(ViadereType.headline)
                    .foregroundStyle(ViadereColor.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)
                VStack(spacing: 0) {
                    ForEach(Array(card.rows.enumerated()), id: \.offset) { index, row in
                        ViadereValueRow(row.label, row.value, emphasized: row.emphasized)
                        if index < card.rows.count - 1 { ViadereHairline() }
                    }
                }
                if !card.risks.isEmpty {
                    ViadereFlowLayout {
                        ForEach(card.risks, id: \.self) { ViadereRiskChip(label: $0, severity: "warning") }
                    }
                }
                if card.finishesInApp {
                    Label(card.verification ?? "Approve in Viadere", systemImage: "faceid")
                        .font(ViadereType.footnote)
                        .foregroundStyle(ViadereColor.textSecondary)
                }
            } else {
                Text(fallbackTitle).font(ViadereType.headline).foregroundStyle(ViadereColor.textPrimary)
                Text(fallbackBody).font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
            }
        }
        .padding(ViadereSpace.m)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(ViadereColor.background)
        .accessibilityElement(children: .combine)
    }
}

#if DEBUG
#Preview("Notification card") {
    NotificationCardView(
        card: NotificationCard(envelope: PreviewData.authorize(), now: Date(), finishesInApp: true),
        fallbackTitle: "Northfield Market", fallbackBody: "")
}
#endif
