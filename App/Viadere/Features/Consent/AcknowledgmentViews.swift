import SwiftUI
import ViadereCore
import ViadereKit

/// The `acknowledge` request inside the approval sheet: the document summary, its version, who sent it, and plain
/// copy that this records a reading, not a legal signature.
struct AcknowledgmentBody: View {
    let envelope: InteractionEnvelope
    let payload: AcknowledgePayload
    let now: Date
    @State private var expanded = false
    @Environment(\.openURL) private var openURL

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.l) {
            VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                if let version = AcknowledgmentPresentation.versionLabel(payload) { ViadereBadge(version, kind: .neutral) }
                Text(AcknowledgmentPresentation.title(payload))
                    .font(ViadereType.title)
                    .foregroundStyle(ViadereColor.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityAddTraits(.isHeader)
            }
            VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                Text(expanded ? AcknowledgmentPresentation.body(payload) : AcknowledgmentPresentation.summary(payload))
                    .font(ViadereType.body)
                    .foregroundStyle(ViadereColor.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                if AcknowledgmentPresentation.isTruncated(payload) {
                    Button(expanded ? "Show less" : "Read the full text") { withAnimation(ViadereMotion.standard) { expanded.toggle() } }
                        .buttonStyle(.viadere(.quiet, fullWidth: false))
                }
            }
            if let url = AcknowledgmentPresentation.documentURL(payload) {
                Button { openURL(url) } label: {
                    HStack(spacing: ViadereSpace.xs) { Image(systemName: "doc.text"); Text("Open the full document") }
                }
                .buttonStyle(.viadere(.secondary))
            }
            let rows = AcknowledgmentPresentation.documentRows(envelope, payload: payload, now: now)
            ViadereRowGroup {
                ForEach(Array(rows.enumerated()), id: \.element.id) { index, row in
                    ViadereValueRow(row.label, row.value)
                    if index < rows.count - 1 { ViadereHairline() }
                }
            }
            ViadereNotice(AcknowledgmentPresentation.disclaimer, kind: .info)
        }
    }
}

/// After deciding: the timestamped record (server time, document version, reference).
struct AcknowledgmentReceipt: View {
    let envelope: InteractionEnvelope
    let payload: AcknowledgePayload
    let outcome: InteractionOutcome?
    let acknowledged: Bool
    let fallback: Date

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.l) {
            VStack(alignment: .leading, spacing: ViadereSpace.s) {
                Image(systemName: acknowledged ? "checkmark.circle" : "xmark.circle")
                    .font(.system(size: 44, weight: .light))
                    .foregroundStyle(acknowledged ? ViadereColor.success : ViadereColor.textSecondary)
                    .accessibilityHidden(true)
                Text(AcknowledgmentPresentation.resultTitle(acknowledged: acknowledged)).font(ViadereType.display).foregroundStyle(ViadereColor.textPrimary)
                Text(AcknowledgmentPresentation.resultMessage(acknowledged: acknowledged, business: envelope.business.safeName))
                    .font(ViadereType.body)
                    .foregroundStyle(ViadereColor.textSecondary)
            }
            let rows = AcknowledgmentPresentation.receiptRows(envelope, payload: payload, outcome: outcome, fallback: fallback)
            ViadereRowGroup {
                ForEach(Array(rows.enumerated()), id: \.element.id) { index, row in
                    ViadereValueRow(row.label, row.value, emphasized: row.emphasized)
                    if index < rows.count - 1 { ViadereHairline() }
                }
            }
            Text(AcknowledgmentPresentation.recordNote).font(ViadereType.footnote).foregroundStyle(ViadereColor.textTertiary)
            ViadereNotice(AcknowledgmentPresentation.disclaimer, kind: .info)
        }
        .padding(.top, ViadereSpace.l)
    }
}

#if DEBUG
#Preview("Acknowledge") {
    PreviewHost { services in
        ApprovalSheet(model: ApprovalViewModel(envelope: PreviewData.acknowledge(), services: services), capture: ScreenCaptureObserver())
    }
}
#endif
