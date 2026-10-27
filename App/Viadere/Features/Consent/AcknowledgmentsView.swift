import SwiftUI
import ViadereCore
import ViadereKit

/// Settings → Acknowledgments: what you read and acknowledged (or declined), with the version and the server's time.
struct AcknowledgmentsView: View {
    let vm: AcknowledgmentsViewModel

    var body: some View {
        SubScreen(title: "Acknowledgments", subtitle: "What you've read and acknowledged, with the version and time.") {
            switch vm.phase {
            case .idle, .loading:
                ViadereLoading().frame(maxWidth: .infinity).padding(.top, ViadereSpace.l)
            case .unavailable:
                ViadereEmptyState("Not available yet", message: "Acknowledgment records will appear here.")
            case .failed(let message):
                ViadereNotice(message, kind: .warning)
            case .loaded:
                if vm.records.isEmpty {
                    ViadereEmptyState("Nothing yet", message: "When you acknowledge a policy, estimate or notice, the record appears here.")
                } else {
                    ViadereRowGroup {
                        ForEach(Array(vm.records.enumerated()), id: \.element.id) { index, record in
                            ViadereRow(record.title, subtitle: "\(record.business.displayName) · \(vm.subtitle(record))",
                                       leading: { ViadereAvatar(name: record.business.displayName, size: 36, isVerified: record.business.isVerified) },
                                       trailing: { record.acknowledged ? AnyView(EmptyView()) : AnyView(ViadereBadge("Declined", kind: .neutral)) })
                            if index < vm.records.count - 1 { ViadereHairline(inset: 50) }
                        }
                    }
                }
            }
            Text(AcknowledgmentPresentation.disclaimer)
                .font(ViadereType.footnote)
                .foregroundStyle(ViadereColor.textTertiary)
        }
        .task { await vm.load() }
        .refreshable { await vm.load() }
    }
}

#if DEBUG
#Preview("Acknowledgments") {
    PreviewHost { services in
        NavigationStack { AcknowledgmentsView(vm: AcknowledgmentsViewModel(services: services)) }
    }
}
#endif
