import SwiftUI
import ViadereKit

/// "Apps you've signed in to with Viadere" (UX_COPY OIDC-09, OIDC-10; ADR-0024 §8). Each row names the client and its website; "Stop {Client}
/// recognizing me" removes the consent after a confirmation (reduce-only: it never signs anything and never adds access).
struct OIDCConsentsView: View {
    @State private var model: OIDCConsentsViewModel
    @State private var pending: OIDCConsentView?

    init(api: any OIDCDeviceAPI) {
        _model = State(initialValue: OIDCConsentsViewModel(api: api))
    }

    var body: some View {
        SubScreen(title: model.title, subtitle: nil, backTitle: "Signed-in sessions") {
            VStack(alignment: .leading, spacing: ViadereSpace.m) {
                switch model.phase {
                case .loading:
                    ProgressView().frame(maxWidth: .infinity)
                case .unavailable, .failed:
                    ViadereNotice("We couldn't load this list. Try again later.", kind: .info)
                case .loaded where model.consents.isEmpty:
                    Text(model.emptyText).font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
                case .loaded:
                    ViadereRowGroup {
                        ForEach(Array(model.consents.enumerated()), id: \.element.id) { index, consent in
                            VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                                ViadereRow(model.row(consent, formatter: { $0.formatted(date: .abbreviated, time: .omitted) }), subtitle: consent.host,
                                           leading: { ViadereIconTile(systemName: "person.crop.square") }, trailing: { EmptyView() })
                                Button(model.revokeTitle(consent)) { pending = consent }
                                    .buttonStyle(.viadere(.quiet, fullWidth: false))
                                    .frame(minHeight: 44)
                            }
                            if index < model.consents.count - 1 { ViadereHairline() }
                        }
                    }
                }
                if let notice = model.notice { ViadereNotice(notice, kind: .warning) }
            }
        }
        .task { await model.load() }
        .confirmationDialog(pending.map { model.revokeTitle($0) } ?? "", isPresented: Binding(get: { pending != nil }, set: { if !$0 { pending = nil } }),
                            titleVisibility: .visible, presenting: pending) { consent in
            Button(model.revokeTitle(consent), role: .destructive) { Task { await model.revoke(consent) } }
            Button("Cancel", role: .cancel) {}
        } message: { consent in
            Text(model.revokeConfirmation(consent))
        }
    }
}
