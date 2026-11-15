import SwiftUI
import ViadereKit

/// What the credential-provider extension shows while it works. Branded and minimal: the extension asks for the person's confirmation and
/// nothing else. The text shown comes from the website's request (its domain and the account name) and is sanitized by `ProviderText`.
@MainActor
final class ProviderFlowModel: ObservableObject {
    enum Step: Equatable {
        case working(String)
        /// A passkey is about to be created: show where and for whom.
        case confirmCreate(site: String, account: String)
        case list(title: String, rows: [Row])
        case failed(String)
    }

    struct Row: Identifiable, Equatable {
        var id: UUID
        var title: String
        var subtitle: String
    }

    @Published var step: Step = .working("Opening")
    var onConfirm: (() -> Void)?
    var onChoose: ((UUID) -> Void)?
    var onCancel: (() -> Void)?
}

struct ProviderFlowView: View {
    @ObservedObject var model: ProviderFlowModel

    var body: some View {
        VStack(spacing: 0) {
            ViadereGrabber().padding(.top, ViadereSpace.s)
            VStack(alignment: .leading, spacing: ViadereSpace.m) {
                HStack {
                    ViadereLockup(.horizontal, ribbonHeight: 20)
                    Spacer()
                    ViadereIconButton(systemName: "xmark", label: "Cancel") { model.onCancel?() }
                }
                content
                Spacer(minLength: 0)
            }
            .padding(ViadereSpace.screen)
        }
        .viadereScreenBackground()
    }

    @ViewBuilder private var content: some View {
        switch model.step {
        case .working(let text):
            VStack(spacing: ViadereSpace.m) {
                ViadereLoading()
                Text(text).font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
            }
            .frame(maxWidth: .infinity)
            .padding(.top, ViadereSpace.xl)
        case .confirmCreate(let site, let account):
            VStack(alignment: .leading, spacing: ViadereSpace.m) {
                Text("Save a passkey for \(site)?").font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
                ViadereCard(padding: ViadereSpace.m) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(site).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                        Text(account).font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                ViadereNotice("It's stored encrypted in Viadere Authenticator. You'll confirm with Face ID or your passcode.", kind: .info)
                Button("Save passkey") { model.onConfirm?() }.buttonStyle(.viadere(.primary))
                Button("Not now") { model.onCancel?() }.buttonStyle(.viadere(.secondary))
            }
        case .list(let title, let rows):
            VStack(alignment: .leading, spacing: ViadereSpace.m) {
                Text(title).font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
                if rows.isEmpty {
                    Text("Nothing saved for this site yet.").font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
                } else {
                    ViadereRowGroup {
                        ForEach(Array(rows.enumerated()), id: \.element.id) { index, row in
                            Button { model.onChoose?(row.id) } label: { ViadereRow(row.title, subtitle: row.subtitle) }.buttonStyle(.plain)
                            if index < rows.count - 1 { ViadereHairline() }
                        }
                    }
                }
            }
        case .failed(let text):
            VStack(alignment: .leading, spacing: ViadereSpace.m) {
                ViadereNotice(text, kind: .warning)
                Button("Close") { model.onCancel?() }.buttonStyle(.viadere(.secondary))
            }
        }
    }
}

/// Text from a website's request, made safe to show.
enum ProviderText {
    static func clean(_ text: String) -> String { UntrustedText.clean(text) }
}
