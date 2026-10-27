import SwiftUI
import ViadereCore
import ViadereKit

/// Settings → Verification history: requests waiting for you, and receipts of what was shared, with withdrawal while it still applies.
struct VerificationHistoryView: View {
    @State private var vm: VerificationHistoryViewModel
    @Environment(\.dismiss) private var dismiss
    var center: VerificationCenter

    init(api: any VerifyAPI, center: VerificationCenter) {
        _vm = State(initialValue: VerificationHistoryViewModel(api: api))
        self.center = center
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                ViadereBackButton("Settings") { dismiss() }.padding(.top, ViadereSpace.s)
                ViadereHeader("Verification history")
                if let message = vm.errorMessage { ViadereNotice(message, kind: .warning).padding(.bottom, ViadereSpace.s) }
                if !vm.pending.isEmpty {
                    ViadereSectionHeader("Waiting for you")
                    ViadereRowGroup {
                        ForEach(vm.pending) { prompt in
                            Button { center.present(prompt.id) } label: {
                                ViadereRow(prompt.recipientName, subtitle: VerificationPromptContent.purposeText(prompt.purposeCode)) { ViadereIconTile(systemName: "person.badge.shield.checkmark") }
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }
                ViadereSectionHeader("Receipts")
                if vm.items.isEmpty && !vm.isLoading {
                    Text("When a business asks you to verify something, a receipt appears here: who asked, what was shared and when.")
                        .font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary).padding(.vertical, ViadereSpace.s)
                }
                ViadereRowGroup {
                    ForEach(vm.items) { item in
                        VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                            ViadereRow(item.recipientName, subtitle: VerificationHistoryViewModel.summary(item)) { ViadereIconTile(systemName: icon(item.status)) }
                            Text("\(VerificationPromptContent.purposeText(item.purposeCode)) · \(item.requestedAt.formatted(date: .abbreviated, time: .shortened))")
                                .font(ViadereType.footnote).foregroundStyle(ViadereColor.textTertiary)
                            if item.revocable {
                                Button("Withdraw before it's shared") { Task { await vm.withdraw(item) } }.buttonStyle(.viadere(.secondary, fullWidth: false))
                            }
                        }
                        .accessibilityElement(children: .combine)
                    }
                }
                Text("Withdrawing stops a disclosure that hasn't happened yet. Something already shared with a business can't be taken back by Viadere; ask the business to delete it.")
                    .font(ViadereType.footnote).foregroundStyle(ViadereColor.textTertiary).padding(.top, ViadereSpace.s)
            }
            .padding(.horizontal, ViadereSpace.screen)
            .padding(.bottom, ViadereSpace.xl)
        }
        .scrollIndicators(.hidden)
        .viadereScreenBackground()
        .toolbar(.hidden, for: .navigationBar)
        .task { await vm.load() }
        .refreshable { await vm.load() }
    }

    private func icon(_ status: ConsumerVerificationStatus) -> String {
        switch status {
        case .released: "checkmark.seal"
        case .declined, .revoked, .cancelled: "hand.raised"
        case .expired: "clock"
        default: "questionmark.circle"
        }
    }
}
