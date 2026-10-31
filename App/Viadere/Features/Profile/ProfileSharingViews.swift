import SwiftUI
import ViadereCore
import ViadereKit

/// "What this business can see": the public name (always shared), a toggle per field in the categories Viadere allows this business, and
/// stop sharing everything. A toggle changes nothing until saved; stopping takes effect on the business's next read.
struct BusinessProfileAccessView: View {
    @State private var vm: BusinessProfileAccessViewModel
    @State private var confirmingRevoke = false
    @Environment(\.dismiss) private var dismiss

    init(api: any ProfileAPI, business: BusinessID) {
        _vm = State(initialValue: BusinessProfileAccessViewModel(api: api, business: business))
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: ViadereSpace.l) {
                ViadereBackButton { dismiss() }
                Text("What \(DisplayTextSanitizer.sanitize(vm.view?.businessName ?? "this business", maxCharacters: 64)) can see")
                    .font(ViadereType.title)
                    .foregroundStyle(ViadereColor.textPrimary)
                    .accessibilityAddTraits(.isHeader)
                ViadereCard {
                    ViadereRow("Public name", subtitle: vm.view?.publicName ?? "No name set", leading: { ViadereIconTile(systemName: "person.crop.circle") }) {
                        ViadereBadge("Always shared")
                    }
                }
                if vm.groups.isEmpty, vm.view != nil {
                    ViadereEmptyState("Nothing else to share", message: "This business isn't allowed to ask for profile details.")
                }
                ForEach(vm.groups, id: \.category) { group in
                    VStack(alignment: .leading, spacing: 0) {
                        ViadereSectionHeader(group.category.title)
                        ViadereRowGroup {
                            ForEach(Array(group.fields.enumerated()), id: \.element.key) { index, field in
                                Toggle(isOn: Binding(get: { vm.isOn(field.key) }, set: { _ in vm.toggle(field.key) })) {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(ProfileRules.title(field.key))
                                        if !field.hasValue {
                                            Text("Not in your profile").font(ViadereType.footnote).foregroundStyle(ViadereColor.textTertiary)
                                        }
                                    }
                                }
                                .toggleStyle(ViadereToggleStyle())
                                .disabled(!vm.canToggle(field.key))
                                if index < group.fields.count - 1 { ViadereHairline() }
                            }
                        }
                    }
                }
                if let error = vm.errorMessage { ViadereNotice(error, kind: .danger) }
                if vm.hasChanges {
                    Button("Save") { Task { await vm.save() } }.buttonStyle(.viadere(.primary)).disabled(vm.isSaving)
                }
                if vm.sharesAnything {
                    if confirmingRevoke {
                        ViadereNotice("The business loses access right away. It keeps your public name while you're connected.", kind: .warning)
                        Button("Stop sharing everything") { Task { await vm.revokeAll(); confirmingRevoke = false } }.buttonStyle(.viadere(.destructive))
                        Button("Cancel") { confirmingRevoke = false }.buttonStyle(.viadere(.quiet))
                    } else {
                        Button("Stop sharing everything") { confirmingRevoke = true }.buttonStyle(.viadere(.destructive))
                    }
                }
            }
            .padding(.horizontal, ViadereSpace.screen)
            .padding(.bottom, ViadereSpace.xl)
        }
        .scrollIndicators(.hidden)
        .viadereScreenBackground()
        .task { await vm.load() }
    }
}

/// A business's profile request (from Alerts): the business, its purpose in its own words, and a choice per field. Nothing is preselected.
/// Sharing needs the device owner (Face ID, Touch ID or passcode).
struct ProfileRequestSheet: View {
    @State private var vm: ProfileRequestViewModel?
    let id: ProfileRequestID
    @State private var loadError: String?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: ViadereSpace.l) {
                if let vm {
                    content(vm)
                } else if let loadError {
                    ViadereNotice(loadError, kind: .danger)
                } else {
                    ProgressView().frame(maxWidth: .infinity)
                }
            }
            .padding(ViadereSpace.screen)
        }
        .task {
            do {
                let prompt = try await AppEnvironment.shared.profileAPI.request(id)
                vm = ProfileRequestViewModel(api: AppEnvironment.shared.profileAPI, prompt: prompt, clock: AppEnvironment.services.clock)
            } catch {
                loadError = (error as? APIError)?.userMessage ?? "Couldn't load this request."
            }
        }
    }

    @ViewBuilder private func content(_ vm: ProfileRequestViewModel) -> some View {
        Text("\(vm.businessName) asks to see")
            .font(ViadereType.title)
            .foregroundStyle(ViadereColor.textPrimary)
            .accessibilityAddTraits(.isHeader)
        ViadereCard {
            VStack(alignment: .leading, spacing: ViadereSpace.xxs) {
                Text("Why, in their words").font(ViadereType.caption).foregroundStyle(ViadereColor.textSecondary)
                Text(vm.purpose).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
            }
        }
        ViadereRowGroup {
            ForEach(Array(vm.prompt.fields.enumerated()), id: \.element.key) { index, field in
                Toggle(isOn: Binding(get: { vm.selected.contains(field.key) || field.alreadyGranted }, set: { _ in vm.toggle(field.key) })) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(ProfileRules.title(field.key))
                        if field.alreadyGranted {
                            Text("Already shared").font(ViadereType.footnote).foregroundStyle(ViadereColor.textTertiary)
                        } else if !field.hasValue {
                            Text("Add it in Profile to share it").font(ViadereType.footnote).foregroundStyle(ViadereColor.textTertiary)
                        }
                    }
                }
                .toggleStyle(ViadereToggleStyle())
                .disabled(!vm.canSelect(field))
                if index < vm.prompt.fields.count - 1 { ViadereHairline() }
            }
        }
        Text("You can stop sharing any of these later from the business's page.")
            .font(ViadereType.footnote)
            .foregroundStyle(ViadereColor.textTertiary)
        if let error = vm.errorMessage { ViadereNotice(error, kind: .danger) }
        if vm.isActionable {
            Button(vm.selected.isEmpty ? "Share nothing" : "Share \(vm.selected.count) selected") {
                Task {
                    let lock = AppEnvironment.services.appLock
                    if !vm.selected.isEmpty, await lock.isAvailable() {
                        guard await lock.authenticate(reason: "Confirm to share with \(vm.businessName)") else { return }
                    }
                    if await (vm.selected.isEmpty ? vm.decline() : vm.approveSelected()) { dismiss() }
                }
            }
            .buttonStyle(.viadere(.primary))
            .disabled(vm.isSubmitting)
            if !vm.selected.isEmpty {
                Button("Decline") { Task { if await vm.decline() { dismiss() } } }.buttonStyle(.viadere(.quiet))
            }
        } else {
            ViadereNotice("This request is no longer open.", kind: .info)
        }
    }
}

/// Every grant and revocation, newest first: which business, which fields (never values), why and when.
struct ProfileReceiptsView: View {
    @State private var vm: ProfileReceiptsViewModel
    @Environment(\.dismiss) private var dismiss

    init(api: any ProfileAPI) { _vm = State(initialValue: ProfileReceiptsViewModel(api: api)) }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: ViadereSpace.l) {
                ViadereBackButton("Settings") { dismiss() }
                Text("Sharing history")
                    .font(ViadereType.display)
                    .foregroundStyle(ViadereColor.textPrimary)
                    .accessibilityAddTraits(.isHeader)
                if vm.receipts.isEmpty {
                    ViadereEmptyState("Nothing shared yet", message: "When you share profile details with a business, a receipt appears here.")
                } else {
                    ViadereRowGroup {
                        ForEach(Array(vm.receipts.enumerated()), id: \.element.id) { index, receipt in
                            ViadereRow(DisplayTextSanitizer.sanitize(receipt.businessName, maxCharacters: 64),
                                       subtitle: "\(ProfileReceiptsViewModel.summary(receipt)) · \(receipt.createdAt.formatted(date: .abbreviated, time: .shortened))",
                                       leading: { ViadereIconTile(systemName: receipt.action == .revoked ? "minus.circle" : "checkmark.circle") },
                                       trailing: { EmptyView() })
                            if index < vm.receipts.count - 1 { ViadereHairline(inset: 50) }
                        }
                    }
                }
                if let error = vm.errorMessage { ViadereNotice(error, kind: .danger) }
            }
            .padding(.horizontal, ViadereSpace.screen)
            .padding(.bottom, ViadereSpace.xl)
        }
        .scrollIndicators(.hidden)
        .viadereScreenBackground()
        .toolbar(.hidden, for: .navigationBar)
        .task { await vm.load() }
    }
}

/// Choose the facts to keep, then verify with an ID in Apple Wallet or a document check (the same methods as business verification requests).
struct ProfileVerificationSheet: View {
    @State private var vm: ProfileVerificationViewModel
    @Environment(\.dismiss) private var dismiss

    init(api: any ProfileAPI) { _vm = State(initialValue: ProfileVerificationViewModel(api: api)) }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: ViadereSpace.l) {
                Text("Verify your profile")
                    .font(ViadereType.title)
                    .foregroundStyle(ViadereColor.textPrimary)
                    .accessibilityAddTraits(.isHeader)
                Text("Viadere keeps only the facts you choose, with when and how they were checked. Never your ID, its number or a photo.")
                    .font(ViadereType.subhead)
                    .foregroundStyle(ViadereColor.textSecondary)
                ViadereRowGroup {
                    ForEach(Array(ProfileVerifiedFactKind.allCases.enumerated()), id: \.element) { index, kind in
                        Toggle(kind.title, isOn: Binding(get: { vm.keep.contains(kind) },
                                                         set: { on in if on { vm.keep.insert(kind) } else { vm.keep.remove(kind) } }))
                            .toggleStyle(ViadereToggleStyle())
                        if index < ProfileVerifiedFactKind.allCases.count - 1 { ViadereHairline() }
                    }
                }
                switch vm.phase {
                case .finished(let status):
                    ViadereNotice(status == .verified ? "Verified. Your profile shows the badge." : "We couldn't confirm that. Nothing was kept.",
                                  kind: status == .verified ? .info : .warning)
                    Button("Done") { dismiss() }.buttonStyle(.viadere(.primary))
                case .failed(let text):
                    ViadereNotice(text, kind: .danger)
                    Button("Try again") { vm.reset() }.buttonStyle(.viadere(.secondary))
                case .started:
                    ProgressView().frame(maxWidth: .infinity)
                case .choosing:
                    Button("Use ID in Apple Wallet") { Task { await vm.verifyWithWallet(presenter: PassKitProfileWalletPresenter()) } }
                        .buttonStyle(.viadere(.primary))
                        .disabled(!vm.canBegin)
                    Button("Scan a document instead") { Task { await vm.verifyWithDocument(service: DocumentVerificationLauncher.shared) } }
                        .buttonStyle(.viadere(.secondary))
                        .disabled(!vm.canBegin)
                }
            }
            .padding(ViadereSpace.screen)
        }
    }
}
