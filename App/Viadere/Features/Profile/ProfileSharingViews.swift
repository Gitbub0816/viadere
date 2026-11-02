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
                        // Shared details as chips (on = shared); a detail missing from the profile is shown but can't be chosen.
                        ViadereChipSet(group.category.title,
                                       chips: group.fields.map { field in
                                           ViadereChipSet<String>.Chip(field.key, ProfileRules.title(field.key), isEnabled: vm.canToggle(field.key),
                                                                       hint: field.hasValue ? nil : "Not in your profile")
                                       },
                                       isSelected: { vm.isOn($0) },
                                       toggle: { vm.toggle($0) })
                        let missing = group.fields.filter { !$0.hasValue }.map { ProfileRules.title($0.key) }
                        if !missing.isEmpty {
                            Text("Not in your profile: \(missing.joined(separator: ", ")).")
                                .font(ViadereType.footnote).foregroundStyle(ViadereColor.textTertiary)
                                .padding(.top, ViadereSpace.xs)
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
        // Each requested detail is a chip: tap to include it. Already shared ones are locked on; ones missing from the profile can't be chosen.
        ViadereCard(padding: ViadereSpace.m) {
            VStack(alignment: .leading, spacing: ViadereSpace.s) {
                ViadereChipSet("Details to share",
                               chips: vm.prompt.fields.map { field in
                                   ViadereChipSet<String>.Chip(field.key, ProfileRules.title(field.key), isLocked: field.alreadyGranted,
                                                               isEnabled: field.alreadyGranted || vm.canSelect(field),
                                                               hint: field.alreadyGranted ? "Already shared" : (field.hasValue ? nil : "Add it in Profile to share it"))
                               },
                               isSelected: { key in vm.selected.contains(key) || vm.prompt.fields.contains { $0.key == key && $0.alreadyGranted } },
                               toggle: { vm.toggle($0) })
                let shared = vm.prompt.fields.filter(\.alreadyGranted).map { ProfileRules.title($0.key) }
                let missing = vm.prompt.fields.filter { !$0.hasValue && !$0.alreadyGranted }.map { ProfileRules.title($0.key) }
                if !shared.isEmpty {
                    Text("Already shared: \(shared.joined(separator: ", ")).").font(ViadereType.footnote).foregroundStyle(ViadereColor.textTertiary)
                }
                if !missing.isEmpty {
                    Text("Add to your profile to share: \(missing.joined(separator: ", ")).").font(ViadereType.footnote).foregroundStyle(ViadereColor.textTertiary)
                }
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
                ViadereBackButton("You") { dismiss() }
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
                ViadereChipSet("Facts to keep",
                               chips: ProfileVerifiedFactKind.allCases.map { ViadereChipSet<ProfileVerifiedFactKind>.Chip($0, $0.title) },
                               isSelected: { vm.keep.contains($0) },
                               toggle: { kind in if vm.keep.contains(kind) { vm.keep.remove(kind) } else { vm.keep.insert(kind) } })
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
