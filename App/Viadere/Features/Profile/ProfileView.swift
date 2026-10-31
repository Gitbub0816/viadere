import SwiftUI
import ViadereCore
import ViadereKit

/// Which profile request is open (from Alerts). `MainShell` presents the sheet.
@MainActor
@Observable
final class ProfileCenter {
    var presentedRequest: ProfileRequestID?
}

struct PresentedProfileRequest: Identifiable {
    let id: ProfileRequestID
}

/// Profile (docs/PROFILES.md): the public name every connected business sees, with a live preview; optional details by category, each
/// shared only with businesses you choose; and the Verified badge from an ID check.
struct ProfileView: View {
    @State private var vm: ProfileEditorViewModel
    @State private var editing: ProfileFieldDefinition?
    @State private var verifying = false
    @Environment(\.dismiss) private var dismiss

    init(api: any ProfileAPI) {
        _vm = State(initialValue: ProfileEditorViewModel(api: api))
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: ViadereSpace.l) {
                ViadereBackButton("Settings") { dismiss() }
                Text("Profile")
                    .font(ViadereType.display)
                    .foregroundStyle(ViadereColor.textPrimary)
                    .accessibilityAddTraits(.isHeader)
                publicNameCard
                verificationCard
                ForEach(vm.categories, id: \.category) { group in
                    categorySection(group.category, fields: group.fields)
                }
                if let error = vm.errorMessage { ViadereNotice(error, kind: .danger) }
                Text("Nothing here is shared until you allow it, business by business. You can stop sharing at any time from the business's page.")
                    .font(ViadereType.footnote)
                    .foregroundStyle(ViadereColor.textTertiary)
            }
            .padding(.horizontal, ViadereSpace.screen)
            .padding(.bottom, ViadereSpace.xl)
        }
        .scrollIndicators(.hidden)
        .viadereScreenBackground()
        .toolbar(.hidden, for: .navigationBar)
        .task { await vm.load() }
        .sheet(item: $editing) { definition in
            ProfileFieldEditor(definition: definition, vm: vm)
                .presentationDetents([.medium, .large])
                .presentationBackground(ViadereColor.background)
        }
        .sheet(isPresented: $verifying, onDismiss: { Task { await vm.load() } }) {
            ProfileVerificationSheet(api: AppEnvironment.shared.profileAPI)
                .presentationDetents([.large])
                .presentationBackground(ViadereColor.background)
        }
    }

    private var publicNameCard: some View {
        ViadereCard {
            VStack(alignment: .leading, spacing: ViadereSpace.s) {
                Text("Public name")
                    .font(ViadereType.headline)
                    .foregroundStyle(ViadereColor.textPrimary)
                Text("Every business you connect to sees this name. It's not private.")
                    .font(ViadereType.subhead)
                    .foregroundStyle(ViadereColor.textSecondary)
                ViadereTextField("Custom name (optional)", text: $vm.publicNameDraft, prompt: vm.profile.derivedPublicName ?? "First name and last initial",
                                 message: vm.publicNameIssue, isError: vm.publicNameIssue != nil)
                HStack(spacing: ViadereSpace.xs) {
                    Text("Businesses see")
                        .font(ViadereType.footnote)
                        .foregroundStyle(ViadereColor.textSecondary)
                    Text(vm.publicNamePreview ?? "No name yet")
                        .font(ViadereType.footnote.weight(.semibold))
                        .foregroundStyle(ViadereColor.textPrimary)
                }
                .accessibilityElement(children: .combine)
                Button("Save name") { Task { await vm.savePublicName() } }
                    .buttonStyle(.viadere(.secondary))
                    .disabled(vm.publicNameIssue != nil || vm.isSaving)
            }
        }
    }

    private var verificationCard: some View {
        ViadereCard {
            VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .top, spacing: ViadereSpace.s) {
                VStack(alignment: .leading, spacing: ViadereSpace.xxs) {
                    HStack(spacing: ViadereSpace.xs) {
                        Text("Verified profile")
                            .font(ViadereType.headline)
                            .foregroundStyle(ViadereColor.textPrimary)
                        if vm.isVerified { ViadereBadge("Verified", kind: .verified) }
                    }
                    Text(vm.isVerified
                         ? vm.profile.verified.map(\.fact.title).joined(separator: " · ")
                         : "Confirm facts with your ID in Apple Wallet or a document check. Only the facts you choose are kept, never the ID itself.")
                        .font(ViadereType.subhead)
                        .foregroundStyle(ViadereColor.textSecondary)
                }
                Spacer(minLength: 0)
            }
            Button(vm.isVerified ? "Verify again" : "Verify with your ID") { verifying = true }
                .buttonStyle(.viadere(vm.isVerified ? .secondary : .primary))
                .padding(.top, ViadereSpace.s)
            if vm.isVerified {
                Button("Remove verification") { Task { await vm.removeVerification() } }
                    .buttonStyle(.viadere(.quiet))
            }
            }
        }
    }

    private func categorySection(_ category: ProfileCategory, fields: [ProfileFieldDefinition]) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            ViadereSectionHeader(category.title)
            ViadereRowGroup {
                ForEach(Array(fields.enumerated()), id: \.element.key) { index, field in
                    Button { editing = field } label: {
                        ViadereRow(field.title, subtitle: subtitle(for: field))
                    }
                    .buttonStyle(.plain)
                    .accessibilityHint("Edit \(field.title)")
                    if index < fields.count - 1 { ViadereHairline() }
                }
            }
        }
    }

    private func subtitle(for field: ProfileFieldDefinition) -> String {
        let entries = vm.entries(for: field.key)
        if entries.isEmpty { return "Not added" }
        if field.isMultiEntry { return entries.map { "\($0.entry ?? "") \($0.value.displayText)" }.joined(separator: ", ") }
        return entries[0].value.displayText
    }
}

/// Adds, changes or removes one field. Choices use the catalog's options; addresses have their own fields.
struct ProfileFieldEditor: View {
    let definition: ProfileFieldDefinition
    let vm: ProfileEditorViewModel
    @State private var text = ""
    @State private var entry = ""
    @State private var line1 = ""
    @State private var line2 = ""
    @State private var locality = ""
    @State private var region = ""
    @State private var postalCode = ""
    @State private var country = "US"
    @Environment(\.dismiss) private var dismiss

    private var value: ProfileValue {
        definition.type == .address
            ? .address(ProfileAddress(line1: line1, line2: line2.isEmpty ? nil : line2, locality: locality, region: region.isEmpty ? nil : region,
                                      postalCode: postalCode.isEmpty ? nil : postalCode, country: country))
            : .text(text)
    }

    private var issue: String? {
        let empty = definition.type == .address ? line1.isEmpty && locality.isEmpty : text.isEmpty
        return empty ? nil : vm.issue(key: definition.key, entry: definition.isMultiEntry ? entry : nil, value: value)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: ViadereSpace.m) {
                Text(definition.title)
                    .font(ViadereType.title)
                    .foregroundStyle(ViadereColor.textPrimary)
                    .accessibilityAddTraits(.isHeader)
                Text(definition.summary)
                    .font(ViadereType.subhead)
                    .foregroundStyle(ViadereColor.textSecondary)
                if let label = definition.entryLabel {
                    ViadereTextField(label.capitalized, text: $entry, prompt: label == "airline" ? "UA" : "")
                }
                switch definition.type {
                case .address:
                    ViadereTextField("Address line 1", text: $line1)
                    ViadereTextField("Address line 2 (optional)", text: $line2)
                    ViadereTextField("City", text: $locality)
                    ViadereTextField("State or region (optional)", text: $region)
                    ViadereTextField("Postal code (optional)", text: $postalCode)
                    ViadereTextField("Country code", text: $country, prompt: "US")
                case .choice:
                    VStack(spacing: 0) {
                        ForEach(definition.allowedValues ?? [], id: \.self) { option in
                            Button { text = option } label: {
                                ViadereRow(option.replacingOccurrences(of: "_", with: " ").capitalized, subtitle: nil, leading: { EmptyView() }) {
                                    if text == option { Image(systemName: "checkmark").foregroundStyle(ViadereColor.accent).accessibilityLabel("Selected") }
                                }
                            }
                            .buttonStyle(.plain)
                        }
                    }
                default:
                    ViadereTextField(definition.title, text: $text, prompt: definition.type == .date ? "YYYY-MM-DD" : "")
                }
                if let issue { ViadereNotice(issue, kind: .warning) }
                Button("Save") {
                    Task { if await vm.set(key: definition.key, entry: definition.isMultiEntry ? entry : nil, value: value) { dismiss() } }
                }
                .buttonStyle(.viadere(.primary))
                .disabled(issue != nil || vm.isSaving)
                if !vm.entries(for: definition.key).isEmpty {
                    ForEach(vm.entries(for: definition.key), id: \.ref) { current in
                        Button("Remove \(current.entry.map { "\($0) " } ?? "")\(definition.title.lowercased())") {
                            Task { if await vm.remove(key: definition.key, entry: current.entry) { dismiss() } }
                        }
                        .buttonStyle(.viadere(.destructive))
                    }
                }
            }
            .padding(ViadereSpace.screen)
        }
        .onAppear {
            guard !definition.isMultiEntry, let current = vm.entries(for: definition.key).first else { return }
            switch current.value {
            case .text(let value): text = value
            case .address(let address):
                line1 = address.line1; line2 = address.line2 ?? ""; locality = address.locality
                region = address.region ?? ""; postalCode = address.postalCode ?? ""; country = address.country
            case .boolean: break
            }
        }
    }
}
