import SwiftUI
import ViadereCore
import ViadereKit

/// A Loop's page and install sheet (SECURITY.md §2.98 "Installed Loops"): who built it (verified name and badge, never business-styled),
/// what it is (the reviewed title and description), what it can do (`LoopPermissionsView`, derived on the device from the definition the
/// device verified against the signed publication), and the customer's choice: add it only, or add it and connect. Nothing is added without
/// Loops turned on (the education) and an explicit tap.
struct LoopDetailView: View {
    let model: AppModel
    var backTitle: String?
    @State private var detail: LoopDetailViewModel
    @State private var showingEducation = false
    @State private var confirmingRemove = false
    @State private var justInstalled: InstalledLoop?
    @Environment(\.dismiss) private var dismiss

    init(model: AppModel, loopId: LoopDefinitionID, source: LoopInstallSource, backTitle: String? = nil) {
        self.model = model
        self.backTitle = backTitle
        let consent = model.loopConsent
        let keys = model.loopKeys
        _detail = State(initialValue: LoopDetailViewModel(loopId: loopId, source: source, api: model.services.loopsAPI, keys: { keys.keys },
                                                          consent: { consent.status }, library: model.loopLibrary,
                                                          onConsent: { consent.adopt($0) }, clock: model.services.clock))
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: ViadereSpace.l) {
                if let backTitle { ViadereBackButton(backTitle) { dismiss() } }
                switch detail.status {
                case .loading:
                    ViadereLoading()
                case .unavailable:
                    ViadereEmptyState("Not available", message: "This Loop isn't available to you right now.")
                case .failed(let message):
                    ViadereNotice(message, kind: .warning)
                    Button("Try again") { Task { await detail.load() } }
                        .buttonStyle(.viadere(.secondary))
                case .ready:
                    if let entry = detail.entry { ready(entry) }
                }
            }
            .padding(.horizontal, ViadereSpace.screen)
            .padding(.vertical, ViadereSpace.m)
        }
        .scrollIndicators(.hidden)
        .viadereScreenBackground()
        .toolbar(.hidden, for: .navigationBar)
        .task {
            if model.loopConsent.status == nil { await model.loopConsent.load() }
            await detail.load()
        }
        .sheet(isPresented: $showingEducation) {
            LoopConsentFlowView(consent: model.loopConsent) { enabled in
                if enabled { Task { await install() } }
            }
            .presentationDetents([.large])
            .presentationBackground(ViadereColor.background)
        }
        .confirmationDialog("Remove this Loop?", isPresented: $confirmingRemove, titleVisibility: .visible) {
            Button("Remove", role: .destructive) { Task { _ = await detail.uninstall() } }
            Button("Keep", role: .cancel) {}
        } message: {
            Text(detail.isConnected ? "Its open requests are cancelled. You stay connected to the business." : "Its open requests are cancelled.")
        }
    }

    @ViewBuilder private func ready(_ entry: LoopDirectoryEntry) -> some View {
        identity(entry)
        if let summary = detail.summary {
            Text(summary)
                .font(ViadereType.body)
                .foregroundStyle(ViadereColor.textPrimary)
                .fixedSize(horizontal: false, vertical: true)
        }
        if let category = entry.category, category.isKnown {
            Label(category.title, systemImage: category.symbol)
                .font(ViadereType.subhead)
                .foregroundStyle(ViadereColor.textSecondary)
        }
        LoopPermissionsView(items: detail.permissions)
        if detail.isInstalled {
            installedActions(entry)
        } else {
            choice(entry)
            installButton(entry)
        }
        if let error = detail.errorMessage { ViadereNotice(error, kind: .warning) }
    }

    /// The verified business, in neutral colors: the Loop's own text sits below it, never in its place.
    private func identity(_ entry: LoopDirectoryEntry) -> some View {
        HStack(alignment: .center, spacing: ViadereSpace.s) {
            LoopIcon(business: entry.business, brand: model.services.brandKits, size: 56)
            VStack(alignment: .leading, spacing: 4) {
                Text(detail.title)
                    .font(ViadereType.title)
                    .foregroundStyle(ViadereColor.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)
                Text(LoopDirectoryViewModel.attribution(entry.business))
                    .font(ViadereType.subhead)
                    .foregroundStyle(ViadereColor.textSecondary)
                ViadereBadge(entry.business.isVerified ? "Verified business" : "Not verified", kind: entry.business.isVerified ? .verified : .danger)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(Text("\(detail.title). Built by \(entry.business.safeName), a verified business on Viadere"))
    }

    /// Install only, or install and connect: two plain selectable rows (VoiceOver reads the selection), install only first.
    @ViewBuilder private func choice(_ entry: LoopDirectoryEntry) -> some View {
        if detail.offersConnect {
            VStack(alignment: .leading, spacing: 0) {
                ViadereSectionHeader("How to add it")
                ViadereRowGroup {
                    choiceRow(.installOnly, title: "Add the Loop only",
                              detail: "\(entry.business.safeName) sees only what you send with it. No connection, no messages.")
                    ViadereHairline(inset: 36)
                    choiceRow(.installAndConnect, title: "Add and connect",
                              detail: "Also connect to \(entry.business.safeName), as when you add a business.")
                }
            }
        } else {
            ViadereNotice("You're connected to \(entry.business.safeName). Removing this Loop later doesn't change that.", kind: .info)
        }
    }

    private func choiceRow(_ mode: LoopInstallMode, title: String, detail text: String) -> some View {
        let selected = detail.mode == mode
        return Button {
            detail.mode = mode
        } label: {
            HStack(alignment: .top, spacing: ViadereSpace.s) {
                Image(systemName: selected ? "largecircle.fill.circle" : "circle")
                    .foregroundStyle(selected ? ViadereColor.textPrimary : ViadereColor.textTertiary)
                    .padding(.top, 2)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                    Text(text).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary).fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }
            .padding(.vertical, ViadereSpace.s)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
    }

    @ViewBuilder private func installButton(_ entry: LoopDirectoryEntry) -> some View {
        if let sentence = detail.authorizationSentence {
            Text(sentence)
                .font(ViadereType.footnote)
                .foregroundStyle(ViadereColor.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        if detail.needsGlobalConsent {
            ViadereNotice("First, a short explanation of how Loops work. It takes a minute.", kind: .info)
        }
        Button(detail.mode == .installAndConnect && detail.offersConnect ? "Add and connect" : "Add Loop") {
            Task {
                if detail.needsGlobalConsent { showingEducation = true } else { await install() }
            }
        }
        .buttonStyle(.viadere(.primary))
        .disabled(!detail.canInstall)
        .accessibilityHint(Text("Adds \(detail.title) to Your Loops"))
    }

    private func install() async {
        switch await detail.install() {
        case .installed(let installed):
            justInstalled = installed
            model.toast = installed.connected && detail.mode == .installAndConnect ? "Added and connected." : "Added to Your Loops."
            if installed.connected { await model.businesses.load() }
        case .needsGlobalConsent:
            showingEducation = true
        case .failed:
            break
        }
    }

    @ViewBuilder private func installedActions(_ entry: LoopDirectoryEntry) -> some View {
        ViadereBadge("In Your Loops", kind: .success)
        if let installed = justInstalled ?? model.loopLibrary.loops.first(where: { $0.loopId == entry.loopId }), installed.isStartable {
            Button("Open") {
                Task { await AppEnvironment.shared.loops.startInstalled(installed, model: model) }
            }
            .buttonStyle(.viadere(.primary))
        }
        Button("Remove Loop") { confirmingRemove = true }
            .buttonStyle(.viadere(.quiet))
    }
}

/// The plugin-style permission list: one row per item, Viadere's words, the business's field labels as plain text.
struct LoopPermissionsView: View {
    let items: [LoopPermissionItem]

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ViadereSectionHeader("What this Loop can do")
            ViadereRowGroup {
                ForEach(Array(items.enumerated()), id: \.element.id) { index, item in
                    HStack(alignment: .top, spacing: ViadereSpace.s) {
                        Image(systemName: item.symbol)
                            .font(.system(size: 17, weight: .regular))
                            .foregroundStyle(ViadereColor.textSecondary)
                            .frame(width: 24)
                            .accessibilityHidden(true)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(item.title).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                                .fixedSize(horizontal: false, vertical: true)
                            if !item.fields.isEmpty {
                                ViadereFlowLayout(spacing: ViadereSpace.xxs) {
                                    ForEach(item.fields, id: \.self) { field in
                                        Text(field)
                                            .font(ViadereType.footnote)
                                            .foregroundStyle(ViadereColor.textPrimary)
                                            .padding(.horizontal, ViadereSpace.xs)
                                            .padding(.vertical, 3)
                                            .background(Capsule().fill(ViadereColor.track))
                                    }
                                }
                            }
                            if let detail = item.detail {
                                Text(detail).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                        Spacer(minLength: 0)
                    }
                    .padding(.vertical, ViadereSpace.s)
                    .accessibilityElement(children: .combine)
                    if index < items.count - 1 { ViadereHairline(inset: 36) }
                }
            }
        }
    }
}

/// Presents the install sheet when an install link (`/lp/{loopId}`) opens the app (`AppModel.loopToInstall`). The one-line hook for the
/// shell: `.loopInstallLinks(model:)`.
struct LoopInstallLinkModifier: ViewModifier {
    @Bindable var model: AppModel

    func body(content: Content) -> some View {
        content.sheet(item: Binding(get: { model.loopToInstall.map(PresentedLoop.init) }, set: { model.loopToInstall = $0?.id })) { presented in
            NavigationStack {
                LoopDetailView(model: model, loopId: presented.id, source: .link)
            }
            .presentationDetents([.large])
            .presentationCornerRadius(ViadereRadius.sheet)
            .presentationBackground(ViadereColor.background)
        }
    }

    private struct PresentedLoop: Identifiable {
        let id: LoopDefinitionID
    }
}

extension View {
    func loopInstallLinks(model: AppModel) -> some View { modifier(LoopInstallLinkModifier(model: model)) }
}
