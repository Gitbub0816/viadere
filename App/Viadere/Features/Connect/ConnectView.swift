import SwiftUI
import ViadereCore
import ViadereKit

/// One field for everything: `@handle`, a permanent code (auto-formatted `AF-2345`), a link or a name,
/// plus the code scanner. Every path converges on the same verified-business review.
struct ConnectView: View {
    @Bindable var model: AppModel
    @State private var vm: ConnectViewModel
    @State private var showingScanner = false
    /// A business link session (WP-C1) opened from a QR, a link, or typed codes.
    @State private var linkSession: PendingLinkSession?
    @State private var showingLinkCodeEntry = false

    init(model: AppModel) {
        self.model = model
        _vm = State(initialValue: ConnectViewModel(services: model.services))
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: ViadereSpace.l) {
                    ViadereHeader("Add business", subtitle: subtitle) {
                        ViadereIconButton(systemName: "xmark", label: "Close") { model.addBusinessPresented = false }
                    }
                    switch vm.phase {
                    case .entry, .failed:
                        entry
                    case .resolving, .connecting:
                        loading
                    case .choose(let matches):
                        chooser(matches)
                    case .review(let profile):
                        ConnectReview(vm: vm, profile: profile)
                    case .connected(let relationship):
                        ConnectedState(relationship: relationship, model: model) { vm.reset() }
                    }
                }
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.bottom, ViadereSpace.xl)
            }
            .scrollDismissesKeyboard(.interactively)
            .scrollIndicators(.hidden)
            .viadereScreenBackground()
            .toolbar(.hidden, for: .navigationBar)
        }
        .viadereAnimation(ViadereMotion.gentle, value: vm.phase)
        .sensoryFeedback(.warning, trigger: vm.phase) { _, now in
            if case .failed = now { return true }
            return false
        }
        .task(id: model.pendingConnect) {
            guard let pending = model.pendingConnect else { return }
            model.pendingConnect = nil
            await vm.open(code: pending.code, link: pending.link, source: pending.source == .code ? .code : .qr)
        }
        .task(id: model.businessToOpen) {
            // A business link (`@handle`) for a business the customer isn't connected to yet: review it here first.
            guard let handle = model.businessToOpen else { return }
            model.businessToOpen = nil
            vm.setInput(handle.display)
            await vm.submit()
        }
        .task(id: model.scannedLookup) {
            // A handle or code read by the shell's scanner.
            guard let text = model.scannedLookup else { return }
            model.scannedLookup = nil
            await vm.handleScanned(text)
        }
        .task(id: model.pendingLinkSession) {
            guard let pending = model.pendingLinkSession else { return }
            model.pendingLinkSession = nil
            linkSession = pending
        }
        .fullScreenCover(isPresented: $showingScanner) {
            CodeScannerScreen { payload, symbology in
                // `ScannedCodePolicy` decides; this sheet only routes what it accepted.
                switch ScannedCodePolicy.evaluate(payload, symbology: symbology) {
                case .rejected(let reason):
                    return reason
                case .lookup(let text):
                    showingScanner = false
                    Task { await vm.handleScanned(text) }
                case .open(.linkSession(let code, let secret)):
                    // A business's link-session code (`/k/…`) opens the link sheet.
                    showingScanner = false
                    linkSession = PendingLinkSession(code: code, secret: secret)
                case .open(.connect(let code, let link)):
                    showingScanner = false
                    Task { await vm.open(code: code, link: link, source: .qr) }
                case .open(let link):
                    // A sign-in, verification, enrollment or Loop code: Add business steps aside and the shell opens its review.
                    showingScanner = false
                    model.addBusinessPresented = false
                    Task { await model.handle(link) }
                }
                return nil
            } onClose: { showingScanner = false }
            .viaderePullDownToDismiss() // the scanner closes with a downward pull, like a sheet
        }
        .sheet(item: $linkSession) { pending in
            LinkSessionSheet(controller: AppEnvironment.shared.link, pending: pending)
                .presentationDetents([.large])
        }
        .sheet(isPresented: $showingLinkCodeEntry) {
            LinkCodeEntrySheet { pending in linkSession = pending }
                .presentationDetents([.medium, .large])
        }
    }

    private var subtitle: String {
        switch vm.phase {
        case .review, .connected, .connecting: "Verified by Viadere"
        default: "A handle, a code, a link or a name"
        }
    }

    // MARK: Entry

    @ViewBuilder private var entry: some View {
        if case .failed(let message) = vm.phase { ViadereNotice(message, kind: .danger) }
        if let scanError = vm.scanError { ViadereNotice(scanError, kind: .warning) }

        ViadereEntryField(
            placeholder: "@handle, AF-2345 or a name",
            text: Binding(get: { vm.input }, set: { vm.setInput($0) }),
            status: fieldStatus, hint: hint, monospaced: vm.state.kind == .code,
            onSubmit: { Task { await vm.submit() } })

        if let code = vm.state.alsoCode {
            Button("Use \(code.display) as a code") { Task { await vm.submitAsCode() } }
                .buttonStyle(.viadere(.quiet, fullWidth: false))
        }

        if !vm.suggestions.isEmpty {
            ViadereRowGroup {
                ForEach(Array(vm.suggestions.enumerated()), id: \.element.id) { index, business in
                    Button { Task { await vm.select(business) } } label: {
                        ViadereRow(business.safeName, subtitle: business.handle?.display ?? business.code.display) {
                            ViadereAvatar(name: business.safeName, size: 36, isVerified: true)
                        }
                    }
                    .buttonStyle(.viaderePressable)
                    if index < vm.suggestions.count - 1 { ViadereHairline(inset: 50) }
                }
            }
        }

        VStack(spacing: ViadereSpace.xs) {
            Button("Continue") { Task { await vm.submit() } }
                .buttonStyle(.viadere(.primary))
                .disabled(!vm.state.canSubmit)
            Button {
                showingScanner = true
            } label: {
                HStack(spacing: ViadereSpace.xs) {
                    Image(systemName: "qrcode.viewfinder")
                    Text("Scan a code")
                }
            }
            .buttonStyle(.viadere(.secondary))
            if AppEnvironment.shared.link.isAvailable {
                Button("Link with a code from a business") { showingLinkCodeEntry = true }
                    .buttonStyle(.viadere(.quiet))
            }
        }
        .padding(.top, ViadereSpace.xs)
        .task(id: vm.input) {
            try? await Task.sleep(for: .milliseconds(300))
            guard !Task.isCancelled else { return }
            await vm.refreshSuggestions()
        }

        Text("Codes use letters and numbers. We treat I as 1 and O as 0, so you can't mistype them.")
            .font(ViadereType.footnote)
            .foregroundStyle(ViadereColor.textTertiary)
            .padding(.top, ViadereSpace.xs)
    }

    private var fieldStatus: ViadereEntryField.Status {
        switch vm.state.validation {
        case .valid: .valid
        case .invalid: .invalid
        default: .none
        }
    }

    private var hint: String? {
        switch vm.state.validation {
        case .incomplete(let text), .invalid(let text): text
        case .valid: vm.state.kind == .code ? "Looks good" : nil
        case .none: vm.state.kind == .empty ? "Try @harborbank, HB-7K29 or \"Copperline\"" : nil
        }
    }

    @ViewBuilder private var loading: some View {
        if case .connecting = vm.phase {
            ViadereLoadingState("Connecting…")
        } else {
            ViadereLoadingState("Looking it up…")
        }
    }

    private func chooser(_ matches: [BusinessSummary]) -> some View {
        VStack(alignment: .leading, spacing: ViadereSpace.s) {
            Text("Which one?").font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
            Text("These are verified businesses that match.").font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
            ViadereRowGroup {
                ForEach(Array(matches.enumerated()), id: \.element.id) { index, business in
                    Button { Task { await vm.select(business) } } label: {
                        ViadereRow(business.safeName, subtitle: business.handle?.display ?? business.code.display) {
                            ViadereAvatar(name: business.safeName, size: 36, isVerified: true)
                        }
                    }
                    .buttonStyle(.viaderePressable)
                    if index < matches.count - 1 { ViadereHairline(inset: 50) }
                }
            }
            Button("Back") { vm.backToEntry() }.buttonStyle(.viadere(.quiet))
        }
    }
}

private struct ConnectedState: View {
    let relationship: Relationship
    let model: AppModel
    let onDone: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.l) {
            // The drawn mark carries the success haptic and the VoiceOver announcement.
            ViadereOutcome(.success, "Connected to \(relationship.business.safeName)",
                           detail: "Sign-in and approval requests will reach you here, usually as a notification you can answer in one tap.")
            VStack(spacing: ViadereSpace.xs) {
                Button("Done") {
                    onDone()
                    model.selectedTab = .businesses
                    model.addBusinessPresented = false
                    Task {
                        await model.home.load()
                        await model.refreshOrganization()
                    }
                }
                .buttonStyle(.viadere(.primary))
                Button("Send a message") {
                    Task {
                        if await model.messages.start(with: relationship.business.id) != nil { model.selectedTab = .messages }
                        onDone()
                        model.addBusinessPresented = false
                        await model.refreshOrganization()
                    }
                }
                .buttonStyle(.viadere(.secondary))
            }
        }
        .padding(.top, ViadereSpace.l)
    }
}

#if DEBUG
#Preview("Connect") {
    PreviewHost { services in ConnectView(model: AppModel(services: services)) }
}
#endif
