import SwiftUI
import ViadereKit

/// Passkeys and one-time codes. Opening the vault asks for Face ID / Touch ID / the passcode; leaving the app locks it again.
struct AuthenticatorView: View {
    let backTitle: String
    @State private var model: AuthenticatorViewModel?
    @State private var showingAdd = false
    @State private var deleting: AuthenticatorViewModel.Row?
    @State private var confirmingErase = false
    @State private var toast: String?
    @Environment(\.scenePhase) private var scenePhase
    @State private var capture = ScreenCaptureObserver()

    init(backTitle: String = "Back") {
        self.backTitle = backTitle
        _model = State(initialValue: AuthenticatorHub.shared.model)
    }

    var body: some View {
        SubScreen(title: "Authenticator", subtitle: "Passkeys and one-time codes, encrypted on this device.", backTitle: backTitle) {
            if let model {
                content(model)
            } else {
                ViadereNotice("Authenticator isn't available on this build.", kind: .warning)
            }
        }
        .overlay(alignment: .bottom) { if let toast { ViadereToast(toast).transition(.opacity) } }
        .task { await model?.load() }
        .task(id: model?.phase) {
            // The codes tick once a second while the list is on screen.
            while !Task.isCancelled, model?.phase == .ready {
                await model?.tick()
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
        .onChange(of: scenePhase) { _, phase in
            // `.inactive` also happens while the Face ID sheet is up, so only the background locks.
            if phase == .background { Task { await model?.lock() } }
        }
        .sheet(isPresented: $showingAdd) {
            if let model {
                AddCodeSheet(model: model) { showingAdd = false }
                    .presentationDetents([.large])
                    .presentationBackground(ViadereColor.background)
            }
        }
        .confirmationDialog("Delete everything in Authenticator on this iPhone?", isPresented: $confirmingErase, titleVisibility: .visible) {
            Button("Delete from this iPhone", role: .destructive) {
                Task { await AuthenticatorHub.shared.wipe(); await model?.load() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Passkeys and codes stored only here are gone for good. If sync is on, your other devices and the encrypted synced copy are not touched.")
        }
        .confirmationDialog("Delete this item?", isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } }), titleVisibility: .visible) {
            Button("Delete", role: .destructive) {
                if let row = deleting { Task { await model?.delete(row.id); await refreshIdentityStore() } }
                deleting = nil
            }
            Button("Cancel", role: .cancel) { deleting = nil }
        } message: {
            Text(deleting?.kind == .passkey
                 ? "The passkey is removed from Authenticator (and from your other devices if sync is on). Sign-in with it stops working; the site may still let you remove it from your account there."
                 : "You'll no longer get codes for this account here. Make sure you can still sign in to it another way.")
        }
    }

    @ViewBuilder private func content(_ model: AuthenticatorViewModel) -> some View {
        if let message = model.message { ViadereNotice(message, kind: .warning) }
        switch model.phase {
        case .loading:
            ViadereLoading().frame(maxWidth: .infinity).padding(.top, ViadereSpace.xl)
        case .failed(let text):
            ViadereNotice(text, kind: .danger)
        case .empty:
            ViadereEmptyState("Keep your passkeys and codes here",
                              message: "Authenticator stores them encrypted. Opening them takes Face ID or your passcode, and nothing leaves this iPhone unless you turn on sync.",
                              actionTitle: "Set up Authenticator") { Task { await model.createVault() } }
                .padding(.top, ViadereSpace.l)
            joinCard(model)
        case .locked:
            VStack(spacing: ViadereSpace.m) {
                ViadereIconTile(systemName: "lock")
                Text("Locked").font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
                Text("Unlock with Face ID or your passcode to see your codes.").font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary).multilineTextAlignment(.center)
                Button("Unlock") { Task { await model.unlock() } }.buttonStyle(.viadere(.primary))
            }
            .frame(maxWidth: .infinity)
            .padding(.top, ViadereSpace.xl)
        case .ready:
            ready(model)
        }
    }

    @ViewBuilder private func ready(_ model: AuthenticatorViewModel) -> some View {
        if capture.isCaptured {
            ViadereNotice("Your screen is being recorded or mirrored, so codes are hidden.", kind: .warning)
        }
        let codes = model.rows.filter { $0.kind == .code }
        let passkeys = model.rows.filter { $0.kind == .passkey }
        HStack {
            Spacer()
            Button { showingAdd = true } label: { Label("Add a code", systemImage: "plus") }
                .buttonStyle(.viadere(.secondary, fullWidth: false))
        }
        if model.rows.isEmpty {
            ViadereNotice("Nothing here yet. Add a code from a site's two-step setup page, or save a passkey when a site offers to.", kind: .info)
        }
        if !codes.isEmpty {
            ViadereSectionHeader("Codes")
            ViadereRowGroup {
                ForEach(Array(codes.enumerated()), id: \.element.id) { index, row in
                    codeRow(row, model: model)
                    if index < codes.count - 1 { ViadereHairline() }
                }
            }
        }
        if !passkeys.isEmpty {
            ViadereSectionHeader("Passkeys")
            ViadereRowGroup {
                ForEach(Array(passkeys.enumerated()), id: \.element.id) { index, row in
                    ViadereRow(row.title, subtitle: row.subtitle, leading: { ViadereIconTile(systemName: "person.badge.key") }, trailing: {
                        Button { deleting = row } label: { Image(systemName: "trash").foregroundStyle(ViadereColor.textTertiary).frame(width: 44, height: 44) }
                            .accessibilityLabel(Text("Delete passkey for \(row.title)"))
                    })
                    if index < passkeys.count - 1 { ViadereHairline() }
                }
            }
        }
        NavigationLink {
            AuthenticatorSyncView(model: model)
        } label: {
            ViadereRow("Sync and devices", subtitle: syncSubtitle(model), leading: { ViadereIconTile(systemName: "arrow.triangle.2.circlepath") })
        }
        .buttonStyle(.plain)
        .padding(.top, ViadereSpace.s)
        Toggle(isOn: Binding(get: { AuthenticatorPreferences.suggestInAutoFill }, set: { newValue in
            AuthenticatorPreferences.suggestInAutoFill = newValue
            Task { if newValue { await refreshIdentityStore() } else { await IdentityStoreSync.clear() } }
        })) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Suggest in AutoFill").font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                Text("Lets iOS offer your passkeys on sign-in screens. iOS then keeps each site and account name (not the keys or codes). Turn off to keep even that out of the system.")
                    .font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
            }
        }
        .toggleStyle(.viadere)
        .padding(.top, ViadereSpace.m)
        Button("Lock now") { Task { await model.lock() } }.buttonStyle(.viadere(.quiet)).padding(.top, ViadereSpace.s)
        Button("Delete Authenticator from this iPhone", role: .destructive) { confirmingErase = true }.buttonStyle(.viadere(.quiet)).padding(.top, ViadereSpace.xs)
    }

    private func syncSubtitle(_ model: AuthenticatorViewModel) -> String {
        guard let info = model.syncInfo else { return "Off" }
        if !info.enabled { return "Off: stored on this iPhone only" }
        return info.pendingChanges == 0 ? "On: end-to-end encrypted, \(info.deviceCount) device\(info.deviceCount == 1 ? "" : "s")" : "On: \(info.pendingChanges) change\(info.pendingChanges == 1 ? "" : "s") waiting"
    }

    private func codeRow(_ row: AuthenticatorViewModel.Row, model: AuthenticatorViewModel) -> some View {
        Button {
            guard let code = model.codeToCopy(row.id), !capture.isCaptured else { return }
            SecurePasteboard.copy(code)
            withAnimation { toast = "Copied. It clears from the clipboard in a minute." }
            Task { try? await Task.sleep(nanoseconds: 2_500_000_000); withAnimation { toast = nil } }
        } label: {
            HStack(spacing: ViadereSpace.m) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(row.title).font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                    if !row.subtitle.isEmpty { Text(row.subtitle).font(ViadereType.footnote).foregroundStyle(ViadereColor.textTertiary) }
                    Text(capture.isCaptured ? "••• •••" : (row.spacedCode ?? "••• •••"))
                        .font(.system(size: 30, weight: .medium, design: .monospaced))
                        .foregroundStyle(ViadereColor.textPrimary)
                        .privacySensitive()
                }
                Spacer(minLength: 0)
                if let remaining = row.secondsRemaining, let period = row.period {
                    ViadereCountdownRing(progress: Double(remaining) / Double(period), label: "\(remaining)", spokenLabel: "Code changes in \(remaining) seconds")
                }
            }
            .padding(.vertical, ViadereSpace.s)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityHint(Text("Copies the code"))
        .contextMenu { Button("Delete", role: .destructive) { deleting = row } }
    }

    private func joinCard(_ model: AuthenticatorViewModel) -> some View {
        NavigationLink {
            AuthenticatorJoinView(model: model)
        } label: {
            ViadereRow("Already use Authenticator on another device?", subtitle: "Add this device, or restore with your recovery key",
                       leading: { ViadereIconTile(systemName: "iphone.and.arrow.forward") })
        }
        .buttonStyle(.plain)
        .padding(.top, ViadereSpace.l)
    }

    private func refreshIdentityStore() async {
        guard AuthenticatorPreferences.suggestInAutoFill, let engine = AuthenticatorHub.shared.engine else { return }
        await IdentityStoreSync.replace(from: engine)
    }
}
