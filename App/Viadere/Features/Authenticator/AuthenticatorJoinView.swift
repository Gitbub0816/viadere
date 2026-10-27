import SwiftUI
import ViadereKit

/// A new device joins an existing vault (pairing code from a device that already has it) or restores it with the recovery key.
/// Signing in to the Viadere account is not part of either: it can't open the vault.
struct AuthenticatorJoinView: View {
    let model: AuthenticatorViewModel
    enum Mode: Hashable { case choose, pair, waiting, recoveryKeyShown, restore }
    @State private var mode: Mode = .choose
    @State private var code = ""
    @State private var recoveryKey = ""
    @State private var newKeyTyped = ""
    @State private var scanning = false
    @State private var capture = ScreenCaptureObserver()

    var body: some View {
        SubScreen(title: "Use your vault here", subtitle: "Add this device or restore it.", backTitle: "Authenticator") {
            switch mode {
            case .choose: choose
            case .pair: pair
            case .waiting: waiting
            case .recoveryKeyShown: newKey
            case .restore: restore
            }
            if let message = model.message { ViadereNotice(message, kind: .warning) }
        }
        .fullScreenCover(isPresented: $scanning) {
            ZStack(alignment: .topTrailing) {
                AuthenticatorQRScanner { text in
                    scanning = false
                    // The QR carries `viadere-vault://pair?c=CODE`; only the code is used.
                    if let components = URLComponents(string: text), components.scheme == "viadere-vault", let value = components.queryItems?.first(where: { $0.name == "c" })?.value {
                        code = value
                    }
                }
                .ignoresSafeArea()
                ViadereIconButton(systemName: "xmark", label: "Cancel scanning") { scanning = false }.padding(ViadereSpace.m)
            }
        }
    }

    private var choose: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.m) {
            Button { mode = .pair } label: { Label("Add this device from another device", systemImage: "iphone.and.arrow.forward") }.buttonStyle(.viadere(.primary))
            Button { mode = .recoveryKeyShown; Task { await model.beginRestore() } } label: { Label("Restore with my recovery key", systemImage: "key") }.buttonStyle(.viadere(.secondary))
            Text("Signing in to Viadere doesn't open your vault. That's deliberate: only your devices or your recovery key can.")
                .font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
        }
    }

    private var pair: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.m) {
            Text("On a device that already has your vault, open Authenticator → Sync and devices → Add a device. Scan its code or type it here.")
                .font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
            Button { scanning = true } label: { Label("Scan the code", systemImage: "qrcode.viewfinder") }.buttonStyle(.viadere(.secondary))
            TextField("XXXX-XXXX-XXXX-…", text: $code, axis: .vertical)
                .font(ViadereType.code).textInputAutocapitalization(.characters).autocorrectionDisabled()
                .padding(ViadereSpace.m)
                .background(RoundedRectangle(cornerRadius: ViadereRadius.card, style: .continuous).fill(ViadereColor.surface))
                .overlay(RoundedRectangle(cornerRadius: ViadereRadius.card, style: .continuous).strokeBorder(ViadereColor.hairline, lineWidth: 1))
            Button("Ask to join") {
                Task { if await model.requestJoin(code: code) { code = ""; mode = .waiting } }
            }
            .buttonStyle(.viadere(.primary)).disabled(code.count < 20)
        }
    }

    private var waiting: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.m) {
            HStack(spacing: ViadereSpace.s) {
                ViadereLoading()
                Text("Approve this device on the other one").font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
            }
            Text("It will show this device's name and ask for Face ID.").font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
        }
        .task {
            while !Task.isCancelled {
                if await model.completeJoin() { return }
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }

    private var newKey: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.m) {
            Text("First, a new recovery key").font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
            Text("Restoring uses up your old recovery key and replaces your vault key. Write down the new recovery key before you continue. It's shown once.")
                .font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
            RecoveryKeyBox(text: model.recoveryKeyText, hidden: capture.isCaptured)
            TextField("Type the new key to confirm", text: $newKeyTyped, axis: .vertical)
                .font(ViadereType.code).textInputAutocapitalization(.characters).autocorrectionDisabled()
                .padding(ViadereSpace.m)
                .background(RoundedRectangle(cornerRadius: ViadereRadius.card, style: .continuous).fill(ViadereColor.surface))
            Button("Continue") { mode = .restore }.buttonStyle(.viadere(.primary)).disabled(newKeyTyped.count < 20)
        }
    }

    private var restore: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.m) {
            Text("Enter your old recovery key").font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
            TextField("VRK1-…", text: $recoveryKey, axis: .vertical)
                .font(ViadereType.code).textInputAutocapitalization(.characters).autocorrectionDisabled()
                .padding(ViadereSpace.m)
                .background(RoundedRectangle(cornerRadius: ViadereRadius.card, style: .continuous).fill(ViadereColor.surface))
            ViadereNotice("Every other device is removed from the vault when you restore. You can add them again afterwards.", kind: .info)
            Button("Restore my vault") {
                Task {
                    if await model.restore(recoveryKey: recoveryKey, confirmingNewKey: newKeyTyped) { recoveryKey = ""; newKeyTyped = "" }
                }
            }
            .buttonStyle(.viadere(.primary)).disabled(recoveryKey.count < 20 || model.isWorking)
        }
    }
}
