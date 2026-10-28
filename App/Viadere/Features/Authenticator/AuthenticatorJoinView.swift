import SwiftUI
import ViadereKit

/// A new device joins an existing vault (pairing code from a device that already has it) or restores it with the recovery key.
/// Signing in to the Viadere account is not part of either: it can't open the vault.
///
/// Restoring has three guarded steps: ask for the recovery envelope and wait out the 72-hour hold (the person's other devices are told and can
/// cancel), check the vault (when it last changed, its devices, how many items) before anything is committed, then confirm the new recovery key.
struct AuthenticatorJoinView: View {
    let model: AuthenticatorViewModel
    enum Mode: Hashable { case choose, pair, waiting, release, check, preview, recoveryKeyShown }
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
            case .release: release
            case .check: check
            case .preview: preview
            case .recoveryKeyShown: newKey
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
            Button { mode = .release } label: { Label("Restore with my recovery key", systemImage: "key") }.buttonStyle(.viadere(.secondary))
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
            Text("It will show this device's name and a code, and ask for Face ID. Check that the code there is the same as this one:")
                .font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
            if let fingerprint = model.ownFingerprint {
                Text(fingerprint).font(ViadereType.code).foregroundStyle(ViadereColor.textPrimary)
                    .accessibilityLabel("Device code \(fingerprint)")
            }
            Text("If the codes differ, don't approve it.").font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
        }
        .task {
            while !Task.isCancelled {
                if await model.completeJoin() { return }
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }

    private var release: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.m) {
            Text("Ask for your recovery key's envelope").font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
            let state = model.restoreRelease?.state
            if let release = model.restoreRelease, state == .holding {
                ViadereNotice("Your other devices were told. Nothing is released until the wait is over.", kind: .info)
                Text("Available").font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                Text(release.releaseAt, format: .dateTime.weekday().day().month().hour().minute()).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                Button("Cancel this request") { Task { await model.cancelRestoreRelease() } }.buttonStyle(.viadere(.secondary))
            } else if let release = model.restoreRelease, state == .released, release.requestedByThisDevice {
                ViadereNotice("Ready. You have until the time below to restore.", kind: .info)
                Text(release.expiresAt, format: .dateTime.weekday().day().month().hour().minute()).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                Button("Continue") { mode = .check }.buttonStyle(.viadere(.primary))
            } else {
                Text("To protect your vault, Viadere waits 72 hours before it hands your recovery key's envelope to a new device, and tells all your other devices so they can stop it. Signing in to your account is not enough.")
                    .font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
                if state == .cancelled || state == .expired { ViadereNotice("The last request was cancelled or ran out. You can ask again.", kind: .warning) }
                Button("Ask for it") { Task { await model.requestRestoreRelease() } }.buttonStyle(.viadere(.primary)).disabled(model.isWorking)
            }
        }
        .task {
            while !Task.isCancelled {
                await model.checkRestoreRelease()
                try? await Task.sleep(nanoseconds: 30_000_000_000)
            }
        }
    }

    private var check: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.m) {
            Text("Enter your recovery key").font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
            Text("Viadere checks your vault on this device first. Nothing changes until you confirm.").font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
            TextField("VRK1-…", text: $recoveryKey, axis: .vertical)
                .font(ViadereType.code).textInputAutocapitalization(.characters).autocorrectionDisabled()
                .padding(ViadereSpace.m)
                .background(RoundedRectangle(cornerRadius: ViadereRadius.card, style: .continuous).fill(ViadereColor.surface))
            Button("Check my vault") {
                Task { if await model.previewRestore(recoveryKey: recoveryKey) { mode = .preview } }
            }
            .buttonStyle(.viadere(.primary)).disabled(recoveryKey.count < 20 || model.isWorking)
        }
    }

    private var preview: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.m) {
            Text("Is this your vault?").font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
            if let preview = model.restorePreview {
                VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                    Text("Last changed").font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                    Text(preview.lastChange, format: .dateTime.day().month().year().hour().minute()).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                    if let by = preview.lastChangedBy { Text("on \(by)").font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary) }
                }
                VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                    Text("Devices").font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                    ForEach(preview.deviceNames, id: \.self) { Text($0).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary) }
                }
                Text("\(preview.passkeyCount) passkeys · \(preview.codeCount) codes").font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                ViadereNotice("If the date is older than your last change, or the devices or counts are not what you expect, stop here: someone may be showing you an older copy.", kind: .warning)
            }
            Button("This is my vault") { mode = .recoveryKeyShown; Task { await model.beginRestore() } }.buttonStyle(.viadere(.primary))
            Button("Not my vault") {
                Task { await model.discardRestorePreview(); recoveryKey = ""; mode = .choose }
            }
            .buttonStyle(.viadere(.secondary))
        }
    }

    private var newKey: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.m) {
            Text("Now a new recovery key").font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
            Text("Restoring uses up your old recovery key and replaces your vault key. Write down the new recovery key, then type it to confirm. It's shown once.")
                .font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
            RecoveryKeyBox(text: model.recoveryKeyText, hidden: capture.isCaptured)
            TextField("Type the new key to confirm", text: $newKeyTyped, axis: .vertical)
                .font(ViadereType.code).textInputAutocapitalization(.characters).autocorrectionDisabled()
                .padding(ViadereSpace.m)
                .background(RoundedRectangle(cornerRadius: ViadereRadius.card, style: .continuous).fill(ViadereColor.surface))
            ViadereNotice("Every other device is removed from the vault when you restore. You can add them again afterwards.", kind: .info)
            Button("Restore my vault") {
                Task {
                    if await model.restore(confirmingNewKey: newKeyTyped) { recoveryKey = ""; newKeyTyped = "" }
                }
            }
            .buttonStyle(.viadere(.primary)).disabled(newKeyTyped.count < 20 || model.isWorking)
        }
    }
}
