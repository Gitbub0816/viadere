import SwiftUI
import UIKit
import ViadereKit

/// Sync, devices and the recovery key. Everything here is explicit: sync is off until the person turns it on, the recovery key is shown once
/// and must be typed back, and removing a device says plainly what it does and does not undo.
struct AuthenticatorSyncView: View {
    let model: AuthenticatorViewModel
    @State private var typedKey = ""
    @State private var showingAddDevice = false
    @State private var removing: VaultDeviceSummary?
    @State private var confirmingTurnOff = false
    @State private var checkingKey = false
    @State private var checkedKey = ""
    @State private var checkResult: Bool?
    @State private var replacingKey = false
    @State private var capture = ScreenCaptureObserver()

    var body: some View {
        SubScreen(title: "Sync and devices", subtitle: "Optional. End-to-end encrypted.", backTitle: "Authenticator") {
            if !(model.syncInfo?.enabled ?? false) { off } else { on }
            if let failure = model.syncFailure { ViadereNotice(failure, kind: .warning) }
        }
        .task { await model.loadDevices() }
        .sheet(isPresented: $showingAddDevice, onDismiss: { Task { await model.cancelAddingDevice() } }) {
            AddDeviceSheet(model: model) { showingAddDevice = false }
                .presentationDetents([.large])
                .presentationBackground(ViadereColor.background)
        }
        .confirmationDialog("Remove this device?", isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } }), titleVisibility: .visible) {
            Button("Remove and replace the vault key", role: .destructive) {
                if let device = removing { Task { await model.removeDevice(device.memberId) } }
                removing = nil
            }
            Button("Cancel", role: .cancel) { removing = nil }
        } message: {
            Text("It can't read anything you add from now on. If it was lost or stolen, also change the passwords and passkeys that were stored on it: it may have copied what it had.")
        }
        .confirmationDialog("Turn off sync?", isPresented: $confirmingTurnOff, titleVisibility: .visible) {
            Button("Turn off and delete the synced copy", role: .destructive) { Task { await model.turnOffSync(deleteFromServer: true) } }
            Button("Turn off, keep the synced copy", role: .none) { Task { await model.turnOffSync(deleteFromServer: false) } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This device keeps its own copy either way. Other devices keep theirs too, but stop updating.")
        }
    }

    // MARK: Off

    @ViewBuilder private var off: some View {
        switch model.syncStep {
        case .idle:
            ViadereCard(padding: ViadereSpace.m) {
                VStack(alignment: .leading, spacing: ViadereSpace.s) {
                    Text("Sync is end-to-end encrypted").font(ViadereType.headline).foregroundStyle(ViadereColor.textPrimary)
                    Text("Your passkeys and codes are encrypted on this iPhone with a key that never leaves your devices. Viadere's servers store only scrambled data they can't read, so Viadere can't see, use or recover your passkeys.")
                        .font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
                    Text("Because of that, if you lose every device you need your recovery key to get your vault back. Signing in to your Viadere account, or proving who you are, is not enough and can't replace it.")
                        .font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
                }
            }
            if !model.syncAvailable {
                ViadereNotice("Sync isn't available yet. Everything keeps working on this iPhone.", kind: .info)
            }
            Button("Turn on sync") { Task { await model.beginEnablingSync() } }
                .buttonStyle(.viadere(.primary))
                .disabled(!model.syncAvailable)
        case .showingRecoveryKey, .enabling:
            recoveryKeyStep
        }
    }

    private var recoveryKeyStep: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.m) {
            Text("Save your recovery key").font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
            Text("This is the only way back in if you lose all your devices. It's shown once. Write it down or store it in a safe place that isn't this iPhone.")
                .font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
            RecoveryKeyBox(text: model.recoveryKeyText, hidden: capture.isCaptured)
            ViadereNotice("Anyone with this key and access to your account can open your vault. Don't photograph it or save it in notes.", kind: .warning)
            Text("Type it back to confirm").font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
            keyField($typedKey)
            Button("Turn on sync") { Task { _ = await model.confirmRecoveryKeyAndEnableSync(typed: typedKey); typedKey = "" } }
                .buttonStyle(.viadere(.primary))
                .disabled(typedKey.count < 20 || model.syncStep == .enabling)
            Button("Cancel") { model.cancelEnablingSync(); typedKey = "" }.buttonStyle(.viadere(.quiet))
        }
    }

    // MARK: On

    @ViewBuilder private var on: some View {
        let info = model.syncInfo
        ViadereCard(padding: ViadereSpace.m) {
            VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                Text("Sync is on").font(ViadereType.headline).foregroundStyle(ViadereColor.textPrimary)
                Text(info?.pendingChanges == 0 ? "Everything is up to date." : "\(info?.pendingChanges ?? 0) change(s) waiting to upload.")
                    .font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                Button("Sync now") { Task { await model.syncNow() } }
                    .buttonStyle(.viadere(.secondary, fullWidth: false)).disabled(model.isWorking)
            }
        }
        ViadereSectionHeader("Devices")
        ViadereRowGroup {
            ForEach(Array(model.devices.enumerated()), id: \.element.id) { index, device in
                ViadereRow(device.label + (device.isThisDevice ? " (this iPhone)" : ""), subtitle: deviceSubtitle(device),
                           leading: { ViadereIconTile(systemName: device.isRecovery ? "key" : "iphone") }, trailing: {
                    if !device.isThisDevice && !device.isRecovery {
                        Button { removing = device } label: { Image(systemName: "minus.circle").foregroundStyle(ViadereColor.danger).frame(width: 44, height: 44) }
                            .accessibilityLabel(Text("Remove \(device.label)"))
                    }
                })
                if index < model.devices.count - 1 { ViadereHairline() }
            }
        }
        Button { showingAddDevice = true } label: { Label("Add a device", systemImage: "plus") }.buttonStyle(.viadere(.secondary))
        ViadereSectionHeader("Recovery key")
        recoverySection(info)
        Button("Turn off sync", role: .destructive) { confirmingTurnOff = true }.buttonStyle(.viadere(.destructive)).padding(.top, ViadereSpace.m)
    }

    private func deviceSubtitle(_ device: VaultDeviceSummary) -> String {
        if device.isRecovery { return "Restores your vault if every device is lost" }
        if device.accountDeviceActive == false { return "Its Viadere sign-in was revoked: remove it" }
        return "Added " + device.addedAt.formatted(date: .abbreviated, time: .omitted)
    }

    @ViewBuilder private func recoverySection(_ info: VaultEngine.SyncInfo?) -> some View {
        if info?.hasRecoveryKey == true {
            ViadereCard(padding: ViadereSpace.m) {
                VStack(alignment: .leading, spacing: ViadereSpace.s) {
                    Text("Check that you still have it").font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                    keyField($checkedKey)
                    Button("Check") { Task { checkResult = await model.verifyRecoveryKey(checkedKey); checkedKey = "" } }
                        .buttonStyle(.viadere(.secondary, fullWidth: false)).disabled(checkedKey.count < 20)
                    if let checkResult {
                        ViadereNotice(checkResult ? "That is your recovery key." : "That doesn't match this vault's recovery key.", kind: checkResult ? .info : .danger)
                    }
                    Button("Make a new recovery key") { replacingKey = true; Task { await model.beginReplacingRecoveryKey() } }
                        .buttonStyle(.viadere(.quiet))
                }
            }
            .sheet(isPresented: $replacingKey, onDismiss: { model.cancelEnablingSync() }) {
                ReplaceRecoveryKeySheet(model: model) { replacingKey = false }
                    .presentationBackground(ViadereColor.background)
            }
        } else {
            ViadereNotice("You have no recovery key. If you lose every device, your vault can't be restored.", kind: .warning)
            Button("Make a recovery key") { replacingKey = true; Task { await model.beginReplacingRecoveryKey() } }.buttonStyle(.viadere(.secondary))
                .sheet(isPresented: $replacingKey, onDismiss: { model.cancelEnablingSync() }) {
                    ReplaceRecoveryKeySheet(model: model) { replacingKey = false }.presentationBackground(ViadereColor.background)
                }
        }
    }

    private func keyField(_ text: Binding<String>) -> some View {
        TextField("VRK1-…", text: text, axis: .vertical)
            .font(ViadereType.code)
            .textInputAutocapitalization(.characters)
            .autocorrectionDisabled()
            .textContentType(.none)
            .padding(ViadereSpace.m)
            .background(RoundedRectangle(cornerRadius: ViadereRadius.card, style: .continuous).fill(ViadereColor.surface))
            .overlay(RoundedRectangle(cornerRadius: ViadereRadius.card, style: .continuous).strokeBorder(ViadereColor.hairline, lineWidth: 1))
    }
}

/// The recovery key as text. Not selectable, not copyable by long-press, hidden while the screen is recorded.
struct RecoveryKeyBox: View {
    let text: String?
    let hidden: Bool

    var body: some View {
        ViadereCard(padding: ViadereSpace.m) {
            Text(hidden ? "Hidden while your screen is recorded" : (text ?? ""))
                .font(ViadereType.code)
                .foregroundStyle(ViadereColor.textPrimary)
                .lineSpacing(6)
                .textSelection(.disabled)
                .privacySensitive()
                .accessibilityLabel(Text("Recovery key"))
        }
    }
}

struct ReplaceRecoveryKeySheet: View {
    let model: AuthenticatorViewModel
    let onClose: () -> Void
    @State private var typed = ""
    @State private var rotate = true
    @State private var capture = ScreenCaptureObserver()

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: ViadereSpace.m) {
                ViadereGrabber().frame(maxWidth: .infinity)
                Text("Your new recovery key").font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary).padding(.top, ViadereSpace.m)
                RecoveryKeyBox(text: model.recoveryKeyText, hidden: capture.isCaptured)
                Text("Write it down. It's shown once. The old key stops working.").font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
                Toggle(isOn: $rotate) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Also replace the vault key").font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                        Text("Recommended if the old recovery key may have been seen by someone else.").font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                    }
                }
                .toggleStyle(.viadere)
                TextField("Type the new key to confirm", text: $typed, axis: .vertical)
                    .font(ViadereType.code).textInputAutocapitalization(.characters).autocorrectionDisabled()
                    .padding(ViadereSpace.m)
                    .background(RoundedRectangle(cornerRadius: ViadereRadius.card, style: .continuous).fill(ViadereColor.surface))
                if let failure = model.syncFailure { ViadereNotice(failure, kind: .warning) }
                Button("Save new key") { Task { if await model.confirmRecoveryKeyReplacement(typed: typed, rotateVaultKey: rotate) { onClose() } } }
                    .buttonStyle(.viadere(.primary)).disabled(typed.count < 20)
                Button("Cancel", action: onClose).buttonStyle(.viadere(.quiet))
            }
            .padding(ViadereSpace.screen)
        }
    }
}

/// Shown on the approving device: the pairing code and QR code, then the request that arrives, then biometric approval.
struct AddDeviceSheet: View {
    let model: AuthenticatorViewModel
    let onClose: () -> Void

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: ViadereSpace.m) {
                ViadereGrabber().frame(maxWidth: .infinity)
                Text("Add a device").font(ViadereType.display).foregroundStyle(ViadereColor.textPrimary).padding(.top, ViadereSpace.m)
                if let invite = model.invite {
                    Text("On the other device, open Authenticator, choose “Already use Authenticator on another device?” and scan this code or type it.")
                        .font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
                    QRCodeView(payload: invite.qrPayload, size: 200).frame(maxWidth: .infinity)
                    Text(invite.code).font(ViadereType.code).foregroundStyle(ViadereColor.textPrimary).textSelection(.disabled).frame(maxWidth: .infinity)
                    if let preview = model.joinPreview {
                        ViadereCard(padding: ViadereSpace.m) {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("“\(preview.deviceLabel)” wants to join").font(ViadereType.headline).foregroundStyle(ViadereColor.textPrimary)
                                Text("Only approve a device you are holding. Its fingerprint: \(preview.fingerprint)").font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                            }
                        }
                        Button("Approve with Face ID") { Task { if await model.approveJoin() { onClose() } } }.buttonStyle(.viadere(.primary))
                    } else {
                        HStack(spacing: ViadereSpace.s) {
                            ViadereLoading()
                            Text("Waiting for the other device").font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                        }
                    }
                } else {
                    ViadereLoading().frame(maxWidth: .infinity)
                }
                if let message = model.message { ViadereNotice(message, kind: .warning) }
                Button("Cancel") { Task { await model.cancelAddingDevice(); onClose() } }.buttonStyle(.viadere(.quiet))
            }
            .padding(ViadereSpace.screen)
        }
        .task {
            await model.beginAddingDevice()
            // The code lives ten minutes; poll for the other device while the sheet is open.
            while !Task.isCancelled, model.invite != nil, model.joinPreview == nil {
                await model.checkForJoinRequest()
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }
}
