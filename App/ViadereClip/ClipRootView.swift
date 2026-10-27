import SwiftUI
import StoreKit
import ViadereKit

struct ClipRootView: View {
    @Bindable var flow: ClipFlowModel
    @State private var showOverlay = false

    var body: some View {
        Group {
            if flow.step == .recoveryCodes, let codes = flow.recoveryCodes {
                // Shown once, full screen, with its own pinned actions.
                RecoveryCodesView(model: codes) { Task { await flow.recoveryCodesSaved() } }
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: ViadereSpace.l) {
                        ViadereLockup(.horizontal, ribbonHeight: 26).padding(.top, ViadereSpace.l)
                        content
                    }
                    .padding(.horizontal, ViadereSpace.screen)
                    .padding(.bottom, ViadereSpace.xl)
                }
                .scrollIndicators(.hidden)
            }
        }
        .viadereScreenBackground()
        .passkeyExplanation(flow.passkeyGate)
        .animation(ViadereMotion.gentle, value: flow.step)
        .animation(ViadereMotion.gentle, value: flow.connect.phase)
        .appStoreOverlay(isPresented: $showOverlay) { SKOverlay.AppClipConfiguration(position: .bottom) }
        .onChange(of: flow.step) { _, step in
            if case .done = step { showOverlay = true }
        }
    }

    @ViewBuilder private var content: some View {
        switch flow.step {
        case .account:
            accountStep
        case .recoveryCodes:
            EmptyView()   // full screen: see `body`
        case .working:
            ViadereLoading(height: 36).frame(maxWidth: .infinity).padding(.top, ViadereSpace.xxl)
        case .done(let name):
            VStack(alignment: .leading, spacing: ViadereSpace.m) {
                Image(systemName: "checkmark.circle").font(.system(size: 44, weight: .light)).foregroundStyle(ViadereColor.success)
                Text("Connected to \(name)").font(ViadereType.display).foregroundStyle(ViadereColor.textPrimary)
                Text("Get the Viadere app to approve sign-ins and purchases right from your notifications.")
                    .font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
            }
        case .idle:
            switch flow.connect.phase {
            case .review(let profile):
                ConnectReview(vm: flow.connect, profile: profile, onConnect: { Task { await flow.continueTapped() } })
            case .resolving, .connecting:
                ViadereLoading(height: 36).frame(maxWidth: .infinity).padding(.top, ViadereSpace.xxl)
            case .failed(let message):
                ViadereNotice(message, kind: .danger)
            default:
                VStack(alignment: .leading, spacing: ViadereSpace.s) {
                    Text("A trusted way to connect.").font(ViadereType.display).foregroundStyle(ViadereColor.textPrimary)
                    Text("Scan a Viadere QR code or open a Viadere link to connect to a verified business.")
                        .font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
                }
            }
        }
    }

    private var accountStep: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.m) {
            Text("Create your account").font(ViadereType.display).foregroundStyle(ViadereColor.textPrimary)
            Text("A passkey keeps it safe: no password to remember or steal.")
                .font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
            ViadereTextField("Your name", text: $flow.displayName, prompt: "Ana Rivera")
                .textContentType(.name)
            if let error = flow.accountError { ViadereNotice(error, kind: .danger) }
            Button("Create passkey and connect") { Task { await flow.createAccountAndConnect() } }
                .buttonStyle(.viadere(.primary))
                .disabled(flow.displayName.trimmingCharacters(in: .whitespaces).isEmpty)
        }
    }
}
