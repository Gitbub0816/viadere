import SwiftUI
import ViadereCore
import ViadereKit

/// "Lost your devices?": recover the account with the recovery ID and one recovery code (§2.26). Hosted by onboarding (the person is
/// signed out). Calm and slow on purpose: the account waits 72 hours, and any device the person still has can cancel.
struct AccountRecoveryView: View {
    @Bindable var vm: AccountRecoveryViewModel
    let onBack: () -> Void
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        Group {
            switch vm.phase {
            case .entry, .working:
                entry
            case .passkeyNeeded:
                passkey
            case .holding(let hold):
                holding(hold)
            case .codes:
                if let codes = vm.codes {
                    RecoveryCodesView(model: codes, title: "Save your new recovery codes", continueTitle: "Continue") {
                        Task { await vm.confirmCodesSaved() }
                    }
                } else {
                    signingIn
                }
            case .signingIn, .done:
                signingIn
            case .ended(let ending):
                ended(ending)
            }
        }
        .animation(ViadereMotion.gentle, value: vm.phase)
        .viadereScreenBackground()
        .task { await vm.resumeIfPending() }
        // On open and when returning to the foreground: a throttled check, never a loop.
        .onChange(of: scenePhase) { _, phase in
            if phase == .active { Task { await vm.checkStatus() } }
        }
    }

    // MARK: Pieces

    private func page<Content: View, Actions: View>(title: String, message: String, @ViewBuilder content: () -> Content,
                                                    @ViewBuilder actions: () -> Actions) -> some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: ViadereSpace.l) {
                    ViadereMark.monochrome(ViadereColor.textTertiary).frame(height: 30).padding(.top, ViadereSpace.l)
                    VStack(alignment: .leading, spacing: ViadereSpace.s) {
                        Text(title).font(ViadereType.display).foregroundStyle(ViadereColor.textPrimary)
                            .fixedSize(horizontal: false, vertical: true)
                            .accessibilityAddTraits(.isHeader)
                        Text(message).font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    content()
                }
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.bottom, ViadereSpace.xl)
            }
            .scrollDismissesKeyboard(.interactively)
            .scrollIndicators(.hidden)
            VStack(spacing: ViadereSpace.xs) { actions() }
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.top, ViadereSpace.s)
                .padding(.bottom, ViadereSpace.m)
                .background(ViadereColor.background)
        }
    }

    private var entry: some View {
        page(title: "Lost your devices?",
             message: "Enter your recovery ID and one of the ten recovery codes you saved when you created your account. You'll then set up a new passkey on this iPhone.") {
            VStack(alignment: .leading, spacing: ViadereSpace.m) {
                ViadereTextField("Recovery ID", text: $vm.recoveryIdText, prompt: "ABCD-EFGH-JKMN",
                                 message: "12 characters, from your saved codes.", isError: vm.errorMessage != nil)
                    .textInputAutocapitalization(.characters)
                    .autocorrectionDisabled()
                ViadereTextField("Recovery code", text: $vm.codeText, prompt: "ABCDE-FGHJK",
                                 message: "Each code works once.", isError: vm.errorMessage != nil)
                    .textInputAutocapitalization(.characters)
                    .autocorrectionDisabled()
                if let message = vm.errorMessage { ViadereNotice(message, kind: .danger) }
            }
        } actions: {
            Button(vm.phase == .working ? "Checking…" : "Continue") { Task { await vm.submit() } }
                .buttonStyle(.viadere(.primary))
                .disabled(!vm.canSubmit)
            Button("Back", action: onBack).buttonStyle(.viadere(.quiet)).disabled(vm.phase == .working)
        }
    }

    private var passkey: some View {
        page(title: "Create a new passkey",
             message: "Your code was accepted and used. Next your iPhone creates a new passkey for your account. Your iPhone will ask for Face ID or your passcode.") {
            if let message = vm.errorMessage { ViadereNotice(message, kind: .danger) }
        } actions: {
            Button("Create passkey") { Task { await vm.registerPasskey() } }.buttonStyle(.viadere(.primary))
            Button("Start over") { vm.startOver() }.buttonStyle(.viadere(.quiet))
        }
    }

    private func holding(_ hold: RecoveryHold) -> some View {
        let now = Date()
        return page(title: "Recovery is on hold", message: AccountRecoveryViewModel.holdExplanation) {
            VStack(alignment: .leading, spacing: ViadereSpace.m) {
                ViadereRowGroup {
                    FactRow(symbol: "clock", title: hold.activatesAt > now ? "Ready \(CoolDownPolicy.timeText(hold.activatesAt, now: now))" : "Ready now",
                            detail: "Open Viadere then and finish setting up this iPhone.")
                    ViadereHairline(inset: 50)
                    FactRow(symbol: "iphone.gen3", title: "Your other devices can cancel",
                            detail: "If this wasn't you, any device you still have can stop it. Until then nothing changes on your account.")
                }
                if let status = vm.statusMessage { ViadereNotice(status, kind: .info) }
            }
        } actions: {
            Button("Check now") { Task { await vm.checkStatus(force: true) } }.buttonStyle(.viadere(.secondary))
            Button("Close", action: onBack).buttonStyle(.viadere(.quiet))
        }
    }

    private var signingIn: some View {
        page(title: "Signing you in",
             message: vm.codesWereNotDelivered
                ? "Your account is recovered. Your new recovery codes were shown earlier and can't be shown again, so generate a new set in Settings once you're in."
                : "Your account is recovered. Your iPhone will ask for Face ID or your passcode to sign in with the new passkey.") {
            if let message = vm.errorMessage { ViadereNotice(message, kind: .danger) } else { ViadereLoading(height: 32).frame(maxWidth: .infinity) }
        } actions: {
            Button("Sign in") { Task { await vm.signIn() } }.buttonStyle(.viadere(.primary))
                .disabled(vm.phase == .signingIn && vm.errorMessage == nil)
        }
    }

    private func ended(_ ending: AccountRecoveryViewModel.Ending) -> some View {
        page(title: ending == .cancelled ? "Recovery was cancelled" : "This recovery ended",
             message: ending == .cancelled
                ? "One of your devices cancelled it, and the recovery codes that started it no longer work. Nothing on your account changed."
                : "The time to finish it ran out. If you still need to recover your account, start again with another recovery code.") {
            EmptyView()
        } actions: {
            Button("Back", action: onBack).buttonStyle(.viadere(.primary))
        }
    }
}

#if DEBUG
#Preview("Recovery · entry") {
    PreviewHost(signedIn: false) { services in
        AccountRecoveryView(vm: AccountRecoveryViewModel(services: services)) {}
    }
}
#endif
