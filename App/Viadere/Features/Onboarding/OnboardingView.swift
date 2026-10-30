import SwiftUI
import UIKit
import ViadereCore
import ViadereKit

/// Owns the onboarding view model for the lifetime of the flow.
struct OnboardingHost: View {
    let model: AppModel
    @State private var viewModel: OnboardingViewModel

    init(model: AppModel, start: OnboardingStep) {
        self.model = model
        _viewModel = State(initialValue: OnboardingViewModel(services: model.services, deviceName: UIDevice.current.model, start: start))
    }

    var body: some View {
        OnboardingView(vm: viewModel)
            .onAppear {
                viewModel.onFinished = { Task { await model.completeOnboarding() } }
            }
    }
}

struct OnboardingView: View {
    @Bindable var vm: OnboardingViewModel

    var body: some View {
        Group {
            switch vm.step {
            case .welcome: WelcomeStep(vm: vm)
            case .recovery:
                if let recovery = vm.recovery {
                    AccountRecoveryView(vm: recovery) { vm.leaveRecovery() }
                } else {
                    WelcomeStep(vm: vm)
                }
            case .device: DeviceStep(vm: vm)
            case .notifications: NotificationsStep(vm: vm)
            case .protect: ProtectStep(vm: vm)
            case .recoveryCodes:
                if let codes = vm.recoveryCodes {
                    RecoveryCodesView(model: codes) { vm.recoveryCodesSaved() }
                } else {
                    // The codes were released (the app locked while they were showing): they can't come back. New ones can be made.
                    ProtectStep(vm: vm)
                }
            case .phone, .done: PhoneStep(vm: vm)
            }
        }
        .animation(ViadereMotion.gentle, value: vm.step)
        .transition(.opacity)
        .viadereScreenBackground()
        .passkeyExplanation(vm.passkeyGate)
        .task { if vm.step == .recovery { await vm.resumeRecoveryIfPending() } }
    }
}

// MARK: - Scaffold

/// Shared layout: quiet progress, a calm title and message, content, and pinned actions.
private struct OnboardingScaffold<Content: View, Actions: View>: View {
    let index: Int
    let title: String
    let message: String
    @ViewBuilder var content: Content
    @ViewBuilder var actions: Actions

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: ViadereSpace.l) {
                    HStack(spacing: 6) {
                        ForEach(0..<4, id: \.self) { dot in
                            Capsule()
                                .fill(dot <= index ? ViadereColor.textPrimary : ViadereColor.hairline)
                                .frame(width: dot == index ? 22 : 8, height: 4)
                        }
                    }
                    .padding(.top, ViadereSpace.l)
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel(Text("Step \(index + 1) of 4"))

                    VStack(alignment: .leading, spacing: ViadereSpace.s) {
                        Text(title)
                            .font(ViadereType.display)
                            .foregroundStyle(ViadereColor.textPrimary)
                            .fixedSize(horizontal: false, vertical: true)
                            .accessibilityAddTraits(.isHeader)
                        Text(message)
                            .font(ViadereType.body)
                            .foregroundStyle(ViadereColor.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    content
                }
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.bottom, ViadereSpace.xl)
            }
            .scrollDismissesKeyboard(.interactively)
            VStack(spacing: ViadereSpace.xs) { actions }
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.top, ViadereSpace.s)
                .padding(.bottom, ViadereSpace.m)
                .background(ViadereColor.background)
        }
    }
}

private struct ErrorLine: View {
    let message: String?
    var body: some View {
        if let message { ViadereNotice(message, kind: .danger) }
    }
}

// MARK: - Steps

private struct WelcomeStep: View {
    @Bindable var vm: OnboardingViewModel

    var body: some View {
        VStack(spacing: 0) {
            Spacer()
            VStack(spacing: ViadereSpace.l) {
                ViadereAnimatedMark(height: 104)
                ViadereWordmark(size: 44)
                Text("A trusted way to connect.")
                    .font(ViadereType.subhead)
                    .tracking(1.2)
                    .foregroundStyle(ViadereColor.textSecondary)
            }
            Spacer()
            VStack(alignment: .leading, spacing: ViadereSpace.s) {
                Text("Connect once to businesses you trust. Approve sign-ins and purchases in a tap, usually without opening the app.")
                    .font(ViadereType.body)
                    .foregroundStyle(ViadereColor.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                ErrorLine(message: vm.errorMessage)
                Button("Get started") { vm.begin() }
                    .buttonStyle(.viadere(.primary))
                    .padding(.top, ViadereSpace.xs)
                Button("I already have an account") { Task { await vm.signIn() } }
                    .buttonStyle(.viadere(.quiet))
                    .disabled(vm.isWorking)
                Button("Lost your devices?") { vm.beginRecovery() }
                    .buttonStyle(.viadere(.quiet))
                    .disabled(vm.isWorking)
            }
            .padding(.horizontal, ViadereSpace.screen)
            .padding(.bottom, ViadereSpace.m)
        }
    }
}

/// Consent and account creation in one place: what registering this iPhone stores, then "Agree and set up". No name, email, phone or
/// passkey is asked for (§2.5a). After a passkey sign-in the same step adds this iPhone to the existing account.
private struct DeviceStep: View {
    @Bindable var vm: OnboardingViewModel

    var body: some View {
        OnboardingScaffold(
            index: 0, title: vm.joinsExistingAccount ? "Add this iPhone" : "Set up this iPhone",
            message: vm.joinsExistingAccount
                ? "Your passkey found your account. This iPhone gets its own keys. It can't approve high-risk requests until one of your trusted devices approves it."
                : "Viadere doesn't ask for your name, email or phone number. This iPhone becomes your account, protected by its own Secure Enclave."
        ) {
            VStack(alignment: .leading, spacing: ViadereSpace.m) {
                ViadereTextField("Device name", text: $vm.deviceName, prompt: "iPhone",
                                 message: "Only you see this, in your list of devices.")
                Text("What registering this iPhone stores")
                    .font(ViadereType.subhead)
                    .foregroundStyle(ViadereColor.textSecondary)
                    .accessibilityAddTraits(.isHeader)
                ViadereRowGroup {
                    FactRow(symbol: "iphone", title: "A device record", detail: "The name above, the kind of device and when it was added.")
                    ViadereHairline(inset: 50)
                    FactRow(symbol: "key", title: "Public keys only",
                            detail: "Approval keys are made in the Secure Enclave and never leave this iPhone. Viadere keeps the public half.")
                    ViadereHairline(inset: 50)
                    FactRow(symbol: "checkmark.circle", title: "A genuine-app check",
                            detail: "Apple confirms this is the real Viadere app on a real iPhone. It says nothing about who you are.")
                    ViadereHairline(inset: 50)
                    FactRow(symbol: "faceid", title: "Face ID stays on your iPhone", detail: "Viadere never sees your face or passcode, only that you approved.")
                }
                ConsentLine()
                ErrorLine(message: vm.errorMessage)
            }
        } actions: {
            Button(vm.isWorking ? "Setting up…" : "Agree and set up") { Task { await vm.enrollDevice() } }
                .buttonStyle(.viadere(.primary))
                .disabled(!vm.canCreateAccount || vm.deviceName.trimmingCharacters(in: .whitespaces).isEmpty)
        }
    }
}

/// The terms and the privacy notice, as links. Continuing is the agreement.
private struct ConsentLine: View {
    private static let terms = URL(string: "https://\(ViadereCore.defaultDomain)/legal/consumer-terms/")
    private static let privacy = URL(string: "https://\(ViadereCore.defaultDomain)/legal/privacy-notice/")

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.xs) {
            Text("By continuing you agree to the Consumer Terms and confirm you've read the Privacy Notice.")
                .font(ViadereType.subhead)
                .foregroundStyle(ViadereColor.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: ViadereSpace.m) {
                if let terms = Self.terms { Link("Consumer Terms", destination: terms) }
                if let privacy = Self.privacy { Link("Privacy Notice", destination: privacy) }
            }
            .font(ViadereType.subhead)
            .tint(ViadereColor.textPrimary)
        }
    }
}

/// "Protect your account": optional recovery credentials. Skipping is allowed, after an honest warning.
private struct ProtectStep: View {
    @Bindable var vm: OnboardingViewModel

    var body: some View {
        OnboardingScaffold(
            index: 2, title: "Protect your account",
            message: "Optional. This iPhone is your account. Add a way back in case it's lost, reset or replaced."
        ) {
            VStack(alignment: .leading, spacing: ViadereSpace.m) {
                ViadereRowGroup {
                    FactRow(symbol: "person.badge.key", title: vm.hasPasskey ? "Passkey added" : "A passkey",
                            detail: vm.hasPasskey ? "A new iPhone on the same Apple Account can find your account with it."
                                                  : "Saved to iCloud Keychain, so a new iPhone can find your account.")
                    ViadereHairline(inset: 50)
                    FactRow(symbol: "list.number", title: vm.hasRecoveryCodes ? "Recovery codes saved" : "Recovery codes",
                            detail: "Ten one-time codes to print or keep in a password manager. They work without any of your devices.")
                }
                if vm.passkeyNotSynced, !vm.hasRecoveryCodes {
                    ViadereNotice("This passkey isn't synced, so it would be lost with this iPhone. Make recovery codes too.", kind: .warning)
                }
                Text("A new device, or one set up after a recovery, can't approve high-risk requests until one of your trusted devices approves it, or the business sets it up again.")
                    .font(ViadereType.subhead)
                    .foregroundStyle(ViadereColor.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                if vm.showsSkipWarning {
                    ViadereNotice(OnboardingViewModel.skipWarning, kind: .warning)
                }
                ErrorLine(message: vm.errorMessage)
            }
        } actions: {
            if vm.showsSkipWarning {
                Button("Go back") { vm.cancelSkip() }
                    .buttonStyle(.viadere(.primary))
                Button("Skip anyway") { vm.confirmSkipProtection() }
                    .buttonStyle(.viadere(.quiet))
            } else {
                if !vm.hasPasskey {
                    Button(vm.isWorking ? "Working…" : "Add a passkey") { Task { await vm.addPasskey() } }
                        .buttonStyle(.viadere(vm.isProtected ? .secondary : .primary))
                        .disabled(vm.isWorking)
                }
                if !vm.hasRecoveryCodes {
                    Button("Make recovery codes") { Task { await vm.makeRecoveryCodes() } }
                        .buttonStyle(.viadere(.secondary))
                        .disabled(vm.isWorking)
                }
                if vm.isProtected {
                    Button("Continue") { vm.continueFromProtection() }
                        .buttonStyle(.viadere(vm.hasPasskey && vm.hasRecoveryCodes ? .primary : .quiet))
                } else {
                    Button("Not now") { vm.skipProtection() }
                        .buttonStyle(.viadere(.quiet))
                        .disabled(vm.isWorking)
                }
            }
        }
    }
}

private struct NotificationsStep: View {
    @Bindable var vm: OnboardingViewModel

    var body: some View {
        OnboardingScaffold(
            index: 1, title: "Only when it matters",
            message: "Viadere interrupts you only when action is required: a sign-in to approve, a purchase to confirm. Nothing promotional unless you ask for it."
        ) {
            VStack(alignment: .leading, spacing: ViadereSpace.m) {
                ViadereRowGroup {
                    FactRow(symbol: "bell", title: "Approve from the notification", detail: "Most requests take one tap and never open the app.")
                    ViadereHairline(inset: 50)
                    FactRow(symbol: "moon", title: "Respects Focus", detail: "Only security requests are time sensitive.")
                }
                if vm.skippedKeys.contains(.approvalBiometric) {
                    ViadereNotice("Face ID isn't set up on this iPhone, so high-value approvals will need another device.", kind: .warning)
                }
            }
        } actions: {
            Button("Turn on notifications") {
                Task {
                    await vm.allowNotifications()
                    UIApplication.shared.registerForRemoteNotifications()
                }
            }
            .buttonStyle(.viadere(.primary))
            Button("Not now") { vm.skipNotifications() }
                .buttonStyle(.viadere(.quiet))
        }
    }
}

private struct PhoneStep: View {
    @Bindable var vm: OnboardingViewModel

    var body: some View {
        OnboardingScaffold(
            index: 3, title: stageTitle, message: stageMessage
        ) {
            VStack(alignment: .leading, spacing: ViadereSpace.m) {
                switch vm.phoneStage {
                case .entry:
                    ViadereTextField("Mobile number", text: Binding(get: { vm.phoneRaw }, set: { vm.setPhone($0) }),
                                     prompt: "(480) 555-0123", message: "We'll text a six-digit code.")
                        .keyboardType(.phonePad)
                        .textContentType(.telephoneNumber)
                case .verify:
                    ViadereOTPField(code: Binding(get: { vm.otp }, set: { vm.setOTP($0) }), isError: vm.errorMessage != nil)
                    Button("Use a different number") { vm.editPhone() }
                        .buttonStyle(.viadere(.quiet, fullWidth: false))
                case .linked(let masked):
                    ViadereNotice("\(masked) is linked. Texts from this number can now reach your verified businesses.", kind: .info)
                }
                ErrorLine(message: vm.errorMessage)
            }
        } actions: {
            switch vm.phoneStage {
            case .entry:
                Button(vm.isWorking ? "Sending…" : "Send code") { Task { await vm.sendCode() } }
                    .buttonStyle(.viadere(.primary))
                    .disabled(!vm.canSendCode)
                Button("Skip for now") { vm.finish() }
                    .buttonStyle(.viadere(.quiet))
            case .verify:
                Button(vm.isWorking ? "Verifying…" : "Verify") { Task { await vm.verifyCode() } }
                    .buttonStyle(.viadere(.primary))
                    .disabled(!vm.canVerify)
            case .linked:
                Button("Done") { vm.finish() }
                    .buttonStyle(.viadere(.primary))
            }
        }
    }

    private var stageTitle: String {
        if case .linked = vm.phoneStage { return "Phone linked" }
        return "Link your phone"
    }

    private var stageMessage: String {
        switch vm.phoneStage {
        case .entry: return "Optional. Link your number so businesses can reach you by text, and so you can text Viadere to find them. Approvals never happen by text."
        case .verify: return "Enter the code we just texted you."
        case .linked: return "You can manage linked numbers any time in Settings."
        }
    }
}

struct FactRow: View {
    let symbol: String
    let title: String
    let detail: String

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            ViadereIconTile(systemName: symbol)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                Text(detail).font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, ViadereSpace.s)
        .accessibilityElement(children: .combine)
    }
}

#if DEBUG
#Preview("Onboarding · welcome") {
    PreviewHost(signedIn: false) { services in
        OnboardingView(vm: OnboardingViewModel(services: services))
    }
}

#Preview("Onboarding · set up") {
    PreviewHost(signedIn: false) { services in
        OnboardingView(vm: OnboardingViewModel(services: services, start: .device))
    }
}

#Preview("Onboarding · protect") {
    PreviewHost(signedIn: false) { services in
        OnboardingView(vm: OnboardingViewModel(services: services, start: .protect))
    }
}

#Preview("Onboarding · notifications") {
    PreviewHost(signedIn: false) { services in
        OnboardingView(vm: OnboardingViewModel(services: services, start: .notifications))
    }
}

#Preview("Onboarding · phone") {
    PreviewHost(signedIn: false) { services in
        OnboardingView(vm: OnboardingViewModel(services: services, start: .phone))
    }
}
#endif
