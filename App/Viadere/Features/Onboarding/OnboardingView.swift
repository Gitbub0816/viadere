import SwiftUI
import UIKit
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
            case .account: AccountStep(vm: vm)
            case .device: DeviceStep(vm: vm)
            case .notifications: NotificationsStep(vm: vm)
            case .phone, .done: PhoneStep(vm: vm)
            }
        }
        .animation(ViadereMotion.gentle, value: vm.step)
        .transition(.opacity)
        .viadereScreenBackground()
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
            }
            .padding(.horizontal, ViadereSpace.screen)
            .padding(.bottom, ViadereSpace.m)
        }
    }
}

private struct AccountStep: View {
    @Bindable var vm: OnboardingViewModel

    var body: some View {
        OnboardingScaffold(
            index: 0, title: "Create your account",
            message: "Viadere uses a passkey: nothing to remember, nothing to phish. Your iPhone will ask for Face ID or your passcode."
        ) {
            VStack(alignment: .leading, spacing: ViadereSpace.m) {
                ViadereTextField("Your name", text: $vm.displayName, prompt: "Ana Rivera",
                                 message: "Shown to businesses you connect with.")
                    .textContentType(.name)
                    .textInputAutocapitalization(.words)
                ErrorLine(message: vm.errorMessage)
            }
        } actions: {
            Button(vm.isWorking ? "Creating…" : "Create passkey") { Task { await vm.createAccount() } }
                .buttonStyle(.viadere(.primary))
                .disabled(!vm.canCreateAccount)
            Button("Sign in instead") { Task { await vm.signIn() } }
                .buttonStyle(.viadere(.quiet))
                .disabled(vm.isWorking)
        }
    }
}

private struct DeviceStep: View {
    @Bindable var vm: OnboardingViewModel

    var body: some View {
        OnboardingScaffold(
            index: 1, title: "Set up this iPhone",
            message: "Approvals are signed by a key created inside this iPhone's Secure Enclave. It can't be copied, exported or used on another device."
        ) {
            VStack(alignment: .leading, spacing: ViadereSpace.m) {
                ViadereTextField("Device name", text: $vm.deviceName, prompt: "Ana's iPhone",
                                 message: "You'll see this in your list of trusted devices.")
                ViadereRowGroup {
                    FactRow(symbol: "faceid", title: "Face ID for approvals", detail: "Required for purchases and high-risk sign-ins.")
                    ViadereHairline(inset: 50)
                    FactRow(symbol: "key", title: "A key that never leaves", detail: "Only a signature is ever sent, never the key.")
                }
                ErrorLine(message: vm.errorMessage)
            }
        } actions: {
            Button(vm.isWorking ? "Setting up…" : "Set up this iPhone") { Task { await vm.enrollDevice() } }
                .buttonStyle(.viadere(.primary))
                .disabled(vm.isWorking || vm.deviceName.trimmingCharacters(in: .whitespaces).isEmpty)
        }
    }
}

private struct NotificationsStep: View {
    @Bindable var vm: OnboardingViewModel

    var body: some View {
        OnboardingScaffold(
            index: 2, title: "Only when it matters",
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
