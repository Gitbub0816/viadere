import SwiftUI
import ViadereKit

/// Top-level switch: launching, onboarding, re-enrollment or the main shell, plus the app lock, toast and the
/// secure approval sheet that any notification, link or tap can present.
struct RootView: View {
    @Bindable var model: AppModel
    var capture: ScreenCaptureObserver

    var body: some View {
        // The lock is NOT drawn in this hierarchy: sheets would cover it. `AppLockWindowController` shows it in a
        // window above everything. Here the content is also hidden, made inert, and rebuilt (`.id(lockEpoch)`)
        // on every lock, which dismisses any sheet, alert or pushed screen presented from inside it.
        content
            .id(model.lockEpoch)
            .opacity(model.isLocked ? 0 : 1)
            .allowsHitTesting(!model.isLocked)
            .accessibilityHidden(model.isLocked)
        .animation(ViadereMotion.gentle, value: model.phase)
        .viadereScreenBackground()
        .passkeyExplanation(model.passkeyGate)
        .onChange(of: model.isLocked, initial: true) { _, locked in
            AppLockWindowController.shared.update(locked: locked, model: model)
        }
        .task { await model.bootstrap() }
        .sheet(item: $model.presentedApproval) { approval in
            ApprovalSheet(model: approval, capture: capture)
                .presentationDetents([.large])
                .presentationDragIndicator(.hidden)
                .presentationCornerRadius(ViadereRadius.sheet)
                .presentationBackground(ViadereColor.background)
        }
        .sheet(item: Binding(get: { AppEnvironment.shared.approve.presented }, set: { if $0 == nil { AppEnvironment.shared.approve.closePresented() } })) { prompt in
            ApproveRequestSheet(prompt: prompt, controller: AppEnvironment.shared.approve, capture: capture)
                .presentationDetents([.large])
                .presentationDragIndicator(.hidden)
                .presentationCornerRadius(ViadereRadius.sheet)
                .presentationBackground(ViadereColor.background)
        }
        .task(id: model.phase) {
            // Approve v2 requests are verified on this phone and shown here; poll gently while the app is open (pushes wake it too).
            guard model.phase == .ready else { return }
            while !Task.isCancelled {
                if !model.isLocked { await AppEnvironment.shared.approve.refresh() }
                try? await Task.sleep(for: .seconds(20))
            }
        }
        .overlay(alignment: .bottom) { ToastHost(model: model) }
    }

    @ViewBuilder private var content: some View {
        switch model.phase {
        case .launching:
            SplashView()
        case .onboarding(let step):
            OnboardingHost(model: model, start: step)
        case .needsReenrollment:
            ReenrollmentView(model: model)
        case .ready:
            MainShell(model: model)
        }
    }
}

/// Shows `model.toast` for a few seconds.
private struct ToastHost: View {
    @Bindable var model: AppModel

    var body: some View {
        Group {
            if let text = model.toast {
                ViadereToast(text)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
                    .task(id: text) {
                        try? await Task.sleep(for: .seconds(3))
                        model.toast = nil
                    }
            }
        }
        .animation(ViadereMotion.standard, value: model.toast)
    }
}

struct SplashView: View {
    var body: some View {
        VStack(spacing: ViadereSpace.l) {
            Spacer()
            ViadereAnimatedMark(height: 110)
            ViadereWordmark(size: 40)
            Text("A trusted way to connect.")
                .font(ViadereType.subhead)
                .tracking(1.2)
                .foregroundStyle(ViadereColor.textSecondary)
            Spacer()
        }
        .frame(maxWidth: .infinity)
        .viadereScreenBackground()
        .accessibilityElement(children: .combine)
        .accessibilityLabel(Text("Viadere. A trusted way to connect."))
    }
}

/// Face ID / passcode gate shown over everything when the optional app lock is on (hosted by `AppLockWindowController`).
struct AppLockView: View {
    let model: AppModel

    var body: some View {
        VStack(spacing: ViadereSpace.l) {
            Spacer()
            ViadereMark().frame(height: 64)
            Text("Viadere is locked")
                .font(ViadereType.title)
                .foregroundStyle(ViadereColor.textPrimary)
            Spacer()
            Button("Unlock with \(model.services.appLock.methodName)") {
                Task { await model.unlock() }
            }
            .buttonStyle(.viadere(.primary))
            .padding(.horizontal, ViadereSpace.screen)
            .padding(.bottom, ViadereSpace.xl)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .viadereScreenBackground()
        .task { await model.unlock() }
    }
}

/// Shown when the Secure Enclave keys were invalidated (Face ID re-enrolled, restore): approvals pause until the
/// owner confirms and the device is enrolled again.
struct ReenrollmentView: View {
    let model: AppModel
    @State private var isWorking = false
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.l) {
            Spacer()
            ViadereMark.monochrome(ViadereColor.textTertiary).frame(height: 36)
            Text("Set this iPhone up again")
                .font(ViadereType.display)
                .foregroundStyle(ViadereColor.textPrimary)
            Text("Your Face ID or device security changed, so the keys that approve requests on this iPhone were retired. You'll confirm it's you with your passkey to create new ones. Until then, requests can be approved on another device.")
                .font(ViadereType.body)
                .foregroundStyle(ViadereColor.textSecondary)
            if let errorMessage { ViadereNotice(errorMessage, kind: .danger) }
            Spacer()
            Button(isWorking ? "Setting up…" : "Set up again") {
                Task {
                    isWorking = true
                    errorMessage = nil
                    do { try await model.reenroll(deviceName: "iPhone") } catch {
                        if let passkey = error as? PasskeyError { if passkey != .cancelled { errorMessage = passkey.userMessage } }
                        else if let attest = error as? AppAttestError { errorMessage = attest.userMessage }
                        else { errorMessage = (error as? APIError)?.userMessage ?? "We couldn't set this iPhone up. Please try again." }
                    }
                    isWorking = false
                }
            }
            .buttonStyle(.viadere(.primary))
            .disabled(isWorking)
            Button("Sign out") { Task { await model.signOut() } }
                .buttonStyle(.viadere(.quiet))
        }
        .padding(.horizontal, ViadereSpace.screen)
        .padding(.bottom, ViadereSpace.l)
        .viadereScreenBackground()
    }
}
