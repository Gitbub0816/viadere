import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

public enum OnboardingStep: Int, Comparable, Sendable {
    /// `recovery` is "Lost your devices?" (§2.26); `recoveryCodes` is the one-time "Save your recovery codes" screen after sign-up.
    case welcome, recovery, account, recoveryCodes, device, notifications, phone, done
    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }
}

public enum OnboardingFlow {
    /// Where to resume after a relaunch.
    ///
    /// The recovery codes are never persisted, so there is nothing to resume on the codes screen: a person who left it unsaved
    /// continues at the device step and generates new codes in Settings. A recovery that is holding resumes on its own screen.
    public static func resume(hasSession: Bool, hasDevice: Bool, primingShown: Bool, complete: Bool, recoveryPending: Bool = false) -> OnboardingStep {
        if complete { return .done }
        if !hasSession { return recoveryPending ? .recovery : .welcome }
        if !hasDevice { return .device }
        if !primingShown { return .notifications }
        return .phone
    }
}

@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class OnboardingViewModel {
    public enum PhoneStage: Equatable, Sendable { case entry, verify, linked(String) }

    public private(set) var step: OnboardingStep
    public private(set) var isWorking = false
    public private(set) var errorMessage: String?
    public var displayName = ""
    public var deviceName: String
    public private(set) var enrolled: DeviceRecord?
    public private(set) var skippedKeys: [DeviceKeyPurpose] = []

    public private(set) var phoneRaw = ""
    public private(set) var otp = ""
    public private(set) var phoneStage: PhoneStage = .entry
    private var phoneLinkId: PhoneLinkID?
    private let services: ViadereServices
    /// Shows the passkey explanation before the system sheet when this enrollment needs an assertion.
    public let passkeyGate = PasskeyExplanationGate()
    public var onFinished: (@MainActor () -> Void)?
    /// The recovery codes from sign-up, on screen once (`.recoveryCodes`). Released as soon as they are confirmed saved.
    public private(set) var recoveryCodes: RecoveryCodesViewModel?
    /// "Lost your devices?". Created when the person opens it, or when a hold from an earlier launch is resumed.
    public private(set) var recovery: AccountRecoveryViewModel?

    public init(services: ViadereServices, deviceName: String = "My iPhone", start: OnboardingStep = .welcome) {
        self.services = services
        self.deviceName = deviceName
        self.step = start
    }

    public var canCreateAccount: Bool { !displayName.trimmingCharacters(in: .whitespaces).isEmpty && !isWorking }
    public var phoneNumber: PhoneNumber? { PhoneInput.normalize(phoneRaw) }
    public var canSendCode: Bool { phoneNumber != nil && !isWorking }
    public var canVerify: Bool { OTPInput.isComplete(otp) && !isWorking }
    public var maxAssurance: DecisionAssurance { enrolled?.maxAssurance ?? .none }

    private func run(_ work: () async throws -> Void) async {
        guard !isWorking else { return }
        isWorking = true
        errorMessage = nil
        defer { isWorking = false }
        do { try await work() } catch let error as APIError { errorMessage = error.userMessage }
        catch let error as PasskeyError { if error != .cancelled { errorMessage = error.userMessage } }
        catch let error as KeyStoreError { errorMessage = Self.message(for: error) }
        catch let error as AppAttestError { errorMessage = error.userMessage }
        catch { errorMessage = "Something went wrong. Please try again." }
    }

    private static func message(for error: KeyStoreError) -> String {
        switch error {
        case .userCancelled: "Setup was cancelled."
        case .unavailable: "This device can't store secure keys."
        default: "We couldn't set up secure keys on this device."
        }
    }

    public func begin() { step = .account }

    /// Formats as the person types (`(480) 555-0123`).
    public func setPhone(_ raw: String) { phoneRaw = PhoneInput.displayFormat(raw) }
    /// Digits only, six at most.
    public func setOTP(_ raw: String) { otp = OTPInput.normalize(raw) }

    public func createAccount() async {
        await run {
            let codes = try await services.account.signUp(displayName: displayName)
            // The codes exist only in this object, and only until they are saved.
            if let codes {
                recoveryCodes = RecoveryCodesViewModel(codes: codes)
                step = .recoveryCodes
            } else {
                step = .device
            }
        }
    }

    public func signIn() async {
        await run {
            try await services.account.signIn()
            // A returning person may already have a device record on this phone.
            if let record = try? await services.records.load() { enrolled = record; step = .notifications } else { step = .device }
        }
    }

    /// "I saved these": releases the codes and continues. Does nothing until the confirmation is ticked.
    public func recoveryCodesSaved() {
        guard let recoveryCodes, recoveryCodes.finish() else { return }
        self.recoveryCodes = nil
        step = .device
    }

    /// The codes screen went away without being confirmed (the app locked or was backgrounded). They are gone; Settings → Security →
    /// Recovery codes generates a new set. Setup continues.
    public func recoveryCodesLost() {
        recoveryCodes?.release()
        recoveryCodes = nil
        if step == .recoveryCodes { step = .device }
    }

    // MARK: Lost your devices?

    public func beginRecovery() {
        let model = AccountRecoveryViewModel(services: services)
        model.onSignedIn = { [weak self] in self?.recoveredAccountSignedIn() }
        recovery = model
        errorMessage = nil
        step = .recovery
    }

    /// Resumes a recovery whose hold was running when the app last closed.
    public func resumeRecoveryIfPending() async {
        if recovery == nil, RecoveryHoldStore(secrets: services.secrets).load() != nil { beginRecovery() }
        await recovery?.resumeIfPending()
    }

    public func leaveRecovery() {
        recovery = nil
        step = .welcome
    }

    private func recoveredAccountSignedIn() {
        recovery = nil
        // The new passkey is the account's passkey. Every old device was revoked, so anything left from an earlier install here is
        // stale: this iPhone is enrolled afresh, like any lapsed account's (it cools down and attests).
        Task { @MainActor in
            try? await services.records.clear()
            try? await services.keys.deleteAllKeys()
            enrolled = nil
            step = .device
        }
    }

    public func enrollDevice() async {
        await run {
            let record = try await services.account.enrollThisDevice(name: deviceName, explain: passkeyGate.explainer)
            enrolled = record
            skippedKeys = DeviceKeyPurpose.allCases.filter { !record.purposes.contains($0) }
            step = .notifications
        }
    }

    public func allowNotifications() async {
        _ = await services.notificationPermission.request()
        services.preferences.setBool(true, for: .notificationPrimingShown)
        step = .phone
    }

    public func skipNotifications() {
        services.preferences.setBool(true, for: .notificationPrimingShown)
        step = .phone
    }

    public func sendCode() async {
        guard let phone = phoneNumber else { return }
        await run {
            let response = try await services.api.startPhoneLink(phone: phone)
            phoneLinkId = response.phoneLinkId
            otp = ""
            phoneStage = .verify
        }
    }

    public func verifyCode() async {
        guard let id = phoneLinkId, OTPInput.isComplete(otp) else { return }
        await run {
            let link = try await services.api.verifyPhoneLink(id: id, code: otp)
            phoneStage = .linked(link.maskedPhone)
        }
    }

    public func editPhone() { phoneStage = .entry; otp = ""; errorMessage = nil }

    public func finish() {
        services.preferences.setBool(true, for: .onboardingComplete)
        step = .done
        onFinished?()
    }
}
