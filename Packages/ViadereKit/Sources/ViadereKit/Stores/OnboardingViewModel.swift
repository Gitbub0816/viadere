import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

public enum OnboardingStep: Int, Comparable, Sendable {
    /// `welcome` is the consent screen (what registering this device stores). `recovery` is "Lost your devices?" (§2.26). `device` creates
    /// the account from this iPhone (§2.5a) or, after a passkey sign-in, enrolls it. `protect` offers the optional recovery credentials;
    /// `recoveryCodes` shows a new set once.
    case welcome, recovery, device, notifications, protect, recoveryCodes, phone, done
    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }
}

public enum OnboardingFlow {
    /// Where to resume after a relaunch.
    ///
    /// The recovery codes are never persisted, so there is nothing to resume on the codes screen: a person who left it unsaved continues
    /// at the protect step (and can make new codes there or in Settings). A recovery that is holding resumes on its own screen.
    public static func resume(hasSession: Bool, hasDevice: Bool, primingShown: Bool, protectionShown: Bool = true, complete: Bool,
                              recoveryPending: Bool = false) -> OnboardingStep {
        if complete { return .done }
        if !hasSession { return recoveryPending ? .recovery : .welcome }
        if !hasDevice { return .device }
        if !primingShown { return .notifications }
        if !protectionShown { return .protect }
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
    public var deviceName: String
    public private(set) var enrolled: DeviceRecord?
    public private(set) var skippedKeys: [DeviceKeyPurpose] = []

    public private(set) var phoneRaw = ""
    public private(set) var otp = ""
    public private(set) var phoneStage: PhoneStage = .entry
    private var phoneLinkId: PhoneLinkID?
    private let services: ViadereServices
    /// Shows the passkey explanation before the system sheet when an enrollment after a passkey sign-in needs an assertion.
    public let passkeyGate = PasskeyExplanationGate()
    public var onFinished: (@MainActor () -> Void)?
    /// A new set of recovery codes, on screen once (`.recoveryCodes`). Released as soon as they are confirmed saved.
    public private(set) var recoveryCodes: RecoveryCodesViewModel?
    /// "Lost your devices?". Created when the person opens it, or when a hold from an earlier launch is resumed.
    public private(set) var recovery: AccountRecoveryViewModel?

    // "Protect your account"
    public private(set) var hasRecoveryCodes = false
    public private(set) var hasPasskey = false
    /// The passkey can't be synced (iCloud Keychain off): recovery codes are the way back if this iPhone is lost.
    public private(set) var passkeyNotSynced = false
    /// The honest warning is on screen; a second, explicit confirmation skips.
    public private(set) var showsSkipWarning = false

    public static let skipWarning =
        "If you lose this iPhone and have no other device, your account can't be recovered. Your connections and history would be lost."

    public init(services: ViadereServices, deviceName: String = "My iPhone", start: OnboardingStep = .welcome) {
        self.services = services
        self.deviceName = deviceName
        self.step = start
    }

    /// No personal field is needed: only that nothing else is running.
    public var canCreateAccount: Bool { !isWorking }
    public var phoneNumber: PhoneNumber? { PhoneInput.normalize(phoneRaw) }
    public var canSendCode: Bool { phoneNumber != nil && !isWorking }
    public var canVerify: Bool { OTPInput.isComplete(otp) && !isWorking }
    public var maxAssurance: DecisionAssurance { enrolled?.maxAssurance ?? .none }
    /// At least one recovery credential was added during setup.
    public var isProtected: Bool { hasRecoveryCodes || hasPasskey }

    private func run(_ work: () async throws -> Void) async {
        guard !isWorking else { return }
        isWorking = true
        errorMessage = nil
        defer { isWorking = false }
        do { try await work() } catch let error as APIError { errorMessage = error.userMessage }
        catch let error as PasskeyError { if error != .cancelled { errorMessage = error.userMessage } }
        catch let error as KeyStoreError { errorMessage = Self.message(for: error) }
        catch let error as AppAttestError { errorMessage = error.userMessage }
        catch let error as ConfirmationError { if error != .userCancelled { errorMessage = error.userMessage } }
        catch { errorMessage = "Something went wrong. Please try again." }
    }

    private static func message(for error: KeyStoreError) -> String {
        switch error {
        case .userCancelled: "Setup was cancelled."
        case .unavailable: "This device can't store secure keys."
        default: "We couldn't set up secure keys on this device."
        }
    }

    /// "Continue" on the consent screen.
    public func begin() {
        errorMessage = nil
        step = .device
    }

    public func setPhone(_ raw: String) { phoneRaw = PhoneInput.displayFormat(raw) }
    /// Digits only, six at most.
    public func setOTP(_ raw: String) { otp = OTPInput.normalize(raw) }

    /// "I already have an account": a passkey sign-in (an existing account, or discovering it on a new iPhone). This iPhone is then enrolled
    /// with that account and starts unapproved until one of its trusted devices approves it.
    public func signIn() async {
        await run {
            try await services.account.signIn()
            // A returning person may already have a device record on this phone.
            if let record = try? await services.records.load() { enrolled = record; step = .notifications } else { step = .device }
        }
    }

    /// "I saved these": releases the codes and goes back to the protect step. Does nothing until the confirmation is ticked.
    public func recoveryCodesSaved() {
        guard let recoveryCodes, recoveryCodes.finish() else { return }
        self.recoveryCodes = nil
        hasRecoveryCodes = true
        step = .protect
    }

    /// The codes screen went away without being confirmed (the app locked or was backgrounded). They are gone; a new set can be made here
    /// or in Settings → Security → Recovery codes.
    public func recoveryCodesLost() {
        recoveryCodes?.release()
        recoveryCodes = nil
        if step == .recoveryCodes { step = .protect }
    }

    // MARK: Protect your account (optional)

    /// A new set of recovery codes, proven with this iPhone's Face ID / passcode key. Shown once.
    public func makeRecoveryCodes() async {
        await run {
            let set = try await services.account.makeRecoveryCodes()
            recoveryCodes = RecoveryCodesViewModel(codes: set)
            step = .recoveryCodes
        }
    }

    /// A passkey (synced by iCloud Keychain where it is on) as a way back into the account from a new device.
    public func addPasskey() async {
        await run {
            let added = try await services.account.addRecoveryPasskey()
            hasPasskey = true
            passkeyNotSynced = !added.backupEligible
        }
    }

    /// "Continue" once something was added.
    public func continueFromProtection() {
        services.preferences.setBool(true, for: .protectionPromptShown)
        showsSkipWarning = false
        step = .phone
    }

    /// "Not now": the first tap shows the honest warning (`skipWarning`); `confirmSkipProtection` skips.
    public func skipProtection() {
        if isProtected { continueFromProtection(); return }
        showsSkipWarning = true
    }

    public func cancelSkip() { showsSkipWarning = false }

    public func confirmSkipProtection() {
        guard showsSkipWarning || isProtected else { return }
        continueFromProtection()
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
        // stale: this iPhone is enrolled afresh. It attests, and it stays unapproved for high-risk requests (D0): after a recovery only a
        // business can set it up again for its own approvals.
        Task { @MainActor in
            try? await services.records.clear()
            try? await services.keys.deleteAllKeys()
            enrolled = nil
            step = .device
        }
    }

    /// Creates the account from this iPhone (§2.5a). After a passkey sign-in (an existing account) it enrolls this iPhone into it instead.
    public func enrollDevice() async {
        await run {
            let record: DeviceRecord
            if await services.sessions.isSignedIn {
                record = try await services.account.enrollThisDevice(name: deviceName, explain: passkeyGate.explainer)
            } else {
                record = try await services.account.createAccount(deviceName: deviceName)
            }
            enrolled = record
            skippedKeys = DeviceKeyPurpose.allCases.filter { !record.purposes.contains($0) }
            step = .notifications
        }
    }

    public func allowNotifications() async {
        _ = await services.notificationPermission.request()
        services.preferences.setBool(true, for: .notificationPrimingShown)
        step = .protect
    }

    public func skipNotifications() {
        services.preferences.setBool(true, for: .notificationPrimingShown)
        step = .protect
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
