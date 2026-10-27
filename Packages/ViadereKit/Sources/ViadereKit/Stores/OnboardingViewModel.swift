import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

public enum OnboardingStep: Int, Comparable, Sendable {
    case welcome, account, device, notifications, phone, done
    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }
}

public enum OnboardingFlow {
    /// Where to resume after a relaunch.
    public static func resume(hasSession: Bool, hasDevice: Bool, primingShown: Bool, complete: Bool) -> OnboardingStep {
        if complete { return .done }
        if !hasSession { return .welcome }
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
    public enum PhoneStage: Equatable { case entry, verify, linked(String) }

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
    public var onFinished: (@MainActor () -> Void)?

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
            try await services.account.signUp(displayName: displayName)
            step = .device
        }
    }

    public func signIn() async {
        await run {
            try await services.account.signIn()
            // A returning person may already have a device record on this phone.
            if let record = try? await services.records.load() { enrolled = record; step = .notifications } else { step = .device }
        }
    }

    public func enrollDevice() async {
        await run {
            let record = try await services.account.enrollThisDevice(name: deviceName)
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
