import Foundation
import ViadereCore

public enum ConfirmationError: Error, Equatable, Sendable {
    case notEnrolled
    /// This device has no user-verified approval key (a request key can never confirm).
    case cannotConfirm
    case keyInvalidated
    case keysUnavailable
    case userCancelled
    case authenticationFailed
    case api(APIError)

    public var userMessage: String {
        switch self {
        case .notEnrolled: "Set up this iPhone before confirming other devices."
        case .cannotConfirm: "Confirming needs Face ID or your passcode, which isn't set up on this iPhone."
        case .keyInvalidated: "Your device security changed. Set this iPhone up again to confirm other devices."
        case .keysUnavailable: "Your keys aren't available right now. Unlock your iPhone and try again."
        case .userCancelled: "Not confirmed. You can try again."
        case .authenticationFailed: "We couldn't verify it's you. Try again."
        case .api(let error):
            switch error.code {
            case .forbidden?, .insufficientAssurance?: "Only a device you already trust can confirm this, and it can't be one that was added recently."
            case .replayDetected?: "That confirmation was already used. Try again."
            default: error.userMessage
            }
        }
    }
}

/// Confirms a security-relevant addition from a device that is already trusted: a **new device** in its cool-down
/// (`POST /v1/devices/{id}/confirm`) or a **newly linked phone** (`POST /v1/phone-links/{id}/confirm`).
///
/// The proof is `ConfirmationProof.sign(...)` made with this device's user-verified approval key (the biometric key when it
/// has one, else the passcode key), so Face ID, Touch ID or the passcode appears. A stolen session plus the new device
/// cannot confirm itself: only a different, trusted device's key can.
public struct ConfirmationService: Sendable {
    private let api: any ViadereAPI
    private let keys: any DeviceKeyStore
    private let records: any DeviceRecordStore
    private let clock: @Sendable () -> Date

    public init(api: any ViadereAPI, keys: any DeviceKeyStore, records: any DeviceRecordStore,
                clock: @escaping @Sendable () -> Date = { Date() }) {
        self.api = api
        self.keys = keys
        self.records = records
        self.clock = clock
    }

    /// Lifts the cool-down of another of this person's devices.
    public func confirm(device target: Device) async throws -> Device {
        let proof = try await makeProof(subject: .device, subjectId: target.id.description,
                                        reason: "Confirm \(UntrustedText.line(target.name, max: 40)) as your device")
        do { return try await api.confirmDevice(target.id, proof: proof) } catch let error as APIError { throw ConfirmationError.api(error) }
    }

    /// Makes a newly linked phone usable now.
    public func confirm(phone: PhoneLink) async throws -> PhoneLink {
        let proof = try await makeProof(subject: .phoneLink, subjectId: phone.id.description,
                                        reason: "Confirm \(UntrustedText.line(phone.maskedPhone, max: 24)) as your phone")
        do { return try await api.confirmPhoneLink(phone.id, proof: proof) } catch let error as APIError { throw ConfirmationError.api(error) }
    }

    /// The signed proof for `subject`, made after Face ID / Touch ID / passcode.
    public func makeProof(subject: ConfirmationProof.Subject, subjectId: String, reason: String) async throws -> ConfirmationProof {
        let record: DeviceRecord
        do {
            guard let loaded = try await records.load() else { throw ConfirmationError.notEnrolled }
            record = loaded
        } catch let error as ConfirmationError { throw error } catch { throw ConfirmationError.notEnrolled }
        let assurance: DecisionAssurance
        if record.purposes.contains(.approvalBiometric) { assurance = .biometric }
        else if record.purposes.contains(.approvalUserPresence) { assurance = .devicePasscode }
        else { throw ConfirmationError.cannotConfirm }
        let purpose = DeviceKeyPurpose.required(for: assurance)
        do {
            let key = try await keys.requireKey(for: purpose)
            return try await ConfirmationProof.sign(subject: subject, subjectId: subjectId.lowercased(), deviceId: record.deviceId,
                                                    assurance: assurance, key: PromptBoundKey(key, prompt: SigningPrompt(reason: reason)),
                                                    now: clock())
        } catch let error as KeyStoreError {
            switch error {
            case .userCancelled: throw ConfirmationError.userCancelled
            case .keyInvalidated, .keyNotFound: throw ConfirmationError.keyInvalidated
            case .temporarilyUnavailable: throw ConfirmationError.keysUnavailable
            default: throw ConfirmationError.authenticationFailed
            }
        } catch {
            throw ConfirmationError.authenticationFailed
        }
    }
}
