import Foundation
import ViadereCore

/// Creates the device's keys and the enrollment proofs (`VIADERE-ENROLL-V1`, SECURITY.md §2.5).
public struct DeviceKeyProvisioner: Sendable {
    public struct Result: Sendable {
        public var registrations: [DeviceKeyRegistration]
        /// Purposes that could not be created on this device (e.g. no biometrics enrolled).
        public var skipped: [DeviceKeyPurpose]
    }

    private let store: any DeviceKeyStore

    public init(store: any DeviceKeyStore) { self.store = store }

    /// Generates fresh keys for every purpose and proves possession of each.
    ///
    /// The `.request` key is mandatory; approval keys are optional. Without biometrics the device can still
    /// enroll, but its `maxAssurance` is lower and high-risk approvals are impossible on it.
    /// - Parameter purposes: which keys to create. The App Clip passes `[.request]` only: it never holds approval keys.
    public func provision(consumerId: ConsumerID, challenge: String,
                          purposes: [DeviceKeyPurpose] = DeviceKeyPurpose.allCases) async throws -> Result {
        var registrations: [DeviceKeyRegistration] = []
        var skipped: [DeviceKeyPurpose] = []
        for purpose in purposes {
            let key: any ManagedSigningKey
            do {
                key = try await store.createKey(for: purpose)
            } catch let error as KeyStoreError {
                if purpose == .request { throw error }
                skipped.append(purpose)
                continue
            }
            do {
                let prompted = PromptBoundKey(key, prompt: SigningPrompt(reason: Self.reason(for: purpose)))
                registrations.append(try await DeviceEnrollment.register(key: prompted, purpose: purpose,
                                                                         hardwareBacked: key.isHardwareBacked,
                                                                         consumerId: consumerId, challenge: challenge))
            } catch {
                // The user declined verification for an optional key: drop it rather than keep an unproven key.
                try? await store.deleteKey(for: purpose)
                if purpose == .request { throw error }
                skipped.append(purpose)
            }
        }
        return Result(registrations: registrations, skipped: skipped)
    }

    static func reason(for purpose: DeviceKeyPurpose) -> String {
        switch purpose {
        case .request: "Set up this device"
        case .approvalUserPresence: "Allow this device to approve requests"
        case .approvalBiometric: "Allow Face ID approvals on this device"
        }
    }
}

/// Consistency between the server-registered device and the local keys.
public enum EnrollmentHealth: Sendable, Equatable {
    case notEnrolled
    case healthy
    /// Keys the server knows about are gone or invalidated (biometrics changed, restore, key deletion).
    case needsReenrollment(missing: [DeviceKeyPurpose])
    /// The keychain can't be read right now (locked, early boot, unexpected status): retry; do **not** re-enroll.
    case unavailable

    public static func check(record: DeviceRecord?, store: any DeviceKeyStore) async -> EnrollmentHealth {
        guard let record else { return .notEnrolled }
        var missing: [DeviceKeyPurpose] = []
        var unavailable = false
        for purpose in record.purposes {
            do {
                // Only "not found" for a key this device enrolled means invalidated.
                if try await store.existingKey(for: purpose) == nil { missing.append(purpose) }
            } catch let error as KeyStoreError {
                switch error {
                case .keyInvalidated, .keyNotFound: missing.append(purpose)
                default: unavailable = true
                }
            } catch {
                unavailable = true
            }
        }
        if !missing.isEmpty { return .needsReenrollment(missing: missing) }
        return unavailable ? .unavailable : .healthy
    }
}
