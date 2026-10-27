import Foundation
import ViadereCore

/// How a Security-framework `OSStatus` should be understood when it comes back from a **key lookup**.
///
/// Pure, so it can be tested on any platform. The distinction matters: a `.biometryCurrentSet` key that is
/// really gone (`errSecItemNotFound`) means the biometrics changed and the device must be set up again, but
/// a locked keychain (`errSecInteractionNotAllowed`, -25308, e.g. a background wake before first unlock or a
/// protected-data race) only means "not right now". Treating the latter as invalidation would push people
/// into a needless re-enrollment, and re-enrollment is a security-sensitive operation.
public enum KeychainStatus {
    public enum Outcome: Sendable, Equatable {
        case success
        /// `errSecItemNotFound`: for a key that should exist, it was invalidated or removed.
        case notFound
        /// The keychain cannot answer right now. Retry later; never treat as invalidation.
        case transient(Int32)
        /// Any other failure: unexpected, reported, never interpreted as invalidation.
        case failure(Int32)
    }

    public static let errSecSuccessValue: Int32 = 0
    public static let itemNotFound: Int32 = -25300
    /// errSecInteractionNotAllowed: the keychain is locked / device not unlocked.
    public static let interactionNotAllowed: Int32 = -25308
    /// errSecInteractionRequired.
    public static let interactionRequired: Int32 = -25315
    /// errSecNotAvailable: no keychain is available (early boot).
    public static let notAvailable: Int32 = -25291
    /// errSecAuthFailed: authorization failed while the keychain was locked.
    public static let authFailed: Int32 = -25293
    /// errSecAllocate, errSecIO (low resources, I/O hiccups).
    public static let allocate: Int32 = -108
    public static let io: Int32 = -36

    static let transientCodes: Set<Int32> = [interactionNotAllowed, interactionRequired, notAvailable, authFailed, allocate, io]

    public static func classify(_ status: Int32) -> Outcome {
        switch status {
        case errSecSuccessValue: .success
        case itemNotFound: .notFound
        case _ where transientCodes.contains(status): .transient(status)
        default: .failure(status)
        }
    }

    /// The error a failed lookup maps to, or `nil` for success/not-found (callers decide what absence means).
    public static func lookupError(_ status: Int32, purpose: DeviceKeyPurpose) -> KeyStoreError? {
        switch classify(status) {
        case .success, .notFound: nil
        case .transient(let code): .temporarilyUnavailable(code)
        case .failure(let code): .unexpectedStatus(code)
        }
    }
}

extension KeychainStatus.Outcome {
    var isTransientOutcome: Bool {
        if case .transient = self { return true }
        return false
    }
}
