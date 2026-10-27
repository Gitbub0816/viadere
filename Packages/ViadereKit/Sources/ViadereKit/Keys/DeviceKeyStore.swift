import Crypto
import Foundation
import ViadereCore

/// Why the user is being asked to verify (shown by Face ID / Touch ID / passcode). Include the business and
/// amount so the prompt itself is meaningful: "Approve $285.28 at Northfield Market".
public struct SigningPrompt: Sendable, Hashable {
    public var reason: String
    public init(reason: String) { self.reason = reason }
    public static let generic = SigningPrompt(reason: "Confirm it's you")
}

/// A device key owned by the client. Extends `DeviceSigningKey` with the prompt and hardware attestation flag.
public protocol ManagedSigningKey: DeviceSigningKey {
    var purpose: DeviceKeyPurpose { get }
    /// True only for Secure Enclave keys. Reported to the server at enrollment.
    var isHardwareBacked: Bool { get }
    func signature(for data: Data, prompt: SigningPrompt) async throws -> P256.Signing.ECDSASignature
}

extension ManagedSigningKey {
    public func signature(for data: Data) async throws -> P256.Signing.ECDSASignature {
        try await signature(for: data, prompt: .generic)
    }
}

/// A key bound to a fixed prompt, so it can be handed to ViadereCore's `DecisionSigner`.
public struct PromptBoundKey: DeviceSigningKey {
    public let key: any ManagedSigningKey
    public let prompt: SigningPrompt

    public init(_ key: any ManagedSigningKey, prompt: SigningPrompt) {
        self.key = key
        self.prompt = prompt
    }

    public var publicKey: DevicePublicKey { key.publicKey }

    public func signature(for data: Data) async throws -> P256.Signing.ECDSASignature {
        try await key.signature(for: data, prompt: prompt)
    }
}

public enum KeyStoreError: Error, Equatable, Sendable {
    /// No Secure Enclave (simulator, release) and no software fallback is compiled in.
    case unavailable
    case keyNotFound(DeviceKeyPurpose)
    /// Biometrics changed (`.biometryCurrentSet`) or the key was otherwise invalidated: re-enroll the device.
    case keyInvalidated(DeviceKeyPurpose)
    case userCancelled
    case authenticationFailed
    /// The device cannot create this key (e.g. no biometrics enrolled for `.approvalBiometric`).
    case creationFailed(DeviceKeyPurpose, Int32)
    case signingFailed(Int32)
}

/// Owns the device keys, one per `DeviceKeyPurpose`.
public protocol DeviceKeyStore: Sendable {
    /// The key for `purpose` if it exists. Throws `.keyInvalidated` when it existed but can no longer be used.
    func existingKey(for purpose: DeviceKeyPurpose) async throws -> (any ManagedSigningKey)?
    /// Creates (replacing any existing) key. Non-exportable; the private half never leaves the store.
    func createKey(for purpose: DeviceKeyPurpose) async throws -> any ManagedSigningKey
    func deleteKey(for purpose: DeviceKeyPurpose) async throws
}

extension DeviceKeyStore {
    public func requireKey(for purpose: DeviceKeyPurpose) async throws -> any ManagedSigningKey {
        guard let key = try await existingKey(for: purpose) else { throw KeyStoreError.keyNotFound(purpose) }
        return key
    }

    public func deleteAllKeys() async throws {
        for purpose in DeviceKeyPurpose.allCases { try await deleteKey(for: purpose) }
    }

    /// Purposes for which a usable key exists.
    public func availablePurposes() async -> Set<DeviceKeyPurpose> {
        var result = Set<DeviceKeyPurpose>()
        for purpose in DeviceKeyPurpose.allCases {
            if let _ = try? await existingKey(for: purpose) { result.insert(purpose) }
        }
        return result
    }
}

/// Maps a required assurance to the key and claim the device must sign with.
public struct SigningPlan: Sendable, Hashable {
    public var assurance: DecisionAssurance
    public var purpose: DeviceKeyPurpose
    /// Whether signing triggers Face ID / Touch ID / passcode.
    public var requiresUserVerification: Bool { assurance != .none }
    public var requiresBiometrics: Bool { assurance == .biometric }

    public init(assurance: DecisionAssurance) {
        self.assurance = assurance
        self.purpose = DeviceKeyPurpose.required(for: assurance)
    }

    /// Cheapest signing method that satisfies `required`.
    public static func plan(for required: RequiredAssurance) -> SigningPlan {
        switch required {
        case .channelReply, .deviceSignature: SigningPlan(assurance: .none)
        case .userVerified: SigningPlan(assurance: .devicePasscode)
        case .deviceBoundBiometric: SigningPlan(assurance: .biometric)
        }
    }
}
