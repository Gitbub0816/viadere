import Foundation
import ViadereCore

/// What the server learned about a key from platform attestation.
public struct AttestationResult: Sendable, Equatable {
    /// True only when Apple's attestation was verified for this key (certificate chain, nonce, app id, counter).
    public var attested: Bool
    /// Short machine-readable reason, recorded in the audit log (`not_configured`, `verified`, `rejected`).
    public var reason: String
    public init(attested: Bool, reason: String) {
        self.attested = attested
        self.reason = reason
    }
}

/// How much the server trusts that a sensitive request comes from a genuine, unmodified app on genuine hardware.
public enum IntegrityVerdict: Sendable, Equatable {
    /// No attestation is configured or provided.
    case unverified
    case verified
    /// Attestation was provided and failed: refuse.
    case failed
}

/// **App Attest / DeviceCheck hook.**
///
/// `hardwareBacked` on a key registration is a client claim, so a stolen bearer token plus a software key could pretend to be a
/// Secure Enclave. The real defence is Apple App Attest: the app attests each key over the enrollment challenge and the server
/// verifies the attestation (certificate chain to Apple's App Attest root, the nonce `SHA-256(authData ‖ SHA-256(challenge))`,
/// the app id hash, the credential id and the counter).
///
/// TODO(app-attest): implement `AppleAppAttestVerifier` once the App Attest root certificate and the app's team id/bundle id are
/// configured, then pass it via `ServerContext(integrity:)`. Until then `UnconfiguredDeviceIntegrityVerifier` is used: every key
/// is stored with `attested = false` and policy or telemetry must not read `hardwareBacked` as proof.
public protocol DeviceIntegrityVerifier: Sendable {
    /// Verifies the attestation sent with an enrollment. Called once per enrollment; the result is stored per key.
    func verifyEnrollment(_ evidence: AppAttestEvidence?, challenge: String, keys: [DeviceKeyRegistration]) async -> AttestationResult
    /// Assesses a sensitive request (for example starting an SMS verification, which costs money) from `deviceId`.
    func assessSensitiveRequest(deviceId: DeviceID, purpose: String) async -> IntegrityVerdict
}

/// The default: nothing is verifiable, so nothing is claimed.
public struct UnconfiguredDeviceIntegrityVerifier: DeviceIntegrityVerifier {
    public init() {}

    public func verifyEnrollment(_ evidence: AppAttestEvidence?, challenge: String, keys: [DeviceKeyRegistration]) async -> AttestationResult {
        AttestationResult(attested: false, reason: evidence == nil ? "not_provided" : "verifier_not_configured")
    }

    public func assessSensitiveRequest(deviceId: DeviceID, purpose: String) async -> IntegrityVerdict { .unverified }
}
