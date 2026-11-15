import Foundation
import ViadereCore

/// What the server learned about a key from platform attestation.
public struct AttestationResult: Sendable, Equatable {
    /// True only when Apple's attestation was verified for this key (certificate chain, nonce, app id, counter).
    public var attested: Bool
    /// Short machine-readable reason, recorded in the audit log (`not_configured`, `not_provided`, `verified`, `bad_chain`, ...).
    public var reason: String
    /// The attested App Attest key: lowercase hex of its identifier (SHA-256 of the X9.63 public key). Set only when `attested`.
    public var keyId: String?
    /// base64url of the attested App Attest public key (X9.63). Set only when `attested`.
    public var publicKey: String?
    /// The attestation counter (always 0 for a fresh attestation).
    public var counter: Int
    /// `production` or `development`: which AAGUID the attestation carried.
    public var environment: String?
    /// The evidence format that was evaluated (`IntegrityEvidenceFormat.rawValue`), or `nil` when none was sent.
    public var format: String?

    public init(attested: Bool, reason: String, keyId: String? = nil, publicKey: String? = nil, counter: Int = 0, environment: String? = nil,
                format: String? = nil) {
        self.format = format
        self.attested = attested
        self.reason = reason
        self.keyId = keyId
        self.publicKey = publicKey
        self.counter = counter
        self.environment = environment
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

/// What the server does with an enrollment that carries no valid App Attest attestation (`APP_ATTEST_MODE`).
public enum AppAttestMode: String, Sendable, CaseIterable {
    /// Attestation is verified when sent and recorded, but never required.
    case off
    /// Unattested devices are accepted but flagged (audit + `Device` record) and cool down for 72 h instead of 24 h.
    case report
    /// Unattested app **and App Clip** devices are refused (`403 attestation_required`). The default in `production` and `staging`.
    case require
}

/// Which Apple App Attest environment the app's builds attest in (the AAGUID `appattestdevelop` or `appattest` + 7 zero bytes).
public enum AppAttestEnvironment: String, Sendable, CaseIterable {
    case development, production

    /// The 16-byte AAGUID an attestation made in this environment carries.
    public var aaguid: Data {
        switch self {
        case .development: Data("appattestdevelop".utf8)
        case .production: Data("appattest".utf8) + Data(repeating: 0, count: 7)
        }
    }
}

/// **App Attest / DeviceCheck hook.**
///
/// `hardwareBacked` on a key registration is a client claim, so a stolen bearer token plus a software key could pretend to be a
/// Secure Enclave. The defence is Apple App Attest: the app attests a key over the enrollment's client data
/// (`AppAttestBinding`, which names the challenge, the account and the exact key list) and the server verifies the attestation
/// (`AppAttestVerifier`: certificate chain to Apple's App Attestation Root CA, the nonce, the app id hash, the credential id, the
/// counter, the AAGUID).
public protocol DeviceIntegrityVerifier: Sendable {
    /// Verifies the platform-neutral evidence of an enrollment (§2.5a). The default implementation dispatches on `format`: only
    /// `apple-app-attest` reaches the Apple verifier below; `android-key-attestation` goes to `AndroidKeyAttestationVerifier` (a stub that
    /// never attests); `none` and unknown formats are unattested. A verifier must never read one format's fields as another's.
    func verifyEnrollment(integrity evidence: IntegrityEvidence?, consumerId: ConsumerID, challenge: String, keys: [DeviceKeyRegistration],
                          clientKind: DeviceClientKind) async -> AttestationResult
    /// Verifies the Apple attestation sent with an enrollment. Called once per enrollment; the result is stored per key.
    func verifyEnrollment(_ evidence: AppAttestEvidence?, consumerId: ConsumerID, challenge: String, keys: [DeviceKeyRegistration],
                          clientKind: DeviceClientKind) async -> AttestationResult
    /// Older entry point without the account and client kind (kept for verifiers written against the first protocol).
    func verifyEnrollment(_ evidence: AppAttestEvidence?, challenge: String, keys: [DeviceKeyRegistration]) async -> AttestationResult
    /// Verifies an App Attest **assertion** made with a previously attested key and returns its counter (strictly greater than
    /// `storedCounter`). `clientData` is the exact bytes the app hashed. Persist the result with `AppAttestAssertions`.
    func verifyAssertion(_ assertion: Data, clientData: Data, publicKeyX963: Data, storedCounter: Int, clientKind: DeviceClientKind) throws -> Int
    /// Assesses a sensitive request (for example starting an SMS verification, which costs money) from `deviceId`.
    func assessSensitiveRequest(deviceId: DeviceID, purpose: String) async -> IntegrityVerdict
    /// The Android verifier this verifier dispatches `android-key-attestation` evidence to. The default is the stub that never attests.
    var android: AndroidKeyAttestationVerifier { get }
}

extension DeviceIntegrityVerifier {
    public var android: AndroidKeyAttestationVerifier { AndroidKeyAttestationVerifier() }

    public func verifyEnrollment(integrity evidence: IntegrityEvidence?, consumerId: ConsumerID, challenge: String, keys: [DeviceKeyRegistration],
                                 clientKind: DeviceClientKind) async -> AttestationResult {
        guard let evidence else { return AttestationResult(attested: false, reason: "not_provided") }
        var result: AttestationResult
        switch evidence.format {
        case .appleAppAttest:
            guard let apple = evidence.appleAppAttest else { return AttestationResult(attested: false, reason: "malformed_object", format: evidence.rawFormat) }
            result = await verifyEnrollment(apple, consumerId: consumerId, challenge: challenge, keys: keys, clientKind: clientKind)
        case .androidKeyAttestation:
            // There is no Android App Clip: such evidence on an App Clip enrollment is never attested.
            result = clientKind == .appClip ? AttestationResult(attested: false, reason: "unsupported_client")
                : await android.verify(evidence.androidKeyAttestation, consumerId: consumerId, challenge: challenge, keys: keys)
        case .none:
            result = AttestationResult(attested: false, reason: "not_provided")
        case .unknown:
            result = AttestationResult(attested: false, reason: "unknown_format")
        }
        result.format = evidence.format.rawValue
        return result
    }

    public func verifyEnrollment(_ evidence: AppAttestEvidence?, consumerId: ConsumerID, challenge: String, keys: [DeviceKeyRegistration],
                                 clientKind: DeviceClientKind) async -> AttestationResult {
        await verifyEnrollment(evidence, challenge: challenge, keys: keys)
    }

    public func verifyEnrollment(_ evidence: AppAttestEvidence?, challenge: String, keys: [DeviceKeyRegistration]) async -> AttestationResult {
        AttestationResult(attested: false, reason: evidence == nil ? "not_provided" : "verifier_not_configured")
    }

    public func verifyAssertion(_ assertion: Data, clientData: Data, publicKeyX963: Data, storedCounter: Int, clientKind: DeviceClientKind) throws -> Int {
        throw AppAttestFailure.notProvided
    }
}

/// Nothing is verifiable, so nothing is claimed (every key is stored `attested = false`). Tests that must not verify use it.
public struct UnconfiguredDeviceIntegrityVerifier: DeviceIntegrityVerifier {
    public init() {}

    public func assessSensitiveRequest(deviceId: DeviceID, purpose: String) async -> IntegrityVerdict { .unverified }
}

/// Android integrity verifier (SECURITY.md §2.5a, §2.114). Without Play Integrity keys (`PLAY_INTEGRITY_ENABLED` off, the default) it is **the
/// fail-closed stub**: it never returns `attested`, whatever it is given, so an Android enrollment is unattested (refused under
/// `APP_ATTEST_MODE=require`, D0 under `report`). With the keys it attests only a classic Play Integrity token that decrypts with the owner's AES key,
/// verifies with the owner's P-256 key, names the configured package and signing certificate, says `PLAY_RECOGNIZED` and
/// `MEETS_DEVICE_INTEGRITY` (or strong), is at most five minutes old, and carries the nonce `PlayIntegrityBinding.nonce` of **this** enrollment.
/// The hardware key attestation chain (`certificateChain`, to Google's roots with the revocation list) is not verified yet (WP-E1): it is
/// size-checked and otherwise ignored, never trusted.
public struct AndroidKeyAttestationVerifier: Sendable {
    let playIntegrity: PlayIntegrityVerifier?

    /// The stub.
    public init() { playIntegrity = nil }

    public init(playIntegrity: PlayIntegrityVerifier?) { self.playIntegrity = playIntegrity }

    /// The verifier for this configuration: the stub unless Play Integrity keys, the package and its certificates are all configured.
    static func configured(_ config: ServerConfig, clock: any ServerClock) -> AndroidKeyAttestationVerifier {
        guard let keys = config.android.playIntegrity, let packageName = config.android.packageName, !config.android.certificateFingerprints.isEmpty else {
            return AndroidKeyAttestationVerifier()
        }
        return AndroidKeyAttestationVerifier(playIntegrity: PlayIntegrityVerifier(keys: keys, packageName: packageName,
                                                                                  certificateFingerprints: config.android.certificateFingerprints, clock: clock))
    }

    public func verify(_ evidence: AndroidKeyAttestationEvidence?, consumerId: ConsumerID, challenge: String, keys: [DeviceKeyRegistration]) async -> AttestationResult {
        let format = IntegrityEvidenceFormat.androidKeyAttestation.rawValue
        guard let evidence else { return AttestationResult(attested: false, reason: "malformed_object", format: format) }
        guard let playIntegrity else { return AttestationResult(attested: false, reason: "verifier_not_implemented", format: format) }
        guard evidence.certificateChain.count <= 10, evidence.certificateChain.allSatisfy({ $0.count <= 8 * 1024 }) else {
            return AttestationResult(attested: false, reason: "malformed_object", format: format)
        }
        guard let token = evidence.playIntegrityToken, !token.isEmpty else {
            return AttestationResult(attested: false, reason: "play_integrity_missing", format: format)
        }
        do {
            try playIntegrity.verify(token: token, nonce: PlayIntegrityBinding.nonce(consumerId: consumerId, challenge: challenge, keys: keys))
            return AttestationResult(attested: true, reason: "verified", environment: "play-integrity", format: format)
        } catch let failure as PlayIntegrityVerifier.Failure {
            return AttestationResult(attested: false, reason: failure.rawValue, format: format)
        } catch {
            return AttestationResult(attested: false, reason: PlayIntegrityVerifier.Failure.malformed.rawValue, format: format)
        }
    }
}
