import Foundation

/// Which kind of platform integrity evidence a client sent (SECURITY.md §2.5a). The protocol is platform-neutral: the server dispatches on
/// `format` and **never** reads one format's fields as another's.
public enum IntegrityEvidenceFormat: String, Codable, Sendable, CaseIterable {
    /// Apple App Attest (`DCAppAttestService.attestKey`), verified against Apple's App Attestation Root CA.
    case appleAppAttest = "apple-app-attest"
    /// Android hardware key attestation (+ optional Play Integrity token). No verifier exists yet: this format is **never** `attested`.
    case androidKeyAttestation = "android-key-attestation"
    /// The client has no integrity evidence to offer (for example a platform without an attestation service).
    case none
    /// A format this build does not know. Treated exactly like missing evidence (unattested), never as attested.
    case unknown

    public init(from decoder: any Decoder) throws {
        self = IntegrityEvidenceFormat(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
    }
}

/// Android key attestation evidence: the attestation certificate chain of the enrolled key (base64 DER, leaf first) and, optionally, a Play
/// Integrity token. Carried and stored for the future verifier; **not** evaluated today.
public struct AndroidKeyAttestationEvidence: Codable, Sendable, Hashable {
    public var certificateChain: [String]
    public var playIntegrityToken: String?

    public init(certificateChain: [String], playIntegrityToken: String? = nil) {
        self.certificateChain = certificateChain
        self.playIntegrityToken = playIntegrityToken
    }
}

/// Platform integrity evidence for an enrollment, as one envelope:
///
/// ```
/// {"format": "apple-app-attest", "keyId": "…", "attestation": "…"}
/// {"format": "android-key-attestation", "certificateChain": ["…"], "playIntegrityToken": "…"}
/// {"format": "none"}
/// ```
///
/// The Apple fields are exactly `AppAttestEvidence` (and are bound to the enrollment by `AppAttestBinding`). A format other than
/// `apple-app-attest` never yields Apple evidence, whatever other fields it carries.
public struct IntegrityEvidence: Codable, Sendable, Hashable {
    public var format: IntegrityEvidenceFormat
    /// The `format` string exactly as received (for audit), also for `.unknown`.
    public var rawFormat: String
    public var appleAppAttest: AppAttestEvidence?
    public var androidKeyAttestation: AndroidKeyAttestationEvidence?

    public init(appleAppAttest evidence: AppAttestEvidence) {
        format = .appleAppAttest
        rawFormat = IntegrityEvidenceFormat.appleAppAttest.rawValue
        appleAppAttest = evidence
        androidKeyAttestation = nil
    }

    public init(androidKeyAttestation evidence: AndroidKeyAttestationEvidence) {
        format = .androidKeyAttestation
        rawFormat = IntegrityEvidenceFormat.androidKeyAttestation.rawValue
        appleAppAttest = nil
        androidKeyAttestation = evidence
    }

    /// Evidence of the kind "nothing to offer" (`{"format": "none"}`). Not named `none`, which would read as `Optional.none`.
    public static let noEvidence = IntegrityEvidence(format: .none, rawFormat: IntegrityEvidenceFormat.none.rawValue)

    private init(format: IntegrityEvidenceFormat, rawFormat: String) {
        self.format = format
        self.rawFormat = rawFormat
        appleAppAttest = nil
        androidKeyAttestation = nil
    }

    enum CodingKeys: String, CodingKey { case format, keyId, attestation, certificateChain, playIntegrityToken }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let raw = try c.decode(String.self, forKey: .format)
        self.init(format: IntegrityEvidenceFormat(rawValue: raw) ?? .unknown, rawFormat: String(raw.prefix(64)))
        switch format {
        case .appleAppAttest:
            appleAppAttest = AppAttestEvidence(keyId: try c.decode(String.self, forKey: .keyId), attestation: try c.decode(String.self, forKey: .attestation))
        case .androidKeyAttestation:
            androidKeyAttestation = AndroidKeyAttestationEvidence(certificateChain: try c.decode([String].self, forKey: .certificateChain),
                                                                  playIntegrityToken: try c.decodeIfPresent(String.self, forKey: .playIntegrityToken))
        case .none, .unknown:
            break
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(rawFormat, forKey: .format)
        if format == .appleAppAttest, let appleAppAttest {
            try c.encode(appleAppAttest.keyId, forKey: .keyId)
            try c.encode(appleAppAttest.attestation, forKey: .attestation)
        }
        if format == .androidKeyAttestation, let androidKeyAttestation {
            try c.encode(androidKeyAttestation.certificateChain, forKey: .certificateChain)
            try c.encodeIfPresent(androidKeyAttestation.playIntegrityToken, forKey: .playIntegrityToken)
        }
    }
}

/// What a server asks of an enrolling client (`AccountEnrollBeginResponse.integrity`).
public struct IntegrityRequirement: Codable, Sendable, Hashable {
    /// Formats one of which **must** verify, or the enrollment is refused (`403 attestation_required`). Empty: evidence is optional.
    public var required: [IntegrityEvidenceFormat]
    /// Formats the server can verify today. Evidence in another format is recorded as unattested.
    public var accepted: [IntegrityEvidenceFormat]

    public init(required: [IntegrityEvidenceFormat], accepted: [IntegrityEvidenceFormat]) {
        self.required = required
        self.accepted = accepted
    }
}

/// The signature algorithm of an enrolled key. Only `ES256` (ECDSA P-256 with SHA-256, raw r‖s, low-S) exists; any other value is kept as
/// received so the server can refuse it (`400`) instead of silently reading it as ES256.
public struct DeviceKeyAlgorithm: RawRepresentable, Codable, Sendable, Hashable {
    public var rawValue: String
    public init(rawValue: String) { self.rawValue = rawValue }

    public static let es256 = DeviceKeyAlgorithm(rawValue: "ES256")

    /// Whether this build (and the server) accepts the algorithm.
    public var isSupported: Bool { self == .es256 }

    public init(from decoder: any Decoder) throws {
        rawValue = String(try decoder.singleValueContainer().decode(String.self).prefix(32))
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(rawValue)
    }
}
