import Foundation

/// How a verification result was established, and what it can and cannot claim (spec §6.1, §6.2, VER-005, VER-007, VER-009).
///
/// The taxonomy keeps the assurance **dimensions** apart (`AssuranceDimensions`) and keeps the **labels** a person or a business sees
/// apart (`VerificationLabel`). Nothing here promotes a weaker result to a stronger claim: a label satisfies exactly one kind of
/// required evidence (`RequiredEvidence.isSatisfied(by:)`), an estimated age satisfies none, and a registered authenticator or a
/// reachable contact is never an identity. Viadere does **not** claim NIST SP 800-63 IAL/AAL/FAL equivalence for any of these.
public enum VerificationMethod: String, Sendable, Codable, CaseIterable, Hashable {
    /// An ISO 18013-5 mdoc (driver's license or national ID) presented from Apple Wallet and verified against the issuer's IACA.
    case walletMdoc = "wallet_mdoc"
    /// A provider session that checked a physical document, a liveness capture and a face match against the document portrait.
    case diditDocumentLiveness = "didit_document_liveness"
    /// A provider selfie age estimation. An **estimate**: it never establishes a verified age or an identity (AGE-002).
    case diditAgeEstimation = "didit_age_estimation"
    /// An enrolled, non-revoked device key (a registered authenticator).
    case deviceAuthenticator = "device_authenticator"
    /// A one-time code delivered to a phone or address the person controls (a reachable contact).
    case contactCode = "contact_code"
    /// Test-mode only: a simulated result for a sandbox customer. Never produced for a live key, never evidence of anything real.
    case sandbox

    /// The labels this method may ever establish: the ceiling, not a promise (the result must still carry the facts, see
    /// `VerificationAssuranceMapper`). Everything not listed is **not** established by the method.
    public var establishes: Set<VerificationLabel> {
        switch self {
        case .walletMdoc, .diditDocumentLiveness: [.verifiedAgeThreshold, .verifiedIdentity]
        case .diditAgeEstimation: [.estimatedAge]
        case .deviceAuthenticator: [.registeredAuthenticator]
        case .contactCode: [.reachableContact]
        case .sandbox: [.verifiedAgeThreshold, .verifiedIdentity]
        }
    }

    /// Who performed the check.
    public var verifier: String {
        switch self {
        case .walletMdoc: "viadere"
        case .diditDocumentLiveness, .diditAgeEstimation: "didit"
        case .deviceAuthenticator, .contactCode: "viadere"
        case .sandbox: "viadere-sandbox"
        }
    }
}

/// The result labels shown to people and returned to businesses (VER-009). There is **no** universal "verified" badge: each label
/// names the one thing it proves.
public enum VerificationLabel: String, Sendable, Codable, CaseIterable, Hashable {
    /// Identity attributes (a legal name, an address) from a validated credential or a document-and-biometric check.
    case verifiedIdentity = "verified_identity"
    /// The person meets an age threshold, backed by a verified birthdate or a trusted threshold credential (AGE-002).
    case verifiedAgeThreshold = "verified_age_threshold"
    /// The person holds an enrolled authenticator. Proves control of a device key, not who the person is.
    case registeredAuthenticator = "registered_authenticator"
    /// A contact point that received a code. Proves reachability, not identity.
    case reachableContact = "reachable_contact"
    /// An age **estimated** from a face image. Never labeled "verified age" and never satisfies an age capability (AGE-002).
    case estimatedAge = "estimated_age"

    /// Plain-language name for the app and the console (accessibility: the text carries the meaning, not a color or icon).
    public var displayName: String {
        switch self {
        case .verifiedIdentity: "Verified identity"
        case .verifiedAgeThreshold: "Verified age threshold"
        case .registeredAuthenticator: "Registered authenticator"
        case .reachableContact: "Reachable contact"
        case .estimatedAge: "Estimated age (not verified)"
        }
    }

    /// What the label does **not** mean, shown next to it (§11.5).
    public var limits: String {
        switch self {
        case .verifiedIdentity: "Describes the attributes and checks that were evaluated. It is not a guarantee of identity or eligibility."
        case .verifiedAgeThreshold: "Confirms only that the threshold is met. It does not reveal a date of birth and is not a legal determination for any service."
        case .registeredAuthenticator: "Shows that a registered device approved a request. It does not prove who the person is."
        case .reachableContact: "Shows that a message can reach the contact. It does not prove identity."
        case .estimatedAge: "An estimate from an image. It is not a verified age."
        }
    }
}

extension RequiredEvidence {
    /// The **only** label that satisfies this evidence requirement. There is no promotion: a verified identity does not satisfy a verified
    /// age threshold (and is not used as one), a registered authenticator satisfies neither, and an estimated age satisfies nothing.
    public func isSatisfied(by label: VerificationLabel) -> Bool {
        switch self {
        case .none: true
        case .registeredAuthenticator: label == .registeredAuthenticator
        case .verifiedAgeThreshold: label == .verifiedAgeThreshold
        case .verifiedIdentity: label == .verifiedIdentity
        }
    }
}

/// Strength of the identity evidence behind a result (the "identity proofing" dimension).
public enum EvidenceStrength: String, Sendable, Codable, Hashable, Comparable, CaseIterable {
    case none
    /// A test-mode simulation: no evidence at all.
    case simulated
    /// Declared by the person, unchecked. Never labeled verified.
    case selfAsserted = "self_asserted"
    /// A facial estimate: a probabilistic signal about a face, no document.
    case biometricEstimate = "biometric_estimate"
    /// A physical document checked by a provider together with a liveness capture and a face match.
    case documentWithBiometricMatch = "document_with_biometric_match"
    /// A credential signed by the issuing authority and validated back to its trust anchor.
    case issuerSignedCredential = "issuer_signed_credential"

    var rank: Int { Self.allCases.firstIndex(of: self) ?? 0 }
    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rank < rhs.rank }
}

/// Strength of the authenticator that was used by the person (separate from the evidence).
public enum AuthenticatorStrength: String, Sendable, Codable, Hashable, CaseIterable {
    case none
    /// A device-held key (the request was device-signed).
    case deviceBound = "device_bound"
    /// A device-held key, unlocked by the person (passcode or biometrics on the device).
    case deviceBoundUserVerified = "device_bound_user_verified"
}

/// How far the issuer of the evidence is trusted.
public enum IssuerTrust: String, Sendable, Codable, Hashable, CaseIterable {
    case none
    /// The issuer certificate chained to a trust anchor Viadere has configured and pinned (an IACA root).
    case configuredTrustAnchor = "configured_trust_anchor"
    /// A provider attests the document; Viadere cannot see the issuer chain.
    case providerAttested = "provider_attested"
}

/// How the evidence is bound to this request, this recipient and this person's device.
public enum PresentationBinding: String, Sendable, Codable, Hashable, CaseIterable {
    case none
    /// The provider session was created for this one attempt (`vendor_data` is the attempt id) and read by Viadere.
    case providerSession = "provider_session"
    /// A device signature over a session transcript that contains this request's single-use nonce, the merchant and the team.
    case deviceSignatureOverTranscript = "device_signature_over_transcript"
}

/// The sensitivity of what the result is used for (from the capability's tier), recorded so a consumer of the result can weigh it.
public enum TransactionRisk: String, Sendable, Codable, Hashable, CaseIterable {
    case low, standard, high, critical
}

/// The recorded assurance dimensions (§6.1). Each is a separate fact; none is derived from another.
public struct AssuranceDimensions: Sendable, Codable, Hashable {
    public var evidence: EvidenceStrength
    public var authenticator: AuthenticatorStrength
    public var issuerTrust: IssuerTrust
    /// When the underlying check happened.
    public var verifiedAt: Date
    /// When the result must be considered stale and the check repeated.
    public var validUntil: Date
    public var presentationBinding: PresentationBinding
    public var transactionRisk: TransactionRisk

    public init(evidence: EvidenceStrength, authenticator: AuthenticatorStrength, issuerTrust: IssuerTrust, verifiedAt: Date, validUntil: Date,
                presentationBinding: PresentationBinding, transactionRisk: TransactionRisk) {
        self.evidence = evidence
        self.authenticator = authenticator
        self.issuerTrust = issuerTrust
        self.verifiedAt = verifiedAt
        self.validUntil = validUntil
        self.presentationBinding = presentationBinding
        self.transactionRisk = transactionRisk
    }

    /// The coarse, stable assurance string a business sees in `assurance`. It names the evidence and the binding; it never claims an
    /// IAL/AAL equivalence.
    public var level: String {
        switch (evidence, presentationBinding) {
        case (.simulated, _): "sandbox_simulated"
        case (.issuerSignedCredential, .deviceSignatureOverTranscript): "issuer_signed_credential_device_bound"
        case (.documentWithBiometricMatch, _): "document_and_biometric_match"
        case (.biometricEstimate, _): "biometric_estimate"
        case (.issuerSignedCredential, _): "issuer_signed_credential"
        default: "unverified"
        }
    }
}

/// Whether the credential behind a result could be checked for revocation (VER-004/007).
public enum RevocationState: String, Sendable, Codable, Hashable, CaseIterable {
    /// The format offers a status mechanism that was not consulted (mdoc without an issuer status list today).
    case notChecked = "not_checked"
    /// There is no revocation mechanism for the evidence (a provider session).
    case notApplicable = "not_applicable"
    case active
    case revoked
}

/// What is recorded about every verification result (VER-007). **Never** contains personal data: no birthdate, no name, no document
/// number, no image, no provider URL.
public struct VerificationProvenance: Sendable, Codable, Hashable {
    public var method: VerificationMethod
    public var verifier: String
    /// The issuer of the evidence, as an identifier without personal data: the lowercase hex SHA-256 prefix (16 hex characters) of the
    /// trust anchor for a Wallet credential, `didit:<ISO country>` for a provider-checked document.
    public var issuer: String
    public var label: VerificationLabel
    public var assurance: AssuranceDimensions
    /// When the result expires; the check must be repeated afterwards (revalidation).
    public var expiresAt: Date
    public var revocation: RevocationState
    public var policyVersion: String

    public init(method: VerificationMethod, issuer: String, label: VerificationLabel, assurance: AssuranceDimensions, expiresAt: Date,
                revocation: RevocationState, policyVersion: String = VerifyPolicy.version) {
        self.method = method
        verifier = method.verifier
        self.issuer = issuer
        self.label = label
        self.assurance = assurance
        self.expiresAt = expiresAt
        self.revocation = revocation
        self.policyVersion = policyVersion
    }

    /// Invariants: the label is one the method may establish (no promotion), and an estimate is never recorded as a verified claim.
    public var isConsistent: Bool {
        method.establishes.contains(label) && expiresAt >= assurance.verifiedAt
            && !(label == .estimatedAge && assurance.evidence > .biometricEstimate)
    }

    /// The policy evidence this provenance is: `nil` for labels that satisfy no capability's evidence requirement (an estimated age, a
    /// reachable contact), so they cannot reach `PolicyEngine`.
    public func evidenceHolding() -> EvidenceHolding? {
        guard isConsistent else { return nil }
        let kind: RequiredEvidence
        switch label {
        case .verifiedAgeThreshold: kind = .verifiedAgeThreshold
        case .verifiedIdentity: kind = .verifiedIdentity
        case .registeredAuthenticator: kind = .registeredAuthenticator
        case .reachableContact, .estimatedAge: return nil
        }
        return EvidenceHolding(kind: kind, verifiedAt: assurance.verifiedAt, expiresAt: expiresAt)
    }
}

/// Policy version and limits of the Verify module. Bumped whenever a mapping, a lifetime or a disclosure rule changes (VER-007).
public enum VerifyPolicy {
    public static let version = "verify-2026-10-27.1"
    /// Longest a verification request may stay open.
    public static let maxRequestLifetime = 600
    public static let minRequestLifetime = 30
    /// How long a produced result stays valid and retrievable by the business (AGE-004). It is also single-use.
    public static let resultValidity: TimeInterval = 900
    /// A Wallet nonce is valid this long (or until the request expires, whichever is first) and for exactly one presentation.
    public static let walletNonceLifetime: TimeInterval = 300
    /// Attempts (Wallet or provider sessions) one request may start.
    public static let maxAttemptsPerRequest = 3
}

/// The mapping from what a verification method observed to the label it may establish (VER-005). Pure; the server calls it after it has
/// validated the evidence.
public enum VerificationAssuranceMapper {
    /// Facts a method observed. Only facts that were validated belong here.
    public struct Observation: Sendable, Hashable {
        public var method: VerificationMethod
        /// The method produced a validated yes/no age statement (a Wallet `age_over_NN` element, or a verified birthdate).
        public var validatedAgeStatement = false
        /// The method produced validated identity attributes (a legal name from a validated credential or document check).
        public var validatedIdentityAttributes = false
        /// A provider returned an estimated age and nothing that establishes it.
        public var estimatedAgeOnly = false

        public init(method: VerificationMethod, validatedAgeStatement: Bool = false, validatedIdentityAttributes: Bool = false, estimatedAgeOnly: Bool = false) {
            self.method = method
            self.validatedAgeStatement = validatedAgeStatement
            self.validatedIdentityAttributes = validatedIdentityAttributes
            self.estimatedAgeOnly = estimatedAgeOnly
        }
    }

    /// The labels the observation establishes: a subset of `method.establishes`. An age estimate only ever yields `.estimatedAge`.
    public static func labels(for observation: Observation) -> Set<VerificationLabel> {
        var out: Set<VerificationLabel> = []
        if observation.validatedAgeStatement { out.insert(.verifiedAgeThreshold) }
        if observation.validatedIdentityAttributes { out.insert(.verifiedIdentity) }
        if observation.estimatedAgeOnly { out.insert(.estimatedAge) }
        switch observation.method {
        case .deviceAuthenticator: out.insert(.registeredAuthenticator)
        case .contactCode: out.insert(.reachableContact)
        default: break
        }
        return out.intersection(observation.method.establishes)
    }

    /// The provenance for a verified age threshold or identity result from a Wallet credential.
    public static func walletDimensions(verifiedAt: Date, validUntil: Date, risk: TransactionRisk) -> AssuranceDimensions {
        AssuranceDimensions(evidence: .issuerSignedCredential, authenticator: .deviceBoundUserVerified, issuerTrust: .configuredTrustAnchor,
                            verifiedAt: verifiedAt, validUntil: validUntil, presentationBinding: .deviceSignatureOverTranscript, transactionRisk: risk)
    }

    /// The dimensions of a test-mode simulation: no evidence, no issuer, no binding.
    public static func sandboxDimensions(verifiedAt: Date, validUntil: Date, risk: TransactionRisk) -> AssuranceDimensions {
        AssuranceDimensions(evidence: .simulated, authenticator: .none, issuerTrust: .none, verifiedAt: verifiedAt, validUntil: validUntil,
                            presentationBinding: .none, transactionRisk: risk)
    }

    /// The dimensions for a result from a provider document, liveness and face-match session.
    public static func providerDimensions(verifiedAt: Date, validUntil: Date, risk: TransactionRisk) -> AssuranceDimensions {
        AssuranceDimensions(evidence: .documentWithBiometricMatch, authenticator: .deviceBound, issuerTrust: .providerAttested,
                            verifiedAt: verifiedAt, validUntil: validUntil, presentationBinding: .providerSession, transactionRisk: risk)
    }
}

extension Sensitivity {
    /// The `TransactionRisk` recorded for a capability of this sensitivity.
    public var transactionRisk: TransactionRisk {
        switch self {
        case .low: .low
        case .standard: .standard
        case .high: .high
        case .critical: .critical
        }
    }
}
