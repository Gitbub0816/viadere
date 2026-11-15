import Crypto
import Foundation

/// Domain separators of the Approve statements (section 2.53 to 2.55).
public enum ApproveDomain {
    public static let enrollment = "VIADERE-APPROVAL-ENROLL-V1\n"
    public static let confirmation = "VIADERE-APPROVAL-CONFIRM-V1\n"
    public static let request = "VIADERE-APPROVAL-REQUEST-V1\n"
    public static let freeze = "VIADERE-APPROVE-FREEZE-V1\n"
}

/// A statement signed by a business operational key published in the directory, carrying the signer's `kid` so the verifier can look the
/// key up (and must then check it is valid, unrevoked and of the right purpose).
public struct BusinessSignedStatement: Sendable, Hashable, Codable {
    public var kid: String
    public var payload: String
    public var signature: String

    public init(kid: String, payload: String, signature: String) {
        self.kid = kid
        self.payload = payload
        self.signature = signature
    }

    var statement: SignedStatement { SignedStatement(payload: payload, signature: signature) }

    static func sign(_ object: [String: JSONValue], domain: String, with key: any DeviceSigningKey) async throws -> BusinessSignedStatement {
        let signed = try await SignedStatement.sign(object, domain: domain, with: key)
        let kid = try KeyIdentifier.make(p256X963: key.publicKey.x963)
        return BusinessSignedStatement(kid: kid, payload: signed.payload, signature: signed.signature)
    }
}

public enum ApprovalEnrollmentError: Error, Sendable, Equatable {
    case malformed(String)
    case badSignature
    case wrongBusiness
    case wrongSubject
    case wrongEnrollment
    case keyMismatch
    case statementMismatch
    case confirmationKeyNotPublished
}

/// The customer's device binding a **pairwise approval key** to one business relationship (APP-002), signed by that very key:
///
/// ```json
/// {"alg":"ES256","assurance":"biometric","business_id":"…","created_at":1800000000,"enrollment_id":"…","hpke_kid":"…",
///  "hpke_public_key":"…","kid":"…","public_key":"…","subject_ref":"sub_…","type":"approval-enrollment","v":1}
/// ```
/// Signed over `"VIADERE-APPROVAL-ENROLL-V1\n" ‖ canonical payload`. The key exists for this business and this relationship only: no other
/// business ever sees the `kid` or the public key (unlinkability, ADR-06).
public struct ApprovalEnrollmentStatement: Sendable, Hashable {
    public var businessId: BusinessID
    public var subject: SubjectRef
    public var enrollmentId: UUID
    /// X9.63 public key of the approval key.
    public var publicKey: DevicePublicKey
    public var kid: String
    /// The device's per-relationship HPKE key for end-to-end encrypted requests.
    public var hpkePublicKey: E2EEPublicKey
    /// The access-control class the key was created with.
    public var assurance: ApprovalAMR
    public var createdAt: Int64

    public init(businessId: BusinessID, subject: SubjectRef, enrollmentId: UUID, publicKey: DevicePublicKey, hpkePublicKey: E2EEPublicKey,
                assurance: ApprovalAMR, createdAt: Date) throws {
        guard assurance != .passcode else { throw ApprovalEnrollmentError.malformed("assurance") }
        self.businessId = businessId
        self.subject = subject
        self.enrollmentId = enrollmentId
        self.publicKey = publicKey
        kid = KeyIdentifier.make(try publicKey.signingKey())
        self.hpkePublicKey = hpkePublicKey
        self.assurance = assurance
        self.createdAt = ViadereDate.unixSeconds(createdAt)
    }

    var object: [String: JSONValue] {
        ["v": .integer(1), "type": .string("approval-enrollment"), "business_id": .string(businessId.description), "subject_ref": .string(subject.rawValue),
         "enrollment_id": .string(enrollmentId.uuidString.lowercased()), "kid": .string(kid), "alg": .string("ES256"),
         "public_key": .string(publicKey.base64URL), "hpke_kid": .string(hpkePublicKey.kid), "hpke_public_key": .string(hpkePublicKey.base64URL),
         "assurance": .string(assurance.rawValue), "created_at": .integer(createdAt)]
    }

    /// Signs with the approval key itself (this is what triggers Face ID for a biometric key).
    public func sign(with key: any DeviceSigningKey) async throws -> SignedStatement {
        guard key.publicKey == publicKey else { throw ApprovalEnrollmentError.keyMismatch }
        return try await SignedStatement.sign(object, domain: ApproveDomain.enrollment, with: key)
    }

    /// Parses and verifies a signed statement: canonical shape, `kid` derivations, and the signature under the key **it contains**
    /// (proof of possession). Binding to a business, subject and enrollment is the caller's job (`checkBinding`).
    public static func verify(_ signed: SignedStatement) throws -> ApprovalEnrollmentStatement {
        guard let o = signed.canonicalObject(), Set(o.keys) == ["v", "type", "business_id", "subject_ref", "enrollment_id", "kid", "alg", "public_key", "hpke_kid",
                                                                  "hpke_public_key", "assurance", "created_at"],
              o["v"]?.int64Value == 1, o["type"]?.stringValue == "approval-enrollment", o["alg"]?.stringValue == "ES256" else { throw ApprovalEnrollmentError.malformed("members") }
        guard let business = o["business_id"]?.stringValue.flatMap(BusinessID.init), let subject = o["subject_ref"]?.stringValue.flatMap({ SubjectRef($0) }),
              let enrollment = o["enrollment_id"]?.stringValue.flatMap({ UUID(uuidString: $0) }), enrollment.uuidString.lowercased() == o["enrollment_id"]?.stringValue,
              let keyText = o["public_key"]?.stringValue, let publicKey = try? DevicePublicKey(base64URL: keyText), publicKey.base64URL == keyText,
              let hpkeText = o["hpke_public_key"]?.stringValue, let hpke = try? E2EEPublicKey(base64URL: hpkeText), hpke.base64URL == hpkeText,
              o["kid"]?.stringValue == KeyIdentifier.make(try publicKey.signingKey()), o["hpke_kid"]?.stringValue == hpke.kid,
              let assurance = o["assurance"]?.stringValue.flatMap(ApprovalAMR.init(rawValue:)), assurance != .passcode,
              let created = o["created_at"]?.int64Value, created > 0 else { throw ApprovalEnrollmentError.malformed("values") }
        guard signed.isValid(domain: ApproveDomain.enrollment, publicKey: publicKey) else { throw ApprovalEnrollmentError.badSignature }
        return try ApprovalEnrollmentStatement(businessId: business, subject: subject, enrollmentId: enrollment, publicKey: publicKey, hpkePublicKey: hpke,
                                               assurance: assurance, createdAt: Date(timeIntervalSince1970: TimeInterval(created)))
    }

    /// Requires the statement to be for exactly this business, customer reference and enrollment.
    public func checkBinding(businessId: BusinessID, subject: SubjectRef, enrollmentId: UUID) throws {
        guard self.businessId == businessId else { throw ApprovalEnrollmentError.wrongBusiness }
        guard self.subject == subject else { throw ApprovalEnrollmentError.wrongSubject }
        guard self.enrollmentId == enrollmentId else { throw ApprovalEnrollmentError.wrongEnrollment }
    }

    /// SHA-256 of the signed payload bytes (hex): what the business's confirmation commits to.
    public static func digest(of signed: SignedStatement) -> String {
        SecureToken.sha256Hex(Data(signed.payload.utf8))
    }

    /// The verifier-side record of this key.
    public var enrolledKey: EnrolledApprovalKey { EnrolledApprovalKey(kid: kid, publicKey: publicKey, subject: subject, assurance: assurance) }
}

/// The business's signed acceptance of one enrollment (ADR-06): it commits to the exact key the business received, so the relay cannot
/// substitute a key without the device noticing.
///
/// ```json
/// {"business_id":"…","confirm_kid":"…","confirmed_at":…,"enrollment_id":"…","kid":"<approval kid>","statement_digest":"<hex>",
///  "subject_ref":"sub_…","type":"approval-enrollment-confirmation","v":1}
/// ```
/// Signed with a directory-published key of purpose `approval-enrollment-confirmation` over
/// `"VIADERE-APPROVAL-CONFIRM-V1\n" ‖ canonical payload`.
public struct ApprovalEnrollmentConfirmation: Sendable, Hashable {
    public var businessId: BusinessID
    public var subject: SubjectRef
    public var enrollmentId: UUID
    /// The approval key being confirmed.
    public var kid: String
    /// `ApprovalEnrollmentStatement.digest(of:)` of the device's signed statement.
    public var statementDigest: String
    public var confirmedAt: Int64

    public init(businessId: BusinessID, subject: SubjectRef, enrollmentId: UUID, kid: String, statementDigest: String, confirmedAt: Date) {
        self.businessId = businessId
        self.subject = subject
        self.enrollmentId = enrollmentId
        self.kid = kid
        self.statementDigest = statementDigest
        self.confirmedAt = ViadereDate.unixSeconds(confirmedAt)
    }

    /// Builds the confirmation of a device statement the business has already verified.
    public init(confirming statement: ApprovalEnrollmentStatement, signed: SignedStatement, at now: Date) {
        self.init(businessId: statement.businessId, subject: statement.subject, enrollmentId: statement.enrollmentId, kid: statement.kid,
                  statementDigest: ApprovalEnrollmentStatement.digest(of: signed), confirmedAt: now)
    }

    func object(confirmKid: String) -> [String: JSONValue] {
        ["v": .integer(1), "type": .string("approval-enrollment-confirmation"), "business_id": .string(businessId.description),
         "subject_ref": .string(subject.rawValue), "enrollment_id": .string(enrollmentId.uuidString.lowercased()), "kid": .string(kid),
         "statement_digest": .string(statementDigest), "confirm_kid": .string(confirmKid), "confirmed_at": .integer(confirmedAt)]
    }

    public func sign(with key: any DeviceSigningKey) async throws -> BusinessSignedStatement {
        let kid = try KeyIdentifier.make(p256X963: key.publicKey.x963)
        return try await BusinessSignedStatement.sign(object(confirmKid: kid), domain: ApproveDomain.confirmation, with: key)
    }

    /// Parses the confirmation and checks its signature with `confirmationKey` (which the caller took from the **verified directory** for
    /// `signed.kid`, purpose `approval-enrollment-confirmation`, valid now).
    public static func verify(_ signed: BusinessSignedStatement, confirmationKey: DevicePublicKey) throws -> ApprovalEnrollmentConfirmation {
        guard KeyIdentifier.make(try confirmationKey.signingKey()) == signed.kid else { throw ApprovalEnrollmentError.keyMismatch }
        guard signed.statement.isValid(domain: ApproveDomain.confirmation, publicKey: confirmationKey) else { throw ApprovalEnrollmentError.badSignature }
        guard let o = signed.statement.canonicalObject(), Set(o.keys) == ["v", "type", "business_id", "subject_ref", "enrollment_id", "kid", "statement_digest", "confirm_kid", "confirmed_at"],
              o["v"]?.int64Value == 1, o["type"]?.stringValue == "approval-enrollment-confirmation", o["confirm_kid"]?.stringValue == signed.kid,
              let business = o["business_id"]?.stringValue.flatMap(BusinessID.init), let subject = o["subject_ref"]?.stringValue.flatMap({ SubjectRef($0) }),
              let enrollment = o["enrollment_id"]?.stringValue.flatMap({ UUID(uuidString: $0) }), enrollment.uuidString.lowercased() == o["enrollment_id"]?.stringValue,
              let kid = o["kid"]?.stringValue, KeyIdentifier.isValid(kid), let digest = o["statement_digest"]?.stringValue, Interaction.isValidContextDigest(digest),
              let confirmed = o["confirmed_at"]?.int64Value, confirmed > 0 else { throw ApprovalEnrollmentError.malformed("confirmation") }
        return ApprovalEnrollmentConfirmation(businessId: business, subject: subject, enrollmentId: enrollment, kid: kid, statementDigest: digest,
                                              confirmedAt: Date(timeIntervalSince1970: TimeInterval(confirmed)))
    }

    /// The device's check that the business confirmed **its** key: same business, customer reference, enrollment, key id and statement.
    public func checkMatches(_ statement: ApprovalEnrollmentStatement, signed: SignedStatement) throws {
        try statement.checkBinding(businessId: businessId, subject: subject, enrollmentId: enrollmentId)
        guard kid == statement.kid else { throw ApprovalEnrollmentError.keyMismatch }
        guard ConstantTime.equals(statementDigest, ApprovalEnrollmentStatement.digest(of: signed)) else { throw ApprovalEnrollmentError.statementMismatch }
    }
}
