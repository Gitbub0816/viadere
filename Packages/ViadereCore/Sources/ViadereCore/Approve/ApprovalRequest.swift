import Crypto
import Foundation

public enum ApprovalRequestError: Error, Sendable, Equatable {
    case malformed(String)
    case badSignature
    case wrongBusiness
    case wrongSubject
    case wrongRequest
    case wrongDevice
    case expired
    case notYetValid
    case lifetimeTooLong
}

/// The request a business shows its customer, signed by the business (section 2.54). Inside an end-to-end envelope it is the plaintext; the
/// signature is what tells the device the request came from the business and not from the relay.
///
/// ```json
/// {"business_id":"…","capability":"transaction.approve","challenge":"…","exp":…,"iat":…,"request_id":"…","subject_ref":"sub_…",
///  "to_kid":"<approval key kid>","transaction":{…ApprovalSubject.canonicalJSON…},"type":"approval-request","v":1}
/// ```
/// Signed with a directory key of purpose `approval-request-signing` over `"VIADERE-APPROVAL-REQUEST-V1\n" ‖ canonical payload`.
public struct ApprovalRequestContent: Sendable, Hashable {
    /// Longest a request may live (the policy maximum for `expires_in_seconds`).
    public static let maxLifetime: TimeInterval = 600

    public var businessId: BusinessID
    public var subject: SubjectRef
    public var requestId: String
    public var challenge: String
    public var details: ApprovalSubject
    /// The approval key this copy of the request is for (each device gets its own signed copy).
    public var toKid: String
    public var issuedAt: Int64
    public var expiresAt: Int64

    public var capability: Capability { details.capability }
    public var expiresAtDate: Date { Date(timeIntervalSince1970: TimeInterval(expiresAt)) }
    public var issuedAtDate: Date { Date(timeIntervalSince1970: TimeInterval(issuedAt)) }

    public init(businessId: BusinessID, subject: SubjectRef, requestId: String, challenge: String, details: ApprovalSubject, toKid: String,
                issuedAt: Date, expiresAt: Date) {
        self.businessId = businessId
        self.subject = subject
        self.requestId = requestId
        self.challenge = challenge
        self.details = details
        self.toKid = toKid
        self.issuedAt = ViadereDate.unixSeconds(issuedAt)
        self.expiresAt = ViadereDate.unixSeconds(expiresAt)
    }

    func object() throws -> [String: JSONValue] {
        let transaction = try JSONDecoder().decode(JSONValue.self, from: try details.canonicalJSON())
        return ["v": .integer(1), "type": .string("approval-request"), "business_id": .string(businessId.description), "subject_ref": .string(subject.rawValue),
                "request_id": .string(requestId), "capability": .string(capability.rawValue), "challenge": .string(challenge), "transaction": transaction,
                "to_kid": .string(toKid), "iat": .integer(issuedAt), "exp": .integer(expiresAt)]
    }

    public func sign(with key: any DeviceSigningKey) async throws -> BusinessSignedStatement {
        try await BusinessSignedStatement.sign(try object(), domain: ApproveDomain.request, with: key)
    }

    /// The bytes that go into the E2EE envelope: the canonical JSON of the signed statement.
    public func sealedPlaintext(signedWith key: any DeviceSigningKey) async throws -> Data {
        let signed = try await sign(with: key)
        return try CanonicalJSON.serialize(.object(["kid": .string(signed.kid), "payload": .string(signed.payload), "signature": .string(signed.signature)]))
    }

    /// Parses decrypted plaintext (see `sealedPlaintext`) into the signed statement. Strict member set.
    public static func parseSigned(_ plaintext: Data) throws -> BusinessSignedStatement {
        guard plaintext.count <= 16 * 1024, case .object(let o)? = try? JSONDecoder().decode(JSONValue.self, from: plaintext), Set(o.keys) == ["kid", "payload", "signature"],
              let kid = o["kid"]?.stringValue, let payload = o["payload"]?.stringValue, let signature = o["signature"]?.stringValue,
              KeyIdentifier.isValid(kid) else { throw ApprovalRequestError.malformed("signed request") }
        return BusinessSignedStatement(kid: kid, payload: payload, signature: signature)
    }

    /// Verifies a signed request. `signingKey` must be the **directory** key for `signed.kid` (purpose `approval-request-signing`, valid now,
    /// not revoked), obtained through a verified `KeyDirectoryVerifier` result for this business.
    ///
    /// Checks the signature, the exact member set, that the request names this business, this customer reference, this approval key and
    /// (when the transport carried one) this request id, and that it is neither expired nor from the future.
    public static func verify(_ signed: BusinessSignedStatement, signingKey: DevicePublicKey, expectedBusiness: BusinessID, expectedSubject: SubjectRef,
                              expectedKid: String, expectedRequestId: String?, now: Date, maxClockSkew: TimeInterval = 60) throws -> ApprovalRequestContent {
        guard (try? signingKey.signingKey()).map({ KeyIdentifier.make($0) == signed.kid }) == true else { throw ApprovalRequestError.badSignature }
        guard signed.statement.isValid(domain: ApproveDomain.request, publicKey: signingKey) else { throw ApprovalRequestError.badSignature }
        guard let o = signed.statement.canonicalObject(), Set(o.keys) == ["v", "type", "business_id", "subject_ref", "request_id", "capability", "challenge", "transaction", "to_kid", "iat", "exp"],
              o["v"]?.int64Value == 1, o["type"]?.stringValue == "approval-request",
              let business = o["business_id"]?.stringValue.flatMap(BusinessID.init), let subject = o["subject_ref"]?.stringValue.flatMap({ SubjectRef($0) }),
              let requestId = o["request_id"]?.stringValue, E2EEContext.validIdentifier(requestId), let challenge = o["challenge"]?.stringValue, ChallengeNonce(challenge) != nil,
              let toKid = o["to_kid"]?.stringValue, KeyIdentifier.isValid(toKid), let iat = o["iat"]?.int64Value, let exp = o["exp"]?.int64Value, exp > iat, iat > 0,
              let transaction = o["transaction"], let details = try? ApprovalSubject.parse(transaction), o["capability"]?.stringValue == details.capability.rawValue else {
            throw ApprovalRequestError.malformed("request")
        }
        guard business == expectedBusiness else { throw ApprovalRequestError.wrongBusiness }
        guard subject == expectedSubject else { throw ApprovalRequestError.wrongSubject }
        guard toKid == expectedKid else { throw ApprovalRequestError.wrongDevice }
        if let expectedRequestId, requestId != expectedRequestId { throw ApprovalRequestError.wrongRequest }
        guard TimeInterval(exp - iat) <= maxLifetime else { throw ApprovalRequestError.lifetimeTooLong }
        guard Date(timeIntervalSince1970: TimeInterval(iat)) <= now.addingTimeInterval(maxClockSkew) else { throw ApprovalRequestError.notYetValid }
        guard Date(timeIntervalSince1970: TimeInterval(exp)) > now else { throw ApprovalRequestError.expired }
        return ApprovalRequestContent(businessId: business, subject: subject, requestId: requestId, challenge: challenge, details: details, toKid: toKid,
                                      issuedAt: Date(timeIntervalSince1970: TimeInterval(iat)), expiresAt: Date(timeIntervalSince1970: TimeInterval(exp)))
    }
}

/// The device's answer: builds and signs an `ApprovalResult` JWS for exactly what was displayed.
public enum ApprovalResultFactory {
    /// How long a result stays valid after the decision (the business must act on it within this window).
    public static let resultLifetime: TimeInterval = 300

    /// - Parameters:
    ///   - displayed: the request content **as the person saw it**: its digest is what gets signed.
    public static func sign(displayed: ApprovalRequestContent, decision: ApprovalDecision, amr: ApprovalAMR, key: any DeviceSigningKey, now: Date) async throws -> String {
        let claims = ApprovalResultClaims(kid: try KeyIdentifier.make(p256X963: key.publicKey.x963), audience: displayed.businessId, subject: displayed.subject,
                                          requestId: displayed.requestId, challenge: displayed.challenge, capability: displayed.capability, decision: decision,
                                          amr: amr, issuedAt: now, expiresAt: now.addingTimeInterval(resultLifetime), transactionDigest: try displayed.details.digest())
        return try await ApprovalResultJWS.sign(claims, with: key)
    }
}
