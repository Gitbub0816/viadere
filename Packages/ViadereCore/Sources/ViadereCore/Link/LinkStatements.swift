import Crypto
import Foundation

/// A statement signed by a key that is named next to it (`{kid, payload, signature}`): business statements (signed by a directory-published key)
/// and Viadere statements (signed by Viadere's `link-descriptor` key) have the same shape.
public typealias ViadereSignedStatement = BusinessSignedStatement

public enum LinkSessionError: Error, Sendable, Equatable {
    case malformed(String)
    case badSignature
    /// The descriptor or result is signed by a key this build (or the business) does not trust.
    case untrustedSigner
    case expired
    case issuedInFuture
    case wrongSession
    case wrongBusiness
    case wrongSubject
    case wrongCapabilities
    case wrongDescriptor
    case statementMismatch
    case approvalStatementMismatch
    case keyMismatch
}

extension LinkSessionError {
    static let skew: Int64 = 60
}

private func capabilitiesValue(_ capabilities: [Capability]) -> JSONValue {
    .array(LinkCapabilities.canonical(capabilities).map { .string($0.rawValue) })
}

private func parseCapabilities(_ value: JSONValue?) -> [Capability]? {
    guard case .array(let items)? = value, !items.isEmpty, items.count <= 8 else { return nil }
    var out: [Capability] = []
    for item in items {
        guard let raw = item.stringValue else { return nil }
        let capability = Capability(rawValue: raw)
        guard capability.isKnown else { return nil }
        out.append(capability)
    }
    // Canonical order, no duplicates: one byte string per set.
    guard out.map(\.rawValue) == LinkCapabilities.canonical(out).map(\.rawValue) else { return nil }
    return out
}

private func lowercaseUUID(_ value: JSONValue?) -> UUID? {
    guard let text = value?.stringValue, let id = UUID(uuidString: text), id.uuidString.lowercased() == text else { return nil }
    return id
}

/// The capability set of a link session in its one canonical form: unique, sorted by raw value.
public enum LinkCapabilities {
    public static func canonical(_ capabilities: [Capability]) -> [Capability] {
        Array(Set(capabilities.map(\.rawValue))).sorted().map(Capability.init(rawValue:))
    }

    /// The approval capabilities among `capabilities` (they need a pairwise approval key).
    public static func approval(_ capabilities: [Capability]) -> [Capability] { capabilities.filter { $0 == .authChallenge || $0 == .transactionApprove } }

    /// The protection an approval key for these capabilities must have (`biometric` for high and critical), or `nil` if none is requested.
    public static func requiredAssurance(_ capabilities: [Capability]) -> ApprovalAMR? {
        let approval = approval(capabilities)
        guard !approval.isEmpty else { return nil }
        let highest = approval.compactMap { $0.definition?.sensitivity }.max() ?? .critical
        return ApprovalAMR.required(for: highest)
    }
}

// MARK: - Descriptor (Viadere → device)

/// What the app shows before the person links a business, **signed by Viadere's `link-descriptor` key** (KMS-held) over
/// `"VIADERE-LINK-DESCRIPTOR-V1\n" ‖ canonical payload`:
///
/// ```json
/// {"business_domain":"northwind.example","business_id":"…","business_name":"Northwind Bank","capabilities":["auth.challenge","message.send"],
///  "display_hint":"Account ending 4821","expires_at":1800000300,"issued_at":1800000000,"root_kid":"…","session_id":"…","signer_kid":"…",
///  "subject_ref":"sub_…","type":"link-session-descriptor","v":1}
/// ```
/// The app accepts it only if the signer is one of the `link-descriptor` keys pinned in the build, and cross-checks `business_id` and `root_kid`
/// against the business's verified key directory. `subject_ref` binds it to the account that looked the code up.
public struct LinkSessionDescriptor: Sendable, Hashable {
    public var sessionId: UUID
    public var businessId: BusinessID
    public var businessName: String
    /// The business's verified domain, or empty.
    public var businessDomain: String
    public var rootKid: String
    public var capabilities: [Capability]
    /// Non-sensitive context the business chose ("Account ending 4821"), or empty.
    public var displayHint: String
    public var subject: SubjectRef
    public var issuedAt: Int64
    public var expiresAt: Int64

    public init(sessionId: UUID, businessId: BusinessID, businessName: String, businessDomain: String, rootKid: String, capabilities: [Capability],
                displayHint: String, subject: SubjectRef, issuedAt: Date, expiresAt: Date) {
        self.sessionId = sessionId
        self.businessId = businessId
        self.businessName = businessName
        self.businessDomain = businessDomain
        self.rootKid = rootKid
        self.capabilities = LinkCapabilities.canonical(capabilities)
        self.displayHint = displayHint
        self.subject = subject
        self.issuedAt = ViadereDate.unixSeconds(issuedAt)
        self.expiresAt = ViadereDate.unixSeconds(expiresAt)
    }

    public var expiresAtDate: Date { Date(timeIntervalSince1970: TimeInterval(expiresAt)) }

    public func object(signerKid: String) -> [String: JSONValue] {
        ["v": .integer(1), "type": .string("link-session-descriptor"), "session_id": .string(sessionId.uuidString.lowercased()),
         "business_id": .string(businessId.description), "business_name": .string(businessName), "business_domain": .string(businessDomain),
         "root_kid": .string(rootKid), "capabilities": capabilitiesValue(capabilities), "display_hint": .string(displayHint),
         "subject_ref": .string(subject.rawValue), "issued_at": .integer(issuedAt), "expires_at": .integer(expiresAt), "signer_kid": .string(signerKid)]
    }

    /// Canonical payload bytes to sign (the server signs `domain ‖ payload` through its key management service).
    public func payload(signerKid: String) throws -> Data { try CanonicalJSON.serialize(.object(object(signerKid: signerKid))) }

    /// Verifies a signed descriptor against the **pinned** `link-descriptor` keys: the signer must be one of them, the signature and the exact
    /// member set must check out, and it must be current.
    public static func verify(_ signed: ViadereSignedStatement, trustedKeys: [DevicePublicKey], now: Date) throws -> LinkSessionDescriptor {
        guard let key = trustedKeys.first(where: { (try? KeyIdentifier.make($0.signingKey())) == signed.kid }) else { throw LinkSessionError.untrustedSigner }
        guard signed.statement.isValid(domain: LinkDomainSeparator.descriptor, publicKey: key) else { throw LinkSessionError.badSignature }
        guard let o = signed.statement.canonicalObject(),
              Set(o.keys) == ["v", "type", "session_id", "business_id", "business_name", "business_domain", "root_kid", "capabilities", "display_hint",
                              "subject_ref", "issued_at", "expires_at", "signer_kid"],
              o["v"]?.int64Value == 1, o["type"]?.stringValue == "link-session-descriptor", o["signer_kid"]?.stringValue == signed.kid,
              let session = lowercaseUUID(o["session_id"]), let business = o["business_id"]?.stringValue.flatMap(BusinessID.init),
              let name = o["business_name"]?.stringValue, !name.isEmpty, name.count <= 120,
              let domain = o["business_domain"]?.stringValue, domain.count <= 253,
              let root = o["root_kid"]?.stringValue, KeyIdentifier.isValid(root),
              let capabilities = parseCapabilities(o["capabilities"]),
              let hint = o["display_hint"]?.stringValue, hint.count <= LinkSessionLimits.displayHintLength,
              let subject = o["subject_ref"]?.stringValue.flatMap({ SubjectRef($0) }),
              let issued = o["issued_at"]?.int64Value, let expires = o["expires_at"]?.int64Value, issued > 0, expires > issued,
              expires - issued <= Int64(LinkSessionLimits.maxLifetime) else { throw LinkSessionError.malformed("descriptor") }
        let nowSeconds = ViadereDate.unixSeconds(now)
        guard issued <= nowSeconds + LinkSessionError.skew else { throw LinkSessionError.issuedInFuture }
        guard expires > nowSeconds else { throw LinkSessionError.expired }
        return LinkSessionDescriptor(sessionId: session, businessId: business, businessName: name, businessDomain: domain, rootKid: root,
                                     capabilities: capabilities, displayHint: hint, subject: subject,
                                     issuedAt: Date(timeIntervalSince1970: TimeInterval(issued)), expiresAt: Date(timeIntervalSince1970: TimeInterval(expires)))
    }

    /// Hex SHA-256 of the descriptor's payload string: what the device's statement commits to.
    public static func digest(of signed: ViadereSignedStatement) -> String { SecureToken.sha256Hex(Data(signed.payload.utf8)) }
}

// MARK: - Statement (device → business, relayed)

/// The device's acceptance of one link session (`VIADERE-LINK-V1`), signed by a fresh **pairwise connection key** it contains (never a device or
/// account key, so two businesses cannot correlate it):
///
/// ```json
/// {"alg":"ES256","approval_statement_digest":"<hex, only with approval capabilities>","business_id":"…","capabilities":["auth.challenge","message.send"],
///  "created_at":1800000010,"descriptor_digest":"<hex>","kid":"…","public_key":"…","session_id":"…","subject_ref":"sub_…","type":"link-statement","v":1}
/// ```
/// When approval capabilities are requested the device also signs an ordinary `ApprovalEnrollmentStatement` (enrollment id = session id) with a new
/// pairwise approval key, and this statement commits to it by digest, so the binding tag and the SAS cover both.
public struct LinkStatement: Sendable, Hashable {
    public var sessionId: UUID
    public var businessId: BusinessID
    public var subject: SubjectRef
    public var capabilities: [Capability]
    public var descriptorDigest: String
    public var publicKey: DevicePublicKey
    public var kid: String
    public var approvalStatementDigest: String?
    public var createdAt: Int64

    public init(sessionId: UUID, businessId: BusinessID, subject: SubjectRef, capabilities: [Capability], descriptorDigest: String, publicKey: DevicePublicKey,
                approvalStatement: SignedStatement?, createdAt: Date) throws {
        self.sessionId = sessionId
        self.businessId = businessId
        self.subject = subject
        self.capabilities = LinkCapabilities.canonical(capabilities)
        self.descriptorDigest = descriptorDigest
        self.publicKey = publicKey
        kid = KeyIdentifier.make(try publicKey.signingKey())
        approvalStatementDigest = approvalStatement.map(ApprovalEnrollmentStatement.digest(of:))
        self.createdAt = ViadereDate.unixSeconds(createdAt)
    }

    var object: [String: JSONValue] {
        var o: [String: JSONValue] = ["v": .integer(1), "type": .string("link-statement"), "session_id": .string(sessionId.uuidString.lowercased()),
                                      "business_id": .string(businessId.description), "subject_ref": .string(subject.rawValue),
                                      "capabilities": capabilitiesValue(capabilities), "descriptor_digest": .string(descriptorDigest), "kid": .string(kid),
                                      "public_key": .string(publicKey.base64URL), "alg": .string("ES256"), "created_at": .integer(createdAt)]
        if let approvalStatementDigest { o["approval_statement_digest"] = .string(approvalStatementDigest) }
        return o
    }

    public func sign(with key: any DeviceSigningKey) async throws -> SignedStatement {
        guard key.publicKey == publicKey else { throw LinkSessionError.keyMismatch }
        return try await SignedStatement.sign(object, domain: LinkDomainSeparator.statement, with: key)
    }

    /// Parses and verifies a signed statement (canonical form, members, the signature under the key it contains). Binding is `checkBinding`.
    public static func verify(_ signed: SignedStatement) throws -> LinkStatement {
        guard let o = signed.canonicalObject() else { throw LinkSessionError.malformed("statement") }
        var expected: Set<String> = ["v", "type", "session_id", "business_id", "subject_ref", "capabilities", "descriptor_digest", "kid", "public_key", "alg", "created_at"]
        if o["approval_statement_digest"] != nil { expected.insert("approval_statement_digest") }
        guard Set(o.keys) == expected, o["v"]?.int64Value == 1, o["type"]?.stringValue == "link-statement", o["alg"]?.stringValue == "ES256",
              let session = lowercaseUUID(o["session_id"]), let business = o["business_id"]?.stringValue.flatMap(BusinessID.init),
              let subject = o["subject_ref"]?.stringValue.flatMap({ SubjectRef($0) }), let capabilities = parseCapabilities(o["capabilities"]),
              let descriptor = o["descriptor_digest"]?.stringValue, Interaction.isValidContextDigest(descriptor),
              let keyText = o["public_key"]?.stringValue, let publicKey = try? DevicePublicKey(base64URL: keyText), publicKey.base64URL == keyText,
              o["kid"]?.stringValue == KeyIdentifier.make(try publicKey.signingKey()),
              let created = o["created_at"]?.int64Value, created > 0 else { throw LinkSessionError.malformed("statement") }
        var approvalDigest: String?
        if let value = o["approval_statement_digest"] {
            guard let digest = value.stringValue, Interaction.isValidContextDigest(digest) else { throw LinkSessionError.malformed("statement") }
            approvalDigest = digest
        }
        guard signed.isValid(domain: LinkDomainSeparator.statement, publicKey: publicKey) else { throw LinkSessionError.badSignature }
        var statement = try LinkStatement(sessionId: session, businessId: business, subject: subject, capabilities: capabilities, descriptorDigest: descriptor,
                                          publicKey: publicKey, approvalStatement: nil, createdAt: Date(timeIntervalSince1970: TimeInterval(created)))
        statement.approvalStatementDigest = approvalDigest
        return statement
    }

    /// Requires the statement to be for exactly this session, business, account and capability set, and — when given — this descriptor.
    public func checkBinding(sessionId: UUID, businessId: BusinessID, subject: SubjectRef, capabilities: [Capability], descriptorDigest: String? = nil) throws {
        guard self.sessionId == sessionId else { throw LinkSessionError.wrongSession }
        guard self.businessId == businessId else { throw LinkSessionError.wrongBusiness }
        guard self.subject == subject else { throw LinkSessionError.wrongSubject }
        guard self.capabilities.map(\.rawValue) == LinkCapabilities.canonical(capabilities).map(\.rawValue) else { throw LinkSessionError.wrongCapabilities }
        if let descriptorDigest, !ConstantTime.equals(self.descriptorDigest, descriptorDigest) { throw LinkSessionError.wrongDescriptor }
    }

    /// Checks the approval statement this link statement commits to: present exactly when approval capabilities were requested, with the matching
    /// digest, valid, and bound to this business, account and session (its enrollment id is the session id). Returns it parsed.
    public func checkApprovalStatement(_ signed: SignedStatement?) throws -> ApprovalEnrollmentStatement? {
        let needsKey = !LinkCapabilities.approval(capabilities).isEmpty
        switch (needsKey, signed, approvalStatementDigest) {
        case (false, nil, nil): return nil
        case (true, let signed?, let digest?):
            guard ConstantTime.equals(ApprovalEnrollmentStatement.digest(of: signed), digest) else { throw LinkSessionError.approvalStatementMismatch }
            let approval: ApprovalEnrollmentStatement
            do { approval = try ApprovalEnrollmentStatement.verify(signed) } catch { throw LinkSessionError.approvalStatementMismatch }
            do { try approval.checkBinding(businessId: businessId, subject: subject, enrollmentId: sessionId) } catch { throw LinkSessionError.approvalStatementMismatch }
            if let required = LinkCapabilities.requiredAssurance(capabilities), !approval.assurance.satisfies(required) {
                throw LinkSessionError.approvalStatementMismatch
            }
            return approval
        default: throw LinkSessionError.approvalStatementMismatch
        }
    }

    public static func digest(of signed: SignedStatement) -> String { SecureToken.sha256Hex(Data(signed.payload.utf8)) }
}

// MARK: - Confirmation (business → device, relayed)

/// How the person verified the link in the business's signed-in session.
public enum LinkVerification: String, Sendable, Hashable, Codable {
    /// The person typed the six digits the app showed into the business's session (the business compared them).
    case sasTyped = "sas_typed"
    /// The business showed the six digits and the person confirmed they match the app (only together with a valid binding tag).
    case sasCompared = "sas_compared"
}

/// The business's signed acceptance of the device's statement, with a directory-published `approval-enrollment-confirmation` key, over
/// `"VIADERE-LINK-CONFIRM-V1\n" ‖ canonical payload`: members `v, type: link-confirmation, business_id, session_id, subject_ref, statement_digest,
/// kid (the connection key), verification, confirm_kid, confirmed_at`. The relay cannot make one; the device checks it covers **its** statement.
public struct LinkConfirmation: Sendable, Hashable {
    public var businessId: BusinessID
    public var sessionId: UUID
    public var subject: SubjectRef
    public var statementDigest: String
    public var kid: String
    public var verification: LinkVerification
    public var confirmedAt: Int64

    public init(confirming statement: LinkStatement, signed: SignedStatement, verification: LinkVerification, at now: Date) {
        businessId = statement.businessId
        sessionId = statement.sessionId
        subject = statement.subject
        statementDigest = LinkStatement.digest(of: signed)
        kid = statement.kid
        self.verification = verification
        confirmedAt = ViadereDate.unixSeconds(now)
    }

    init(businessId: BusinessID, sessionId: UUID, subject: SubjectRef, statementDigest: String, kid: String, verification: LinkVerification, confirmedAt: Int64) {
        self.businessId = businessId
        self.sessionId = sessionId
        self.subject = subject
        self.statementDigest = statementDigest
        self.kid = kid
        self.verification = verification
        self.confirmedAt = confirmedAt
    }

    func object(confirmKid: String) -> [String: JSONValue] {
        ["v": .integer(1), "type": .string("link-confirmation"), "business_id": .string(businessId.description), "session_id": .string(sessionId.uuidString.lowercased()),
         "subject_ref": .string(subject.rawValue), "statement_digest": .string(statementDigest), "kid": .string(kid),
         "verification": .string(verification.rawValue), "confirm_kid": .string(confirmKid), "confirmed_at": .integer(confirmedAt)]
    }

    public func sign(with key: any DeviceSigningKey) async throws -> BusinessSignedStatement {
        let kid = try KeyIdentifier.make(p256X963: key.publicKey.x963)
        return try await BusinessSignedStatement.sign(object(confirmKid: kid), domain: LinkDomainSeparator.confirmation, with: key)
    }

    /// Parses and checks the signature with `confirmationKey`, which the caller took from the **verified directory** for `signed.kid`.
    public static func verify(_ signed: BusinessSignedStatement, confirmationKey: DevicePublicKey) throws -> LinkConfirmation {
        guard KeyIdentifier.make(try confirmationKey.signingKey()) == signed.kid else { throw LinkSessionError.keyMismatch }
        guard signed.statement.isValid(domain: LinkDomainSeparator.confirmation, publicKey: confirmationKey) else { throw LinkSessionError.badSignature }
        guard let o = signed.statement.canonicalObject(),
              Set(o.keys) == ["v", "type", "business_id", "session_id", "subject_ref", "statement_digest", "kid", "verification", "confirm_kid", "confirmed_at"],
              o["v"]?.int64Value == 1, o["type"]?.stringValue == "link-confirmation", o["confirm_kid"]?.stringValue == signed.kid,
              let business = o["business_id"]?.stringValue.flatMap(BusinessID.init), let session = lowercaseUUID(o["session_id"]),
              let subject = o["subject_ref"]?.stringValue.flatMap({ SubjectRef($0) }),
              let digest = o["statement_digest"]?.stringValue, Interaction.isValidContextDigest(digest),
              let kid = o["kid"]?.stringValue, KeyIdentifier.isValid(kid),
              let verification = o["verification"]?.stringValue.flatMap(LinkVerification.init(rawValue:)),
              let confirmed = o["confirmed_at"]?.int64Value, confirmed > 0 else { throw LinkSessionError.malformed("confirmation") }
        return LinkConfirmation(businessId: business, sessionId: session, subject: subject, statementDigest: digest, kid: kid, verification: verification,
                                confirmedAt: confirmed)
    }

    /// The device's (and the relay's) check that the business confirmed exactly this statement.
    public func checkMatches(_ statement: LinkStatement, signed: SignedStatement) throws {
        guard businessId == statement.businessId else { throw LinkSessionError.wrongBusiness }
        guard sessionId == statement.sessionId else { throw LinkSessionError.wrongSession }
        guard subject == statement.subject else { throw LinkSessionError.wrongSubject }
        guard kid == statement.kid else { throw LinkSessionError.keyMismatch }
        guard ConstantTime.equals(statementDigest, LinkStatement.digest(of: signed)) else { throw LinkSessionError.statementMismatch }
    }
}

// MARK: - Result (Viadere → business)

/// Viadere's signed account of a completed session for the business (key `link-descriptor`, `"VIADERE-LINK-RESULT-V1\n" ‖ payload`):
/// members `v, type: link-result, session_id, business_id, subject_ref, statement_digest, approval_statement_digest?, completed_at, signer_kid`.
/// It tells the business which pairwise `subject_ref` completed the session and which statement it relayed; the business still authenticates
/// the statement itself (binding tag, SAS) before it confirms.
public struct LinkResult: Sendable, Hashable {
    public var sessionId: UUID
    public var businessId: BusinessID
    public var subject: SubjectRef
    public var statementDigest: String
    public var approvalStatementDigest: String?
    public var completedAt: Int64

    public init(sessionId: UUID, businessId: BusinessID, subject: SubjectRef, statementDigest: String, approvalStatementDigest: String?, completedAt: Date) {
        self.sessionId = sessionId
        self.businessId = businessId
        self.subject = subject
        self.statementDigest = statementDigest
        self.approvalStatementDigest = approvalStatementDigest
        self.completedAt = ViadereDate.unixSeconds(completedAt)
    }

    public func object(signerKid: String) -> [String: JSONValue] {
        var o: [String: JSONValue] = ["v": .integer(1), "type": .string("link-result"), "session_id": .string(sessionId.uuidString.lowercased()),
                                      "business_id": .string(businessId.description), "subject_ref": .string(subject.rawValue),
                                      "statement_digest": .string(statementDigest), "completed_at": .integer(completedAt), "signer_kid": .string(signerKid)]
        if let approvalStatementDigest { o["approval_statement_digest"] = .string(approvalStatementDigest) }
        return o
    }

    public func payload(signerKid: String) throws -> Data { try CanonicalJSON.serialize(.object(object(signerKid: signerKid))) }

    /// Verifies against Viadere's `link-descriptor` public keys the business pinned (SDK configuration).
    public static func verify(_ signed: ViadereSignedStatement, trustedKeys: [DevicePublicKey]) throws -> LinkResult {
        guard let key = trustedKeys.first(where: { (try? KeyIdentifier.make($0.signingKey())) == signed.kid }) else { throw LinkSessionError.untrustedSigner }
        guard signed.statement.isValid(domain: LinkDomainSeparator.result, publicKey: key) else { throw LinkSessionError.badSignature }
        guard let o = signed.statement.canonicalObject() else { throw LinkSessionError.malformed("result") }
        var expected: Set<String> = ["v", "type", "session_id", "business_id", "subject_ref", "statement_digest", "completed_at", "signer_kid"]
        if o["approval_statement_digest"] != nil { expected.insert("approval_statement_digest") }
        guard Set(o.keys) == expected, o["v"]?.int64Value == 1, o["type"]?.stringValue == "link-result", o["signer_kid"]?.stringValue == signed.kid,
              let session = lowercaseUUID(o["session_id"]), let business = o["business_id"]?.stringValue.flatMap(BusinessID.init),
              let subject = o["subject_ref"]?.stringValue.flatMap({ SubjectRef($0) }),
              let digest = o["statement_digest"]?.stringValue, Interaction.isValidContextDigest(digest),
              let completed = o["completed_at"]?.int64Value, completed > 0 else { throw LinkSessionError.malformed("result") }
        var approval: String?
        if let value = o["approval_statement_digest"] {
            guard let text = value.stringValue, Interaction.isValidContextDigest(text) else { throw LinkSessionError.malformed("result") }
            approval = text
        }
        return LinkResult(sessionId: session, businessId: business, subject: subject, statementDigest: digest, approvalStatementDigest: approval,
                          completedAt: Date(timeIntervalSince1970: TimeInterval(completed)))
    }
}

/// Limits of the link-session protocol.
public enum LinkSessionLimits {
    /// A link session lives at most five minutes (§2.12: the QR must be short-lived).
    public static let maxLifetime = 300
    public static let minLifetime = 60
    public static let displayHintLength = 40
    public static let customerRefLength = 128
    public static let maxCapabilities = 8
}
