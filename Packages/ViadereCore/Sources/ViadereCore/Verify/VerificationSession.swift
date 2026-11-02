import Crypto
import Foundation

// MARK: - Verification sessions ("Verify with Viadere", `docs/VERIFY-BUTTON.md`, `docs/SECURITY.md` §2.60)
//
// A business shows a "Verify with Viadere" button on its website or in its app. Its **server** creates a short-lived, single-use verification
// session for one capability (`age.minimum`, `identity.*`) and the web origin it will show the button on. The button hands the session's link
// (`https://{link domain}/v/{CODE}`) to the Viadere app — directly by universal link / App Link on a phone, or as a QR code (or the typed code)
// on a desktop. The app looks the code up, receives a **descriptor signed by Viadere's `link-descriptor` key** that names the verified business,
// its verified domain and the origin the session was created for, shows them, and — only if the person accepts — connects to the business and
// opens an ordinary verification request (the existing Verify consent, disclosure receipt and evidence flow, unchanged). When the request ends,
// Viadere signs a `VerificationSessionResult` for the business. Nothing the browser or the business's front end holds is trusted: the business's
// server reads the session with its API key and verifies the signed result against the `link-descriptor` keys it pinned.

/// Domain separators of the verification-session protocol. Each signed object has its own, and none is shared with link sessions, so a value
/// made for one protocol is never valid in the other even though the same `link-descriptor` key signs both.
public enum VerificationSessionDomainSeparator {
    /// Viadere's signed descriptor of a session, for the device.
    public static let descriptor = "VIADERE-VERIFY-SESSION-DESCRIPTOR-V1\n"
    /// Viadere's signed result of a session, for the business.
    public static let result = "VIADERE-VERIFY-SESSION-RESULT-V1\n"
}

/// Limits of the verification-session protocol.
public enum VerificationSessionLimits {
    /// The code (QR, link, typed) is valid for at most five minutes, like a link session (§2.12: a QR must be short-lived).
    public static let minLifetime = 60
    public static let maxLifetime = 300
    public static let defaultLifetime = 300
    /// Once accepted, the person has this long to finish the verification (the request's own lifetime, `VerifyPolicy.maxRequestLifetime`).
    public static var requestLifetime: Int { VerifyPolicy.maxRequestLifetime }
    public static let returnURLLength = 512
    public static let purposeCodeLength = 64
    public static let maxParameters = 8
}

public enum VerificationSessionError: Error, Sendable, Equatable {
    case malformed(String)
    case badSignature
    /// Signed by a key this build (or the business) does not trust.
    case untrustedSigner
    case expired
    case issuedInFuture
    case wrongSession
    case wrongBusiness
    case wrongOrigin
    case wrongCapability
    /// The origin is not inside the business's verified domain.
    case originOutsideBusinessDomain
}

/// The short single-use code of a verification session: eight characters of the Approve alphabet (40 bits, no look-alikes), shown `ABCD-EFGH`.
/// Lookup is rationed per account and globally and the session lives at most five minutes, so the code space cannot be searched.
public enum VerificationSessionCode {
    public static let length = ApprovalEnrollmentCode.length
    public static func generate() -> String { ApprovalEnrollmentCode.generate() }
    public static func canonical(_ input: String) -> String? { ApprovalEnrollmentCode.canonical(input) }
    public static func display(_ canonical: String) -> String { ApprovalEnrollmentCode.display(canonical) }
}

/// The link of a verification session: `https://{link domain}/v/{CODE}`. It carries **no secret** and nothing about the business or the person;
/// the app learns everything from the signed descriptor.
public enum VerificationSessionLink {
    public static func build(code: String, domain: LinkDomain = .current) -> String { "\(domain.origin)\(APIRoutes.Web.verificationSessionPrefix)\(code)" }

    /// Strict: https, exactly the link domain (no `www.`, no port, no user info), path `/v/{CODE}` with a canonical code, no query and no fragment.
    public static func parse(_ link: URL, domain: LinkDomain = .current) -> String? {
        guard link.scheme == "https", domain.matches(link.host), link.host == link.host?.lowercased(), link.user == nil, link.password == nil,
              link.port == nil, let components = URLComponents(url: link, resolvingAgainstBaseURL: false), components.query == nil,
              components.fragment == nil else { return nil }
        let parts = components.percentEncodedPath.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3, parts[0].isEmpty, parts[1] == "v", let code = VerificationSessionCode.canonical(parts[2]), code == parts[2] else { return nil }
        return code
    }
}

/// The web origin a verification session is bound to (`https://shop.example`): https only, a plain DNS host (the `LinkDomain` rules), no port,
/// no user info, no path beyond `/`, no query, no fragment. Canonical form is lower case without a trailing slash.
public enum VerificationSessionOrigin {
    public static func canonical(_ text: String) -> String? {
        guard text.utf8.count <= 300, let components = URLComponents(string: text), components.scheme?.lowercased() == "https",
              components.user == nil, components.password == nil, components.port == nil, components.query == nil, components.fragment == nil,
              components.percentEncodedPath.isEmpty || components.percentEncodedPath == "/",
              let host = components.host?.lowercased(), LinkDomain.isValid(host) else { return nil }
        return "https://" + host
    }

    /// The host of a canonical origin.
    public static func host(of origin: String) -> String? {
        guard let canonical = canonical(origin) else { return nil }
        return String(canonical.dropFirst("https://".count))
    }

    /// Whether the origin's host is `domain` or one of its subdomains (`shop.northwind.example` is within `northwind.example`;
    /// `northwind.example.evil.test` and `evilnorthwind.example` are not).
    public static func isWithin(_ origin: String, domain: String) -> Bool {
        guard let host = host(of: origin), !domain.isEmpty, LinkDomain.isValid(domain.lowercased()) else { return false }
        let d = domain.lowercased()
        return host == d || host.hasSuffix("." + d)
    }

    /// A return URL the app may open after the verification: https, **the session's origin exactly** (same host, no port, no user info), a path
    /// and an optional query, no fragment, at most 512 bytes, printable ASCII only. Returns the URL unchanged, or `nil`.
    public static func validReturnURL(_ text: String, origin: String) -> String? {
        guard let canonicalOrigin = canonical(origin), (1...VerificationSessionLimits.returnURLLength).contains(text.utf8.count),
              text.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7F }), let components = URLComponents(string: text), components.scheme == "https",
              components.user == nil, components.password == nil, components.port == nil, components.fragment == nil,
              let host = components.host, host == host.lowercased(), "https://" + host == canonicalOrigin,
              components.percentEncodedPath.hasPrefix("/") else { return nil }
        return text
    }
}

/// A purpose code: lower-case snake case, 2 to 64 characters (`age_restricted_purchase`). Never free text.
public enum VerificationPurposeCode {
    public static func isValid(_ code: String) -> Bool {
        (2...VerificationSessionLimits.purposeCodeLength).contains(code.utf8.count) && code.utf8.first.map { $0 >= 0x61 && $0 <= 0x7A } == true
            && code.utf8.allSatisfy { ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x5F }
    }
}

// MARK: - Status and DTOs

/// Where a verification session stands.
public enum VerificationSessionStatus: String, Codable, Sendable, Hashable {
    /// Created by the business; waiting for the app.
    case open
    /// The app accepted it (consumed once, compare-and-swap): a verification request is open for the person.
    case accepted
    /// The request ended; `result` holds Viadere's signed `VerificationSessionResult` (`verified` or `not_verified`).
    case completed
    /// Nobody accepted it in time.
    case expired
    case cancelled
    case unknown

    public init(from decoder: any Decoder) throws {
        self = VerificationSessionStatus(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
    }
}

/// `POST /v1/business/verification-sessions`, called by the business's **server** (never its front end: the API key never leaves the server).
public struct CreateVerificationSessionRequest: Codable, Sendable, Hashable {
    /// `age.minimum`, `identity.name`, `identity.address` or `identity.verified`.
    public var capability: Capability
    /// The capability's typed parameters (`{"years": 18}`).
    public var parameters: [String: JSONValue]?
    public var purposeCode: String
    /// The web origin the button is shown on (`https://shop.example`). It must be the business's verified domain or a subdomain of it; the app
    /// shows it, and the signed result names it.
    public var origin: String
    /// Where the app sends the person after the verification (same origin exactly), or `nil`.
    public var returnURL: String?
    /// A registered webhook endpoint (subscribed to `verification.completed`), never a URL.
    public var callbackId: String?
    /// 60...300 (default 300): how long the QR / link / code can be accepted.
    public var expiresInSeconds: Int?

    public init(capability: Capability, parameters: [String: JSONValue]? = nil, purposeCode: String, origin: String, returnURL: String? = nil,
                callbackId: String? = nil, expiresInSeconds: Int? = nil) {
        self.capability = capability
        self.parameters = parameters
        self.purposeCode = purposeCode
        self.origin = origin
        self.returnURL = returnURL
        self.callbackId = callbackId
        self.expiresInSeconds = expiresInSeconds
    }

    enum CodingKeys: String, CodingKey {
        case capability, parameters, purposeCode = "purpose_code", origin, returnURL = "return_url", callbackId = "callback_id", expiresInSeconds = "expires_in_seconds"
    }
}

/// The answer to a create: what the business renders into its button (`link`, `code`) and keeps on its server (`session_id`).
public struct VerificationSessionTicket: Codable, Sendable, Hashable {
    public var sessionId: UUID
    /// Canonical code (eight characters); show it as `ABCD-EFGH` for a person who types it into the app.
    public var code: String
    /// `https://{link domain}/v/{CODE}`: the button's target and the QR content.
    public var link: String
    public var expiresAt: Date

    public init(sessionId: UUID, code: String, link: String, expiresAt: Date) {
        self.sessionId = sessionId
        self.code = code
        self.link = link
        self.expiresAt = expiresAt
    }

    public var displayCode: String { VerificationSessionCode.display(code) }

    enum CodingKeys: String, CodingKey { case sessionId = "session_id", code, link, expiresAt = "expires_at" }
}

/// The business's view of its session (`GET /v1/business/verification-sessions/{id}`). **Trust only `result`**, after
/// `VerificationSessionResult.verify` against the `link-descriptor` keys you pinned and `check(...)` against the session you created.
public struct VerificationSessionView: Codable, Sendable, Hashable {
    public var sessionId: UUID
    public var status: VerificationSessionStatus
    public var capability: Capability
    public var purposeCode: String
    public var origin: String
    public var createdAt: Date
    public var expiresAt: Date
    /// Once accepted: the verification request opened for the person, and the pairwise reference of their account.
    public var requestId: VerificationRequestID?
    public var subjectRef: SubjectRef?
    /// Once completed: the single-use result reference (`GET /v1/verification-results/{result_ref}` returns the attribute values).
    public var resultRef: VerificationResultRef?
    /// Once completed: Viadere's signed `VerificationSessionResult`.
    public var result: ViadereSignedStatement?
    public var completedAt: Date?

    public init(sessionId: UUID, status: VerificationSessionStatus, capability: Capability, purposeCode: String, origin: String, createdAt: Date, expiresAt: Date,
                requestId: VerificationRequestID? = nil, subjectRef: SubjectRef? = nil, resultRef: VerificationResultRef? = nil,
                result: ViadereSignedStatement? = nil, completedAt: Date? = nil) {
        self.sessionId = sessionId
        self.status = status
        self.capability = capability
        self.purposeCode = purposeCode
        self.origin = origin
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.requestId = requestId
        self.subjectRef = subjectRef
        self.resultRef = resultRef
        self.result = result
        self.completedAt = completedAt
    }

    enum CodingKeys: String, CodingKey {
        case sessionId = "session_id", status, capability, purposeCode = "purpose_code", origin, createdAt = "created_at", expiresAt = "expires_at"
        case requestId = "request_id", subjectRef = "subject_ref", resultRef = "result_ref", result, completedAt = "completed_at"
    }
}

/// `POST /v1/verification-sessions/lookup` (the app).
public struct VerificationSessionLookupRequest: Codable, Sendable, Hashable {
    public var code: String
    public init(code: String) { self.code = code }
}

/// What the app shows before the person accepts. **Only `descriptor` is trusted**, after `VerificationSessionDescriptor.verify` with the pinned
/// keys; the other members are conveniences that must agree with it.
public struct VerificationSessionOffer: Codable, Sendable, Hashable {
    public var sessionId: UUID
    public var descriptor: ViadereSignedStatement
    public var business: BusinessSummary
    public var subjectRef: SubjectRef
    /// The account is already connected to this business (otherwise accepting also connects it; the app says so).
    public var alreadyConnected: Bool
    public var expiresAt: Date

    public init(sessionId: UUID, descriptor: ViadereSignedStatement, business: BusinessSummary, subjectRef: SubjectRef, alreadyConnected: Bool, expiresAt: Date) {
        self.sessionId = sessionId
        self.descriptor = descriptor
        self.business = business
        self.subjectRef = subjectRef
        self.alreadyConnected = alreadyConnected
        self.expiresAt = expiresAt
    }

    enum CodingKeys: String, CodingKey {
        case sessionId = "session_id", descriptor, business, subjectRef = "subject_ref", alreadyConnected = "already_connected", expiresAt = "expires_at"
    }
}

/// `POST /v1/verification-sessions/{id}/accept`: the app quotes the digest of the descriptor it verified and showed, so the session is accepted
/// for exactly that business, origin, capability and purpose.
public struct VerificationSessionAcceptRequest: Codable, Sendable, Hashable {
    public var descriptorDigest: String
    public init(descriptorDigest: String) { self.descriptorDigest = descriptorDigest }
    enum CodingKeys: String, CodingKey { case descriptorDigest = "descriptor_digest" }
}

/// The answer to an accept: the verification request's prompt (continue with the ordinary Verify consent) and where to return afterwards.
public struct VerificationSessionAccepted: Codable, Sendable, Hashable {
    public var sessionId: UUID
    public var prompt: VerificationPrompt
    /// Same origin as the descriptor's; the app re-checks it with `VerificationSessionOrigin.validReturnURL` before opening it.
    public var returnURL: String?

    public init(sessionId: UUID, prompt: VerificationPrompt, returnURL: String?) {
        self.sessionId = sessionId
        self.prompt = prompt
        self.returnURL = returnURL
    }

    enum CodingKeys: String, CodingKey { case sessionId = "session_id", prompt, returnURL = "return_url" }
}

// MARK: - Signed objects

private func strictUUID(_ value: JSONValue?) -> UUID? {
    guard let text = value?.stringValue, let id = UUID(uuidString: text), id.uuidString.lowercased() == text else { return nil }
    return id
}

private func parametersValue(_ value: JSONValue?) -> [String: JSONValue]? {
    guard case .object(let object)? = value, object.count <= VerificationSessionLimits.maxParameters else { return nil }
    for (key, item) in object {
        // Parameter names: lower-case snake case, 1 to 32 characters (`years`).
        guard (1...32).contains(key.utf8.count), key.utf8.first.map({ $0 >= 0x61 && $0 <= 0x7A }) == true,
              key.utf8.allSatisfy({ ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x5F }) else { return nil }
        switch item {
        case .string, .integer, .bool: continue
        default: return nil
        }
    }
    return object
}

private func trustedKey(for signed: ViadereSignedStatement, in keys: [DevicePublicKey]) -> DevicePublicKey? {
    keys.first { (try? KeyIdentifier.make($0.signingKey())) == signed.kid }
}

/// What the app shows before the person accepts, **signed by Viadere's `link-descriptor` key** over
/// `"VIADERE-VERIFY-SESSION-DESCRIPTOR-V1\n" ‖ canonical payload`:
///
/// ```json
/// {"business_domain":"northwind.example","business_id":"…","business_name":"Northwind Spirits","capability":"age.minimum",
///  "expires_at":1800000300,"issued_at":1800000000,"origin":"https://shop.northwind.example","parameters":{"years":21},
///  "purpose_code":"age_restricted_purchase","session_id":"…","signer_kid":"…","subject_ref":"sub_…","type":"verify-session-descriptor","v":1}
/// ```
/// The app accepts it only if the signer is a pinned `link-descriptor` key, it is current, and `origin` lies inside `business_domain`.
public struct VerificationSessionDescriptor: Sendable, Hashable {
    public var sessionId: UUID
    public var businessId: BusinessID
    public var businessName: String
    /// The business's verified domain.
    public var businessDomain: String
    /// The web origin the business created the session for.
    public var origin: String
    public var capability: Capability
    public var parameters: [String: JSONValue]
    public var purposeCode: String
    public var subject: SubjectRef
    public var issuedAt: Int64
    public var expiresAt: Int64

    public init(sessionId: UUID, businessId: BusinessID, businessName: String, businessDomain: String, origin: String, capability: Capability,
                parameters: [String: JSONValue], purposeCode: String, subject: SubjectRef, issuedAt: Date, expiresAt: Date) {
        self.sessionId = sessionId
        self.businessId = businessId
        self.businessName = businessName
        self.businessDomain = businessDomain
        self.origin = origin
        self.capability = capability
        self.parameters = parameters
        self.purposeCode = purposeCode
        self.subject = subject
        self.issuedAt = ViadereDate.unixSeconds(issuedAt)
        self.expiresAt = ViadereDate.unixSeconds(expiresAt)
    }

    public var expiresAtDate: Date { Date(timeIntervalSince1970: TimeInterval(expiresAt)) }
    /// The origin's host, for display ("Started on shop.northwind.example").
    public var originHost: String { VerificationSessionOrigin.host(of: origin) ?? origin }

    public func object(signerKid: String) -> [String: JSONValue] {
        ["v": .integer(1), "type": .string("verify-session-descriptor"), "session_id": .string(sessionId.uuidString.lowercased()),
         "business_id": .string(businessId.description), "business_name": .string(businessName), "business_domain": .string(businessDomain),
         "origin": .string(origin), "capability": .string(capability.rawValue), "parameters": .object(parameters), "purpose_code": .string(purposeCode),
         "subject_ref": .string(subject.rawValue), "issued_at": .integer(issuedAt), "expires_at": .integer(expiresAt), "signer_kid": .string(signerKid)]
    }

    public func payload(signerKid: String) throws -> Data { try CanonicalJSON.serialize(.object(object(signerKid: signerKid))) }

    /// Verifies a signed descriptor against the **pinned** `link-descriptor` keys: trusted signer, valid signature, exact member set, current,
    /// a canonical origin inside the verified business domain.
    public static func verify(_ signed: ViadereSignedStatement, trustedKeys: [DevicePublicKey], now: Date) throws -> VerificationSessionDescriptor {
        guard let key = trustedKey(for: signed, in: trustedKeys) else { throw VerificationSessionError.untrustedSigner }
        guard signed.statement.isValid(domain: VerificationSessionDomainSeparator.descriptor, publicKey: key) else { throw VerificationSessionError.badSignature }
        guard let o = signed.statement.canonicalObject(),
              Set(o.keys) == ["v", "type", "session_id", "business_id", "business_name", "business_domain", "origin", "capability", "parameters",
                              "purpose_code", "subject_ref", "issued_at", "expires_at", "signer_kid"],
              o["v"]?.int64Value == 1, o["type"]?.stringValue == "verify-session-descriptor", o["signer_kid"]?.stringValue == signed.kid,
              let session = strictUUID(o["session_id"]), let business = o["business_id"]?.stringValue.flatMap(BusinessID.init),
              let name = o["business_name"]?.stringValue, !name.isEmpty, name.count <= 120,
              let domain = o["business_domain"]?.stringValue, LinkDomain.isValid(domain),
              let origin = o["origin"]?.stringValue, VerificationSessionOrigin.canonical(origin) == origin,
              let capabilityText = o["capability"]?.stringValue, Capability(rawValue: capabilityText).isKnown,
              let parameters = parametersValue(o["parameters"]),
              let purpose = o["purpose_code"]?.stringValue, VerificationPurposeCode.isValid(purpose),
              let subject = o["subject_ref"]?.stringValue.flatMap({ SubjectRef($0) }),
              let issued = o["issued_at"]?.int64Value, let expires = o["expires_at"]?.int64Value, issued > 0, expires > issued,
              expires - issued <= Int64(VerificationSessionLimits.maxLifetime) else { throw VerificationSessionError.malformed("descriptor") }
        guard VerificationSessionOrigin.isWithin(origin, domain: domain) else { throw VerificationSessionError.originOutsideBusinessDomain }
        let nowSeconds = ViadereDate.unixSeconds(now)
        guard issued <= nowSeconds + 60 else { throw VerificationSessionError.issuedInFuture }
        guard expires > nowSeconds else { throw VerificationSessionError.expired }
        return VerificationSessionDescriptor(sessionId: session, businessId: business, businessName: name, businessDomain: domain, origin: origin,
                                             capability: Capability(rawValue: capabilityText), parameters: parameters, purposeCode: purpose, subject: subject,
                                             issuedAt: Date(timeIntervalSince1970: TimeInterval(issued)), expiresAt: Date(timeIntervalSince1970: TimeInterval(expires)))
    }

    /// Hex SHA-256 of the descriptor's payload string: what the app quotes when it accepts.
    public static func digest(of signed: ViadereSignedStatement) -> String { SecureToken.sha256Hex(Data(signed.payload.utf8)) }
}

/// Viadere's signed account of how a session ended, for the business (`link-descriptor` key, `"VIADERE-VERIFY-SESSION-RESULT-V1\n"`):
///
/// ```json
/// {"business_id":"…","capability":"age.minimum","completed_at":1800000200,"origin":"https://shop.northwind.example","outcome":"verified",
///  "parameters":{"years":21},"purpose_code":"age_restricted_purchase","request_id":"req_…","result_ref_digest":"<hex>","session_id":"…",
///  "signer_kid":"…","subject_ref":"sub_…","type":"verify-session-result","v":1}
/// ```
/// It carries **no personal data**: the outcome only. Attribute values (`identity.name`, `identity.address`) are fetched once with the result
/// reference, whose digest it commits to.
public struct VerificationSessionResult: Sendable, Hashable {
    public var sessionId: UUID
    public var businessId: BusinessID
    public var requestId: VerificationRequestID
    public var subject: SubjectRef
    public var capability: Capability
    public var parameters: [String: JSONValue]
    public var purposeCode: String
    public var origin: String
    public var outcome: VerificationOutcome
    public var resultRefDigest: String
    public var completedAt: Int64

    public init(sessionId: UUID, businessId: BusinessID, requestId: VerificationRequestID, subject: SubjectRef, capability: Capability,
                parameters: [String: JSONValue], purposeCode: String, origin: String, outcome: VerificationOutcome, resultRef: VerificationResultRef, completedAt: Date) {
        self.init(sessionId: sessionId, businessId: businessId, requestId: requestId, subject: subject, capability: capability, parameters: parameters,
                  purposeCode: purposeCode, origin: origin, outcome: outcome, resultRefDigest: Self.digest(of: resultRef), completedAt: ViadereDate.unixSeconds(completedAt))
    }

    init(sessionId: UUID, businessId: BusinessID, requestId: VerificationRequestID, subject: SubjectRef, capability: Capability, parameters: [String: JSONValue],
         purposeCode: String, origin: String, outcome: VerificationOutcome, resultRefDigest: String, completedAt: Int64) {
        self.sessionId = sessionId
        self.businessId = businessId
        self.requestId = requestId
        self.subject = subject
        self.capability = capability
        self.parameters = parameters
        self.purposeCode = purposeCode
        self.origin = origin
        self.outcome = outcome
        self.resultRefDigest = resultRefDigest
        self.completedAt = completedAt
    }

    public static func digest(of ref: VerificationResultRef) -> String { SecureToken.sha256Hex(Data(ref.rawValue.utf8)) }

    public var completedAtDate: Date { Date(timeIntervalSince1970: TimeInterval(completedAt)) }

    public func object(signerKid: String) -> [String: JSONValue] {
        ["v": .integer(1), "type": .string("verify-session-result"), "session_id": .string(sessionId.uuidString.lowercased()),
         "business_id": .string(businessId.description), "request_id": .string(requestId.description), "subject_ref": .string(subject.rawValue),
         "capability": .string(capability.rawValue), "parameters": .object(parameters), "purpose_code": .string(purposeCode), "origin": .string(origin),
         "outcome": .string(outcome.rawValue), "result_ref_digest": .string(resultRefDigest), "completed_at": .integer(completedAt), "signer_kid": .string(signerKid)]
    }

    public func payload(signerKid: String) throws -> Data { try CanonicalJSON.serialize(.object(object(signerKid: signerKid))) }

    /// Verifies against Viadere's `link-descriptor` public keys the business pinned.
    public static func verify(_ signed: ViadereSignedStatement, trustedKeys: [DevicePublicKey]) throws -> VerificationSessionResult {
        guard let key = trustedKey(for: signed, in: trustedKeys) else { throw VerificationSessionError.untrustedSigner }
        guard signed.statement.isValid(domain: VerificationSessionDomainSeparator.result, publicKey: key) else { throw VerificationSessionError.badSignature }
        guard let o = signed.statement.canonicalObject(),
              Set(o.keys) == ["v", "type", "session_id", "business_id", "request_id", "subject_ref", "capability", "parameters", "purpose_code", "origin",
                              "outcome", "result_ref_digest", "completed_at", "signer_kid"],
              o["v"]?.int64Value == 1, o["type"]?.stringValue == "verify-session-result", o["signer_kid"]?.stringValue == signed.kid,
              let session = strictUUID(o["session_id"]), let business = o["business_id"]?.stringValue.flatMap(BusinessID.init),
              let request = o["request_id"]?.stringValue.flatMap(VerificationRequestID.init),
              let subject = o["subject_ref"]?.stringValue.flatMap({ SubjectRef($0) }),
              let capabilityText = o["capability"]?.stringValue, Capability(rawValue: capabilityText).isKnown,
              let parameters = parametersValue(o["parameters"]),
              let purpose = o["purpose_code"]?.stringValue, VerificationPurposeCode.isValid(purpose),
              let origin = o["origin"]?.stringValue, VerificationSessionOrigin.canonical(origin) == origin,
              let outcome = o["outcome"]?.stringValue.flatMap(VerificationOutcome.init(rawValue:)),
              let digest = o["result_ref_digest"]?.stringValue, Interaction.isValidContextDigest(digest),
              let completed = o["completed_at"]?.int64Value, completed > 0 else { throw VerificationSessionError.malformed("result") }
        return VerificationSessionResult(sessionId: session, businessId: business, requestId: request, subject: subject, capability: Capability(rawValue: capabilityText),
                                         parameters: parameters, purposeCode: purpose, origin: origin, outcome: outcome, resultRefDigest: digest, completedAt: completed)
    }

    /// The checks a business makes before acting on a result: **its** session, **its** business, the origin and the capability it asked for.
    public func check(sessionId: UUID, businessId: BusinessID, origin: String, capability: Capability) throws {
        guard self.sessionId == sessionId else { throw VerificationSessionError.wrongSession }
        guard self.businessId == businessId else { throw VerificationSessionError.wrongBusiness }
        guard let expected = VerificationSessionOrigin.canonical(origin), self.origin == expected else { throw VerificationSessionError.wrongOrigin }
        guard self.capability == capability else { throw VerificationSessionError.wrongCapability }
    }

    /// Whether `ref` is the result reference this statement commits to.
    public func matches(_ ref: VerificationResultRef) -> Bool { ConstantTime.equals(resultRefDigest, Self.digest(of: ref)) }
}

// MARK: - Routes

extension APIRoutes {
    /// Business: a single-use, ≤ 5 min session for one capability on one origin (the "Verify with Viadere" button). Live keys only.
    public static let businessVerificationSessionCreate = Endpoint<CreateVerificationSessionRequest, VerificationSessionTicket>(
        "business.verificationSessions.create", .POST, "/v1/business/verification-sessions", auth: .businessAPIKey)
    public static let businessVerificationSessionGet = Endpoint<EmptyBody, VerificationSessionView>(
        "business.verificationSessions.get", .GET, "/v1/business/verification-sessions/{sessionId}", auth: .businessAPIKey)
    /// Cancels an open session (an accepted one runs to its result).
    public static let businessVerificationSessionCancel = Endpoint<EmptyBody, VerificationSessionView>(
        "business.verificationSessions.cancel", .POST, "/v1/business/verification-sessions/{sessionId}/cancel", auth: .businessAPIKey)
    /// Device: the signed descriptor of a session code (rate-limited per account and globally; every failure is the same `404`).
    public static let verificationSessionLookup = Endpoint<VerificationSessionLookupRequest, VerificationSessionOffer>(
        "verificationSessions.lookup", .POST, "/v1/verification-sessions/lookup", auth: .deviceSignedBearer)
    /// Device: accepts the session (consumed once) and opens the verification request.
    public static let verificationSessionAccept = Endpoint<VerificationSessionAcceptRequest, VerificationSessionAccepted>(
        "verificationSessions.accept", .POST, "/v1/verification-sessions/{sessionId}/accept", auth: .deviceSignedBearer)

    public static let verificationSessionEndpoints: [AnyEndpoint] = [
        businessVerificationSessionCreate.descriptor, businessVerificationSessionGet.descriptor, businessVerificationSessionCancel.descriptor,
        verificationSessionLookup.descriptor, verificationSessionAccept.descriptor,
    ]
}
