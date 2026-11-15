import Foundation

/// The number-match member of `POST /v1/business/auth-approvals` and of the device's request view (ADR-0022 §2.2). `code` is present only for a
/// server-visible request (the relay can read it; number matching defends against fatigue, not against the relay, T-MFA-1). In an end-to-end request the
/// code travels only inside the business-signed `ApprovalRequest` v2, and this member carries the length.
public struct AuthApprovalNumberMatch: Codable, Sendable, Hashable {
    public var digits: Int
    public var code: String?
    public init(digits: Int, code: String? = nil) {
        self.digits = digits
        self.code = code
    }
}

/// `POST /v1/business/auth-approvals` (ADR-0020 §1, §2a; ADR-0022 §1-§5): an Approve v2 request **with number matching**. Strict: any member not listed
/// (a `tenant_id`, an `audience`) is refused. The tenant is the API key's business.
///
/// * `number_match` is required on this route (number matching is not optional here); `match_tag`, and `match_prefix_tag` for 3 digits, are the SDK's HMAC
///   tags of the code (`AuthMatchTags`), used by the api to keep one person's open codes collision-free and prefix-free.
/// * `risk` (default `medium`): `high` and `critical`, and every `transaction.approve`, need 3 digits and an end-to-end request (`422 e2ee_required`).
/// * `session_handle`: the only input to supersession (ADR-0022 §5.2 item 1).
public struct AuthApprovalCreateRequest: Codable, Sendable, Hashable {
    public var requestId: String
    public var subjectRef: SubjectRef
    public var capability: Capability
    public var risk: AuthApprovalRisk?
    public var challenge: String?
    public var transaction: TransactionDetails?
    public var authentication: AuthenticationDetails?
    public var envelopes: [ApprovalEnvelopeDelivery]?
    public var expiresInSeconds: Int?
    public var numberMatch: AuthApprovalNumberMatch
    public var matchTag: String
    public var matchPrefixTag: String?
    public var sessionHandle: String?

    public init(requestId: String, subjectRef: SubjectRef, capability: Capability, risk: AuthApprovalRisk? = nil, challenge: String? = nil,
                transaction: TransactionDetails? = nil, authentication: AuthenticationDetails? = nil, envelopes: [ApprovalEnvelopeDelivery]? = nil,
                expiresInSeconds: Int? = nil, numberMatch: AuthApprovalNumberMatch, matchTag: String, matchPrefixTag: String? = nil, sessionHandle: String? = nil) {
        self.requestId = requestId
        self.subjectRef = subjectRef
        self.capability = capability
        self.risk = risk
        self.challenge = challenge
        self.transaction = transaction
        self.authentication = authentication
        self.envelopes = envelopes
        self.expiresInSeconds = expiresInSeconds
        self.numberMatch = numberMatch
        self.matchTag = matchTag
        self.matchPrefixTag = matchPrefixTag
        self.sessionHandle = sessionHandle
    }

    enum CodingKeys: String, CodingKey, CaseIterable {
        case requestId = "request_id", subjectRef = "subject_ref", capability, risk, challenge, transaction, authentication, envelopes
        case expiresInSeconds = "expires_in_seconds", numberMatch = "number_match", matchTag = "match_tag", matchPrefixTag = "match_prefix_tag"
        case sessionHandle = "session_handle"
    }

    public static var memberNames: Set<String> { Set(CodingKeys.allCases.map(\.rawValue)) }

    public init(from decoder: any Decoder) throws {
        let any = try decoder.container(keyedBy: ApprovalMemberKey.self)
        guard Set(any.allKeys.map(\.stringValue)).isSubset(of: Self.memberNames) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "unknown member"))
        }
        let c = try decoder.container(keyedBy: CodingKeys.self)
        requestId = try c.decode(String.self, forKey: .requestId)
        subjectRef = try c.decode(SubjectRef.self, forKey: .subjectRef)
        capability = try c.decode(Capability.self, forKey: .capability)
        risk = try c.decodeIfPresent(AuthApprovalRisk.self, forKey: .risk)
        challenge = try c.decodeIfPresent(String.self, forKey: .challenge)
        transaction = try c.decodeIfPresent(TransactionDetails.self, forKey: .transaction)
        authentication = try c.decodeIfPresent(AuthenticationDetails.self, forKey: .authentication)
        envelopes = try c.decodeIfPresent([ApprovalEnvelopeDelivery].self, forKey: .envelopes)
        expiresInSeconds = try c.decodeIfPresent(Int.self, forKey: .expiresInSeconds)
        numberMatch = try c.decode(AuthApprovalNumberMatch.self, forKey: .numberMatch)
        matchTag = try c.decode(String.self, forKey: .matchTag)
        matchPrefixTag = try c.decodeIfPresent(String.self, forKey: .matchPrefixTag)
        sessionHandle = try c.decodeIfPresent(String.self, forKey: .sessionHandle)
    }

    /// The Approve v2 request this creates (the existing request semantics, SECURITY §2.55).
    public var approvalRequest: CreateApprovalRequest {
        CreateApprovalRequest(requestId: requestId, subjectRef: subjectRef, capability: capability, challenge: challenge, transaction: transaction,
                              authentication: authentication, envelopes: envelopes, expiresInSeconds: expiresInSeconds)
    }

    /// The effective risk: a payment is never below `high`.
    public var effectiveRisk: AuthApprovalRisk {
        let declared = risk ?? .medium
        return capability == .transactionApprove ? max(declared, .high) : declared
    }

    /// Shape rules that need no database (ADR-0022 §2.1, §4.3, ADR-0020 §2a). `nil` when the request is well-formed.
    public func validate() -> AuthDeliveryValidationIssue? {
        let digits = numberMatch.digits
        guard (2...3).contains(digits) else { return AuthDeliveryValidationIssue("number_match.digits", "invalid") }
        if ApprovalNumberMatch.requiredDigits(capability: capability, risk: effectiveRisk) == 3, digits != 3 {
            return AuthDeliveryValidationIssue("number_match.digits", "three_required")
        }
        if envelopes != nil {
            // End to end: the code is inside the signed envelope only.
            guard numberMatch.code == nil else { return AuthDeliveryValidationIssue("number_match.code", "not_allowed") }
        } else {
            guard let code = numberMatch.code, ApprovalNumberMatch.isValid(code: code, digits: digits) else { return AuthDeliveryValidationIssue("number_match.code", "invalid") }
            // The requirement is in the digest the business checks, so a relay cannot strip it (ADR-0022 §3).
            if let authentication, authentication.matchDigits != digits { return AuthDeliveryValidationIssue("authentication.match_digits", "invalid") }
        }
        if let issue = AuthMatchTagMembers(matchTag: matchTag, matchPrefixTag: matchPrefixTag).validate(hasNumberMatch: true, threeDigit: digits == 3) { return issue }
        if let handle = sessionHandle, !AuthDeliveryValidation.isValidSessionHandle(handle) { return AuthDeliveryValidationIssue("session_handle", "invalid") }
        return nil
    }
}

/// `POST /v1/approve/requests/{approvalId}/deny` (ADR-0022 §5.5): the **reduce-only** deny from the notification action. Signed by the device `request` key
/// (the ordinary device-signed request), never by an approval key and never needing Face ID. It can only refuse: it never approves, never records a signed
/// result, and counts as one denial toward the pause.
public struct ApproveDenyRequest: Codable, Sendable, Hashable {
    /// "This wasn't me" (`reported`); default a plain Deny.
    public var report: Bool?
    public init(report: Bool? = nil) { self.report = report }

    enum CodingKeys: String, CodingKey, CaseIterable { case report }

    public init(from decoder: any Decoder) throws {
        let any = try decoder.container(keyedBy: ApprovalMemberKey.self)
        guard Set(any.allKeys.map(\.stringValue)).isSubset(of: Set(CodingKeys.allCases.map(\.rawValue))) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "unknown member"))
        }
        report = try decoder.container(keyedBy: CodingKeys.self).decodeIfPresent(Bool.self, forKey: .report)
    }
}

extension APIRoutes {
    // MARK: Push approvals (ADR-0020 §1, ADR-0022; behind `AUTH_DELIVERY_ENABLED` and `APPROVE_V2_ENABLED`)
    /// Creates an Approve v2 request with number matching. Scope `approvals:manage`; `Idempotency-Key` required.
    public static let businessAuthApprovalCreate = Endpoint<AuthApprovalCreateRequest, ApprovalRequestView>(
        "business.authApprovals.create", .POST, "/v1/business/auth-approvals", auth: .businessAPIKey)
    /// The relay's view (status and `result_ref`). **Never authorize on it**: verify the signed result.
    public static let businessAuthApprovalGet = Endpoint<EmptyBody, ApprovalRequestView>(
        "business.authApprovals.get", .GET, "/v1/business/auth-approvals/{requestId}", auth: .businessAPIKey)
    /// Device: the reduce-only Deny from the `viadere.approve` notification action (request key, no unlock).
    public static let approveRequestDeny = Endpoint<ApproveDenyRequest, SubmitApprovalResultResponse>(
        "approve.requests.deny", .POST, "/v1/approve/requests/{approvalId}/deny", auth: .deviceSignedBearer)

    public static let authApprovalEndpoints: [AnyEndpoint] = [
        businessAuthApprovalCreate.descriptor, businessAuthApprovalGet.descriptor, approveRequestDeny.descriptor,
    ]
}

/// What an Approve v2 push may contain (ADR-0022 §5.5, F-15, Stage 4 review R4-03): a generic alert, category `viadere.approve`, interruption level
/// **`active`** (never `time-sensitive`), `mutable-content`, and one custom key `req` = this device's opaque request id (the relay's delivery UUID, lowercase).
/// No business, amount, payee or number. `apns-collapse-id` is that same id (a header, not part of the payload).
public enum ApprovePushPayloadPolicy {
    public static let category = "viadere.approve"
    public static let interruptionLevel = "active"
    public static let customKeys: Set<String> = ["req"]
    public static let apsKeys: Set<String> = ["alert", "category", "thread-id", "interruption-level", "mutable-content"]

    public static func isAllowed(_ payload: [String: Any]) -> Bool {
        guard Set(payload.keys) == customKeys.union(["aps"]), let aps = payload["aps"] as? [String: Any], Set(aps.keys).isSubset(of: apsKeys),
              let alert = aps["alert"] as? [String: Any], Set(alert.keys).isSubset(of: ["title", "body"]),
              aps["category"] as? String == category, aps["interruption-level"] as? String == interruptionLevel,
              let req = payload["req"] as? String, let id = UUID(uuidString: req), id.uuidString.lowercased() == req else { return false }
        return true
    }
}

/// Any member name, for the strict decoders above.
private struct ApprovalMemberKey: CodingKey {
    var stringValue: String
    var intValue: Int? { nil }
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { nil }
}
