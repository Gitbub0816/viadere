import Foundation

// Wire types of the auth-delivery API (ADR-0020 sections 1 and 2). Every request type is **closed**: a member it does not define, `tenant_id`
// and `audience` included, fails decoding (the server answers `422 validation_failed`). The tenant is the authenticated API key's business,
// never a field of the payload (spec Appendix A).

private struct StrictKey: CodingKey {
    var stringValue: String
    var intValue: Int? { nil }
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { nil }
}

/// Refuses a JSON object with any member outside `allowed`.
private func requireOnly(_ decoder: any Decoder, _ allowed: Set<String>) throws {
    let keys = try decoder.container(keyedBy: StrictKey.self).allKeys.map(\.stringValue)
    guard Set(keys).isSubset(of: allowed) else {
        throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "unknown member"))
    }
}

// MARK: Create

/// `destination` of a magic-link delivery: the business's own URL (`link_mode: "business"`, with its signed statement) or a link-service reference.
public struct AuthDestinationRequest: Codable, Sendable, Hashable {
    public var linkMode: AuthLinkMode
    /// `business`: the single-use URL on a verified host. A bearer value: stored only sealed, never logged, never in a webhook.
    public var url: String?
    /// `business`: the compact `viadere-destination+jws` (ADR-0031 section 3). It commits to the URL's digest and host; it is not a bearer value.
    public var signature: String?
    /// `viadere` (Stage 6): refused until the authority exists.
    public var linkClientId: String?
    public var returnUrl: String?
    public var codeChallenge: String?
    public var codeChallengeMethod: String?

    public init(linkMode: AuthLinkMode, url: String? = nil, signature: String? = nil, linkClientId: String? = nil, returnUrl: String? = nil,
                codeChallenge: String? = nil, codeChallengeMethod: String? = nil) {
        self.linkMode = linkMode
        self.url = url
        self.signature = signature
        self.linkClientId = linkClientId
        self.returnUrl = returnUrl
        self.codeChallenge = codeChallenge
        self.codeChallengeMethod = codeChallengeMethod
    }

    enum CodingKeys: String, CodingKey {
        case linkMode = "link_mode", url, signature, linkClientId = "link_client_id", returnUrl = "return_url"
        case codeChallenge = "code_challenge", codeChallengeMethod = "code_challenge_method"
    }

    public init(from decoder: any Decoder) throws {
        try requireOnly(decoder, Set(["link_mode", "url", "signature", "link_client_id", "return_url", "code_challenge", "code_challenge_method"]))
        let c = try decoder.container(keyedBy: CodingKeys.self)
        linkMode = try c.decode(AuthLinkMode.self, forKey: .linkMode)
        url = try c.decodeIfPresent(String.self, forKey: .url)
        signature = try c.decodeIfPresent(String.self, forKey: .signature)
        linkClientId = try c.decodeIfPresent(String.self, forKey: .linkClientId)
        returnUrl = try c.decodeIfPresent(String.self, forKey: .returnUrl)
        codeChallenge = try c.decodeIfPresent(String.self, forKey: .codeChallenge)
        codeChallengeMethod = try c.decodeIfPresent(String.self, forKey: .codeChallengeMethod)
    }
}

/// `otp` of a code delivery: the partner-generated code. Viadere delivers it and never verifies it.
public struct AuthOTPPayload: Codable, Sendable, Hashable {
    public var code: String
    public var codeKind: AuthCodeKind

    public init(code: String, codeKind: AuthCodeKind = .otp) {
        self.code = code
        self.codeKind = codeKind
    }

    enum CodingKeys: String, CodingKey { case code, codeKind = "code_kind" }

    public init(from decoder: any Decoder) throws {
        try requireOnly(decoder, Set(["code", "code_kind"]))
        let c = try decoder.container(keyedBy: CodingKeys.self)
        code = try c.decode(String.self, forKey: .code)
        codeKind = try c.decode(AuthCodeKind.self, forKey: .codeKind)
    }
}

/// `fallback`: email is **refused** in every environment until the email-fallback gate of ADR-0020 section 7 is met (it is decoded so the refusal is explicit).
public struct AuthFallback: Codable, Sendable, Hashable {
    public struct Email: Codable, Sendable, Hashable {
        public var address: String
        public init(address: String) { self.address = address }
        public init(from decoder: any Decoder) throws {
            try requireOnly(decoder, Set(["address"]))
            address = try decoder.container(keyedBy: CodingKeys.self).decode(String.self, forKey: .address)
        }
        enum CodingKeys: String, CodingKey { case address }
    }

    public var email: Email?
    public init(email: Email? = nil) { self.email = email }

    public init(from decoder: any Decoder) throws {
        try requireOnly(decoder, Set(["email"]))
        email = try decoder.container(keyedBy: CodingKeys.self).decodeIfPresent(Email.self, forKey: .email)
    }

    enum CodingKeys: String, CodingKey { case email }
}

/// `callback`: a registered v2 webhook subscription that receives this delivery's events (instead of every subscription of the tenant).
public struct AuthCallback: Codable, Sendable, Hashable {
    public var webhookId: WebhookSubscriptionID
    public init(webhookId: WebhookSubscriptionID) { self.webhookId = webhookId }

    enum CodingKeys: String, CodingKey { case webhookId = "webhook_id" }

    public init(from decoder: any Decoder) throws {
        try requireOnly(decoder, Set(["webhook_id"]))
        webhookId = try decoder.container(keyedBy: CodingKeys.self).decode(WebhookSubscriptionID.self, forKey: .webhookId)
    }
}

/// `POST /v1/business/auth-deliveries` (strict, at most 16 KiB).
public struct AuthDeliveryCreateRequest: Codable, Sendable, Hashable {
    public static let maxBytes = 16 * 1024

    public var method: AuthDeliveryMethod
    /// The business's own id, unique per tenant (also the default idempotency scope): `[A-Za-z0-9_.:-]`, 1 to 128.
    public var requestId: String
    /// The tenant's pairwise reference for the customer (SECURITY section 2.30). Unknown, unreachable or paused: the same `404 not_deliverable`.
    public var subjectRef: SubjectRef
    public var purpose: AuthDeliveryPurpose
    /// A Viadere-owned template id (UX_COPY). The business cannot supply text.
    public var template: String
    public var variables: [String: String]?
    public var destination: AuthDestinationRequest?
    public var otp: AuthOTPPayload?
    public var correlationId: String?
    public var clientTransactionRef: String?
    public var expiresInSeconds: Int?
    public var channels: [AuthDeliveryChannel]?
    public var fallback: AuthFallback?
    public var callback: AuthCallback?
    /// Opaque value the business derives from its own initiating session (ADR-0020 revision 3): 1 to 64 of `[A-Za-z0-9_-]`, class T, never shown, never in a webhook.
    /// The only input to supersession: a new `sign_in` replaces an open one only when both carry the same handle.
    public var sessionHandle: String?

    public init(method: AuthDeliveryMethod, requestId: String, subjectRef: SubjectRef, purpose: AuthDeliveryPurpose, template: String,
                variables: [String: String]? = nil, destination: AuthDestinationRequest? = nil, otp: AuthOTPPayload? = nil,
                correlationId: String? = nil, clientTransactionRef: String? = nil, expiresInSeconds: Int? = nil,
                channels: [AuthDeliveryChannel]? = nil, fallback: AuthFallback? = nil, callback: AuthCallback? = nil, sessionHandle: String? = nil) {
        self.sessionHandle = sessionHandle
        self.method = method
        self.requestId = requestId
        self.subjectRef = subjectRef
        self.purpose = purpose
        self.template = template
        self.variables = variables
        self.destination = destination
        self.otp = otp
        self.correlationId = correlationId
        self.clientTransactionRef = clientTransactionRef
        self.expiresInSeconds = expiresInSeconds
        self.channels = channels
        self.fallback = fallback
        self.callback = callback
    }

    enum CodingKeys: String, CodingKey {
        case method, requestId = "request_id", subjectRef = "subject_ref", purpose, template, variables, destination, otp
        case correlationId = "correlation_id", clientTransactionRef = "client_transaction_ref", expiresInSeconds = "expires_in_seconds"
        case channels, fallback, callback, sessionHandle = "session_handle"
    }

    public static let memberNames: Set<String> = Set(["method", "request_id", "subject_ref", "purpose", "template", "variables", "destination", "otp",
                                                       "correlation_id", "client_transaction_ref", "expires_in_seconds", "channels", "fallback", "callback", "session_handle"])

    public init(from decoder: any Decoder) throws {
        try requireOnly(decoder, Self.memberNames)
        let c = try decoder.container(keyedBy: CodingKeys.self)
        method = try c.decode(AuthDeliveryMethod.self, forKey: .method)
        requestId = try c.decode(String.self, forKey: .requestId)
        subjectRef = try c.decode(SubjectRef.self, forKey: .subjectRef)
        purpose = try c.decode(AuthDeliveryPurpose.self, forKey: .purpose)
        template = try c.decode(String.self, forKey: .template)
        variables = try c.decodeIfPresent([String: String].self, forKey: .variables)
        destination = try c.decodeIfPresent(AuthDestinationRequest.self, forKey: .destination)
        otp = try c.decodeIfPresent(AuthOTPPayload.self, forKey: .otp)
        correlationId = try c.decodeIfPresent(String.self, forKey: .correlationId)
        clientTransactionRef = try c.decodeIfPresent(String.self, forKey: .clientTransactionRef)
        expiresInSeconds = try c.decodeIfPresent(Int.self, forKey: .expiresInSeconds)
        channels = try c.decodeIfPresent([AuthDeliveryChannel].self, forKey: .channels)
        fallback = try c.decodeIfPresent(AuthFallback.self, forKey: .fallback)
        callback = try c.decodeIfPresent(AuthCallback.self, forKey: .callback)
        sessionHandle = try c.decodeIfPresent(String.self, forKey: .sessionHandle)
    }
}

// MARK: Business views

/// `POST /v1/business/auth-deliveries` response (`201`; `200` on an idempotent replay) and `GET .../{id}` / `.../cancel` / `.../complete`.
/// **Never a secret**: no URL, no code, no variables, no destination host.
public struct AuthDeliveryView: Codable, Sendable, Hashable {
    public var id: AuthDeliveryID
    public var requestId: String
    public var method: AuthDeliveryMethod
    public var purpose: AuthDeliveryPurpose
    public var status: AuthDeliveryStatus
    public var expiresAt: Date
    public var createdAt: Date
    public var correlationId: String?
    public var clientTransactionRef: String?
    /// Terminal reason (`superseded`, `cancelled_by_business`, `denied_by_customer`, `not_attempted`, ...). Never a reason that discloses reachability.
    public var reason: String?
    /// Present on `GET`: one entry per transition (state and time only).
    public var events: [AuthDeliveryEventView]?

    public init(id: AuthDeliveryID, requestId: String, method: AuthDeliveryMethod, purpose: AuthDeliveryPurpose, status: AuthDeliveryStatus,
                expiresAt: Date, createdAt: Date, correlationId: String? = nil, clientTransactionRef: String? = nil, reason: String? = nil,
                events: [AuthDeliveryEventView]? = nil) {
        self.id = id
        self.requestId = requestId
        self.method = method
        self.purpose = purpose
        self.status = status
        self.expiresAt = expiresAt
        self.createdAt = createdAt
        self.correlationId = correlationId
        self.clientTransactionRef = clientTransactionRef
        self.reason = reason
        self.events = events
    }

    enum CodingKeys: String, CodingKey {
        case id, requestId = "request_id", method, purpose, status, expiresAt = "expires_at", createdAt = "created_at"
        case correlationId = "correlation_id", clientTransactionRef = "client_transaction_ref", reason, events
    }
}

public struct AuthDeliveryEventView: Codable, Sendable, Hashable {
    public var status: AuthDeliveryStatus
    public var at: Date
    public var reason: String?
    public init(status: AuthDeliveryStatus, at: Date, reason: String? = nil) {
        self.status = status
        self.at = at
        self.reason = reason
    }
}

/// What the business tells Viadere about its own verification (`POST .../complete`).
public enum AuthDeliveryOutcome: String, Codable, Sendable, CaseIterable {
    case succeeded, failed
}

public struct AuthDeliveryCompleteRequest: Codable, Sendable, Hashable {
    public var outcome: AuthDeliveryOutcome
    public init(outcome: AuthDeliveryOutcome) { self.outcome = outcome }

    public init(from decoder: any Decoder) throws {
        try requireOnly(decoder, Set(["outcome"]))
        outcome = try decoder.container(keyedBy: CodingKeys.self).decode(AuthDeliveryOutcome.self, forKey: .outcome)
    }

    enum CodingKeys: String, CodingKey { case outcome }
}

// MARK: Device views

/// The inbox and fetch view (`GET /v1/auth-deliveries[/{id}]`): enough to render the item, **no secret**. The destination host, the signed
/// destination statement and the template variables are display data; the URL and the code arrive only from `open`.
public struct AuthDeliveryDisplay: Codable, Sendable, Hashable {
    public var id: AuthDeliveryID
    public var method: AuthDeliveryMethod
    public var purpose: AuthDeliveryPurpose
    public var template: String
    public var status: AuthDeliveryStatus
    /// The business as Viadere knows it (verified display name). For a business link the device shows the authority record's name instead (ADR-0031).
    public var businessId: BusinessID
    public var businessName: String
    public var expiresAt: Date
    public var createdAt: Date
    /// The business's request id (the statement's `brq` claim).
    public var requestId: String
    /// `magic_link` only: the lowercase host of the URL, as the business signed it.
    public var destinationHost: String?
    /// `magic_link` only: the compact `viadere-destination+jws` the device verifies before it enables Continue (ADR-0031 section 4).
    public var destinationStatement: String?
    public var codeKind: AuthCodeKind?
    /// Template variables (`action_display`, `reference`): personal data, shown only here, deleted at the terminal state.
    public var variables: [String: String]?
    /// Delivered silently (no alert push) because a per-subject budget was exhausted: the inbox still shows it (ADR-0020 section 8).
    public var silent: Bool

    public init(id: AuthDeliveryID, method: AuthDeliveryMethod, purpose: AuthDeliveryPurpose, template: String, status: AuthDeliveryStatus,
                businessId: BusinessID, businessName: String, expiresAt: Date, createdAt: Date, requestId: String, destinationHost: String? = nil,
                destinationStatement: String? = nil, codeKind: AuthCodeKind? = nil, variables: [String: String]? = nil, silent: Bool = false) {
        self.id = id
        self.method = method
        self.purpose = purpose
        self.template = template
        self.status = status
        self.businessId = businessId
        self.businessName = businessName
        self.expiresAt = expiresAt
        self.createdAt = createdAt
        self.requestId = requestId
        self.destinationHost = destinationHost
        self.destinationStatement = destinationStatement
        self.codeKind = codeKind
        self.variables = variables
        self.silent = silent
    }

    enum CodingKeys: String, CodingKey {
        case id, method, purpose, template, status, businessId = "business_id", businessName = "business_name", expiresAt = "expires_at"
        case createdAt = "created_at", requestId = "request_id", destinationHost = "destination_host", destinationStatement = "destination_statement"
        case codeKind = "code_kind", variables, silent
    }
}

/// `POST /v1/auth-deliveries/{id}/open`: the secret, **once**. The ciphertext is deleted in the same transaction.
public struct AuthDeliveryOpenResponse: Codable, Sendable, Hashable {
    public var id: AuthDeliveryID
    public var method: AuthDeliveryMethod
    public var url: String?
    public var code: String?
    public var codeKind: AuthCodeKind?
    public var openedAt: Date

    public init(id: AuthDeliveryID, method: AuthDeliveryMethod, url: String? = nil, code: String? = nil, codeKind: AuthCodeKind? = nil, openedAt: Date) {
        self.id = id
        self.method = method
        self.url = url
        self.code = code
        self.codeKind = codeKind
        self.openedAt = openedAt
    }

    enum CodingKeys: String, CodingKey { case id, method, url, code, codeKind = "code_kind", openedAt = "opened_at" }
}

/// `POST /v1/auth-deliveries/{id}/deny`: "Deny" or "This wasn't me". Always safe to send (reduce-only).
public struct AuthDeliveryDenyRequest: Codable, Sendable, Hashable {
    /// `true` for "This wasn't me": counted for fatigue protection and reported to the business as a denial.
    public var report: Bool?
    /// `destination_unverified`: the device refused the destination (ADR-0031 section 4). Audited and alerted.
    public var reason: String?
    public init(report: Bool? = nil, reason: String? = nil) {
        self.report = report
        self.reason = reason
    }

    public static let allowedReasons: Set<String> = ["destination_unverified"]

    public init(from decoder: any Decoder) throws {
        try requireOnly(decoder, Set(["report", "reason"]))
        let c = try decoder.container(keyedBy: CodingKeys.self)
        report = try c.decodeIfPresent(Bool.self, forKey: .report)
        reason = try c.decodeIfPresent(String.self, forKey: .reason)
    }

    enum CodingKeys: String, CodingKey { case report, reason }
}

// MARK: Webhook payloads

/// The event a business receives (opaque envelope, `request_id` = the delivery id) and the schema of `contracts/schemas/auth-delivery-event-v1.json`.
/// Webhooks carry **no** URL, code, token, subject reference, variable or personal data (ADR-0025 section 5).
public struct AuthDeliveryEventPayload: Codable, Sendable, Hashable {
    public var deliveryId: AuthDeliveryID
    public var status: AuthDeliveryStatus
    public var reason: String?

    public init(deliveryId: AuthDeliveryID, status: AuthDeliveryStatus, reason: String? = nil) {
        self.deliveryId = deliveryId
        self.status = status
        self.reason = reason
    }

    enum CodingKeys: String, CodingKey { case deliveryId = "delivery_id", status, reason }
}
