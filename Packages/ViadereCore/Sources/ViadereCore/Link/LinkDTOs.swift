import Foundation

/// Where a link session stands.
public enum LinkSessionStatus: String, Codable, Sendable, Hashable {
    /// Created by the business; waiting for a device.
    case open
    /// A device accepted it (consumed once, compare-and-swap); waiting for the business's confirmation. The connection is **not** active yet.
    case deviceCompleted = "device_completed"
    /// The business confirmed: the connection is active.
    case confirmed
    /// Nobody completed it in time, or the business never confirmed (then the pending connection and key were ended and reported).
    case expired
    case cancelled
    case unknown

    public init(from decoder: any Decoder) throws {
        self = LinkSessionStatus(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
    }
}

// MARK: - Business

/// `POST /v1/business/link-sessions`. The business has just authenticated its customer (a step-up in its own session) and wants to link that
/// customer's Viadere app. Never a phone number or an email.
public struct CreateLinkSessionRequest: Codable, Sendable, Hashable {
    /// The business's own opaque reference for its customer record (1 to 128 of `[A-Za-z0-9._:-]`). Viadere stores only its keyed hash, to
    /// rate-limit per customer; it is never returned or shown.
    public var customerRef: String
    /// What the connection may be used for: registered, linkable actions only (`ActionRegistry`).
    public var capabilities: [Capability]
    /// Non-sensitive context shown in the app ("Account ending 4821"): at most 40 printable characters, no digits run longer than four.
    public var displayHint: String?
    /// 60...300 (default 300).
    public var expiresInSeconds: Int?

    public init(customerRef: String, capabilities: [Capability], displayHint: String? = nil, expiresInSeconds: Int? = nil) {
        self.customerRef = customerRef
        self.capabilities = capabilities
        self.displayHint = displayHint
        self.expiresInSeconds = expiresInSeconds
    }

    enum CodingKeys: String, CodingKey {
        case customerRef = "customer_ref", capabilities, displayHint = "display_hint", expiresInSeconds = "expires_in_seconds"
    }
}

/// The relay's answer to a create. **`link` is a suggestion and is never shown**: the SDK builds the link with the session secret
/// (`LinkSessionInvitation`) and checks `root_kid` against the business's own root.
public struct LinkSessionTicket: Codable, Sendable, Hashable {
    public var sessionId: UUID
    public var code: String
    public var link: String
    public var rootKid: String
    public var expiresAt: Date

    public init(sessionId: UUID, code: String, link: String, rootKid: String, expiresAt: Date) {
        self.sessionId = sessionId
        self.code = code
        self.link = link
        self.rootKid = rootKid
        self.expiresAt = expiresAt
    }

    enum CodingKeys: String, CodingKey { case sessionId = "session_id", code, link, rootKid = "root_kid", expiresAt = "expires_at" }
}

/// The business's view of a session (`GET /v1/business/link-sessions/{id}`). Before confirming, the business verifies `statement` itself
/// (binding tag or SAS); `result` is Viadere's signed account of who completed it.
public struct LinkSessionView: Codable, Sendable, Hashable {
    public var sessionId: UUID
    public var status: LinkSessionStatus
    public var capabilities: [Capability]
    public var createdAt: Date
    public var expiresAt: Date
    /// After the device completed: the pairwise reference of the account that did. `connectionId` is the same value (the spec's "connection id").
    public var subjectRef: SubjectRef?
    public var connectionId: SubjectRef?
    public var statement: SignedStatement?
    public var bindingTag: String?
    public var approvalStatement: SignedStatement?
    public var result: ViadereSignedStatement?
    public var completedAt: Date?
    public var confirmedAt: Date?

    public init(sessionId: UUID, status: LinkSessionStatus, capabilities: [Capability], createdAt: Date, expiresAt: Date, subjectRef: SubjectRef? = nil,
                statement: SignedStatement? = nil, bindingTag: String? = nil, approvalStatement: SignedStatement? = nil, result: ViadereSignedStatement? = nil,
                completedAt: Date? = nil, confirmedAt: Date? = nil) {
        self.sessionId = sessionId
        self.status = status
        self.capabilities = capabilities
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.subjectRef = subjectRef
        connectionId = subjectRef
        self.statement = statement
        self.bindingTag = bindingTag
        self.approvalStatement = approvalStatement
        self.result = result
        self.completedAt = completedAt
        self.confirmedAt = confirmedAt
    }

    enum CodingKeys: String, CodingKey {
        case sessionId = "session_id", status, capabilities, createdAt = "created_at", expiresAt = "expires_at", subjectRef = "subject_ref"
        case connectionId = "connection_id", statement, bindingTag = "binding_tag", approvalStatement = "approval_statement", result
        case completedAt = "completed_at", confirmedAt = "confirmed_at"
    }
}

/// `POST /v1/business/link-sessions/{id}/confirm`: the business's `LinkConfirmation` and, when approval capabilities were linked, its ordinary
/// `ApprovalEnrollmentConfirmation` of the approval key (enrollment id = session id).
public struct ConfirmLinkSessionRequest: Codable, Sendable, Hashable {
    public var confirmation: BusinessSignedStatement
    public var approvalConfirmation: BusinessSignedStatement?

    public init(confirmation: BusinessSignedStatement, approvalConfirmation: BusinessSignedStatement? = nil) {
        self.confirmation = confirmation
        self.approvalConfirmation = approvalConfirmation
    }

    enum CodingKeys: String, CodingKey { case confirmation, approvalConfirmation = "approval_confirmation" }
}

// MARK: - Device

public struct LinkSessionLookupRequest: Codable, Sendable, Hashable {
    public var code: String
    public init(code: String) { self.code = code }
}

/// What the app shows before the person links (`POST /v1/link-sessions/lookup`). **Only `descriptor` is trusted**, after `LinkSessionDescriptor.verify`
/// with the pinned keys and a cross-check with the business's key directory; the other members are conveniences that must agree with it.
public struct LinkSessionOffer: Codable, Sendable, Hashable {
    public var sessionId: UUID
    public var descriptor: ViadereSignedStatement
    public var business: BusinessSummary
    public var subjectRef: SubjectRef
    public var capabilities: [Capability]
    /// The approval key's protection when approval capabilities are requested.
    public var requiredAssurance: ApprovalAMR?
    public var expiresAt: Date
    /// The account is already connected to this business (the session then adds the capabilities after the business confirms).
    public var alreadyConnected: Bool

    public init(sessionId: UUID, descriptor: ViadereSignedStatement, business: BusinessSummary, subjectRef: SubjectRef, capabilities: [Capability],
                requiredAssurance: ApprovalAMR?, expiresAt: Date, alreadyConnected: Bool) {
        self.sessionId = sessionId
        self.descriptor = descriptor
        self.business = business
        self.subjectRef = subjectRef
        self.capabilities = capabilities
        self.requiredAssurance = requiredAssurance
        self.expiresAt = expiresAt
        self.alreadyConnected = alreadyConnected
    }

    enum CodingKeys: String, CodingKey {
        case sessionId = "session_id", descriptor, business, subjectRef = "subject_ref", capabilities, requiredAssurance = "required_assurance"
        case expiresAt = "expires_at", alreadyConnected = "already_connected"
    }
}

/// `POST /v1/link-sessions/{id}/complete`.
public struct CompleteLinkSessionRequest: Codable, Sendable, Hashable {
    /// `LinkStatement`, signed by the connection key it contains.
    public var statement: SignedStatement
    /// `LinkSessionSecret.bindingTag(for:)` when the app opened the QR or link (it holds `es`); absent on the typed path. Opaque to the relay.
    public var bindingTag: String?
    /// `ApprovalEnrollmentStatement` (enrollment id = session id) when approval capabilities are requested.
    public var approvalStatement: SignedStatement?
    /// App Attest assertion (CBOR, base64url) over `LinkAppAttest.clientData` for an attested device (`APP_ATTEST_ASSERTION_MODE`).
    public var appAttestAssertion: String?

    public init(statement: SignedStatement, bindingTag: String? = nil, approvalStatement: SignedStatement? = nil, appAttestAssertion: String? = nil) {
        self.statement = statement
        self.bindingTag = bindingTag
        self.approvalStatement = approvalStatement
        self.appAttestAssertion = appAttestAssertion
    }

    enum CodingKeys: String, CodingKey {
        case statement, bindingTag = "binding_tag", approvalStatement = "approval_statement", appAttestAssertion = "app_attest_assertion"
    }
}

/// The device's view of its session (`GET /v1/link-sessions/{id}`, and the answer to complete): the business's confirmation once given
/// (**verify it against the key directory**), the connection, and the session as an alert.
public struct LinkSessionDeviceView: Codable, Sendable, Hashable {
    public var sessionId: UUID
    public var status: LinkSessionStatus
    public var business: BusinessSummary
    public var subjectRef: SubjectRef
    public var capabilities: [Capability]
    public var expiresAt: Date
    /// The latest moment the business may confirm (expiry plus the grace); after it the session is ended and reported.
    public var confirmBy: Date
    public var confirmation: BusinessSignedStatement?
    public var connection: CustomerBusinessConnection?
    public var alert: AlertDescriptor

    public init(sessionId: UUID, status: LinkSessionStatus, business: BusinessSummary, subjectRef: SubjectRef, capabilities: [Capability], expiresAt: Date,
                confirmBy: Date, confirmation: BusinessSignedStatement?, connection: CustomerBusinessConnection?, alert: AlertDescriptor) {
        self.sessionId = sessionId
        self.status = status
        self.business = business
        self.subjectRef = subjectRef
        self.capabilities = capabilities
        self.expiresAt = expiresAt
        self.confirmBy = confirmBy
        self.confirmation = confirmation
        self.connection = connection
        self.alert = alert
    }

    enum CodingKeys: String, CodingKey {
        case sessionId = "session_id", status, business, subjectRef = "subject_ref", capabilities, expiresAt = "expires_at", confirmBy = "confirm_by"
        case confirmation, connection, alert
    }
}

// MARK: - Connections (spec v4 D2 `CustomerBusinessConnection`)

/// How a customer connected a business (spec v4 C3: QR, verified handle, approved code), or a business-initiated link session.
public enum ConnectionMethod: String, Codable, Sendable, Hashable {
    case qr, handle, code, linkSession = "link_session", other
    case unknown

    public init(from decoder: any Decoder) throws {
        self = ConnectionMethod(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
    }

    public init(source: ConnectSource) {
        switch source {
        case .qr, .appClip, .link, .button: self = .qr
        case .handle, .search: self = .handle
        case .code: self = .code
        case .sms: self = .other
        }
    }
}

public enum ConnectionStatus: String, Codable, Sendable, Hashable {
    /// A link session completed on the device and waits for the business's confirmation: nothing can be sent or asked yet.
    case pending
    case active
    case disconnected
    case unknown

    public init(from decoder: any Decoder) throws {
        self = ConnectionStatus(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
    }
}

/// The customer's per-business preferences (spec v4 C7, D2 `BusinessPreference`). `marketing` mirrors the marketing consent purpose.
public struct ConnectionPreferences: Codable, Sendable, Hashable {
    public var marketing: Bool
    public var muted: Bool
    public var favorite: Bool

    public init(marketing: Bool = false, muted: Bool = false, favorite: Bool = false) {
        self.marketing = marketing
        self.muted = muted
        self.favorite = favorite
    }
}

/// Today's relationship, as the organization model of spec v4 D2 names it: one per (customer, business), with the **scopes** the customer granted
/// (the capabilities of the link session that created or extended it) and the customer's **preferences**. The business only ever sees the
/// pairwise `subject_ref`; `relationshipId` is the customer's own handle.
public struct CustomerBusinessConnection: Codable, Sendable, Hashable {
    public var relationshipId: RelationshipID
    public var businessId: BusinessID
    public var status: ConnectionStatus
    public var method: ConnectionMethod
    public var scopes: [Capability]
    public var preferences: ConnectionPreferences
    public var createdAt: Date
    public var linkedAt: Date?

    public init(relationshipId: RelationshipID, businessId: BusinessID, status: ConnectionStatus, method: ConnectionMethod, scopes: [Capability],
                preferences: ConnectionPreferences, createdAt: Date, linkedAt: Date?) {
        self.relationshipId = relationshipId
        self.businessId = businessId
        self.status = status
        self.method = method
        self.scopes = scopes
        self.preferences = preferences
        self.createdAt = createdAt
        self.linkedAt = linkedAt
    }

    enum CodingKeys: String, CodingKey {
        case relationshipId = "relationship_id", businessId = "business_id", status, method, scopes, preferences, createdAt = "created_at", linkedAt = "linked_at"
    }
}
