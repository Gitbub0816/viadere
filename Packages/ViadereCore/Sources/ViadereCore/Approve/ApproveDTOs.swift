import Foundation

// MARK: - Shared enums

/// Where an approval enrollment stands.
public enum ApprovalEnrollmentStatus: String, Codable, Sendable, Hashable {
    /// Created by the business; waiting for the customer's device.
    case pending
    /// The customer confirmed on the device and the relay holds the key; waiting for the business's signed confirmation.
    case deviceCompleted = "device_completed"
    /// Confirmed by the business: the key is active.
    case confirmed
    case expired
    case cancelled
    case unknown

    public init(from decoder: any Decoder) throws {
        self = ApprovalEnrollmentStatus(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
    }
}

public enum ApprovalKeyStatus: String, Codable, Sendable, Hashable {
    /// Enrolled by the device, awaiting the business's confirmation: **cannot approve anything yet**.
    case pending
    case active
    case revoked
    case unknown

    public init(from decoder: any Decoder) throws {
        self = ApprovalKeyStatus(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
    }
}

public enum ApprovalRequestStatus: String, Codable, Sendable, Hashable {
    case pending, approved, denied, reported, expired, cancelled
    case unknown

    public init(from decoder: any Decoder) throws {
        self = ApprovalRequestStatus(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
    }

    public var isFinal: Bool { self != .pending }
}

/// Whether the relay could read a request's details.
public enum ApprovalProtection: String, Codable, Sendable, Hashable {
    /// The details were HPKE-encrypted to the device by the business and signed by it: the relay saw ciphertext only.
    case endToEnd = "end_to_end"
    /// The details were sent in the clear to Viadere (spec 14.2 format). The relay could read them, and nothing but the API key vouches for them.
    case serverVisible = "server_visible"
    case unknown

    public init(from decoder: any Decoder) throws {
        self = ApprovalProtection(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
    }
}

// MARK: - Business: enrollment

/// `POST /v1/business/approve/enrollments`: start an enrollment for an existing relationship. Never a phone number (APP-001).
public struct CreateApprovalEnrollmentRequest: Codable, Sendable, Hashable {
    public var subjectRef: SubjectRef
    /// The capability the key is for; decides the key's access control (`auth.challenge` and `transaction.approve` both require biometrics).
    public var capability: Capability
    /// 60...900, default 600.
    public var expiresInSeconds: Int?

    public init(subjectRef: SubjectRef, capability: Capability, expiresInSeconds: Int? = nil) {
        self.subjectRef = subjectRef
        self.capability = capability
        self.expiresInSeconds = expiresInSeconds
    }

    enum CodingKeys: String, CodingKey {
        case subjectRef = "subject_ref", capability, expiresInSeconds = "expires_in_seconds"
    }
}

/// What the business shows its customer, in its own logged-in session.
public struct ApprovalEnrollmentTicket: Codable, Sendable, Hashable {
    public var enrollmentId: UUID
    /// Eight characters of the unambiguous alphabet, single use, shown as `ABCD-EFGH`.
    public var code: String
    /// `https://viadere.com/a/{CODE}?rk={root kid}`: opens the app (universal link / QR). `rk` is the business's root key id, so the app
    /// can check the directory against what the business displayed, not against what the relay says.
    public var deepLink: String
    public var expiresAt: Date

    public init(enrollmentId: UUID, code: String, deepLink: String, expiresAt: Date) {
        self.enrollmentId = enrollmentId
        self.code = code
        self.deepLink = deepLink
        self.expiresAt = expiresAt
    }

    enum CodingKeys: String, CodingKey {
        case enrollmentId = "enrollment_id", code, deepLink = "deep_link", expiresAt = "expires_at"
    }
}

/// `GET /v1/business/approve/enrollments/{id}`: the business's view, including the device's signed statement once it arrived.
public struct ApprovalEnrollmentView: Codable, Sendable, Hashable {
    public var enrollmentId: UUID
    public var subjectRef: SubjectRef
    public var capability: Capability
    public var status: ApprovalEnrollmentStatus
    public var expiresAt: Date
    public var createdAt: Date
    /// The device's signed enrollment statement. **Verify it yourself** (`ApprovalEnrollmentStatement.verify`): the relay forwards it.
    public var deviceStatement: SignedStatement?
    /// The key id from the statement (convenience; trust only what `verify` returns).
    public var kid: String?
    public var confirmation: BusinessSignedStatement?

    public init(enrollmentId: UUID, subjectRef: SubjectRef, capability: Capability, status: ApprovalEnrollmentStatus, expiresAt: Date, createdAt: Date,
                deviceStatement: SignedStatement? = nil, kid: String? = nil, confirmation: BusinessSignedStatement? = nil) {
        self.enrollmentId = enrollmentId
        self.subjectRef = subjectRef
        self.capability = capability
        self.status = status
        self.expiresAt = expiresAt
        self.createdAt = createdAt
        self.deviceStatement = deviceStatement
        self.kid = kid
        self.confirmation = confirmation
    }

    enum CodingKeys: String, CodingKey {
        case enrollmentId = "enrollment_id", subjectRef = "subject_ref", capability, status, expiresAt = "expires_at", createdAt = "created_at"
        case deviceStatement = "device_statement", kid, confirmation
    }
}

/// `POST /v1/business/approve/enrollments/{id}/confirm`.
public struct ConfirmApprovalEnrollmentRequest: Codable, Sendable, Hashable {
    public var confirmation: BusinessSignedStatement
    public init(confirmation: BusinessSignedStatement) { self.confirmation = confirmation }
}

/// An enrolled approval key as the business sees it.
public struct ApprovalKeyView: Codable, Sendable, Hashable {
    public var kid: String
    public var subjectRef: SubjectRef
    public var status: ApprovalKeyStatus
    public var assurance: ApprovalAMR
    /// X9.63 public key, base64url.
    public var publicKey: String
    public var hpkeKid: String
    public var hpkePublicKey: String
    public var createdAt: Date
    public var activatedAt: Date?
    public var revokedAt: Date?
    /// `consumer`, `business` or `system`.
    public var revokedBy: String?
    public var deviceStatement: SignedStatement

    public init(kid: String, subjectRef: SubjectRef, status: ApprovalKeyStatus, assurance: ApprovalAMR, publicKey: String, hpkeKid: String, hpkePublicKey: String,
                createdAt: Date, activatedAt: Date?, revokedAt: Date?, revokedBy: String?, deviceStatement: SignedStatement) {
        self.kid = kid
        self.subjectRef = subjectRef
        self.status = status
        self.assurance = assurance
        self.publicKey = publicKey
        self.hpkeKid = hpkeKid
        self.hpkePublicKey = hpkePublicKey
        self.createdAt = createdAt
        self.activatedAt = activatedAt
        self.revokedAt = revokedAt
        self.revokedBy = revokedBy
        self.deviceStatement = deviceStatement
    }

    enum CodingKeys: String, CodingKey {
        case kid, subjectRef = "subject_ref", status, assurance, publicKey = "public_key", hpkeKid = "hpke_kid", hpkePublicKey = "hpke_public_key"
        case createdAt = "created_at", activatedAt = "activated_at", revokedAt = "revoked_at", revokedBy = "revoked_by", deviceStatement = "device_statement"
    }

    /// The verifier-side record, after the caller verified `deviceStatement`.
    public func enrolledKey() throws -> EnrolledApprovalKey {
        let statement = try ApprovalEnrollmentStatement.verify(deviceStatement)
        guard statement.kid == kid, statement.subject == subjectRef else { throw ApprovalEnrollmentError.keyMismatch }
        var enrolled = statement.enrolledKey
        enrolled.revoked = status != .active
        return enrolled
    }
}

public struct RevokeApprovalKeyRequest: Codable, Sendable, Hashable {
    public var reason: String?
    public init(reason: String? = nil) { self.reason = reason }
}

// MARK: - Business: requests

/// A device-specific encrypted delivery of one request.
public struct ApprovalEnvelopeDelivery: Codable, Sendable, Hashable {
    /// The approval key (device) this copy is for.
    public var kid: String
    public var envelope: E2EEEnvelope
    public init(kid: String, envelope: E2EEEnvelope) {
        self.kid = kid
        self.envelope = envelope
    }
}

/// `POST /v1/business/approve/requests` (spec 14.2 plus end-to-end delivery).
///
/// * **Server-visible** (`transaction` or `authentication` present): the relay sees the details; `challenge` is required.
/// * **End-to-end** (`envelopes` present): the relay sees only ciphertext; one envelope per enrolled device key.
/// Exactly one of `transaction`, `authentication`, `envelopes`.
public struct CreateApprovalRequest: Codable, Sendable, Hashable {
    /// The business's own unique id for this request (`[A-Za-z0-9._:-]`, 16...64). Idempotency key: the same id with the same body returns
    /// the original request; with a different body it is a conflict.
    public var requestId: String
    public var subjectRef: SubjectRef
    public var capability: Capability
    public var challenge: String?
    public var transaction: TransactionDetails?
    public var authentication: AuthenticationDetails?
    public var envelopes: [ApprovalEnvelopeDelivery]?
    /// 30...600, default 120.
    public var expiresInSeconds: Int?

    public init(requestId: String, subjectRef: SubjectRef, capability: Capability, challenge: String? = nil, transaction: TransactionDetails? = nil,
                authentication: AuthenticationDetails? = nil, envelopes: [ApprovalEnvelopeDelivery]? = nil, expiresInSeconds: Int? = nil) {
        self.requestId = requestId
        self.subjectRef = subjectRef
        self.capability = capability
        self.challenge = challenge
        self.transaction = transaction
        self.authentication = authentication
        self.envelopes = envelopes
        self.expiresInSeconds = expiresInSeconds
    }

    enum CodingKeys: String, CodingKey {
        case requestId = "request_id", subjectRef = "subject_ref", capability, challenge, transaction, authentication, envelopes
        case expiresInSeconds = "expires_in_seconds"
    }
}

/// The business's view of a request. **The status is the relay's say-so: never authorize on it.** Fetch the result, verify the signature
/// and the bound details yourself (`ApprovalVerifier` in the SDK).
public struct ApprovalRequestView: Codable, Sendable, Hashable {
    public var requestId: String
    public var subjectRef: SubjectRef
    public var capability: Capability
    public var status: ApprovalRequestStatus
    public var protection: ApprovalProtection
    public var expiresAt: Date
    public var createdAt: Date
    public var decidedAt: Date?
    /// Present once the customer decided: `GET /v1/business/approve/results/{resultRef}`.
    public var resultRef: String?
    /// Why a request that never reached the customer ended (`auto_denied`, `frozen`, `no_active_key`).
    public var reason: String?
    /// Devices the request was delivered to.
    public var deliveredTo: Int

    public init(requestId: String, subjectRef: SubjectRef, capability: Capability, status: ApprovalRequestStatus, protection: ApprovalProtection,
                expiresAt: Date, createdAt: Date, decidedAt: Date? = nil, resultRef: String? = nil, reason: String? = nil, deliveredTo: Int = 0) {
        self.requestId = requestId
        self.subjectRef = subjectRef
        self.capability = capability
        self.status = status
        self.protection = protection
        self.expiresAt = expiresAt
        self.createdAt = createdAt
        self.decidedAt = decidedAt
        self.resultRef = resultRef
        self.reason = reason
        self.deliveredTo = deliveredTo
    }

    enum CodingKeys: String, CodingKey {
        case requestId = "request_id", subjectRef = "subject_ref", capability, status, protection, expiresAt = "expires_at", createdAt = "created_at"
        case decidedAt = "decided_at", resultRef = "result_ref", reason, deliveredTo = "delivered_to"
    }
}

/// `GET /v1/business/approve/results/{resultRef}`: the signed result, retrieved with the calling business's own credentials (recipient-bound).
public struct ApprovalResultResponse: Codable, Sendable, Hashable {
    public var resultRef: String
    public var requestId: String
    /// The compact JWS (section 2.54). Verify it with `ApprovalResultVerifier` against your own records.
    public var result: String
    public var kid: String
    public var decidedAt: Date

    public init(resultRef: String, requestId: String, result: String, kid: String, decidedAt: Date) {
        self.resultRef = resultRef
        self.requestId = requestId
        self.result = result
        self.kid = kid
        self.decidedAt = decidedAt
    }

    enum CodingKeys: String, CodingKey { case resultRef = "result_ref", requestId = "request_id", result, kid, decidedAt = "decided_at" }
}

/// `POST /v1/business/approve/freeze`: the business stops approvals for one relationship (it can lift only its own freeze).
public struct BusinessFreezeRequest: Codable, Sendable, Hashable {
    public var subjectRef: SubjectRef
    public var frozen: Bool
    public var reason: String?
    public init(subjectRef: SubjectRef, frozen: Bool, reason: String? = nil) {
        self.subjectRef = subjectRef
        self.frozen = frozen
        self.reason = reason
    }
    enum CodingKeys: String, CodingKey { case subjectRef = "subject_ref", frozen, reason }
}

public struct FreezeStatus: Codable, Sendable, Hashable {
    public var subjectRef: SubjectRef
    public var frozen: Bool
    public init(subjectRef: SubjectRef, frozen: Bool) {
        self.subjectRef = subjectRef
        self.frozen = frozen
    }
    enum CodingKeys: String, CodingKey { case subjectRef = "subject_ref", frozen }
}

// MARK: - Business: key directory

/// `POST /v1/business/key-directory/entries`: publishes one signed entry (root registration, succession, key or revocation).
public struct PublishKeyEntryRequest: Codable, Sendable, Hashable {
    /// base64url of `KeyLogEntry.leafData()`.
    public var entry: String
    public init(entry: String) { self.entry = entry }
}

public struct PublishKeyEntryResponse: Codable, Sendable, Hashable {
    public var index: Int
    public var treeSize: Int
    public var sth: SignedTreeHead
    public init(index: Int, treeSize: Int, sth: SignedTreeHead) {
        self.index = index
        self.treeSize = treeSize
        self.sth = sth
    }
    enum CodingKeys: String, CodingKey { case index, treeSize = "tree_size", sth }
}

// MARK: - Device: enrollment

public struct ApproveEnrollmentLookupRequest: Codable, Sendable, Hashable {
    /// The code as typed or scanned (separators and case are ignored).
    public var code: String
    public init(code: String) { self.code = code }
}

/// What the app shows before the customer confirms (APP-003): the verified business, what the key is for, what protection it needs.
public struct ApproveEnrollmentPreview: Codable, Sendable, Hashable {
    public var enrollmentId: UUID
    public var business: BusinessSummary
    public var relationshipId: RelationshipID
    public var subjectRef: SubjectRef
    public var capability: Capability
    /// `biometric` for high and critical capabilities.
    public var requiredAssurance: ApprovalAMR
    public var expiresAt: Date

    public init(enrollmentId: UUID, business: BusinessSummary, relationshipId: RelationshipID, subjectRef: SubjectRef, capability: Capability,
                requiredAssurance: ApprovalAMR, expiresAt: Date) {
        self.enrollmentId = enrollmentId
        self.business = business
        self.relationshipId = relationshipId
        self.subjectRef = subjectRef
        self.capability = capability
        self.requiredAssurance = requiredAssurance
        self.expiresAt = expiresAt
    }

    enum CodingKeys: String, CodingKey {
        case enrollmentId = "enrollment_id", business, relationshipId = "relationship_id", subjectRef = "subject_ref", capability
        case requiredAssurance = "required_assurance", expiresAt = "expires_at"
    }
}

public struct CompleteApproveEnrollmentRequest: Codable, Sendable, Hashable {
    /// `ApprovalEnrollmentStatement` signed by the new approval key.
    public var statement: SignedStatement
    public init(statement: SignedStatement) { self.statement = statement }
}

/// A key enrolled by this account, as the app sees it.
public struct ApproveKey: Codable, Sendable, Hashable, Identifiable {
    public var id: String { kid }
    public var kid: String
    public var enrollmentId: UUID
    public var business: BusinessSummary
    public var relationshipId: RelationshipID
    public var subjectRef: SubjectRef
    public var deviceId: DeviceID
    public var status: ApprovalKeyStatus
    public var assurance: ApprovalAMR
    public var createdAt: Date
    public var activatedAt: Date?
    public var revokedAt: Date?
    public var revokedBy: String?
    /// The signed statement the device made (kept so the app can verify the business's confirmation against it).
    public var statement: SignedStatement
    /// The business's signed confirmation, once given. **Verify it against the key directory before trusting the key.**
    public var confirmation: BusinessSignedStatement?

    public init(kid: String, enrollmentId: UUID, business: BusinessSummary, relationshipId: RelationshipID, subjectRef: SubjectRef, deviceId: DeviceID,
                status: ApprovalKeyStatus, assurance: ApprovalAMR, createdAt: Date, activatedAt: Date?, revokedAt: Date?, revokedBy: String?,
                statement: SignedStatement, confirmation: BusinessSignedStatement?) {
        self.kid = kid
        self.enrollmentId = enrollmentId
        self.business = business
        self.relationshipId = relationshipId
        self.subjectRef = subjectRef
        self.deviceId = deviceId
        self.status = status
        self.assurance = assurance
        self.createdAt = createdAt
        self.activatedAt = activatedAt
        self.revokedAt = revokedAt
        self.revokedBy = revokedBy
        self.statement = statement
        self.confirmation = confirmation
    }

    enum CodingKeys: String, CodingKey {
        case kid, enrollmentId = "enrollment_id", business, relationshipId = "relationship_id", subjectRef = "subject_ref", deviceId = "device_id"
        case status, assurance, createdAt = "created_at", activatedAt = "activated_at", revokedAt = "revoked_at", revokedBy = "revoked_by", statement, confirmation
    }
}

// MARK: - Device: requests

/// A request waiting for this device.
public struct ApproveDeviceRequest: Codable, Sendable, Hashable, Identifiable {
    /// The relay's id (use it in the decision route).
    public var id: UUID
    public var requestId: String
    public var business: BusinessSummary
    public var subjectRef: SubjectRef
    public var capability: Capability
    /// The approval key this copy is for.
    public var kid: String
    public var protection: ApprovalProtection
    public var status: ApprovalRequestStatus
    public var createdAt: Date
    public var expiresAt: Date
    /// End-to-end requests: the ciphertext addressed to this device's HPKE key.
    public var envelope: E2EEEnvelope?
    /// Server-visible requests: the details and challenge as the relay holds them (no business signature: say so in the UI).
    public var challenge: String?
    public var transaction: TransactionDetails?
    public var authentication: AuthenticationDetails?
    /// Requests from this business to this customer in the last hour, including this one.
    public var requestsInWindow: Int
    /// True when the customer has received several: the app must say so (SEC-DEV-008).
    public var showFatigueWarning: Bool

    public init(id: UUID, requestId: String, business: BusinessSummary, subjectRef: SubjectRef, capability: Capability, kid: String, protection: ApprovalProtection,
                status: ApprovalRequestStatus, createdAt: Date, expiresAt: Date, envelope: E2EEEnvelope? = nil, challenge: String? = nil,
                transaction: TransactionDetails? = nil, authentication: AuthenticationDetails? = nil, requestsInWindow: Int = 1, showFatigueWarning: Bool = false) {
        self.id = id
        self.requestId = requestId
        self.business = business
        self.subjectRef = subjectRef
        self.capability = capability
        self.kid = kid
        self.protection = protection
        self.status = status
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.envelope = envelope
        self.challenge = challenge
        self.transaction = transaction
        self.authentication = authentication
        self.requestsInWindow = requestsInWindow
        self.showFatigueWarning = showFatigueWarning
    }

    enum CodingKeys: String, CodingKey {
        case id, requestId = "request_id", business, subjectRef = "subject_ref", capability, kid, protection, status, createdAt = "created_at"
        case expiresAt = "expires_at", envelope, challenge, transaction, authentication, requestsInWindow = "requests_in_window", showFatigueWarning = "show_fatigue_warning"
    }
}

/// `POST /v1/approve/requests/{id}/result`.
public struct SubmitApprovalResultRequest: Codable, Sendable, Hashable {
    /// The compact JWS the device signed with the pairwise approval key.
    public var result: String
    public init(result: String) { self.result = result }
}

public struct SubmitApprovalResultResponse: Codable, Sendable, Hashable {
    public var id: UUID
    public var status: ApprovalRequestStatus
    public init(id: UUID, status: ApprovalRequestStatus) {
        self.id = id
        self.status = status
    }
}

// MARK: - Device: freeze

public enum ApproveFreezeScope: String, Codable, Sendable, Hashable {
    /// Every approval for every business.
    case account
    /// One business relationship.
    case relationship
}

/// `POST /v1/approve/freeze`. Freezing needs only a signed device request (it is always safe); lifting a freeze needs a trusted device and a
/// biometric proof (`ApproveFreezeProof`).
public struct ApproveFreezeRequest: Codable, Sendable, Hashable {
    public var scope: ApproveFreezeScope
    public var relationshipId: RelationshipID?
    public var frozen: Bool
    /// Required when `frozen == false`.
    public var proof: SignedStatement?

    public init(scope: ApproveFreezeScope, relationshipId: RelationshipID? = nil, frozen: Bool, proof: SignedStatement? = nil) {
        self.scope = scope
        self.relationshipId = relationshipId
        self.frozen = frozen
        self.proof = proof
    }

    enum CodingKeys: String, CodingKey { case scope, relationshipId = "relationship_id", frozen, proof }
}

public struct ApproveFreezeEntry: Codable, Sendable, Hashable {
    public var scope: ApproveFreezeScope
    public var relationshipId: RelationshipID?
    /// `consumer` or `business`.
    public var by: String
    public var since: Date

    public init(scope: ApproveFreezeScope, relationshipId: RelationshipID?, by: String, since: Date) {
        self.scope = scope
        self.relationshipId = relationshipId
        self.by = by
        self.since = since
    }

    enum CodingKeys: String, CodingKey { case scope, relationshipId = "relationship_id", by, since }
}

public struct ApproveFreezeState: Codable, Sendable, Hashable {
    public var entries: [ApproveFreezeEntry]
    public var accountFrozen: Bool { entries.contains { $0.scope == .account } }
    public init(entries: [ApproveFreezeEntry]) { self.entries = entries }
}

/// The biometric proof that lifts a freeze: a statement signed with the device's `approvalBiometric` key over
/// `"VIADERE-APPROVE-FREEZE-V1\n" ‖ canonical {"action":"unfreeze","device_id","relationship_id"?,"scope","signed_at","v":1}`.
public struct ApproveFreezeProof: Sendable, Hashable {
    public var scope: ApproveFreezeScope
    public var relationshipId: RelationshipID?
    public var deviceId: DeviceID
    public var signedAt: Int64

    public init(scope: ApproveFreezeScope, relationshipId: RelationshipID?, deviceId: DeviceID, signedAt: Date) {
        self.scope = scope
        self.relationshipId = relationshipId
        self.deviceId = deviceId
        self.signedAt = ViadereDate.unixSeconds(signedAt)
    }

    var object: [String: JSONValue] {
        var object: [String: JSONValue] = ["v": .integer(1), "action": .string("unfreeze"), "scope": .string(scope.rawValue),
                                          "device_id": .string(deviceId.description), "signed_at": .integer(signedAt)]
        if let relationshipId { object["relationship_id"] = .string(relationshipId.description) }
        return object
    }

    public func sign(with biometricKey: any DeviceSigningKey) async throws -> SignedStatement {
        try await SignedStatement.sign(object, domain: ApproveDomain.freeze, with: biometricKey)
    }

    /// Parses a proof and checks its signature with `deviceKey` (the device's registered `approvalBiometric` key).
    public static func verify(_ signed: SignedStatement, deviceKey: DevicePublicKey) -> ApproveFreezeProof? {
        guard signed.isValid(domain: ApproveDomain.freeze, publicKey: deviceKey), let o = signed.canonicalObject(),
              Set(o.keys).isSubset(of: ["v", "action", "scope", "device_id", "signed_at", "relationship_id"]),
              o["v"]?.int64Value == 1, o["action"]?.stringValue == "unfreeze", let scope = o["scope"]?.stringValue.flatMap(ApproveFreezeScope.init(rawValue:)),
              let device = o["device_id"]?.stringValue.flatMap(DeviceID.init), let signedAt = o["signed_at"]?.int64Value, signedAt > 0 else { return nil }
        var relationship: RelationshipID?
        if let raw = o["relationship_id"] {
            guard let value = raw.stringValue.flatMap(RelationshipID.init) else { return nil }
            relationship = value
        }
        guard (scope == .relationship) == (relationship != nil) else { return nil }
        return ApproveFreezeProof(scope: scope, relationshipId: relationship, deviceId: device, signedAt: Date(timeIntervalSince1970: TimeInterval(signedAt)))
    }
}

// MARK: - Webhook v2 (spec 14.3)

/// The opaque webhook envelope of the `2026-10-27` version. It names what happened and where to fetch it, nothing else.
public struct WebhookEnvelopeV2: Codable, Sendable, Hashable {
    public static let version = "2026-10-27"

    public var id: String
    public var type: String
    public var version: String
    public var tenantId: String
    public var requestId: String
    public var occurredAt: Date
    public var resultRef: String?

    public init(id: String, type: String, version: String = WebhookEnvelopeV2.version, tenantId: String, requestId: String, occurredAt: Date, resultRef: String?) {
        self.id = id
        self.type = type
        self.version = version
        self.tenantId = tenantId
        self.requestId = requestId
        self.occurredAt = occurredAt
        self.resultRef = resultRef
    }

    enum CodingKeys: String, CodingKey { case id, type, version, tenantId = "tenant_id", requestId = "request_id", occurredAt = "occurred_at", resultRef = "result_ref" }

    public init(from decoder: any Decoder) throws {
        // Strict: an envelope with any member this version does not define is refused (it must stay opaque).
        let any = try decoder.container(keyedBy: AnyKey.self)
        guard Set(any.allKeys.map(\.stringValue)).isSubset(of: Set(CodingKeys.allCases.map(\.rawValue))) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "unknown member"))
        }
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        type = try c.decode(String.self, forKey: .type)
        version = try c.decode(String.self, forKey: .version)
        tenantId = try c.decode(String.self, forKey: .tenantId)
        requestId = try c.decode(String.self, forKey: .requestId)
        occurredAt = try c.decode(Date.self, forKey: .occurredAt)
        resultRef = try c.decodeIfPresent(String.self, forKey: .resultRef)
    }
}

extension WebhookEnvelopeV2.CodingKeys: CaseIterable {}

private struct AnyKey: CodingKey {
    var stringValue: String
    var intValue: Int? { nil }
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { nil }
}

/// Event types of the Approve webhooks.
public extension WebhookEventType {
    static let approveEnrollmentDeviceCompleted = WebhookEventType(rawValue: "approve.enrollment.device_completed")
    static let approveEnrollmentConfirmed = WebhookEventType(rawValue: "approve.enrollment.confirmed")
    static let approveKeyRevoked = WebhookEventType(rawValue: "approve.key.revoked")
    static let approveRequestDecided = WebhookEventType(rawValue: "approve.request.decided")
    static let approveRequestExpired = WebhookEventType(rawValue: "approve.request.expired")
    static let approveFrozen = WebhookEventType(rawValue: "approve.frozen")

    /// The events a v2 (opaque) subscription may receive.
    static let opaqueEvents: [WebhookEventType] = [
        .approveEnrollmentDeviceCompleted, .approveEnrollmentConfirmed, .approveKeyRevoked, .approveRequestDecided, .approveRequestExpired, .approveFrozen,
        .interactionDecided, .interactionExpired, .interactionCancelled,
        // Verify (WP3): `verification.completed` carries only `request_id` and `result_ref`.
        .verificationCompleted,
    ]
}
