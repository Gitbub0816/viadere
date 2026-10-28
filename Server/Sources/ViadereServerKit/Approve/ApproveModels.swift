import Fluent
import Foundation
import ViadereCore

/// One entry of the key-directory transparency log. Append-only (database triggers); `idx` is the leaf index.
final class KDLogEntryRecord: Model, @unchecked Sendable {
    static let schema = "kd_log_entries"
    @ID(key: .id) var id: UUID?
    @Field(key: "idx") var idx: Int
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "entry_type") var entryType: String
    /// base64url of the canonical entry bytes (the leaf data).
    @Field(key: "entry") var entry: String
    /// Lowercase hex leaf hash.
    @Field(key: "leaf_hash") var leafHash: String
    @Field(key: "created_at") var createdAt: Date

    init() {}

    init(idx: Int, businessId: UUID, entryType: String, entry: String, leafHash: String, now: Date) {
        id = UUID()
        self.idx = idx
        self.businessId = businessId
        self.entryType = entryType
        self.entry = entry
        self.leafHash = leafHash
        createdAt = now
    }
}

/// A signed tree head. Append-only.
final class KDTreeHeadRecord: Model, @unchecked Sendable {
    static let schema = "kd_tree_heads"
    @ID(key: .id) var id: UUID?
    @Field(key: "tree_size") var treeSize: Int
    @Field(key: "root_hash") var rootHash: String
    @Field(key: "payload") var payload: String
    @Field(key: "signature") var signature: String
    @Field(key: "created_at") var createdAt: Date

    init() {}

    init(head: SignedTreeHead, treeSize: Int, rootHash: String, now: Date) {
        id = UUID()
        self.treeSize = treeSize
        self.rootHash = rootHash
        payload = head.payload
        signature = head.signature
        createdAt = now
    }

    var signed: SignedTreeHead { SignedTreeHead(payload: payload, signature: signature) }
}

final class ApproveEnrollmentRecord: Model, @unchecked Sendable {
    static let schema = "approve_enrollments"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "relationship_id") var relationshipId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "subject_ref") var subjectRef: String
    @Field(key: "capability") var capability: String
    /// `biometric` or `presence`: the access control the key must be created with.
    @Field(key: "required_assurance") var requiredAssurance: String
    /// HMAC of the canonical code (the plaintext code is shown once, to the business).
    @Field(key: "code_hash") var codeHash: String
    @Field(key: "status") var status: String
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "claimed_device_id") var claimedDeviceId: UUID?
    @OptionalField(key: "statement_payload") var statementPayload: String?
    @OptionalField(key: "statement_signature") var statementSignature: String?
    @OptionalField(key: "kid") var kid: String?
    @OptionalField(key: "device_completed_at") var deviceCompletedAt: Date?
    /// JSON of the business's `BusinessSignedStatement`.
    @OptionalField(key: "confirmation") var confirmation: String?
    @OptionalField(key: "confirmed_at") var confirmedAt: Date?
    @OptionalField(key: "cancelled_at") var cancelledAt: Date?
    /// The device's binding tag (opaque to the relay: only the business, which holds the enrollment secret, can verify it).
    @OptionalField(key: "binding_tag") var bindingTag: String?

    init() {}

    var statusValue: ApprovalEnrollmentStatus { ApprovalEnrollmentStatus(rawValue: status) ?? .unknown }

    var deviceStatement: SignedStatement? {
        guard let statementPayload, let statementSignature else { return nil }
        return SignedStatement(payload: statementPayload, signature: statementSignature)
    }
}

final class ApproveKeyRecord: Model, @unchecked Sendable {
    static let schema = "approve_keys"
    @ID(key: .id) var id: UUID?
    /// Unique across the whole platform: a key serves exactly one business relationship (pairwise).
    @Field(key: "kid") var kid: String
    @Field(key: "enrollment_id") var enrollmentId: UUID
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "relationship_id") var relationshipId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "device_id") var deviceId: UUID
    @Field(key: "subject_ref") var subjectRef: String
    @Field(key: "public_key") var publicKey: String
    @Field(key: "hpke_kid") var hpkeKid: String
    @Field(key: "hpke_public_key") var hpkePublicKey: String
    @Field(key: "assurance") var assurance: String
    @Field(key: "status") var status: String
    @Field(key: "statement_payload") var statementPayload: String
    @Field(key: "statement_signature") var statementSignature: String
    @OptionalField(key: "confirmation") var confirmation: String?
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "activated_at") var activatedAt: Date?
    @OptionalField(key: "revoked_at") var revokedAt: Date?
    @OptionalField(key: "revoked_by") var revokedBy: String?
    @OptionalField(key: "revoke_reason") var revokeReason: String?

    init() {}

    var statusValue: ApprovalKeyStatus { ApprovalKeyStatus(rawValue: status) ?? .unknown }
    var assuranceValue: ApprovalAMR { ApprovalAMR(rawValue: assurance) ?? .biometric }
    var statement: SignedStatement { SignedStatement(payload: statementPayload, signature: statementSignature) }
    var isActive: Bool { statusValue == .active }
}

final class ApproveRequestRecord: Model, @unchecked Sendable {
    static let schema = "approve_requests"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    /// The business's own id; unique per business (idempotency).
    @Field(key: "request_id") var requestId: String
    @Field(key: "relationship_id") var relationshipId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "subject_ref") var subjectRef: String
    @Field(key: "capability") var capability: String
    /// `end_to_end` or `server_visible`.
    @Field(key: "protection") var protection: String
    @Field(key: "request_hash") var requestHash: String
    /// Server-visible requests only: the business's nonce.
    @OptionalField(key: "challenge") var challenge: String?
    /// Server-visible requests only: the displayed details as AES-GCM-sealed JSON (row-bound). End-to-end requests hold nothing here.
    @OptionalField(key: "details_sealed") var detailsSealed: String?
    @Field(key: "status") var status: String
    @OptionalField(key: "reason") var reason: String?
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "decided_at") var decidedAt: Date?
    @OptionalField(key: "decided_kid") var decidedKid: String?
    @OptionalField(key: "decision") var decision: String?
    @OptionalField(key: "amr") var amr: String?
    @OptionalField(key: "result_ref") var resultRef: String?
    @OptionalField(key: "result_jws") var resultJWS: String?
    /// Keys the request was delivered to (count).
    @Field(key: "delivered") var delivered: Int

    init() {}

    var statusValue: ApprovalRequestStatus { ApprovalRequestStatus(rawValue: status) ?? .unknown }
    var protectionValue: ApprovalProtection { ApprovalProtection(rawValue: protection) ?? .unknown }
}

/// One copy of a request addressed to one enrolled key (one device).
final class ApproveDeliveryRecord: Model, @unchecked Sendable {
    static let schema = "approve_deliveries"
    @ID(key: .id) var id: UUID?
    @Field(key: "request_id") var requestId: UUID
    @Field(key: "kid") var kid: String
    @Field(key: "device_id") var deviceId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    /// End-to-end requests: the canonical envelope bytes (ciphertext; the relay cannot read it).
    @OptionalField(key: "envelope") var envelope: String?
    @Field(key: "created_at") var createdAt: Date

    init() {}
}

final class ApproveFreezeRecord: Model, @unchecked Sendable {
    static let schema = "approve_freezes"
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "scope") var scope: String
    @OptionalField(key: "relationship_id") var relationshipId: UUID?
    @OptionalField(key: "business_id") var businessId: UUID?
    /// `consumer` or `business`.
    @Field(key: "frozen_by") var frozenBy: String
    @OptionalField(key: "reason") var reason: String?
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "lifted_at") var liftedAt: Date?

    init() {}

    var scopeValue: ApproveFreezeScope { ApproveFreezeScope(rawValue: scope) ?? .relationship }
}

/// The opaque reference one `approve.frozen` webhook carries for one business (random, never derived from the subject or the freeze, so two
/// businesses cannot link a customer by comparing events). `GET /v1/business/approve/freezes/{ref}` resolves it with the business's own key.
final class ApproveFreezeEventRecord: Model, @unchecked Sendable {
    static let schema = "approve_freeze_events"
    @ID(key: .id) var id: UUID?
    @Field(key: "ref") var ref: String
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "relationship_id") var relationshipId: UUID
    @Field(key: "created_at") var createdAt: Date

    init() {}

    static func newRef() -> String { "frz_" + SecureToken.generate(byteCount: 16) }
    static func isValidRef(_ value: String) -> Bool { value.hasPrefix("frz_") && Base64URL.isValid(String(value.dropFirst(4)), minLength: 22, maxLength: 22) }
}
