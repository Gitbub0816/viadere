import Fluent
import Foundation
import ViadereCore

/// A verification request a business created for one of its connected customers (spec §14.1). Holds the request's parameters and its
/// state, **never evidence**: no birthdate, no name, no document data and no image is ever written to this table or any other Verify table.
final class VerificationRequestRecord: Model, @unchecked Sendable {
    static let schema = "verification_requests"

    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    /// The API key that created it: policy is evaluated again, with this key's capabilities, when the disclosure is made.
    @Field(key: "key_id") var keyId: UUID
    @Field(key: "livemode") var livemode: Bool
    @Field(key: "relationship_id") var relationshipId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "subject_ref") var subjectRef: String
    @Field(key: "capability") var capability: String
    /// Canonical JSON of the capability parameters (for example `{"years":18}`).
    @Field(key: "parameters") var parameters: String
    @Field(key: "purpose") var purpose: String
    /// The business's registered webhook subscription that receives `verification.completed`, if any.
    @OptionalField(key: "callback_id") var callbackId: UUID?
    @Field(key: "recipient_name") var recipientName: String
    /// `pending_consent`, `consented`, `released`, `not_verified`, `declined`, `expired`, `cancelled`, `revoked` (`ConsumerVerificationStatus`).
    @Field(key: "status") var status: String
    @OptionalField(key: "receipt_id") var receiptId: UUID?
    @OptionalField(key: "result_id") var resultId: UUID?
    @Field(key: "attempt_count") var attemptCount: Int
    /// SHA-256 of the `Idempotency-Key` and of the canonical request body.
    @Field(key: "idempotency_hash") var idempotencyHash: String
    @Field(key: "request_hash") var requestHash: String
    @OptionalField(key: "label") var label: String?
    @OptionalField(key: "disclosed_fields") var disclosedFields: String?
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "decided_at") var decidedAt: Date?

    init() {}

    init(id: UUID, businessId: UUID, keyId: UUID, livemode: Bool, relationshipId: UUID, consumerId: UUID, subjectRef: String, capability: Capability,
         parameters: String, purpose: String, callbackId: UUID?, recipientName: String, idempotencyHash: String, requestHash: String, now: Date,
         expiresAt: Date) {
        self.id = id
        self.businessId = businessId
        self.keyId = keyId
        self.livemode = livemode
        self.relationshipId = relationshipId
        self.consumerId = consumerId
        self.subjectRef = subjectRef
        self.capability = capability.rawValue
        self.parameters = parameters
        self.purpose = purpose
        self.callbackId = callbackId
        self.recipientName = recipientName
        status = ConsumerVerificationStatus.pendingConsent.rawValue
        attemptCount = 0
        self.idempotencyHash = idempotencyHash
        self.requestHash = requestHash
        createdAt = now
        self.expiresAt = expiresAt
    }

    var requestID: VerificationRequestID { VerificationRequestID(id!) }
    var capabilityValue: Capability { Capability(rawValue: capability) }
    var consumerStatus: ConsumerVerificationStatus { ConsumerVerificationStatus(rawValue: status) ?? .cancelled }
    var parameterValues: [String: JSONValue] {
        (try? ViadereJSON.decode(JSONValue.self, from: Data(parameters.utf8)))?.objectValue ?? [:]
    }
}

/// One try at verifying (a Wallet presentment or a provider session) for a request. Stores the single-use Wallet nonce and the provider
/// session reference: operational identifiers, not evidence.
final class VerificationAttemptRecord: Model, @unchecked Sendable {
    static let schema = "verification_attempts"

    @ID(key: .id) var id: UUID?
    @Field(key: "request_id") var requestId: UUID
    @Field(key: "business_id") var businessId: UUID
    /// `wallet` or `document`.
    @Field(key: "method") var method: String
    /// `issued`, `processing`, `succeeded`, `failed`.
    @Field(key: "status") var status: String
    /// Wallet: the single-use nonce (base64url). Cleared as soon as the presentation is consumed.
    @OptionalField(key: "nonce") var nonce: String?
    /// Provider session id. The provider's `vendor_data` is this attempt's id, so the provider holds nothing that links to a person.
    @OptionalField(key: "provider_session_id") var providerSessionId: String?
    /// Internal failure reason (audit only; never shown to the business).
    @OptionalField(key: "failure_reason") var failureReason: String?
    /// Provider purge: `pending`, `done` or `failed` (retried), `nil` for methods without a provider session.
    @OptionalField(key: "purge_status") var purgeStatus: String?
    @Field(key: "purge_attempts") var purgeAttempts: Int
    @OptionalField(key: "purged_at") var purgedAt: Date?
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "finished_at") var finishedAt: Date?

    init() {}

    init(id: UUID = UUID(), requestId: UUID, businessId: UUID, method: VerificationMethodKind, nonce: String?, now: Date, expiresAt: Date) {
        self.id = id
        self.requestId = requestId
        self.businessId = businessId
        self.method = method.rawValue
        status = "issued"
        self.nonce = nonce
        purgeAttempts = 0
        createdAt = now
        self.expiresAt = expiresAt
    }
}

/// The result of a request: what the business may retrieve **once**. The payload (the capability's output fields) is sealed with the
/// data-encryption key bound to this row and **erased** when the business retrieves it or when it expires; the provenance record holds no
/// personal data and stays as the evidence of how the result was established (VER-007).
final class VerificationResultRecord: Model, @unchecked Sendable {
    static let schema = "verification_results"

    @ID(key: .id) var id: UUID?
    @Field(key: "request_id") var requestId: UUID
    @Field(key: "business_id") var businessId: UUID
    /// SHA-256 of the `result_ref` (the reference itself is shown once, in the webhook and the request resource).
    @Field(key: "ref_hash") var refHash: String
    @Field(key: "outcome") var outcome: String
    @OptionalField(key: "payload") var payload: String?
    @OptionalField(key: "provenance") var provenance: String?
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "retrieved_at") var retrievedAt: Date?

    init() {}

    init(id: UUID = UUID(), requestId: UUID, businessId: UUID, refHash: String, outcome: VerificationOutcome, now: Date, expiresAt: Date) {
        self.id = id
        self.requestId = requestId
        self.businessId = businessId
        self.refHash = refHash
        self.outcome = outcome.rawValue
        createdAt = now
        self.expiresAt = expiresAt
    }
}

/// Deduplication of provider webhook deliveries (`event_id` is stable across retries).
final class VerificationProviderEventRecord: Model, @unchecked Sendable {
    static let schema = "verification_provider_events"

    @ID(key: .id) var id: UUID?
    @Field(key: "provider") var provider: String
    @Field(key: "event_id") var eventId: String
    @Field(key: "received_at") var receivedAt: Date

    init() {}

    init(provider: String, eventId: String, now: Date) {
        id = UUID()
        self.provider = provider
        self.eventId = eventId
        receivedAt = now
    }
}
