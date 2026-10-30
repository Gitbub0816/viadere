import Fluent
import Foundation
import ViadereCore

/// One business link session (WP-C1, `docs/SECURITY.md` §2.59). The code and the business's customer reference are stored only as keyed hashes.
final class LinkSessionRecord: Model, @unchecked Sendable {
    static let schema = "link_sessions"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "api_key_id") var apiKeyId: UUID
    @Field(key: "livemode") var livemode: Bool
    @Field(key: "code_hash") var codeHash: String
    @Field(key: "customer_ref_hash") var customerRefHash: String
    /// Canonical capability ids, comma-separated.
    @Field(key: "capabilities") var capabilities: String
    @OptionalField(key: "display_hint") var displayHint: String?
    /// The business's root key id when the session was created (the descriptor names it; the SDK checks it against its own).
    @Field(key: "root_kid") var rootKid: String
    @Field(key: "status") var status: String
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "claimed_consumer_id") var claimedConsumerId: UUID?
    @OptionalField(key: "claimed_device_id") var claimedDeviceId: UUID?
    @OptionalField(key: "relationship_id") var relationshipId: UUID?
    /// The connection did not exist before this session (it is removed again if the business never confirms).
    @Field(key: "relationship_created") var relationshipCreated: Bool
    /// The status the connection had before this session made it `pending_link` (restored if the business never confirms).
    @OptionalField(key: "relationship_prior_status") var relationshipPriorStatus: String?
    @OptionalField(key: "subject_ref") var subjectRef: String?
    @OptionalField(key: "statement_payload") var statementPayload: String?
    @OptionalField(key: "statement_signature") var statementSignature: String?
    @OptionalField(key: "statement_digest") var statementDigest: String?
    @OptionalField(key: "connection_kid") var connectionKid: String?
    /// Opaque to the relay: only the business, which holds `es`, can verify it.
    @OptionalField(key: "binding_tag") var bindingTag: String?
    @OptionalField(key: "approval_statement_payload") var approvalStatementPayload: String?
    @OptionalField(key: "approval_statement_signature") var approvalStatementSignature: String?
    @OptionalField(key: "approval_kid") var approvalKid: String?
    /// JSON of Viadere's signed `LinkResult` (`ViadereSignedStatement`).
    @OptionalField(key: "result") var result: String?
    @OptionalField(key: "completed_at") var completedAt: Date?
    /// JSON of the business's `LinkConfirmation` (`BusinessSignedStatement`).
    @OptionalField(key: "confirmation") var confirmation: String?
    @OptionalField(key: "verification") var verification: String?
    @OptionalField(key: "confirmed_at") var confirmedAt: Date?
    @OptionalField(key: "cancelled_at") var cancelledAt: Date?
    /// Why an unconfirmed session ended: `not_completed`, `unconfirmed`, `cancelled`.
    @OptionalField(key: "ended_reason") var endedReason: String?

    init() {}

    var statusValue: LinkSessionStatus { LinkSessionStatus(rawValue: status) ?? .unknown }
    var capabilityList: [Capability] { capabilities.split(separator: ",").map { Capability(rawValue: String($0)) } }
    var needsApprovalKey: Bool { !LinkCapabilities.approval(capabilityList).isEmpty }

    var statement: SignedStatement? {
        guard let statementPayload, let statementSignature else { return nil }
        return SignedStatement(payload: statementPayload, signature: statementSignature)
    }

    var approvalStatement: SignedStatement? {
        guard let approvalStatementPayload, let approvalStatementSignature else { return nil }
        return SignedStatement(payload: approvalStatementPayload, signature: approvalStatementSignature)
    }

    var signedResult: ViadereSignedStatement? { result.flatMap { try? ViadereJSON.decode(ViadereSignedStatement.self, from: Data($0.utf8)) } }
    var signedConfirmation: BusinessSignedStatement? { confirmation.flatMap { try? ViadereJSON.decode(BusinessSignedStatement.self, from: Data($0.utf8)) } }
}
