import Fluent
import Foundation
import SQLKit
import ViadereCore

/// One authentication delivery (ADR-0020). Data classes (ADR-0026): **P** (pending secret: the business URL, the partner code, the template variables) lives
/// only in `auth_delivery_secrets`, sealed, and is deleted at the first terminal state; **T** (transaction metadata) lives here for 30 days after the
/// terminal state. This row never holds a URL, a code, a variable value, a customer reference or a contact.
final class AuthDeliveryRecord: Model, @unchecked Sendable {
    static let schema = "auth_deliveries"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    /// The business's own id, unique per tenant.
    @Field(key: "request_id") var requestId: String
    /// SHA-256 of the canonical create request: same request id and hash replays, another hash is `409 idempotency_conflict`.
    @Field(key: "request_hash") var requestHash: String
    @Field(key: "relationship_id") var relationshipId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "api_key_id") var apiKeyId: UUID
    @Field(key: "livemode") var livemode: Bool
    @Field(key: "method") var method: String
    @Field(key: "purpose") var purpose: String
    @Field(key: "template") var template: String
    @Field(key: "status") var status: String
    /// Incremented by every transition: the compare-and-swap column (a lost race changes nothing).
    @Field(key: "version") var version: Int
    @OptionalField(key: "reason") var reason: String?
    /// `push,inbox` (never `sms`).
    @Field(key: "channels") var channels: String
    /// SHA-256 of the canonical variables (the values themselves are P class and only in the sealed row).
    @OptionalField(key: "variables_sha256") var variablesSHA256: String?
    /// `magic_link`: the lowercase host the business signed, and its compact `viadere-destination+jws` (a digest of the URL, not a bearer value).
    @OptionalField(key: "destination_host") var destinationHost: String?
    @OptionalField(key: "destination_statement") var destinationStatement: String?
    @OptionalField(key: "code_kind") var codeKind: String?
    /// Delivered without an alert push because a per-subject budget was exhausted (the inbox still shows it).
    @Field(key: "silent") var silent: Bool
    @OptionalField(key: "callback_webhook_id") var callbackWebhookId: UUID?
    @OptionalField(key: "correlation_id") var correlationId: String?
    @OptionalField(key: "client_transaction_ref") var clientTransactionRef: String?
    /// The business's opaque `session_handle` (class T): the only input to supersession.
    @OptionalField(key: "session_handle") var sessionHandle: String?
    @Field(key: "dispatch_attempts") var dispatchAttempts: Int
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "delivered_at") var deliveredAt: Date?
    @OptionalField(key: "opened_at") var openedAt: Date?
    @OptionalField(key: "ended_at") var endedAt: Date?

    init() {}

    var statusValue: AuthDeliveryStatus { AuthDeliveryStatus(rawValue: status) ?? .failed }
    var methodValue: AuthDeliveryMethod { AuthDeliveryMethod(rawValue: method) ?? .notice }
    var purposeValue: AuthDeliveryPurpose { AuthDeliveryPurpose(rawValue: purpose) ?? .accountNotice }
    var wireId: AuthDeliveryID { AuthDeliveryID(id!) }
}

/// The P-class secret of an open delivery: `AES-256-GCM` under `AUTH_SECRET_KEY` with the row-bound additional data
/// `auth_delivery_secrets.ciphertext#<delivery id>`. Deleted when the delivery is opened, denied, cancelled, expired or ended.
final class AuthDeliverySecretRecord: Model, @unchecked Sendable {
    static let schema = "auth_delivery_secrets"
    @ID(custom: "delivery_id", generatedBy: .user) var id: UUID?
    @Field(key: "ciphertext") var ciphertext: String
    @Field(key: "key_id") var keyId: String
    @Field(key: "expires_at") var expiresAt: Date

    init() {}

    static let sealContext = "auth_delivery_secrets.ciphertext"
}

/// One row per transition: state and time only.
final class AuthDeliveryEventRecord: Model, @unchecked Sendable {
    static let schema = "auth_delivery_events"
    @ID(key: .id) var id: UUID?
    @Field(key: "delivery_id") var deliveryId: UUID
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "status") var status: String
    @OptionalField(key: "reason") var reason: String?
    @Field(key: "actor") var actor: String
    @Field(key: "at") var at: Date

    init() {}
}

/// A host a tenant may use for business-mode magic links (ADR-0021 section 2): an exact A-label host on the tenant's verified domain with the
/// `auth_links` purpose. Added only after a fresh dashboard step-up (console, a later stage) or the authority admin path; a young tenant's host
/// is held for 24 hours (`activated_at` in the future).
final class AuthDestinationHostRecord: Model, @unchecked Sendable {
    static let schema = "auth_destination_hosts"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "host") var host: String
    @Field(key: "created_by") var createdBy: String
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "activated_at") var activatedAt: Date
    @OptionalField(key: "revoked_at") var revokedAt: Date?

    init() {}
}

/// `AuthDelivery.v1` (additive, forward-only): the delivery tables, the allowed hosts, and the signature version of webhook subscriptions.
struct CreateAuthDeliverySchema: AsyncMigration {
    var name: String { "AuthDelivery.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema(AuthDeliveryRecord.schema)
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("request_id", .string, .required)
            .field("request_hash", .string, .required)
            .field("relationship_id", .uuid, .required)
            .field("consumer_id", .uuid, .required)
            .field("api_key_id", .uuid, .required)
            .field("livemode", .bool, .required)
            .field("method", .string, .required)
            .field("purpose", .string, .required)
            .field("template", .string, .required)
            .field("status", .string, .required)
            .field("version", .int, .required)
            .field("reason", .string)
            .field("channels", .string, .required)
            .field("variables_sha256", .string)
            .field("destination_host", .string)
            .field("destination_statement", .string)
            .field("code_kind", .string)
            .field("silent", .bool, .required, .sql(.default(false)))
            .field("callback_webhook_id", .uuid)
            .field("correlation_id", .string)
            .field("client_transaction_ref", .string)
            .field("session_handle", .string)
            .field("dispatch_attempts", .int, .required, .sql(.default(0)))
            .field("created_at", .datetime, .required)
            .field("expires_at", .datetime, .required)
            .field("delivered_at", .datetime)
            .field("opened_at", .datetime)
            .field("ended_at", .datetime)
            .unique(on: "business_id", "request_id")
            .create()
        try await db.schema(AuthDeliverySecretRecord.schema)
            .field("delivery_id", .uuid, .identifier(auto: false), .references(AuthDeliveryRecord.schema, "id", onDelete: .cascade))
            .field("ciphertext", .string, .required)
            .field("key_id", .string, .required)
            .field("expires_at", .datetime, .required)
            .create()
        try await db.schema(AuthDeliveryEventRecord.schema)
            .id()
            .field("delivery_id", .uuid, .required, .references(AuthDeliveryRecord.schema, "id", onDelete: .cascade))
            .field("business_id", .uuid, .required)
            .field("status", .string, .required)
            .field("reason", .string)
            .field("actor", .string, .required)
            .field("at", .datetime, .required)
            .create()
        try await db.schema(AuthDestinationHostRecord.schema)
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("host", .string, .required)
            .field("created_by", .string, .required)
            .field("created_at", .datetime, .required)
            .field("activated_at", .datetime, .required)
            .field("revoked_at", .datetime)
            .unique(on: "business_id", "host")
            .create()
        // Webhook signature version (ADR-0025): existing subscriptions stay `v1`; the dual-signing window of a migration ends at `v2_dual_until`.
        try await db.schema("webhook_subscriptions").field("signature_version", .string, .required, .sql(.default("v1"))).update()
        try await db.schema("webhook_subscriptions").field("v2_dual_until", .datetime).update()

        guard let sql = db as? any SQLDatabase else { return }
        for (name, table, columns) in [
            ("idx_auth_deliveries_business", AuthDeliveryRecord.schema, "business_id, status"),
            ("idx_auth_deliveries_consumer", AuthDeliveryRecord.schema, "consumer_id, status, expires_at"),
            ("idx_auth_deliveries_due", AuthDeliveryRecord.schema, "status, expires_at"),
            ("idx_auth_deliveries_ended", AuthDeliveryRecord.schema, "ended_at"),
            ("idx_auth_delivery_secrets_expiry", AuthDeliverySecretRecord.schema, "expires_at"),
            ("idx_auth_delivery_events_delivery", AuthDeliveryEventRecord.schema, "delivery_id, at"),
        ] {
            // Compile-time constant identifiers only.
            try await sql.raw(SQLQueryString("CREATE INDEX IF NOT EXISTS \(unsafeRaw: name) ON \(unsafeRaw: table) (\(unsafeRaw: columns))")).run()
        }
    }

    func revert(on db: any Database) async throws {
        guard let sql = db as? any SQLDatabase else { return }
        for table in [AuthDestinationHostRecord.schema, AuthDeliveryEventRecord.schema, AuthDeliverySecretRecord.schema, AuthDeliveryRecord.schema] {
            try await sql.raw(SQLQueryString("DROP TABLE IF EXISTS \(unsafeRaw: table)")).run()
        }
        try await db.schema("webhook_subscriptions").deleteField("signature_version").update()
        try await db.schema("webhook_subscriptions").deleteField("v2_dual_until").update()
    }
}
