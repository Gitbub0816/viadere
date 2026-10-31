import Fluent
import FluentSQL
import Foundation
import SQLKit
import ViadereCore

// MARK: - Definitions, revisions, reviews, publications (WP-3.2)

/// A business's Loop (stable identity across revisions). `business_id` is always the authenticated tenant that created it.
final class LoopDefinitionRecord: Model, @unchecked Sendable {
    static let schema = "loop_definitions"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "key") var key: String
    @Field(key: "created_by") var createdBy: UUID
    @Field(key: "created_at") var createdAt: Date
    init() {}
}

/// One immutable revision. Content columns (`definition_json`, `definition_hash`, `revision`, `definition_id`, `business_id`) can never be
/// updated (database trigger); only the pipeline state moves, by compare-and-swap along `LoopRevisionState.canMove`.
final class LoopRevisionRecord: Model, @unchecked Sendable {
    static let schema = "loop_revisions"
    @ID(key: .id) var id: UUID?
    @Field(key: "definition_id") var definitionId: UUID
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "revision") var revision: Int
    @Field(key: "schema_version") var schemaVersion: Int
    /// Canonical JSON of the submitted definition (business-authored display text; not customer data).
    @Field(key: "definition_json") var definitionJSON: String
    @Field(key: "definition_hash") var definitionHash: String
    @Field(key: "state") var state: String
    @Field(key: "risk_class") var riskClass: String
    @Field(key: "required_review") var requiredReview: String
    @Field(key: "rule_hits_json") var ruleHitsJSON: String
    @Field(key: "rule_set_version") var ruleSetVersion: Int
    @Field(key: "registry_version") var registryVersion: Int
    /// The locked template this revision was built from (fast path: pre-filled checklist, still reviewed).
    @OptionalField(key: "template_key") var templateKey: String?
    @Field(key: "created_by") var createdBy: UUID
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "decided_at") var decidedAt: Date?
    init() {}

    var stateValue: LoopRevisionState { LoopRevisionState(rawValue: state) ?? .rejected }
}

/// A pipeline record: the automated pass/fail and each human decision, bound to the exact hash that was reviewed.
final class LoopReviewRecord: Model, @unchecked Sendable {
    static let schema = "loop_reviews"
    @ID(key: .id) var id: UUID?
    @Field(key: "revision_id") var revisionId: UUID
    @Field(key: "business_id") var businessId: UUID
    /// `automated`, `reviewer_1`, `reviewer_2`.
    @Field(key: "stage") var stage: String
    @OptionalField(key: "reviewer_id") var reviewerId: UUID?
    /// `pass`, `fail`, `approve`, `reject`, `request_changes`.
    @Field(key: "decision") var decision: String
    @Field(key: "definition_hash") var definitionHash: String
    @OptionalField(key: "rule_hits_json") var ruleHitsJSON: String?
    /// The reviewer's reason (field-encrypted; shown to the author for reject and request_changes).
    @OptionalField(key: "notes_sealed") var notesSealed: String?
    @Field(key: "at") var at: Date
    init() {}
}

/// A signed publication of one approved revision. `id` is the manifest's `published_definition_id`.
final class LoopPublicationRecord: Model, @unchecked Sendable {
    static let schema = "loop_publications"
    @ID(key: .id) var id: UUID?
    @Field(key: "revision_id") var revisionId: UUID
    @Field(key: "definition_id") var definitionId: UUID
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "revision") var revision: Int
    @Field(key: "manifest_jws") var manifestJWS: String
    @Field(key: "kid") var kid: String
    @Field(key: "definition_hash") var definitionHash: String
    /// `active`, `suspended`, `revoked`, `retired` (`LoopPublicationStatus`).
    @Field(key: "status") var status: String
    @Field(key: "rollout_percent") var rolloutPercent: Int
    @Field(key: "valid_from") var validFrom: Date
    @Field(key: "not_after") var notAfter: Date
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "status_reason") var statusReason: String?
    @OptionalField(key: "status_changed_at") var statusChangedAt: Date?
    @OptionalField(key: "superseded_by") var supersededBy: UUID?
    init() {}

    var statusValue: LoopPublicationStatus { LoopPublicationStatus(rawValue: status) ?? .revoked }
}

final class LoopRolloutAllowRecord: Model, @unchecked Sendable {
    static let schema = "loop_rollout_allowlist"
    @ID(key: .id) var id: UUID?
    @Field(key: "publication_id") var publicationId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "added_by") var addedBy: UUID
    @Field(key: "added_at") var addedAt: Date
    init() {}
}

/// A customer report (one per account and publication).
final class LoopReportRecord: Model, @unchecked Sendable {
    static let schema = "loop_reports"
    @ID(key: .id) var id: UUID?
    @Field(key: "publication_id") var publicationId: UUID
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "instance_id") var instanceId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "reason") var reason: String
    /// `open`, `reviewed`.
    @Field(key: "state") var state: String
    @Field(key: "at") var at: Date
    init() {}
}

/// Operator kill switch for **every** Loop of one business (the per-Loop switch is the publication's `suspended` status).
final class LoopSwitchRecord: Model, @unchecked Sendable {
    static let schema = "loop_switches"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "reason") var reason: String
    @Field(key: "set_by") var setBy: UUID
    @Field(key: "set_at") var setAt: Date
    @OptionalField(key: "cleared_at") var clearedAt: Date?
    init() {}
}

/// Operator-console permissions beyond sign-in (FX-3: `loop_reviewer`). Granted by the `grant-operator-permission` command only.
final class OperatorPermissionRecord: Model, @unchecked Sendable {
    static let schema = "operator_permissions"
    @ID(key: .id) var id: UUID?
    @Field(key: "user_id") var userId: UUID
    @Field(key: "permission") var permission: String
    @Field(key: "granted_at") var grantedAt: Date
    @OptionalField(key: "revoked_at") var revokedAt: Date?
    init() {}
}

// MARK: - Runtime (WP-3.3) and consent (WP-3.5)

final class LoopInstanceRecord: Model, @unchecked Sendable {
    static let schema = "loop_instances"
    @ID(key: .id) var id: UUID?
    @Field(key: "publication_id") var publicationId: UUID
    @Field(key: "revision_id") var revisionId: UUID
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "relationship_id") var relationshipId: UUID
    @Field(key: "entry_point") var entryPoint: String
    @Field(key: "state") var state: String
    @Field(key: "current_step_id") var currentStepId: String
    @Field(key: "expires_at") var expiresAt: Date
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "updated_at") var updatedAt: Date
    init() {}

    var stateValue: LoopInstanceState { LoopInstanceState(rawValue: state) ?? .cancelled }
}

/// An immutable action event (append-only: a database trigger refuses every UPDATE). Inputs are field-encrypted.
final class LoopActionEventRecord: Model, @unchecked Sendable {
    static let schema = "loop_action_events"
    @ID(key: .id) var id: UUID?
    @Field(key: "instance_id") var instanceId: UUID
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "device_id") var deviceId: UUID
    @Field(key: "step_id") var stepId: String
    @Field(key: "action_id") var actionId: String
    @Field(key: "action_type") var actionType: String
    @Field(key: "action_schema_version") var actionSchemaVersion: Int
    @Field(key: "delivers") var delivers: Bool
    @Field(key: "inputs_sealed") var inputsSealed: String
    @Field(key: "request_digest") var requestDigest: String
    @Field(key: "idempotency_key") var idempotencyKey: String
    @Field(key: "correlation_id") var correlationId: String
    @OptionalField(key: "response_due_at") var responseDueAt: Date?
    @Field(key: "created_at") var createdAt: Date
    init() {}
}

/// Outcomes are appended, never updated (`LoopOutcomeMachine`); `seq` makes concurrent appends to one event collide on a unique key.
final class LoopActionOutcomeRecord: Model, @unchecked Sendable {
    static let schema = "loop_action_outcomes"
    @ID(key: .id) var id: UUID?
    @Field(key: "event_id") var eventId: UUID
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "seq") var seq: Int
    @Field(key: "outcome") var outcome: String
    @Field(key: "source") var source: String
    @OptionalField(key: "actor_id") var actorId: UUID?
    @OptionalField(key: "reason") var reason: String?
    @Field(key: "at") var at: Date
    init() {}

    var outcomeValue: LoopActionOutcome { LoopActionOutcome(rawValue: outcome) ?? .unknown }
}

/// The customer's Loop consents: `business_id` nil is the global enablement. Revocation sets `revoked_at`; rows are kept as history.
final class LoopConsentRecord: Model, @unchecked Sendable {
    static let schema = "loop_consents"
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @OptionalField(key: "business_id") var businessId: UUID?
    @Field(key: "text_version") var textVersion: Int
    @Field(key: "text_digest") var textDigest: String
    @OptionalField(key: "comprehension_passed_at") var comprehensionPassedAt: Date?
    @Field(key: "granted_at") var grantedAt: Date
    @OptionalField(key: "revoked_at") var revokedAt: Date?
    init() {}
}

// MARK: - Hosted inbox (WP-3.4)

final class InboxQueueRecord: Model, @unchecked Sendable {
    static let schema = "inbox_queues"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "key") var key: String
    @Field(key: "name") var name: String
    /// `OperatingHours` JSON (weekday → open/close minutes) or nil for always open.
    @OptionalField(key: "hours_json") var hoursJSON: String?
    @Field(key: "timezone") var timezone: String
    @Field(key: "created_at") var createdAt: Date
    init() {}
}

final class InboxItemRecord: Model, @unchecked Sendable {
    static let schema = "inbox_items"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "instance_id") var instanceId: UUID
    /// Unique: a delivery processed twice yields one item.
    @Field(key: "event_id") var eventId: UUID
    @Field(key: "queue_key") var queueKey: String
    @OptionalField(key: "assignee_id") var assigneeId: UUID?
    /// `new`, `open`, `waiting` (asked the customer for more information), `closed`.
    @Field(key: "state") var state: String
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "updated_at") var updatedAt: Date
    @OptionalField(key: "closed_at") var closedAt: Date?
    init() {}
}

final class InboxReadRecord: Model, @unchecked Sendable {
    static let schema = "inbox_reads"
    @ID(key: .id) var id: UUID?
    @Field(key: "item_id") var itemId: UUID
    @Field(key: "staff_id") var staffId: UUID
    @Field(key: "read_at") var readAt: Date
    init() {}
}

final class InboxNoteRecord: Model, @unchecked Sendable {
    static let schema = "inbox_notes"
    @ID(key: .id) var id: UUID?
    @Field(key: "item_id") var itemId: UUID
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "author_id") var authorId: UUID
    /// `note` (internal), `info_request` (sent to the customer as the outcome reason), `assignment`.
    @Field(key: "kind") var kind: String
    @Field(key: "body_sealed") var bodySealed: String
    @Field(key: "created_at") var createdAt: Date
    init() {}
}

// MARK: - Migrations

/// `Loops.v1` (additive, forward-only): definitions, revisions, reviews, publications, rollout allow-list, reports, switches, operator
/// permissions, instances, action events and outcomes, consents. Content immutability and event append-only are database triggers on both
/// PostgreSQL and SQLite, so no code path (and no runtime-role SQL) can edit a reviewed revision or rewrite an event.
struct CreateLoopsSchema: AsyncMigration {
    var name: String { "Loops.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema(LoopDefinitionRecord.schema).id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("key", .string, .required)
            .field("created_by", .uuid, .required)
            .field("created_at", .datetime, .required)
            .unique(on: "business_id", "key").create()
        try await db.schema(LoopRevisionRecord.schema).id()
            .field("definition_id", .uuid, .required, .references(LoopDefinitionRecord.schema, "id"))
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("revision", .int, .required)
            .field("schema_version", .int, .required)
            .field("definition_json", .string, .required)
            .field("definition_hash", .string, .required)
            .field("state", .string, .required)
            .field("risk_class", .string, .required)
            .field("required_review", .string, .required)
            .field("rule_hits_json", .string, .required)
            .field("rule_set_version", .int, .required)
            .field("registry_version", .int, .required)
            .field("template_key", .string)
            .field("created_by", .uuid, .required)
            .field("created_at", .datetime, .required)
            .field("decided_at", .datetime)
            .unique(on: "definition_id", "revision").create()
        try await db.schema(LoopReviewRecord.schema).id()
            .field("revision_id", .uuid, .required, .references(LoopRevisionRecord.schema, "id"))
            .field("business_id", .uuid, .required)
            .field("stage", .string, .required)
            .field("reviewer_id", .uuid)
            .field("decision", .string, .required)
            .field("definition_hash", .string, .required)
            .field("rule_hits_json", .string)
            .field("notes_sealed", .string)
            .field("at", .datetime, .required)
            // One decision per reviewer per revision.
            .unique(on: "revision_id", "stage").create()
        try await db.schema(LoopPublicationRecord.schema).id()
            .field("revision_id", .uuid, .required, .references(LoopRevisionRecord.schema, "id"))
            .field("definition_id", .uuid, .required, .references(LoopDefinitionRecord.schema, "id"))
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("revision", .int, .required)
            .field("manifest_jws", .string, .required)
            .field("kid", .string, .required)
            .field("definition_hash", .string, .required)
            .field("status", .string, .required)
            .field("rollout_percent", .int, .required)
            .field("valid_from", .datetime, .required)
            .field("not_after", .datetime, .required)
            .field("created_at", .datetime, .required)
            .field("status_reason", .string)
            .field("status_changed_at", .datetime)
            .field("superseded_by", .uuid)
            .unique(on: "revision_id").create()
        try await db.schema(LoopRolloutAllowRecord.schema).id()
            .field("publication_id", .uuid, .required, .references(LoopPublicationRecord.schema, "id"))
            .field("consumer_id", .uuid, .required)
            .field("added_by", .uuid, .required)
            .field("added_at", .datetime, .required)
            .unique(on: "publication_id", "consumer_id").create()
        try await db.schema(LoopSwitchRecord.schema).id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("reason", .string, .required)
            .field("set_by", .uuid, .required)
            .field("set_at", .datetime, .required)
            .field("cleared_at", .datetime).create()
        try await db.schema(OperatorPermissionRecord.schema).id()
            .field("user_id", .uuid, .required, .references("dashboard_users", "id"))
            .field("permission", .string, .required)
            .field("granted_at", .datetime, .required)
            .field("revoked_at", .datetime).create()
        try await db.schema(LoopInstanceRecord.schema).id()
            .field("publication_id", .uuid, .required, .references(LoopPublicationRecord.schema, "id"))
            .field("revision_id", .uuid, .required, .references(LoopRevisionRecord.schema, "id"))
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("relationship_id", .uuid, .required)
            .field("entry_point", .string, .required)
            .field("state", .string, .required)
            .field("current_step_id", .string, .required)
            .field("expires_at", .datetime, .required)
            .field("created_at", .datetime, .required)
            .field("updated_at", .datetime, .required).create()
        try await db.schema(LoopReportRecord.schema).id()
            .field("publication_id", .uuid, .required, .references(LoopPublicationRecord.schema, "id"))
            .field("business_id", .uuid, .required)
            .field("instance_id", .uuid, .required)
            .field("consumer_id", .uuid, .required)
            .field("reason", .string, .required)
            .field("state", .string, .required)
            .field("at", .datetime, .required)
            .unique(on: "publication_id", "consumer_id").create()
        try await db.schema(LoopActionEventRecord.schema).id()
            .field("instance_id", .uuid, .required, .references(LoopInstanceRecord.schema, "id"))
            .field("business_id", .uuid, .required)
            .field("consumer_id", .uuid, .required)
            .field("device_id", .uuid, .required)
            .field("step_id", .string, .required)
            .field("action_id", .string, .required)
            .field("action_type", .string, .required)
            .field("action_schema_version", .int, .required)
            .field("delivers", .bool, .required)
            .field("inputs_sealed", .string, .required)
            .field("request_digest", .string, .required)
            .field("idempotency_key", .string, .required)
            .field("correlation_id", .string, .required)
            .field("response_due_at", .datetime)
            .field("created_at", .datetime, .required)
            .unique(on: "instance_id", "idempotency_key").create()
        try await db.schema(LoopActionOutcomeRecord.schema).id()
            .field("event_id", .uuid, .required, .references(LoopActionEventRecord.schema, "id"))
            .field("business_id", .uuid, .required)
            .field("seq", .int, .required)
            .field("outcome", .string, .required)
            .field("source", .string, .required)
            .field("actor_id", .uuid)
            .field("reason", .string)
            .field("at", .datetime, .required)
            .unique(on: "event_id", "seq").create()
        try await db.schema(LoopConsentRecord.schema).id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("business_id", .uuid)
            .field("text_version", .int, .required)
            .field("text_digest", .string, .required)
            .field("comprehension_passed_at", .datetime)
            .field("granted_at", .datetime, .required)
            .field("revoked_at", .datetime).create()

        guard let sql = db as? any SQLDatabase else { return }
        for (name, table, columns) in [("idx_loop_revisions_state", LoopRevisionRecord.schema, "state, created_at"),
                                       ("idx_loop_publications_definition", LoopPublicationRecord.schema, "definition_id, status"),
                                       ("idx_loop_instances_consumer", LoopInstanceRecord.schema, "consumer_id, created_at"),
                                       ("idx_loop_instances_business", LoopInstanceRecord.schema, "business_id, state"),
                                       ("idx_loop_events_instance", LoopActionEventRecord.schema, "instance_id, created_at"),
                                       ("idx_loop_outcomes_event", LoopActionOutcomeRecord.schema, "event_id, seq"),
                                       ("idx_loop_consents_consumer", LoopConsentRecord.schema, "consumer_id, business_id")] {
            // Compile-time constant identifiers only.
            try await sql.raw(SQLQueryString("CREATE INDEX IF NOT EXISTS \(unsafeRaw: name) ON \(unsafeRaw: table) (\(unsafeRaw: columns))")).run()
        }
        try await LoopImmutability.install(on: sql, postgres: DB.isPostgres(db))
    }

    func revert(on db: any Database) async throws {
        if let sql = db as? any SQLDatabase { try await LoopImmutability.uninstall(on: sql, postgres: DB.isPostgres(db)) }
        for table in [LoopConsentRecord.schema, LoopActionOutcomeRecord.schema, LoopActionEventRecord.schema, LoopReportRecord.schema,
                      LoopInstanceRecord.schema, OperatorPermissionRecord.schema, LoopSwitchRecord.schema, LoopRolloutAllowRecord.schema,
                      LoopPublicationRecord.schema, LoopReviewRecord.schema, LoopRevisionRecord.schema, LoopDefinitionRecord.schema] {
            try await db.schema(table).delete()
        }
    }
}

/// Database-level guards (defense in depth beside the services' compare-and-swap):
/// * `loop_revisions`: content columns are never updated (an edit is a new revision, FX-3).
/// * `loop_action_events`, `loop_action_outcomes`, `loop_reviews`: append-only (no UPDATE at all).
enum LoopImmutability {
    static let contentColumns = "definition_json, definition_hash, revision, definition_id, business_id, schema_version"
    static let appendOnly = [LoopActionEventRecord.schema, LoopActionOutcomeRecord.schema, LoopReviewRecord.schema]

    static func install(on sql: any SQLDatabase, postgres: Bool) async throws {
        // Statements are compile-time constants.
        if postgres {
            try await sql.raw("""
            CREATE OR REPLACE FUNCTION viadere_loop_immutable() RETURNS trigger AS $$
            BEGIN RAISE EXCEPTION 'viadere: % is immutable', TG_TABLE_NAME; END; $$ LANGUAGE plpgsql
            """).run()
            try await sql.raw(SQLQueryString("CREATE TRIGGER loop_revisions_content_immutable BEFORE UPDATE OF \(unsafeRaw: contentColumns) ON loop_revisions FOR EACH ROW EXECUTE FUNCTION viadere_loop_immutable()")).run()
            for table in appendOnly {
                try await sql.raw(SQLQueryString("CREATE TRIGGER \(unsafeRaw: table)_append_only BEFORE UPDATE ON \(unsafeRaw: table) FOR EACH ROW EXECUTE FUNCTION viadere_loop_immutable()")).run()
            }
        } else {
            try await sql.raw(SQLQueryString("CREATE TRIGGER loop_revisions_content_immutable BEFORE UPDATE OF \(unsafeRaw: contentColumns) ON loop_revisions BEGIN SELECT RAISE(ABORT, 'loop_revisions content is immutable'); END")).run()
            for table in appendOnly {
                try await sql.raw(SQLQueryString("CREATE TRIGGER \(unsafeRaw: table)_append_only BEFORE UPDATE ON \(unsafeRaw: table) BEGIN SELECT RAISE(ABORT, '\(unsafeRaw: table) is append-only'); END")).run()
            }
        }
    }

    static func uninstall(on sql: any SQLDatabase, postgres: Bool) async throws {
        for table in appendOnly {
            let statement: SQLQueryString = postgres ? "DROP TRIGGER IF EXISTS \(unsafeRaw: table)_append_only ON \(unsafeRaw: table)" : "DROP TRIGGER IF EXISTS \(unsafeRaw: table)_append_only"
            try await sql.raw(statement).run()
        }
        let drop: SQLQueryString = postgres ? "DROP TRIGGER IF EXISTS loop_revisions_content_immutable ON loop_revisions" : "DROP TRIGGER IF EXISTS loop_revisions_content_immutable"
        try await sql.raw(drop).run()
        if postgres { try await sql.raw("DROP FUNCTION IF EXISTS viadere_loop_immutable()").run() }
    }
}

/// `Inbox.v1` (additive): hosted business inbox queues, items, read receipts and notes.
struct CreateInboxSchema: AsyncMigration {
    var name: String { "Inbox.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema(InboxQueueRecord.schema).id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("key", .string, .required)
            .field("name", .string, .required)
            .field("hours_json", .string)
            .field("timezone", .string, .required)
            .field("created_at", .datetime, .required)
            .unique(on: "business_id", "key").create()
        try await db.schema(InboxItemRecord.schema).id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("instance_id", .uuid, .required, .references(LoopInstanceRecord.schema, "id"))
            .field("event_id", .uuid, .required, .references(LoopActionEventRecord.schema, "id"))
            .field("queue_key", .string, .required)
            .field("assignee_id", .uuid)
            .field("state", .string, .required)
            .field("created_at", .datetime, .required)
            .field("updated_at", .datetime, .required)
            .field("closed_at", .datetime)
            .unique(on: "event_id").create()
        try await db.schema(InboxReadRecord.schema).id()
            .field("item_id", .uuid, .required, .references(InboxItemRecord.schema, "id"))
            .field("staff_id", .uuid, .required)
            .field("read_at", .datetime, .required)
            .unique(on: "item_id", "staff_id").create()
        try await db.schema(InboxNoteRecord.schema).id()
            .field("item_id", .uuid, .required, .references(InboxItemRecord.schema, "id"))
            .field("business_id", .uuid, .required)
            .field("author_id", .uuid, .required)
            .field("kind", .string, .required)
            .field("body_sealed", .string, .required)
            .field("created_at", .datetime, .required).create()
        guard let sql = db as? any SQLDatabase else { return }
        try await sql.raw("CREATE INDEX IF NOT EXISTS idx_inbox_items_business ON inbox_items (business_id, state, created_at)").run()
    }

    func revert(on db: any Database) async throws {
        for table in [InboxNoteRecord.schema, InboxReadRecord.schema, InboxItemRecord.schema, InboxQueueRecord.schema] { try await db.schema(table).delete() }
    }
}
