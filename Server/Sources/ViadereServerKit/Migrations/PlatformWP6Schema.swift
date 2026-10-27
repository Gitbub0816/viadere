import Fluent
import FluentSQL
import Foundation
import SQLKit

/// WP6 (business platform and operational gaps): onboarding state, domain control, contract acceptance, API-key lifecycle columns, webhook
/// ownership verification and pause, console security settings, two-person approvals, operator switches (`platform_flags`), operator notices,
/// support tickets, data requests, retention configuration, consumer exports and account freezes.
///
/// **Data migration (read before deploying):**
/// - The five legacy dashboard roles become the nine WP6 roles: `admin` -> `org_admin`, `support` -> `messaging_operator`; `owner`, `developer`
///   and `analyst` keep their names. Memberships and open invitations are rewritten; nothing else changes.
/// - Every existing business gets an onboarding row marked `grandfathered`. A verified business keeps its production keys (go-live is recorded as
///   approved by `system:wp6-migration`), but must accept the current contract versions by `contracts_due_at` (60 days after the migration) or the
///   ongoing-assurance job starts its grace period.
/// - Existing API keys keep working (no key id; they are looked up by their hash exactly as before).
struct CreatePlatformWP6Schema: AsyncMigration {
    var name: String { "CreatePlatformWP6Schema.v1" }

    static let migrationActor = "system:wp6-migration"
    /// Days a grandfathered business has to accept the current contract versions.
    static let legacyContractGraceDays = 60

    private func addColumn(_ db: any Database, _ table: String, _ build: (SchemaBuilder) -> SchemaBuilder) async throws {
        try await build(db.schema(table)).update()
    }

    func prepare(on db: any Database) async throws {
        // MARK: Onboarding
        try await db.schema("business_onboarding")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("workspace_at", .datetime, .required)
            .field("control_verified_at", .datetime)
            .field("control_method", .string)
            .field("control_domain", .string)
            .field("legal_status", .string, .required, .sql(.default("none")))
            .field("legal_registry_number", .string)
            .field("legal_jurisdiction", .string)
            .field("legal_registry_name", .string)
            .field("legal_evidence_refs", .string)
            .field("legal_submitted_at", .datetime)
            .field("legal_reviewed_by", .string)
            .field("legal_reviewed_at", .datetime)
            .field("legal_note", .string)
            .field("enhanced_status", .string, .required, .sql(.default("not_required")))
            .field("enhanced_reference", .string)
            .field("enhanced_reviewed_by", .string)
            .field("enhanced_reviewed_at", .datetime)
            .field("sandbox_key_at", .datetime)
            .field("sandbox_relationship_at", .datetime)
            .field("test_event_at", .datetime)
            .field("golive_status", .string, .required, .sql(.default("none")))
            .field("golive_requested_at", .datetime)
            .field("golive_requested_by", .string)
            .field("golive_use_case", .string)
            .field("golive_volume", .string)
            .field("golive_decided_at", .datetime)
            .field("golive_decided_by", .string)
            .field("golive_note", .string)
            .field("grandfathered", .bool, .required, .sql(.default(false)))
            .field("contracts_due_at", .datetime)
            .field("assurance_checked_at", .datetime)
            .field("assurance_grace_started_at", .datetime)
            .field("assurance_failure", .string)
            .field("assurance_suspended", .bool, .required, .sql(.default(false)))
            .field("created_at", .datetime, .required)
            .field("updated_at", .datetime, .required)
            .unique(on: "business_id")
            .create()

        try await db.schema("business_domains")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("domain", .string, .required)
            .field("token", .string, .required)
            .field("status", .string, .required)
            .field("method", .string)
            // Set only while the domain is verified: the unique constraint makes one verified owner per domain (NULLs are distinct).
            .field("verified_domain", .string)
            .field("created_by", .string, .required)
            .field("created_at", .datetime, .required)
            .field("verified_at", .datetime)
            .field("last_checked_at", .datetime)
            .field("next_check_at", .datetime)
            .field("failures", .int, .required, .sql(.default(0)))
            .field("last_error", .string)
            .unique(on: "business_id", "domain")
            .unique(on: "verified_domain")
            .create()

        try await db.schema("contract_acceptances")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("slug", .string, .required)
            .field("version", .string, .required)
            .field("accepted_by", .uuid, .required)
            .field("accepted_at", .datetime, .required)
            .field("ip_hash", .string, .required)
            .field("ua_hash", .string, .required)
            .unique(on: "business_id", "slug", "version")
            .create()

        // MARK: Console security
        try await db.schema("business_security_settings")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("console_ip_allowlist", .string, .required, .sql(.default("")))
            .field("privileged_inactivity_seconds", .int, .required, .sql(.default(300)))
            .field("two_person_required", .bool, .required, .sql(.default(false)))
            .field("mtls_required", .bool, .required, .sql(.default(false)))
            .field("alert_subscriptions", .string, .required, .sql(.default("")))
            .field("contacts_ciphertext", .string)
            .field("updated_at", .datetime, .required)
            .field("updated_by", .uuid)
            .unique(on: "business_id")
            .create()

        try await db.schema("business_mtls_certs")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("kind", .string, .required)
            .field("fingerprint", .string, .required)
            .field("label", .string, .required)
            .field("subject", .string)
            .field("not_after", .datetime)
            .field("created_by", .uuid, .required)
            .field("created_at", .datetime, .required)
            .field("revoked_at", .datetime)
            .field("revoked_by", .uuid)
            .unique(on: "kind", "fingerprint")
            .create()

        try await db.schema("dashboard_known_contexts")
            .id()
            .field("user_id", .uuid, .required)
            .field("dimension", .string, .required)
            .field("value_hash", .string, .required)
            .field("first_seen_at", .datetime, .required)
            .field("last_seen_at", .datetime, .required)
            .unique(on: "user_id", "dimension", "value_hash")
            .create()

        try await db.schema("pending_changes")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("kind", .string, .required)
            .field("payload_json", .string, .required)
            .field("requested_by", .uuid, .required)
            .field("requested_at", .datetime, .required)
            .field("expires_at", .datetime, .required)
            .field("status", .string, .required)
            .field("decided_by", .uuid)
            .field("decided_at", .datetime)
            .field("decision_note", .string)
            .field("executed_at", .datetime)
            .create()

        // MARK: Support, notices, data requests
        try await db.schema("support_tickets")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("kind", .string, .required)
            .field("subject", .string, .required)
            .field("body_ciphertext", .string, .required)
            .field("status", .string, .required)
            .field("created_by", .uuid, .required)
            .field("created_at", .datetime, .required)
            .field("updated_at", .datetime, .required)
            .field("operator_note", .string)
            .field("decided_by", .string)
            .create()

        try await db.schema("operator_notices")
            .id()
            .field("audience", .string, .required)
            .field("scope", .string, .required)
            .field("business_id", .uuid)
            .field("severity", .string, .required)
            .field("title", .string, .required)
            .field("body", .string, .required)
            .field("created_by", .string, .required)
            .field("created_at", .datetime, .required)
            .field("status", .string, .required)
            .field("cursor", .string)
            .field("delivered", .int, .required, .sql(.default(0)))
            .create()

        try await db.schema("data_requests")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("kind", .string, .required)
            .field("status", .string, .required)
            .field("requested_by", .uuid, .required)
            .field("created_at", .datetime, .required)
            .field("decided_by", .string)
            .field("decided_at", .datetime)
            .field("note", .string)
            .field("artifact", .string)
            .field("artifact_expires_at", .datetime)
            .field("downloaded_at", .datetime)
            .field("completed_at", .datetime)
            .create()

        // MARK: Operator switches (G-1, G-5, G-6, G-12, G-15) and retention
        try await db.schema("platform_flags")
            .id()
            .field("flag", .string, .required)
            .field("scope", .string, .required)
            .field("value", .string, .required)
            .field("reason", .string, .required)
            .field("updated_by", .string, .required)
            .field("updated_at", .datetime, .required)
            .unique(on: "flag", "scope")
            .create()

        try await db.schema("retention_settings")
            .id()
            .field("scope", .string, .required)
            .field("data_class", .string, .required)
            .field("days", .int, .required)
            .field("updated_by", .string, .required)
            .field("updated_at", .datetime, .required)
            .unique(on: "scope", "data_class")
            .create()

        try await db.schema("legal_holds")
            .id()
            .field("scope_kind", .string, .required)
            .field("scope_id", .string)
            .field("reason", .string, .required)
            .field("created_by", .string, .required)
            .field("created_at", .datetime, .required)
            .field("released_at", .datetime)
            .field("released_by", .string)
            .create()

        // MARK: Consumer rights, freezes
        try await db.schema("consumer_exports")
            .id()
            .field("consumer_id", .uuid, .required)
            .field("device_id", .uuid, .required)
            .field("status", .string, .required)
            .field("recipient_key", .string, .required)
            .field("bundle", .string)
            .field("created_at", .datetime, .required)
            .field("ready_at", .datetime)
            .field("expires_at", .datetime, .required)
            .field("downloads", .int, .required, .sql(.default(0)))
            .create()

        try await db.schema("account_freezes")
            .id()
            .field("consumer_id", .uuid, .required)
            .field("reason", .string, .required)
            .field("frozen_by", .string, .required)
            .field("frozen_at", .datetime, .required)
            .field("released_at", .datetime)
            .field("released_by", .string)
            .create()

        // MARK: Columns on existing tables
        for (column, type) in [("kid", DatabaseSchema.DataType.string), ("ip_allowlist", .string), ("last_used_ip_hash", .string),
                               ("auto_revoke_at", .datetime), ("rotated_to", .uuid), ("rotated_from", .uuid), ("cert_binding", .uuid),
                               ("created_by", .uuid), ("revoked_by", .string), ("revoke_reason", .string)] {
            try await addColumn(db, "business_api_keys") { $0.field(.definition(name: .key(column), dataType: type, constraints: [])) }
        }
        try await addColumn(db, "business_api_keys") { $0.field("requires_mtls", .bool, .required, .sql(.default(false))) }
        for (column, type) in [("verified_at", DatabaseSchema.DataType.datetime), ("verification_challenge_hash", .string),
                               ("verification_expires_at", .datetime), ("last_verify_error", .string), ("paused_at", .datetime),
                               ("paused_by", .string), ("pause_reason", .string)] {
            try await addColumn(db, "webhook_subscriptions") { $0.field(.definition(name: .key(column), dataType: type, constraints: [])) }
        }
        for (column, type) in [("ip_hash", DatabaseSchema.DataType.string), ("ip_masked", .string), ("ua_hash", .string), ("ua_label", .string),
                               ("country", .string)] {
            try await addColumn(db, "dashboard_sessions") { $0.field(.definition(name: .key(column), dataType: type, constraints: [])) }
        }
        try await addColumn(db, "audit_events") { $0.field("key_epoch", .int) }

        if let sql = db as? any SQLDatabase {
            let indexes: [(String, String, String)] = [
                ("idx_api_keys_kid", "business_api_keys", "kid"),
                ("idx_domains_due", "business_domains", "status, next_check_at"),
                ("idx_acceptances_business", "contract_acceptances", "business_id"),
                ("idx_pending_business", "pending_changes", "business_id, status"),
                ("idx_tickets_business", "support_tickets", "business_id, created_at"),
                ("idx_notices_status", "operator_notices", "status, created_at"),
                ("idx_exports_consumer", "consumer_exports", "consumer_id, created_at"),
                ("idx_freezes_consumer", "account_freezes", "consumer_id"),
                ("idx_known_ctx_user", "dashboard_known_contexts", "user_id"),
                ("idx_sessions_user", "dashboard_sessions", "user_id, revoked_at"),
            ]
            for (name, table, columns) in indexes {
                // Identifiers are compile-time constants above; no user input reaches this statement.
                try await sql.raw(SQLQueryString("CREATE INDEX IF NOT EXISTS \(unsafeRaw: name) ON \(unsafeRaw: table) (\(unsafeRaw: columns))")).run()
            }
            // One key id per key (NULLs are distinct: legacy keys have none).
            try await sql.raw("CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_kid_unique ON business_api_keys (kid)").run()
        }

        try await Self.migrateRoles(on: db)
        try await Self.backfillOnboarding(on: db, now: Date())
    }

    func revert(on db: any Database) async throws {
        guard let sql = db as? any SQLDatabase else { return }
        for table in ["account_freezes", "consumer_exports", "legal_holds", "retention_settings", "platform_flags", "data_requests", "operator_notices",
                      "support_tickets", "pending_changes", "dashboard_known_contexts", "business_mtls_certs", "business_security_settings",
                      "contract_acceptances", "business_domains", "business_onboarding"] {
            try await sql.raw(SQLQueryString("DROP TABLE IF EXISTS \(unsafeRaw: table)")).run()
        }
    }

    /// Legacy role names -> WP6 role names (see `OrgRole.legacyNames`). Idempotent.
    static func migrateRoles(on db: any Database) async throws {
        for (old, new) in [("admin", "org_admin"), ("support", "messaging_operator")] {
            try await OrgMembershipRecord.query(on: db).filter(\.$role == old).set(\.$role, to: new).update()
            try await OrgInviteRecord.query(on: db).filter(\.$role == old).set(\.$role, to: new).update()
        }
    }

    /// An onboarding row for every business that has none. Verified businesses keep production access (grandfathered).
    static func backfillOnboarding(on db: any Database, now: Date) async throws {
        let existing = Set(try await BusinessOnboardingRecord.query(on: db).all().map(\.businessId))
        for business in try await BusinessRecord.query(on: db).all() {
            guard let id = business.id, !existing.contains(id) else { continue }
            let row = BusinessOnboardingRecord(businessId: id, now: business.createdAt)
            row.grandfathered = true
            row.updatedAt = now
            if business.status == .verified || business.status == .suspended {
                row.goLiveStatus = "approved"
                row.goLiveDecidedAt = now
                row.goLiveDecidedBy = migrationActor
                row.goLiveNote = "Grandfathered: verified before onboarding stages existed."
                row.contractsDueAt = now.addingTimeInterval(Double(legacyContractGraceDays) * 86_400)
            }
            try await row.create(on: db)
        }
    }
}
