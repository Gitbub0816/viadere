import Fluent
import FluentSQL
import Foundation
import SQLKit
import ViadereCore

/// WP2 (capability catalog and policy engine): entitlements, operator switches, law/policy rules, per-request disclosure receipts,
/// capability scopes on API keys and the pairwise `subject_ref` of every relationship.
///
/// **Data migration (read before deploying):**
/// - Every existing API key keeps working for what it did: a key with any interaction, message or status scope becomes a
///   **messaging** key (`message.send`, `contact.reachable`, `consent.request`).
/// - It additionally carries `auth.challenge` and/or `transaction.approve` **only if its business has already issued interactions of
///   kind `authenticate` / `authorize`** (so no live integration stops), and that business is **grandfathered**: tier A plus those
///   capabilities are recorded as entitlements granted by `system:wp2-migration` with the reason, for an operator to review.
/// - Keys with only webhook or reward scopes get no capability (they never could send).
/// - `relationships.subject_ref` is left empty; the background job fills it (the key lives in the environment, not here).
struct CreatePolicyWP2Schema: AsyncMigration {
    var name: String { "CreatePolicyWP2Schema.v1" }

    static let migrationActor = "system:wp2-migration"

    func prepare(on db: any Database) async throws {
        try await db.schema("business_entitlements")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("kind", .string, .required)
            .field("value", .string, .required)
            .field("granted_by", .string, .required)
            .field("justification", .string, .required)
            .field("review_reference", .string)
            .field("granted_at", .datetime, .required)
            .field("expires_at", .datetime)
            .field("revoked_at", .datetime)
            .field("revoked_by", .string)
            .field("revoke_justification", .string)
            .create()

        try await db.schema("capability_switches")
            .id()
            .field("capability", .string, .required)
            .field("scope", .string, .required)
            .field("disabled", .bool, .required)
            .field("reason", .string, .required)
            .field("updated_by", .string, .required)
            .field("updated_at", .datetime, .required)
            .unique(on: "capability", "scope")
            .create()

        try await db.schema("policy_rules")
            .id()
            .field("capability", .string, .required)
            .field("kind", .string, .required)
            .field("jurisdictions", .string, .required)
            .field("reason", .string, .required)
            .field("active", .bool, .required)
            .field("created_by", .string, .required)
            .field("created_at", .datetime, .required)
            .field("deactivated_by", .string)
            .field("deactivated_at", .datetime)
            .create()

        try await db.schema("disclosure_receipts")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("consumer_id", .uuid, .required)
            .field("subject_ref", .string, .required)
            .field("recipient_name", .string, .required)
            .field("capability", .string, .required)
            .field("purpose", .string, .required)
            .field("fields", .string, .required)
            .field("request_id", .string, .required)
            .field("granted_at", .datetime, .required)
            .field("expires_at", .datetime, .required)
            .field("revoked_at", .datetime)
            .field("consumed_at", .datetime)
            .unique(on: "business_id", "capability", "request_id")
            .create()

        try await db.schema("business_api_keys").field("capabilities", .string, .required, .sql(.default(""))).update()
        try await db.schema("relationships").field("subject_ref", .string).update()

        if let sql = db as? any SQLDatabase {
            let indexes: [(String, String, String)] = [
                ("idx_entitlements_business", "business_entitlements", "business_id, kind"),
                ("idx_receipts_consumer", "disclosure_receipts", "consumer_id, expires_at"),
            ]
            for (name, table, columns) in indexes {
                // Identifiers are compile-time constants above; no user input reaches this statement.
                try await sql.raw(SQLQueryString("CREATE INDEX IF NOT EXISTS \(unsafeRaw: name) ON \(unsafeRaw: table) (\(unsafeRaw: columns))")).run()
            }
            // One subject_ref per business: a collision would let one customer be addressed as another (NULLs are distinct).
            try await sql.raw("CREATE UNIQUE INDEX IF NOT EXISTS idx_relationships_subject_ref ON relationships (business_id, subject_ref)").run()
        }

        try await Self.grandfatherExistingKeys(on: db, now: Date())
    }

    func revert(on db: any Database) async throws {
        guard let sql = db as? any SQLDatabase else { return }
        try await sql.raw("DROP INDEX IF EXISTS idx_relationships_subject_ref").run()
        try await db.schema("relationships").deleteField("subject_ref").update()
        try await db.schema("business_api_keys").deleteField("capabilities").update()
        for table in ["disclosure_receipts", "policy_rules", "capability_switches", "business_entitlements"] {
            try await sql.raw(SQLQueryString("DROP TABLE IF EXISTS \(unsafeRaw: table)")).run()
        }
    }

    private struct IssuedKind: Decodable {
        var business_id: UUID
        var kind: String
    }

    /// Gives pre-existing keys their capabilities and records the entitlements of businesses that already issued approval-class
    /// interactions. Idempotent: only keys with no capabilities recorded are touched, and an existing active entitlement is not
    /// duplicated. Public to the test target so the migration notes above can be proven.
    static func grandfatherExistingKeys(on db: any Database, now: Date) async throws {
        guard let sql = db as? any SQLDatabase else { return }
        let rows = try await sql.raw("SELECT DISTINCT business_id, kind FROM interactions WHERE kind IN ('authenticate', 'authorize')")
            .all(decoding: IssuedKind.self)
        var kindsByBusiness: [UUID: Set<String>] = [:]
        for row in rows { kindsByBusiness[row.business_id, default: []].insert(row.kind) }

        let messagingScopes: Set<String> = [BusinessAPIKeys.Scope.interactionsWrite, BusinessAPIKeys.Scope.interactionsRead,
                                            BusinessAPIKeys.Scope.messagesWrite, BusinessAPIKeys.Scope.statusesWrite]
        for key in try await BusinessAPIKeyRecord.query(on: db).filter(\.$capabilities == "").all() {
            let scopes = key.scopeSet
            guard !scopes.isDisjoint(with: messagingScopes) else { continue }
            var capabilities = Set(Capability.messaging)
            let kinds = kindsByBusiness[key.businessId] ?? []
            if scopes.contains(BusinessAPIKeys.Scope.interactionsWrite) || scopes.contains(BusinessAPIKeys.Scope.interactionsRead) {
                if kinds.contains("authenticate") { capabilities.insert(.authChallenge) }
                if kinds.contains("authorize") { capabilities.insert(.transactionApprove) }
            }
            key.capabilities = capabilities.map(\.rawValue).sorted().joined(separator: ",")
            try await key.update(on: db)
        }

        for (businessId, kinds) in kindsByBusiness.sorted(by: { $0.key.uuidString < $1.key.uuidString }) {
            var grants: [(String, String, String)] = [(BusinessEntitlementRecord.tierKind, BusinessRiskTier.a.rawValue,
                                                       "Grandfathered tier A: the business issued approval-class interactions before capability enforcement.")]
            if kinds.contains("authenticate") {
                grants.append((BusinessEntitlementRecord.capabilityKind, Capability.authChallenge.rawValue,
                               "Grandfathered: the business issued authenticate interactions before capability enforcement. Operator review pending."))
            }
            if kinds.contains("authorize") {
                grants.append((BusinessEntitlementRecord.capabilityKind, Capability.transactionApprove.rawValue,
                               "Grandfathered: the business issued authorize interactions before capability enforcement. Operator review pending."))
            }
            for (kind, value, why) in grants {
                let existing = try await BusinessEntitlementRecord.query(on: db).filter(\.$businessId == businessId)
                    .filter(\.$kind == kind).filter(\.$value == value).filter(\.$revokedAt == nil).count()
                guard existing == 0 else { continue }
                try await BusinessEntitlementRecord(businessId: businessId, kind: kind, value: value, grantedBy: migrationActor,
                                                    justification: why, reviewReference: nil, now: now).create(on: db)
            }
        }
    }
}
