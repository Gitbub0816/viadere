import Fluent
import Foundation
import ViadereCore

/// Who may register or replace a business root key (condition 4 of the Phase 2 gate).
///
/// A root registration or succession entry is accepted only when
/// 1. the business has a **verified domain** (WP6 onboarding), and
/// 2. a person with `manageSecurity` authorized exactly this root key id in the dashboard with a **fresh passkey step-up**
///    (`DashboardActions.requireReauth`), within the last 15 minutes, once.
///
/// Without that, a stolen `keydirectory:manage` API key could register its own root for a business that has none (squatting it for good,
/// because a root can then only be replaced by a succession signed with that root) or, on a compromised root, rotate it away.
struct RootAuthorization {
    let db: any Database
    let ctx: ServerContext

    static func kind(of statement: KeyStatement) -> (kind: String, kid: String)? {
        switch statement {
        case .root(let root): (KeyRootAuthorizationRecord.registerKind, root.rootKid)
        case .succession(let succession): (KeyRootAuthorizationRecord.successionKind, succession.newRootKid)
        default: nil
        }
    }

    func hasVerifiedDomain(businessId: UUID) async throws -> Bool {
        try await BusinessDomainRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$status == "verified").filter(\.$verifiedDomain != nil).count() > 0
    }

    /// Called by the dashboard after the passkey step-up. The kind follows the log: `register` while the business has no root, `succession` otherwise
    /// (`kind` is only for tests that probe the mismatch).
    @discardableResult
    func authorize(businessId: UUID, user: UUID, rootKid: String, kind forced: String? = nil) async throws -> KeyRootAuthorizationRecord {
        guard KeyIdentifier.isValid(rootKid) else { throw APIError.validation("Enter the key id of the root key (it starts with bk_).", details: ["root_kid": "invalid"]) }
        guard try await hasVerifiedDomain(businessId: businessId) else {
            throw APIError(.forbidden, .forbidden, "Verify a domain you control (Organization > Onboarding) before registering or changing a root key.",
                           details: ["reason": "verified_domain_required"])
        }
        let state = try await KeyLogService(db: db, ctx: ctx).state(for: businessId)
        let kind = forced ?? (state.currentRoot == nil ? KeyRootAuthorizationRecord.registerKind : KeyRootAuthorizationRecord.successionKind)
        if kind == KeyRootAuthorizationRecord.successionKind, state.currentRoot?.kid == rootKid {
            throw APIError.conflict("That key is already your root key.")
        }
        let now = ctx.now
        let record = KeyRootAuthorizationRecord()
        record.id = UUID()
        record.businessId = businessId
        record.kind = kind
        record.rootKid = rootKid
        record.authorizedBy = user.uuidString.lowercased()
        record.createdAt = now
        record.expiresAt = now.addingTimeInterval(KeyRootAuthorizationRecord.lifetime)
        try await record.create(on: db)
        _ = try await AuditService(db: db, ctx: ctx).record("keydirectory.root_authorized", actor: AuditActor(kind: .business, id: record.authorizedBy), businessId: BusinessID(businessId),
                                                           subjectType: "key_root_authorization", subjectId: record.id?.uuidString.lowercased(), metadata: ["kind": kind, "kid": rootKid])
        return record
    }

    /// A refusal raised inside the publish transaction. The caller audits it **after** the rollback (a write on another connection while the
    /// transaction is open would contend with it) and answers `403`.
    struct Refused: Error {
        var reason: String
        var kind: String
        var kid: String

        var apiError: APIError {
            APIError(.forbidden, .forbidden,
                     "A root key is registered or changed only after a signed-in person authorizes it in your dashboard with a passkey (Approve > Root key). An API key cannot do it alone.",
                     details: ["reason": reason])
        }
    }

    /// Inside the publish transaction: burns the matching authorization, or throws `Refused`. Rolls back with the entry if the entry is then rejected.
    func consume(businessId: UUID, statement: KeyStatement, on tx: any Database) async throws {
        guard let (kind, kid) = Self.kind(of: statement) else { return }
        guard try await RootAuthorization(db: tx, ctx: ctx).hasVerifiedDomain(businessId: businessId) else {
            throw Refused(reason: "verified_domain_required", kind: kind, kid: kid)
        }
        let now = ctx.now
        let candidates = try await KeyRootAuthorizationRecord.query(on: tx).filter(\.$businessId == businessId).filter(\.$kind == kind).filter(\.$rootKid == kid)
            .filter(\.$consumedAt == nil).filter(\.$expiresAt > now).all()
        for candidate in candidates {
            if try await DB.swapFromNull(tx, table: KeyRootAuthorizationRecord.schema, id: candidate.id!, column: "consumed_at", newValue: now) { return }
        }
        throw Refused(reason: "dashboard_step_up_required", kind: kind, kid: kid)
    }
}
