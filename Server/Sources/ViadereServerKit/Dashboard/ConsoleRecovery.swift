import Fluent
import Foundation
import SQLKit
import Vapor
import ViadereCore

/// Recovery of a business console user who lost every passkey (G25, docs/SECURITY.md §2.111).
///
/// * **Admin path (preferred).** An Owner or Organization Admin of the same organization, with a fresh passkey assertion, who may manage the
///   member's role (`RoleGrantPolicy`), starts it for someone else (never themselves). The link goes to the member's own verified address.
/// * **Operator path (only when nobody else can).** Allowed only while the organization has no other Owner or Organization Admin with a working
///   passkey. One operator requests it with the recorded identity-proof checklist and a reason; a **different** operator confirms the checklist
///   and approves; a **waiting period** follows, during which every other member and the security contacts are told and the request can be
///   cancelled; only then is the link released.
///
/// Either way the release revokes the member's sessions and blocks sign-in (`status = recovering`) so the only thing the member can do is enroll
/// a new passkey from a one-hour, single-use link emailed to them; completing it deletes every old passkey and signs the member in. Every step
/// is audited (`console.recovery_*`).
final class ConsoleRecoveryRecord: Model, @unchecked Sendable {
    static let schema = "console_recoveries"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "user_id") var userId: UUID
    @Field(key: "membership_id") var membershipId: UUID
    /// `admin` or `operator`.
    @Field(key: "path") var path: String
    /// `requested` (operator path, waiting for the second operator), `waiting` (approved, in the waiting period), `released` (link issued),
    /// `completed`, `cancelled` or `expired`.
    @Field(key: "state") var state: String
    @Field(key: "requested_by") var requestedBy: UUID
    @Field(key: "requested_at") var requestedAt: Date
    @Field(key: "reason") var reason: String
    /// The identity-proof checklist items the requester and the approver confirmed (`ConsoleRecovery.checklist` keys, comma-separated).
    @OptionalField(key: "requester_checks") var requesterChecks: String?
    @OptionalField(key: "approver_checks") var approverChecks: String?
    @OptionalField(key: "approved_by") var approvedBy: UUID?
    @OptionalField(key: "approved_at") var approvedAt: Date?
    @OptionalField(key: "release_at") var releaseAt: Date?
    @OptionalField(key: "released_by") var releasedBy: UUID?
    @OptionalField(key: "released_at") var releasedAt: Date?
    @OptionalField(key: "completed_at") var completedAt: Date?
    @OptionalField(key: "cancelled_by") var cancelledBy: String?
    @OptionalField(key: "cancelled_at") var cancelledAt: Date?
    @Field(key: "expires_at") var expiresAt: Date

    init() {}

    static let openStates = ["requested", "waiting", "released"]
    var isOpen: Bool { Self.openStates.contains(state) }
}

/// `ConsoleRecovery.v1` (additive): the recovery table and the link from an enrollment link to the recovery it completes.
struct CreateConsoleRecoverySchema: AsyncMigration {
    var name: String { "ConsoleRecovery.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema(ConsoleRecoveryRecord.schema).id()
            .field("business_id", .uuid, .required, .references("businesses", "id", onDelete: .cascade))
            .field("user_id", .uuid, .required, .references("dashboard_users", "id", onDelete: .cascade))
            .field("membership_id", .uuid, .required)
            .field("path", .string, .required)
            .field("state", .string, .required)
            .field("requested_by", .uuid, .required)
            .field("requested_at", .datetime, .required)
            .field("reason", .string, .required)
            .field("requester_checks", .string)
            .field("approver_checks", .string)
            .field("approved_by", .uuid)
            .field("approved_at", .datetime)
            .field("release_at", .datetime)
            .field("released_by", .uuid)
            .field("released_at", .datetime)
            .field("completed_at", .datetime)
            .field("cancelled_by", .string)
            .field("cancelled_at", .datetime)
            .field("expires_at", .datetime, .required)
            .create()
        try await db.schema(ConsoleEnrollmentRecord.schema).field("recovery_id", .uuid).update()
        guard let sql = db as? any SQLDatabase else { return }
        try await sql.raw("CREATE INDEX IF NOT EXISTS idx_console_recoveries_user ON console_recoveries (user_id, state)").run()
    }

    func revert(on db: any Database) async throws {
        try await db.schema(ConsoleEnrollmentRecord.schema).deleteField("recovery_id").update()
        try await db.schema(ConsoleRecoveryRecord.schema).delete()
    }
}

struct ConsoleRecovery {
    let db: any Database
    let ctx: ServerContext

    /// Owner decision (recorded in §2.111): the operator path waits 72 hours between approval and release.
    static let waitingPeriod: TimeInterval = 72 * 3600
    /// An operator request or an approved recovery that is never released expires after 14 days.
    static let lifetime: TimeInterval = 14 * 24 * 3600
    static let reasonLength = 8...300
    static let userStatus = "recovering"

    /// The identity-proof checklist of the operator path. **Owner/legal decision, not KYC:** what each item requires (which documents, which
    /// channels) is for the owner and counsel to set; the server only makes both operators confirm every item and records who did.
    static let checklist: [(key: String, text: String)] = [
        ("contact_on_file", "Reached the requester through the email address on file for this console account, and the requester answered from it."),
        ("organization_confirmed", "Confirmed the request with the organization through a contact on file that the requester does not control (legal entity contact, registered phone, security contact)."),
        ("authority_checked", "Checked that the requester holds the role being restored and that the organization's legal entity record is current."),
        ("no_other_admin", "Confirmed that the organization has no other Owner or Organization Admin who can re-enroll the requester from the console."),
        ("audit_reviewed", "Reviewed the account's recent audit events and found no sign of takeover (new devices, role changes, key changes)."),
    ]

    static func checks(_ submitted: [String]) -> String? {
        let keys = Set(submitted)
        return checklist.allSatisfy { keys.contains($0.key) } ? checklist.map(\.key).joined(separator: ",") : nil
    }

    // MARK: Lookups

    private func liveMembership(_ membershipId: UUID, businessId: UUID) async throws -> OrgMembershipRecord {
        guard let m = try await OrgMembershipRecord.query(on: db).filter(\.$id == membershipId).filter(\.$businessId == businessId).filter(\.$removedAt == nil).first() else {
            throw APIError.notFound
        }
        return m
    }

    /// The target must be an ordinary business user whose only live membership is this organization: a recovery restores the whole account, so
    /// it must never reach another tenant's console.
    private func target(_ membership: OrgMembershipRecord) async throws -> DashboardUserRecord {
        guard let user = try await DashboardUserRecord.find(membership.userId, on: db), user.kind == "business",
              user.status == "active" || user.status == Self.userStatus else { throw APIError.notFound }
        let elsewhere = try await OrgMembershipRecord.query(on: db).filter(\.$userId == membership.userId).filter(\.$removedAt == nil)
            .filter(\.$businessId != membership.businessId).count()
        guard elsewhere == 0 else {
            throw APIError(.forbidden, .forbidden, "This person is also a member of another organization. Contact Viadere support.")
        }
        return user
    }

    /// Other Owners and Organization Admins of the organization who could re-enroll the member themselves: active, with at least one passkey.
    func otherAdmins(businessId: UUID, excluding userId: UUID) async throws -> Int {
        let members = try await OrgMembershipRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$removedAt == nil)
            .filter(\.$role ~~ [OrgRole.owner.rawValue, OrgRole.orgAdmin.rawValue]).filter(\.$userId != userId).all()
        var count = 0
        for m in members {
            guard let user = try await DashboardUserRecord.find(m.userId, on: db), user.status == "active" else { continue }
            if try await DashboardPasskeyRecord.query(on: db).filter(\.$userId == m.userId).count() > 0 { count += 1 }
        }
        return count
    }

    func open(userId: UUID) async throws -> ConsoleRecoveryRecord? {
        try await ConsoleRecoveryRecord.query(on: db).filter(\.$userId == userId).filter(\.$state ~~ ConsoleRecoveryRecord.openStates).first()
    }

    func openForBusiness(_ businessId: UUID) async throws -> [ConsoleRecoveryRecord] {
        try await ConsoleRecoveryRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$state ~~ ConsoleRecoveryRecord.openStates)
            .sort(\.$requestedAt, .descending).all()
    }

    private func audit(_ action: String, _ record: ConsoleRecoveryRecord, actor: AuditActor, outcome: AuditEvent.Outcome = .success,
                       metadata: [String: String] = [:], on database: (any Database)? = nil) async throws {
        _ = try await AuditService(db: database ?? db, ctx: ctx).record(action, outcome: outcome, actor: actor, businessId: BusinessID(record.businessId),
            subjectType: "console_recovery", subjectId: record.id?.uuidString.lowercased(),
            metadata: metadata.merging(["path": record.path, "user": record.userId.uuidString.lowercased()], uniquingKeysWith: { a, _ in a }))
    }

    static func businessActor(_ id: UUID) -> AuditActor { AuditActor(kind: .business, id: id.uuidString.lowercased()) }
    static func operatorActor(_ id: UUID) -> AuditActor { AuditActor(kind: .operator_, id: id.uuidString.lowercased()) }

    private func swapState(_ id: UUID, from: String, to: String, extra: [(String, any Encodable & Sendable)] = [], on database: (any Database)? = nil) async throws -> Bool {
        try await DB.swap(database ?? db, table: ConsoleRecoveryRecord.schema, id: id, column: "state", expected: from, newValue: to, extra: extra)
    }

    // MARK: Admin path

    /// An Owner or Organization Admin re-enrolls another member. The caller has passed the console step-up (`requireReauth`).
    @discardableResult
    func adminStart(principal: DashboardPrincipal, membershipId: UUID, reason: String) async throws -> ConsoleRecoveryRecord {
        guard principal.realm == .business, principal.can(.manageTeam), let businessId = principal.business?.id, let actorId = principal.user.id,
              let actorRole = principal.role else { throw APIError.forbidden }
        let membership = try await liveMembership(membershipId, businessId: businessId)
        guard membership.userId != actorId else {
            _ = try await AuditService(db: db, ctx: ctx).record("console.recovery_refused", outcome: .denied, actor: Self.businessActor(actorId),
                businessId: BusinessID(businessId), subjectType: "user", subjectId: actorId.uuidString.lowercased(), metadata: ["why": "self"])
            throw APIError(.forbidden, .forbidden, "You cannot recover your own access. Another Owner or Organization Admin, or Viadere support, has to do it.")
        }
        guard let role = OrgRole(rawValue: membership.role), RoleGrantPolicy.mayManage(actor: actorRole, role: role) else {
            throw APIError(.forbidden, .forbidden, "You cannot recover access for a member with that role.")
        }
        let note = reason.trimmingCharacters(in: .whitespacesAndNewlines)
        guard Self.reasonLength.contains(note.count) else { throw APIError.validation("Record why (8 to 300 characters).", details: ["reason": "required"]) }
        let user = try await target(membership)
        if let existing = try await open(userId: user.id!) {
            // A link that expired unused can be sent again by the same path; anything else is already under way.
            guard existing.path == "admin", existing.state == "released" else { throw APIError.conflict("A recovery for this person is already open.") }
            try await issueLink(existing, user: user, by: Self.businessActor(actorId), releasedBy: actorId)
            return existing
        }
        let record = ConsoleRecoveryRecord()
        record.id = UUID()
        record.businessId = businessId
        record.userId = user.id!
        record.membershipId = membershipId
        record.path = "admin"
        record.state = "released"
        record.requestedBy = actorId
        record.requestedAt = ctx.now
        record.reason = note
        record.approvedBy = actorId
        record.approvedAt = ctx.now
        record.expiresAt = ctx.now.addingTimeInterval(Self.lifetime)
        try await record.create(on: db)
        try await audit("console.recovery_started", record, actor: Self.businessActor(actorId), metadata: ["reason": note])
        try await issueLink(record, user: user, by: Self.businessActor(actorId), releasedBy: actorId)
        await Notifier(db: db, ctx: ctx).notifyBusiness(businessId, roles: [.owner, .orgAdmin, .securityAdmin], includeSecurityContacts: true, topic: .roleChanges,
            subject: "A team member's console access is being recovered",
            text: "An administrator of your organization started a passkey recovery for \(user.displayName). Their sessions were signed out and they received a one-time link to set up a new passkey; their old passkeys stop working when they do. If you did not expect this, review the Team page and the audit log.",
            kind: "console-recovery-started")
        return record
    }

    // MARK: Operator path

    @discardableResult
    func operatorRequest(operatorId: UUID, businessId: UUID, membershipId: UUID, reason: String, checks submitted: [String]) async throws -> ConsoleRecoveryRecord {
        guard try await BusinessRecord.find(businessId, on: db) != nil else { throw APIError.notFound }
        let membership = try await liveMembership(membershipId, businessId: businessId)
        let user = try await target(membership)
        let note = reason.trimmingCharacters(in: .whitespacesAndNewlines)
        guard Self.reasonLength.contains(note.count) else { throw APIError.validation("Record why (8 to 300 characters).", details: ["reason": "required"]) }
        guard let checks = Self.checks(submitted) else { throw APIError.validation("Confirm every item of the checklist.", details: ["checks": "incomplete"]) }
        guard try await otherAdmins(businessId: businessId, excluding: user.id!) == 0 else {
            _ = try await AuditService(db: db, ctx: ctx).record("console.recovery_refused", outcome: .denied, actor: Self.operatorActor(operatorId),
                businessId: BusinessID(businessId), subjectType: "user", subjectId: user.id?.uuidString.lowercased(), metadata: ["why": "other_admin"])
            throw APIError(.forbidden, .forbidden, "This organization has another Owner or Organization Admin with a working passkey: they recover the member from the console (Team).")
        }
        guard try await open(userId: user.id!) == nil else { throw APIError.conflict("A recovery for this person is already open.") }
        let record = ConsoleRecoveryRecord()
        record.id = UUID()
        record.businessId = businessId
        record.userId = user.id!
        record.membershipId = membershipId
        record.path = "operator"
        record.state = "requested"
        record.requestedBy = operatorId
        record.requestedAt = ctx.now
        record.reason = note
        record.requesterChecks = checks
        record.expiresAt = ctx.now.addingTimeInterval(Self.lifetime)
        try await record.create(on: db)
        try await audit("console.recovery_requested", record, actor: Self.operatorActor(operatorId), metadata: ["reason": note, "checks": checks])
        return record
    }

    /// The second operator confirms the checklist themselves and approves; the waiting period starts and the organization is told.
    func operatorApprove(id: UUID, operatorId: UUID, checks submitted: [String]) async throws {
        try await expireDue()
        guard let record = try await ConsoleRecoveryRecord.find(id, on: db), record.path == "operator" else { throw APIError.notFound }
        guard record.state == "requested" else { throw APIError.conflict("This recovery is not waiting for approval.") }
        guard record.requestedBy != operatorId else {
            try await audit("console.recovery_approval_refused", record, actor: Self.operatorActor(operatorId), outcome: .denied, metadata: ["why": "same_operator"])
            throw APIError(.forbidden, .forbidden, "A second, different operator has to approve this recovery.")
        }
        guard let checks = Self.checks(submitted) else { throw APIError.validation("Confirm every item of the checklist.", details: ["checks": "incomplete"]) }
        guard try await otherAdmins(businessId: record.businessId, excluding: record.userId) == 0 else {
            throw APIError(.forbidden, .forbidden, "The organization now has another Owner or Organization Admin: they recover the member from the console.")
        }
        let releaseAt = ctx.now.addingTimeInterval(Self.waitingPeriod)
        guard try await swapState(id, from: "requested", to: "waiting", extra: [("approved_by", operatorId), ("approved_at", ctx.now), ("approver_checks", checks),
                                                                               ("release_at", releaseAt)]) else {
            throw APIError.conflict("This recovery was already decided.")
        }
        try await audit("console.recovery_approved", record, actor: Self.operatorActor(operatorId), metadata: ["checks": checks, "release_at": ViadereDate.format(releaseAt)])
        let user = try await DashboardUserRecord.find(record.userId, on: db)
        let name = user?.displayName ?? "a team member"
        let text = """
        Viadere support approved a recovery of the console access of \(name) (who reported losing every passkey). It completes no earlier than \(ViadereDate.format(releaseAt)) (UTC): then \(name) receives a one-time link to set up a new passkey, and their old passkeys stop working.

        If you did not expect this, contact Viadere support before then; the recovery can be cancelled until the link is used.
        """
        await Notifier(db: db, ctx: ctx).notifyBusiness(record.businessId, roles: Set(OrgRole.allCases), includeSecurityContacts: true,
                                                        subject: "Console access recovery for your organization", text: text, kind: "console-recovery-approved")
        if let user, let email = try? ctx.cipher.openString(user.emailCiphertext, context: "dashboard_users.email", rowId: user.id!) {
            try? await ctx.email.send(EmailMessage(to: email, subject: "Your Viadere console access recovery", text: text, kind: "console-recovery-approved"))
        }
    }

    /// Releases the link after the waiting period (any operator); a released recovery whose link expired unused can be released again.
    func operatorRelease(id: UUID, operatorId: UUID) async throws {
        try await expireDue()
        guard let record = try await ConsoleRecoveryRecord.find(id, on: db), record.path == "operator" else { throw APIError.notFound }
        guard record.state == "waiting" || record.state == "released" else { throw APIError.conflict("This recovery is not approved.") }
        if record.state == "waiting" {
            guard let releaseAt = record.releaseAt, ctx.now >= releaseAt else {
                try await audit("console.recovery_release_refused", record, actor: Self.operatorActor(operatorId), outcome: .denied, metadata: ["why": "waiting_period"])
                throw APIError.conflict("The waiting period has not ended. The link can be released after \(record.releaseAt.map { ViadereDate.format($0) } ?? "the waiting period").")
            }
            guard try await otherAdmins(businessId: record.businessId, excluding: record.userId) == 0 else {
                throw APIError(.forbidden, .forbidden, "The organization now has another Owner or Organization Admin: they recover the member from the console.")
            }
            guard try await swapState(id, from: "waiting", to: "released") else { throw APIError.conflict("This recovery changed. Reload.") }
        } else if try await ConsoleEnrollmentRecord.query(on: db).filter(\.$recoveryId == id).filter(\.$state == "open").filter(\.$expiresAt > ctx.now).first() != nil {
            throw APIError.conflict("The current link is still valid.")
        }
        guard let user = try await DashboardUserRecord.find(record.userId, on: db) else { throw APIError.notFound }
        try await issueLink(record, user: user, by: Self.operatorActor(operatorId), releasedBy: operatorId)
    }

    /// Cancels an open recovery: an operator (any state), the member themselves while they still have a session, or an admin who could have
    /// started it. A released one gives the member their old passkeys back (they were never deleted).
    func cancel(id: UUID, actor: AuditActor, by label: String, businessId: UUID? = nil) async throws {
        guard let record = try await ConsoleRecoveryRecord.find(id, on: db), businessId == nil || record.businessId == businessId else { throw APIError.notFound }
        guard record.isOpen, try await swapState(id, from: record.state, to: "cancelled", extra: [("cancelled_by", label), ("cancelled_at", ctx.now)]) else {
            throw APIError.conflict("This recovery is no longer open.")
        }
        try await ConsoleEnrollmentRecord.query(on: db).filter(\.$recoveryId == id).filter(\.$state == "open").set(\.$state, to: "revoked").update()
        if record.state == "released" {
            try await DashboardUserRecord.query(on: db).filter(\.$id == record.userId).filter(\.$status == Self.userStatus).set(\.$status, to: "active").update()
        }
        try await audit("console.recovery_cancelled", record, actor: actor)
    }

    /// The member cancels a recovery of their own account (proof they still have access) or an admin who may manage them does.
    func businessCancel(id: UUID, principal: DashboardPrincipal) async throws {
        guard principal.realm == .business, let businessId = principal.business?.id, let userId = principal.user.id,
              let record = try await ConsoleRecoveryRecord.query(on: db).filter(\.$id == id).filter(\.$businessId == businessId).first() else { throw APIError.notFound }
        var allowed = record.userId == userId
        if !allowed, principal.can(.manageTeam), let actorRole = principal.role,
           let m = try await OrgMembershipRecord.find(record.membershipId, on: db), let role = OrgRole(rawValue: m.role) {
            allowed = RoleGrantPolicy.mayManage(actor: actorRole, role: role)
        }
        guard allowed else { throw APIError.forbidden }
        try await cancel(id: id, actor: Self.businessActor(userId), by: "business:" + userId.uuidString.lowercased(), businessId: businessId)
    }

    func expireDue() async throws {
        let now = ctx.now
        guard try await ConsoleRecoveryRecord.query(on: db).filter(\.$state ~~ ["requested", "waiting"]).filter(\.$expiresAt <= now).count() > 0 else { return }
        try await ConsoleRecoveryRecord.query(on: db).filter(\.$state ~~ ["requested", "waiting"]).filter(\.$expiresAt <= now).set(\.$state, to: "expired").update()
    }

    // MARK: Release and completion

    /// Signs the member out everywhere, blocks sign-in until they enroll, and emails them a one-hour single-use enrollment link (older open
    /// links of the member are revoked). The link never appears in the console or the operator console.
    private func issueLink(_ record: ConsoleRecoveryRecord, user: DashboardUserRecord, by actor: AuditActor, releasedBy: UUID) async throws {
        let token = SecureToken.generate()
        let now = ctx.now
        let userId = user.id!
        try await db.transaction { tx in
            try await DashboardUserRecord.query(on: tx).filter(\.$id == userId).set(\.$status, to: Self.userStatus).update()
            try await DashboardSessionRecord.query(on: tx).filter(\.$userId == userId).filter(\.$revokedAt == nil).set(\.$revokedAt, to: now).update()
            try await ConsoleEnrollmentRecord.query(on: tx).filter(\.$userId == userId).filter(\.$state == "open").set(\.$state, to: "revoked").update()
            let enrollment = ConsoleEnrollmentRecord()
            enrollment.id = UUID()
            enrollment.userId = userId
            enrollment.businessId = record.businessId
            enrollment.tokenHash = SecureToken.hash(token)
            enrollment.state = "open"
            enrollment.createdAt = now
            enrollment.expiresAt = now.addingTimeInterval(ConsoleEnrollmentRecord.lifetime)
            enrollment.recoveryId = record.id
            try await enrollment.create(on: tx)
            try await ConsoleRecoveryRecord.query(on: tx).filter(\.$id == record.id!).set(\.$releasedBy, to: releasedBy).set(\.$releasedAt, to: now).update()
            try await audit("console.recovery_released", record, actor: actor, metadata: ["expires_at": ViadereDate.format(enrollment.expiresAt)], on: tx)
        }
        let link = (ctx.config.dashboardOrigin ?? ctx.config.relyingPartyOrigin) + ConsoleEnrollmentRoutes.pagePrefix + token
        guard let email = try? ctx.cipher.openString(user.emailCiphertext, context: "dashboard_users.email", rowId: userId) else { return }
        do {
            try await ctx.email.send(EmailMessage(to: email, subject: "Set up a new passkey for your Viadere console", text: """
            Your access to your organization's Viadere console is being recovered. Open this link within one hour to set up a new passkey:

            \(link)

            Until you do, you cannot sign in. Your old passkeys stop working once the new one is set up. If you did not ask for this, do not open the link and contact your organization's administrator or Viadere support.
            """, kind: "console-recovery"))
        } catch {
            ctx.logger.warning("recovery email failed", metadata: ["kind": "console-recovery"])
        }
    }

    /// Called inside the enrollment transaction when the link belongs to a recovery: completes it, deletes every earlier passkey of the member,
    /// revokes every session and makes the account active again. Returns false when the recovery is no longer released (cancelled meanwhile).
    static func complete(recoveryId: UUID, userId: UUID, on tx: any Database, ctx: ServerContext) async throws -> Bool {
        guard try await DB.swap(tx, table: ConsoleRecoveryRecord.schema, id: recoveryId, column: "state", expected: "released", newValue: "completed",
                                extra: [("completed_at", ctx.now)]) else { return false }
        let removed = try await DashboardPasskeyRecord.query(on: tx).filter(\.$userId == userId).count()
        try await DashboardPasskeyRecord.query(on: tx).filter(\.$userId == userId).delete()
        try await DashboardSessionRecord.query(on: tx).filter(\.$userId == userId).filter(\.$revokedAt == nil).set(\.$revokedAt, to: ctx.now).update()
        try await DashboardUserRecord.query(on: tx).filter(\.$id == userId).set(\.$status, to: "active").update()
        if let record = try await ConsoleRecoveryRecord.find(recoveryId, on: tx) {
            _ = try await AuditService(db: tx, ctx: ctx).record("console.recovery_completed", actor: businessActor(userId), businessId: BusinessID(record.businessId),
                subjectType: "console_recovery", subjectId: recoveryId.uuidString.lowercased(),
                metadata: ["path": record.path, "passkeys_revoked": String(removed)])
        }
        return true
    }
}

// MARK: - Console routes (Team page actions)

private struct RecoveryStartForm: Content { var reason: String? }

enum ConsoleRecoveryRoutes {
    static func register(_ pages: any RoutesBuilder) {
        pages.post("dashboard", "team", "members", ":id", "recover") { req -> Response in
            let (p, _) = try req.businessDashboard
            guard p.can(.manageTeam) else { throw APIError.forbidden }
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).requireReauth(next: "/dashboard/team")
            let form = try req.content.decode(RecoveryStartForm.self)
            try await ConsoleRecovery(db: req.db, ctx: req.ctx).adminStart(principal: p, membershipId: try req.uuid("id"), reason: form.reason ?? "")
            return DashboardResponses.redirect("/dashboard/team?m=recovery-started")
        }
        pages.post("dashboard", "team", "recoveries", ":id", "cancel") { req -> Response in
            let (p, _) = try req.businessDashboard
            try await ConsoleRecovery(db: req.db, ctx: req.ctx).businessCancel(id: try req.uuid("id"), principal: p)
            return DashboardResponses.redirect("/dashboard/team?m=recovery-cancelled")
        }
    }

    /// The open recoveries of the organization, for the Team page (members only see that one exists; the member concerned and admins who may
    /// manage them can cancel it).
    static func card(_ req: Request, p: DashboardPrincipal, businessId: UUID, names: [UUID: String]) async throws -> String {
        let open = try await ConsoleRecovery(db: req.db, ctx: req.ctx).openForBusiness(businessId)
        guard !open.isEmpty else { return "" }
        let rows = open.map { r -> [String] in
            let stage = switch r.state {
            case "requested": "Viadere is verifying the request"
            case "waiting": "Waiting period until \(DashboardFormat.optional(r.releaseAt))"
            default: "Link sent; waiting for the new passkey"
            }
            let cancel = (r.userId == p.user.id || p.can(.manageTeam))
                ? ConsoleUI.form("/dashboard/team/recoveries/\(r.id!.uuidString.lowercased())/cancel", csrf: DashboardUI.csrf(p),
                                 ConsoleUI.button("Cancel recovery", .danger, small: true, ariaLabel: "Cancel the recovery of \(names[r.userId] ?? "this member")")) : ""
            return [DashboardUI.esc(names[r.userId] ?? "—"), r.path == "operator" ? "Viadere support" : "Administrator", DashboardUI.esc(stage), DashboardFormat.date(r.requestedAt), cancel]
        }
        return ConsoleUI.card("Passkey recoveries", description: "Open recoveries of members who lost every passkey. If you did not expect one, cancel it and contact Viadere support.",
                              tone: .warning, DashboardFormat.table(["Member", "Started by", "Stage", "Started", ""], rows, caption: "Open passkey recoveries"))
    }
}
