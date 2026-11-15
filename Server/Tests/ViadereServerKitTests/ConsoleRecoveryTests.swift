import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// G25 (docs/SECURITY.md §2.111): recovery of a business console user who lost every passkey. Each test starts from the exploit path.
final class ConsoleRecoveryTests: XCTestCase {
    static let checks = ConsoleRecovery.checklist.map { ("check_\($0.key)", "1") }

    /// The enrollment link from the last recovery email to `address`.
    static func recoveryToken(_ h: TestHarness, _ address: String) throws -> String {
        let message = try XCTUnwrap(h.emails.messages(to: address).last(where: { $0.kind == "console-recovery" }), "no recovery email")
        let range = try XCTUnwrap(message.text.range(of: ConsoleEnrollmentRoutes.pagePrefix))
        return String(message.text[range.upperBound...].prefix { !$0.isWhitespace })
    }

    /// Runs the enrollment ceremony of a console link; returns the new session and the new credential id.
    static func enroll(_ h: TestHarness, token: String) async throws -> (session: DashSession?, credentialId: String, result: HTTPResult) {
        let begin = try await h.jsonPost("/dashboard/auth/enroll/begin", EnrollBeginBody(token: token))
        guard begin.status == .ok else { return (nil, "", begin) }
        let options = try begin.json(PasskeyRegistrationOptions.self)
        let credentialId = SecureToken.generate(byteCount: 16)
        let finish = try await h.jsonPost("/dashboard/auth/enroll/finish", PasskeyRegistrationFinishRequest(ceremonyId: options.ceremonyId,
            credential: h.registrationCredential(for: options, credentialId: credentialId, publicKey: SecureToken.generate(byteCount: 32))))
        return (h.sessionCookie(finish).map { DashSession(token: $0.value, realm: .business) }, credentialId, finish)
    }

    static func membership(_ h: TestHarness, _ userId: UUID) async throws -> UUID {
        try await OrgMembershipRecord.query(on: h.db).filter(\.$userId == userId).first()!.id!
    }

    // MARK: Admin path

    func testAUserCannotRecoverThemselvesAndAnAdminReEnrollsAnotherMember() async throws {
        try await withHarness { h in
            let (owner, ownerAccount, _) = try await h.verifiedOwner()
            let (devSession, devAccount) = try await h.addMember(owner: owner, role: .developer, email: "dev@example.com", name: "Dana Dev")
            // Self-recovery is refused: not even an Owner can re-enroll themselves.
            let ownMembership = try await Self.membership(h, ownerAccount.userId)
            let selfAttempt = try await h.formPost("/dashboard/team/members/\(ownMembership.uuidString.lowercased())/recover", owner, [("reason", "I lost my passkeys yesterday")])
            XCTAssertEqual(selfAttempt.status, .forbidden, selfAttempt.text)
            // A member without manageTeam cannot start one for anybody.
            let byDev = try await h.formPost("/dashboard/team/members/\(ownMembership.uuidString.lowercased())/recover", devSession, [("reason", "Owner lost their passkeys")])
            XCTAssertEqual(byDev.status, .forbidden, byDev.text)
            try await eq(try await ConsoleRecoveryRecord.query(on: h.db).count(), 0)

            // The Owner re-enrolls the developer.
            let devMembership = try await Self.membership(h, devAccount.userId)
            let started = try await h.formPost("/dashboard/team/members/\(devMembership.uuidString.lowercased())/recover", owner, [("reason", "Dana lost her laptop and phone")])
            XCTAssertEqual(started.status, .seeOther, started.text)
            XCTAssertFalse(started.text.contains("/dashboard/enroll/"), "the admin never sees the link")
            // Before enrolling, the member can do nothing: the old session is gone and the old passkey does not sign in.
            let oldSession = try await h.page("/dashboard", devSession)
            XCTAssertNotEqual(oldSession.status, .ok)
            let (loggedIn, _) = try await h.dashLogin(devAccount)
            XCTAssertNil(loggedIn, "an account in recovery cannot sign in with an old passkey")
            // The link (to the member's own address) enrolls a new passkey; every old passkey is deleted and the new one works.
            let token = try Self.recoveryToken(h, "dev@example.com")
            let enrolled = try await Self.enroll(h, token: token)
            XCTAssertEqual(enrolled.result.status, .ok, enrolled.result.text)
            let newSession = try XCTUnwrap(enrolled.session)
            try await eq(try await h.page("/dashboard", newSession).status, .ok)
            let passkeys = try await DashboardPasskeyRecord.query(on: h.db).filter(\.$userId == devAccount.userId).all()
            XCTAssertEqual(passkeys.map(\.credentialId), [enrolled.credentialId])
            var stale = devAccount
            stale.credentialId = devAccount.credentialId
            let (oldPasskey, _) = try await h.dashLogin(stale)
            XCTAssertNil(oldPasskey, "the old passkey is revoked at completion")
            var fresh = devAccount
            fresh.credentialId = enrolled.credentialId
            let (signedIn, _) = try await h.dashLogin(fresh)
            XCTAssertNotNil(signedIn)
            // The link is single use.
            try await eq(try await Self.enroll(h, token: token).result.status, .unprocessableEntity)
            let actions = Set(try await h.auditActions())
            for action in ["console.recovery_refused", "console.recovery_started", "console.recovery_released", "console.recovery_completed", "dashboard.console_enrolled"] {
                XCTAssertTrue(actions.contains(action), action)
            }
            try await eq(try await ConsoleRecoveryRecord.query(on: h.db).first()?.state, "completed")
        }
    }

    func testAnOrganizationAdminCannotRecoverAnOwnerOrAMemberOfAnotherOrganization() async throws {
        try await withHarness { h in
            let (owner, ownerAccount, _) = try await h.verifiedOwner()
            let (admin, _) = try await h.addMember(owner: owner, role: .orgAdmin, email: "admin@example.com")
            let ownerMembership = try await Self.membership(h, ownerAccount.userId)
            let attempt = try await h.formPost("/dashboard/team/members/\(ownerMembership.uuidString.lowercased())/recover", admin, [("reason", "The owner asked me to do it")])
            XCTAssertEqual(attempt.status, .forbidden, attempt.text)
            // Another tenant's membership id is not found.
            let (other, _, _) = try await h.verifiedOwner(email: "birch@example.com", org: "Birch Bakery", handle: "birchbakery")
            let foreign = try await h.formPost("/dashboard/team/members/\(ownerMembership.uuidString.lowercased())/recover", other, [("reason", "Cross-tenant recovery attempt")])
            XCTAssertEqual(foreign.status, .notFound, foreign.text)
            try await eq(try await ConsoleRecoveryRecord.query(on: h.db).count(), 0)
        }
    }

    // MARK: Operator path

    /// An organization whose only Owner lost every passkey, plus one other non-admin member.
    func lonelyOwner(_ h: TestHarness) async throws -> (owner: DashSession, account: DashAccount, businessId: UUID, membership: UUID) {
        let (owner, account, businessId) = try await h.verifiedOwner()
        _ = try await h.addMember(owner: owner, role: .analyst, email: "analyst@example.com")
        return (owner, account, businessId, try await Self.membership(h, account.userId))
    }

    func request(_ h: TestHarness, _ op: DashSession, business: UUID, membership: UUID, checks: [(String, String)] = checks) async throws -> HTTPResult {
        try await h.formPost("/operator/recoveries", op, [("businessId", business.uuidString.lowercased()), ("membershipId", membership.uuidString.lowercased()),
                                                         ("reason", "Owner lost both devices; ticket SUP-1042")] + checks)
    }

    func testTheOperatorPathNeedsTwoOperatorsTheChecklistAndTheWaitingPeriod() async throws {
        try await withHarness { h in
            let (_, ownerAccount, businessId, membership) = try await lonelyOwner(h)
            let (op1, op1Account) = try await h.enrolledOperator("ops1@viadere.test")
            let (op2, op2Account) = try await h.enrolledOperator("ops2@viadere.test")
            // The checklist must be complete.
            let partial = try await request(h, op1, business: businessId, membership: membership, checks: Array(Self.checks.prefix(2)))
            XCTAssertEqual(partial.status, .unprocessableEntity, partial.text)
            let requested = try await request(h, op1, business: businessId, membership: membership)
            XCTAssertEqual(requested.status, .seeOther, requested.text)
            let record = try await XCTUnwrapAsync(try await ConsoleRecoveryRecord.query(on: h.db).first())
            let base = "/operator/recoveries/\(record.id!.uuidString.lowercased())"
            // A single operator cannot approve their own request, and nothing can be released before approval.
            let selfApproval = try await h.formPost("\(base)/approve", op1, Self.checks)
            XCTAssertEqual(selfApproval.status, .forbidden, selfApproval.text)
            try await eq(try await h.formPost("\(base)/release", op1).status, .conflict)
            try await eq(try await h.formPost("\(base)/release", op2).status, .conflict)
            // The second operator must tick the checklist too.
            try await eq(try await h.formPost("\(base)/approve", op2, Array(Self.checks.dropLast())).status, .unprocessableEntity)
            let approved = try await h.formPost("\(base)/approve", op2, Self.checks)
            XCTAssertEqual(approved.status, .seeOther, approved.text)
            // The organization's other contacts are told, and the member too.
            XCTAssertFalse(h.emails.messages(to: "analyst@example.com").filter { $0.kind == "console-recovery-approved" }.isEmpty)
            XCTAssertFalse(h.emails.messages(to: ownerAccount.email).filter { $0.kind == "console-recovery-approved" }.isEmpty)
            // The waiting period cannot be skipped, by either operator.
            for op in [op1, op2] {
                let early = try await h.formPost("\(base)/release", op)
                XCTAssertEqual(early.status, .conflict, early.text)
            }
            XCTAssertTrue(h.emails.messages(to: ownerAccount.email).filter { $0.kind == "console-recovery" }.isEmpty)
            h.clock.advance(by: ConsoleRecovery.waitingPeriod - 60)
            let (op1Again, _) = try await h.dashLogin(op1Account, realm: .operator)
            try await eq(try await h.formPost("\(base)/release", try XCTUnwrap(op1Again)).status, .conflict)
            h.clock.advance(by: 120)
            let (op1Late, _) = try await h.dashLogin(op1Account, realm: .operator)
            let released = try await h.formPost("\(base)/release", try XCTUnwrap(op1Late))
            XCTAssertEqual(released.status, .seeOther, released.text)
            // The member enrolls from their own address and must do so before anything else.
            let (oldLogin, _) = try await h.dashLogin(ownerAccount)
            XCTAssertNil(oldLogin)
            let enrolled = try await Self.enroll(h, token: try Self.recoveryToken(h, ownerAccount.email))
            XCTAssertEqual(enrolled.result.status, .ok, enrolled.result.text)
            try await eq(try await DashboardPasskeyRecord.query(on: h.db).filter(\.$userId == ownerAccount.userId).count(), 1)
            let actions = try await h.auditActions()
            for action in ["console.recovery_requested", "console.recovery_approval_refused", "console.recovery_approved", "console.recovery_release_refused",
                           "console.recovery_released", "console.recovery_completed"] {
                XCTAssertTrue(actions.contains(action), action)
            }
            // The audit names both operators.
            let events = try await AuditEventRecord.query(on: h.db).filter(\.$action ~~ ["console.recovery_requested", "console.recovery_approved"]).all()
            XCTAssertEqual(Set(events.compactMap(\.actorId)), [op1Account.userId.uuidString.lowercased(), op2Account.userId.uuidString.lowercased()])
        }
    }

    func testTheOperatorPathIsClosedWhileAnotherAdminCanDoItAndTheMemberCanCancel() async throws {
        try await withHarness { h in
            let (owner, account, businessId) = try await h.verifiedOwner()
            let (admin, adminAccount) = try await h.addMember(owner: owner, role: .orgAdmin, email: "admin@example.com")
            _ = admin
            let membership = try await Self.membership(h, account.userId)
            let (op1, _) = try await h.enrolledOperator("ops1@viadere.test")
            let (op2, _) = try await h.enrolledOperator("ops2@viadere.test")
            // Another Organization Admin with a working passkey exists: the operator path is refused.
            let refused = try await request(h, op1, business: businessId, membership: membership)
            XCTAssertEqual(refused.status, .forbidden, refused.text)
            try await eq(try await ConsoleRecoveryRecord.query(on: h.db).count(), 0)
            // Once that admin has no passkey (lost too), the operator path opens.
            try await DashboardPasskeyRecord.query(on: h.db).filter(\.$userId == adminAccount.userId).delete()
            try await eq(try await request(h, op1, business: businessId, membership: membership).status, .seeOther)
            let record = try await XCTUnwrapAsync(try await ConsoleRecoveryRecord.query(on: h.db).first())
            try await eq(try await h.formPost("/operator/recoveries/\(record.id!.uuidString.lowercased())/approve", op2, Self.checks).status, .seeOther)
            // The member still has a session (an attacker impersonated them to support): they cancel it from the Team page.
            let team = try await h.page("/dashboard/team", owner)
            XCTAssertTrue(team.text.contains("Passkey recoveries"), team.text)
            try await eq(try await h.formPost("/dashboard/team/recoveries/\(record.id!.uuidString.lowercased())/cancel", owner).status, .seeOther)
            try await eq(try await ConsoleRecoveryRecord.find(record.id!, on: h.db)?.state, "cancelled")
            h.clock.advance(by: ConsoleRecovery.waitingPeriod + 60)
            let (op1Late, _) = try await h.dashLogin(try await DashAccountFor(h, "ops1@viadere.test"), realm: .operator)
            try await eq(try await h.formPost("/operator/recoveries/\(record.id!.uuidString.lowercased())/release", try XCTUnwrap(op1Late)).status, .conflict)
            XCTAssertTrue(h.emails.messages(to: account.email).filter { $0.kind == "console-recovery" }.isEmpty)
            let actions = try await h.auditActions()
            XCTAssertTrue(actions.contains("console.recovery_cancelled"))
            XCTAssertTrue(actions.contains("console.recovery_refused"))
            // Another business's member cannot cancel it (not found).
            let (other, _, _) = try await h.verifiedOwner(email: "birch@example.com", org: "Birch Bakery", handle: "birchbakery")
            try await eq(try await h.formPost("/dashboard/team/recoveries/\(record.id!.uuidString.lowercased())/cancel", other).status, .notFound)
        }
    }

    /// The operator account for an address (sign-in helper needs the credential id of the enrolled passkey).
    func DashAccountFor(_ h: TestHarness, _ email: String) async throws -> DashAccount {
        let user = try await DashboardUserRecord.query(on: h.db).filter(\.$emailHash == DashboardAuthService(db: h.db, ctx: h.ctx).emailHash(email)).first()!
        let passkey = try await DashboardPasskeyRecord.query(on: h.db).filter(\.$userId == user.id!).first()!
        return DashAccount(email: email, credentialId: passkey.credentialId, publicKey: passkey.publicKey, userId: user.id!, businessId: nil)
    }
}
