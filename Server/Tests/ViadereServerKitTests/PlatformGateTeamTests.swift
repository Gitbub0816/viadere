import XCTest
import Fluent
import ViadereCore
@testable import ViadereServerKit

/// Platform gate (Phase 0/1 and enterprise Phase 4) review: step-up on every team and alert change (M2) and two-person approval that cannot be
/// bypassed or weakened (M3). Each test reproduces the exploit path first.
final class PlatformGateTeamTests: XCTestCase {
    private func fresh(_ h: TestHarness, _ session: DashSession, _ account: DashAccount) async throws {
        h.clock.advance(by: 30)
        try await h.dashReauth(session, account)
    }

    private func membership(_ h: TestHarness, _ account: DashAccount, _ businessId: UUID) async throws -> OrgMembershipRecord {
        try await XCTUnwrapAsync(await OrgMembershipRecord.query(on: h.db).filter(\.$userId == account.userId).filter(\.$businessId == businessId).first())
    }

    // MARK: M2

    func testAStolenConsoleCookieCannotAddMembersChangeRolesOrSilenceAlertsWithoutAPasskey() async throws {
        try await withHarness { h in
            let (owner, ownerAccount, businessId) = try await h.verifiedOwner()
            let (_, developerAccount) = try await h.addMember(owner: owner, role: .developer, email: "dev@example.com")
            try await fresh(h, owner, ownerAccount)
            let (security, securityAccount) = try await h.addMember(owner: owner, role: .securityAdmin, email: "sec@example.com")
            let developer = try await membership(h, developerAccount, businessId)
            // The cookie is stolen later: no fresh passkey assertion any more.
            h.clock.advance(by: 20 * 60)

            let invite = try await h.formPost("/dashboard/team/invite", owner, [("email", "attacker@example.com"), ("role", "developer")])
            XCTAssertEqual(invite.status, .forbidden, invite.text)
            XCTAssertTrue(invite.text.contains("Confirm with passkey"))
            let role = try await h.formPost("/dashboard/team/members/\(developer.id!.uuidString.lowercased())/role", owner, [("role", "analyst")])
            XCTAssertEqual(role.status, .forbidden, role.text)
            let remove = try await h.formPost("/dashboard/team/members/\(developer.id!.uuidString.lowercased())/remove", owner)
            XCTAssertEqual(remove.status, .forbidden, remove.text)
            let silence = try await h.formPost("/dashboard/security/alerts", security, [("contacts", "attacker@example.com")])
            XCTAssertEqual(silence.status, .forbidden, silence.text)
            let after = try await membership(h, developerAccount, businessId)
            XCTAssertEqual(after.role, "developer")
            XCTAssertNil(after.removedAt)
            let topics = try await SecuritySettings(db: h.db, ctx: h.ctx).subscriptions(businessId: businessId)
            XCTAssertEqual(topics, Set(SecurityAlertTopic.allCases), "the alerts stayed on")
            let contacts = try await SecuritySettings(db: h.db, ctx: h.ctx).contacts(businessId: businessId)
            XCTAssertTrue(contacts.isEmpty)

            // With a passkey the change goes through, and the owners are told even though the alerts were just turned off.
            try await fresh(h, security, securityAccount)
            let before = h.emails.sent.count
            let saved = try await h.formPost("/dashboard/security/alerts", security, [("contacts", "ir@example.com")])
            XCTAssertEqual(saved.status, .seeOther, saved.text)
            let told = h.emails.sent.dropFirst(before).filter { $0.to == "owner@example.com" && $0.subject.contains("alert") }
            XCTAssertFalse(told.isEmpty, "the owner is told when alert settings or contacts change, whatever the subscriptions")
            XCTAssertFalse(told.contains { $0.text.contains("attacker") || $0.text.contains("ir@example.com") }, "no contact address in the notice")
        }
    }

    // MARK: M3

    private func twoPersonTeam(_ h: TestHarness) async throws -> (owner: DashSession, ownerAccount: DashAccount, security: DashSession, securityAccount: DashAccount,
                                                                   admin: DashSession, adminAccount: DashAccount, developerAccount: DashAccount, businessId: UUID) {
        let (owner, ownerAccount, businessId) = try await h.verifiedOwner()
        let (_, developerAccount) = try await h.addMember(owner: owner, role: .developer, email: "dev@example.com")
        try await fresh(h, owner, ownerAccount)
        let (security, securityAccount) = try await h.addMember(owner: owner, role: .securityAdmin, email: "sec@example.com")
        try await fresh(h, owner, ownerAccount)
        let (admin, adminAccount) = try await h.addMember(owner: owner, role: .orgAdmin, email: "admin@example.com")
        try await fresh(h, owner, ownerAccount)
        let on = try await h.formPost("/dashboard/security/approvals/two-person", owner, [("enabled", "1")])
        XCTAssertEqual(on.status, .seeOther, on.text)
        return (owner, ownerAccount, security, securityAccount, admin, adminAccount, developerAccount, businessId)
    }

    func testDisablingTwoPersonApprovalIsItselfAPendingChange() async throws {
        try await withHarness { h in
            let t = try await twoPersonTeam(h)
            try await fresh(h, t.security, t.securityAccount)
            // A single Security Admin (or a stolen session of one) used to switch it off alone.
            let off = try await h.formPost("/dashboard/security/approvals/two-person", t.security)
            XCTAssertEqual(off.status, .seeOther, off.text)
            let settings = try await SecuritySettings(db: h.db, ctx: h.ctx).settings(businessId: t.businessId)
            XCTAssertTrue(settings.twoPersonRequired, "still on: the request waits for a second person")
            let change = try await XCTUnwrapAsync(await PendingChangeRecord.query(on: h.db).filter(\.$businessId == t.businessId).filter(\.$status == "pending").first())
            let id = change.id!.uuidString.lowercased()
            // Not by the requester, and not by an approver without the right to manage security.
            try await fresh(h, t.security, t.securityAccount)
            let own = try await h.formPost("/dashboard/security/approvals/\(id)/approve", t.security)
            XCTAssertEqual(own.status, .forbidden)
            try await fresh(h, t.admin, t.adminAccount)
            let weak = try await h.formPost("/dashboard/security/approvals/\(id)/approve", t.admin)
            XCTAssertEqual(weak.status, .forbidden, "an Organization Admin cannot approve a security setting")
            let still = try await SecuritySettings(db: h.db, ctx: h.ctx).settings(businessId: t.businessId)
            XCTAssertTrue(still.twoPersonRequired)
            try await fresh(h, t.owner, t.ownerAccount)
            let ok = try await h.formPost("/dashboard/security/approvals/\(id)/approve", t.owner)
            XCTAssertEqual(ok.status, .seeOther, ok.text)
            let done = try await SecuritySettings(db: h.db, ctx: h.ctx).settings(businessId: t.businessId)
            XCTAssertFalse(done.twoPersonRequired)
            let actions = try await h.auditActions(t.businessId)
            XCTAssertTrue(actions.contains("security.two_person_set"))
        }
    }

    func testTheApproverMustManageTheMembersCurrentRoleNotOnlyTheTarget() async throws {
        try await withHarness { h in
            let t = try await twoPersonTeam(h)
            let securityMember = try await membership(h, t.securityAccount, t.businessId)
            // The owner asks to demote the Security Admin to developer: an Organization Admin may grant "developer", but may not touch a Security Admin.
            try await fresh(h, t.owner, t.ownerAccount)
            let ask = try await h.formPost("/dashboard/team/members/\(securityMember.id!.uuidString.lowercased())/role", t.owner, [("role", "developer")])
            XCTAssertEqual(ask.status, .seeOther, ask.text)
            let change = try await XCTUnwrapAsync(await PendingChangeRecord.query(on: h.db).filter(\.$kind == "role_grant").filter(\.$status == "pending").first())
            try await fresh(h, t.admin, t.adminAccount)
            let approve = try await h.formPost("/dashboard/security/approvals/\(change.id!.uuidString.lowercased())/approve", t.admin)
            XCTAssertEqual(approve.status, .forbidden, approve.text)
            let after = try await membership(h, t.securityAccount, t.businessId)
            XCTAssertEqual(after.role, "security_admin")
        }
    }

    func testARoleChangedSinceTheRequestVoidsIt() async throws {
        try await withHarness { h in
            let t = try await twoPersonTeam(h)
            let developer = try await membership(h, t.developerAccount, t.businessId)
            try await fresh(h, t.owner, t.ownerAccount)
            let ask = try await h.formPost("/dashboard/team/members/\(developer.id!.uuidString.lowercased())/role", t.owner, [("role", "analyst")])
            XCTAssertEqual(ask.status, .seeOther, ask.text)
            let change = try await XCTUnwrapAsync(await PendingChangeRecord.query(on: h.db).filter(\.$kind == "role_grant").filter(\.$status == "pending").first())
            // Before the second person looks, the member's role is changed (here: straight in the store) to something the approver may not touch.
            developer.role = "security_admin"
            try await developer.update(on: h.db)
            try await fresh(h, t.admin, t.adminAccount)
            let approve = try await h.formPost("/dashboard/security/approvals/\(change.id!.uuidString.lowercased())/approve", t.admin)
            XCTAssertNotEqual(approve.status, .seeOther, approve.text)
            let after = try await membership(h, t.developerAccount, t.businessId)
            XCTAssertEqual(after.role, "security_admin", "a stale approval never rewrites the role")
            let voided = try await XCTUnwrapAsync(await PendingChangeRecord.find(change.id!, on: h.db))
            XCTAssertEqual(voided.status, "void")
        }
    }

    func testRemovingAMemberWaitsForASecondPersonWhenTwoPersonApprovalIsOn() async throws {
        try await withHarness { h in
            let t = try await twoPersonTeam(h)
            let developer = try await membership(h, t.developerAccount, t.businessId)
            try await fresh(h, t.owner, t.ownerAccount)
            let ask = try await h.formPost("/dashboard/team/members/\(developer.id!.uuidString.lowercased())/remove", t.owner)
            XCTAssertEqual(ask.status, .seeOther, ask.text)
            let waiting = try await membership(h, t.developerAccount, t.businessId)
            XCTAssertNil(waiting.removedAt, "removal waits for a second person")
            let change = try await XCTUnwrapAsync(await PendingChangeRecord.query(on: h.db).filter(\.$kind == "role_grant").filter(\.$status == "pending").first())
            let id = change.id!.uuidString.lowercased()
            let own = try await h.formPost("/dashboard/security/approvals/\(id)/approve", t.owner)
            XCTAssertEqual(own.status, .forbidden)
            try await fresh(h, t.admin, t.adminAccount)
            let ok = try await h.formPost("/dashboard/security/approvals/\(id)/approve", t.admin)
            XCTAssertEqual(ok.status, .seeOther, ok.text)
            let gone = try await membership(h, t.developerAccount, t.businessId)
            XCTAssertNotNil(gone.removedAt)
            // An approver who may not manage the member's role cannot approve their removal.
            let securityMember = try await membership(h, t.securityAccount, t.businessId)
            try await fresh(h, t.owner, t.ownerAccount)
            let askSecurity = try await h.formPost("/dashboard/team/members/\(securityMember.id!.uuidString.lowercased())/remove", t.owner)
            XCTAssertEqual(askSecurity.status, .seeOther, askSecurity.text)
            let second = try await XCTUnwrapAsync(await PendingChangeRecord.query(on: h.db).filter(\.$kind == "role_grant").filter(\.$status == "pending").first())
            try await fresh(h, t.admin, t.adminAccount)
            let denied = try await h.formPost("/dashboard/security/approvals/\(second.id!.uuidString.lowercased())/approve", t.admin)
            XCTAssertEqual(denied.status, .forbidden, denied.text)
            let kept = try await membership(h, t.securityAccount, t.businessId)
            XCTAssertNil(kept.removedAt)
        }
    }
}
