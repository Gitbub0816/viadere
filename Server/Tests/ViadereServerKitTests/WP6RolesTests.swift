import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// The nine roles, the permission matrix (code = documentation), separation of duties, two-person approval and step-up re-authentication.
final class WP6RolesTests: XCTestCase {
    // MARK: Matrix

    func testPermissionMatrixDocumentMatchesTheCode() throws {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("docs/ops/CONSOLE-ROLES.md")
        var text = try String(contentsOf: url, encoding: .utf8)
        let begin = try XCTUnwrap(text.range(of: OrgRoleMatrix.beginMarker))
        let end = try XCTUnwrap(text.range(of: OrgRoleMatrix.endMarker))
        if ProcessInfo.processInfo.environment["WRITE_ROLES_DOC"] == "1" {
            text.replaceSubrange(begin.upperBound..<end.lowerBound, with: "\n" + OrgRoleMatrix.markdown() + "\n")
            try text.write(to: url, atomically: true, encoding: .utf8)
        }
        let embedded = String(text[text.range(of: OrgRoleMatrix.beginMarker)!.upperBound..<text.range(of: OrgRoleMatrix.endMarker)!.lowerBound]).trimmingCharacters(in: .whitespacesAndNewlines)
        XCTAssertEqual(embedded, OrgRoleMatrix.markdown(), "docs/ops/CONSOLE-ROLES.md is out of date: run with WRITE_ROLES_DOC=1")
    }

    func testThereAreNineRolesAndEveryPermissionIsHeldBySomeone() {
        XCTAssertEqual(OrgRole.allCases.count, 9)
        XCTAssertEqual(Set(OrgRole.allCases.map(\.title)), ["Owner", "Organization Admin", "Developer", "Messaging Operator", "Verification Compliance Admin",
                                                            "Security Admin", "Analyst", "Billing Admin", "Read-only Auditor"])
        for permission in DashboardPermission.allCases { XCTAssertFalse(permission.roles.isEmpty, "\(permission)") }
        // Least privilege: only the Owner holds everything; nobody but the owner manages billing and the team and the credentials at once.
        for role in OrgRole.allCases where role != .owner {
            XCTAssertFalse(DashboardPermission.allCases.allSatisfy { $0.roles.contains(role) }, "\(role)")
        }
        // The read-only roles can change nothing.
        let mutating = DashboardPermission.allCases.filter { $0.rawValue.hasPrefix("manage") || ["revokeAPIKeys", "elevateKeyScope", "acceptContracts", "requestGoLive", "approveChanges"].contains($0.rawValue) }
        for role in [OrgRole.analyst, .auditor] {
            XCTAssertEqual(mutating.filter { $0.roles.contains(role) }, [], "\(role)")
        }
        // No credential permission for the roles that only need to see data.
        for role in [OrgRole.messagingOperator, .verificationAdmin, .analyst, .billingAdmin, .auditor] {
            XCTAssertFalse(role.permits(.manageAPIKeys), "\(role)")
            XCTAssertFalse(role.permits(.viewAPIKeys) && role != .auditor, "\(role)")
        }
        XCTAssertFalse(OrgRole.auditor.permits(.manageAPIKeys))
    }

    // MARK: Separation of duties (policy)

    func testNoSingleLowPrivilegeRoleCanIssueCredentialsWidenScopeAndGrantRoles() {
        let widens = DashboardPermission.elevateKeyScope.roles
        let grants = DashboardPermission.manageTeam.roles
        let issues = DashboardPermission.manageAPIKeys.roles
        // Widening a credential and managing people only coincide in the Owner.
        XCTAssertEqual(widens.intersection(grants), [.owner])
        XCTAssertEqual(widens, [.owner, .securityAdmin])
        // The roles that can grant roles cannot grant the ones that widen scope or manage people, except the Owner.
        XCTAssertEqual(OrgRole.orgAdmin.grantableRoles.intersection([.owner, .orgAdmin, .securityAdmin]), [])
        XCTAssertEqual(OrgRole.securityAdmin.grantableRoles, [])
        XCTAssertEqual(OrgRole.developer.grantableRoles, [])
        XCTAssertTrue(issues.isSuperset(of: [.developer]))
        XCTAssertFalse(DashboardPermission.elevateKeyScope.roles.contains(.developer))
        // Whoever can approve a second person's request is not a plain developer.
        XCTAssertFalse(DashboardPermission.approveChanges.roles.contains(.developer))
        XCTAssertTrue(RoleGrantPolicy.mayManage(actor: .owner, role: .owner))
        XCTAssertFalse(RoleGrantPolicy.mayManage(actor: .orgAdmin, role: .owner))
        XCTAssertFalse(RoleGrantPolicy.mayManage(actor: .developer, role: .analyst))
    }

    func testLegacyRoleNamesAreAcceptedAndMapped() {
        XCTAssertEqual(OrgRole.parse("admin"), .orgAdmin)
        XCTAssertEqual(OrgRole.parse("support"), .messagingOperator)
        for role in OrgRole.allCases { XCTAssertEqual(OrgRole.parse(role.rawValue), role) }
        XCTAssertNil(OrgRole.parse("root"))
        XCTAssertNil(OrgRole.parse(""))
    }

    func testStoredLegacyRolesAreMigratedAndTheMigrationIsIdempotent() async throws {
        try await withHarness { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            // Rows as an old deployment would have left them.
            let admin = try await h.addMember(owner: owner, role: .developer, email: "old-admin@example.com").account
            let support = try await h.addMember(owner: owner, role: .analyst, email: "old-support@example.com").account
            let membershipA = try await XCTUnwrapAsync(await OrgMembershipRecord.query(on: h.db).filter(\.$userId == admin.userId).first())
            let membershipS = try await XCTUnwrapAsync(await OrgMembershipRecord.query(on: h.db).filter(\.$userId == support.userId).first())
            membershipA.role = "admin"
            membershipS.role = "support"
            try await membershipA.update(on: h.db)
            try await membershipS.update(on: h.db)
            _ = try await h.formPost("/dashboard/team/invite", owner, [("email", "pending@example.com"), ("role", "support")])
            let invite = try await XCTUnwrapAsync(await OrgInviteRecord.query(on: h.db).filter(\.$businessId == businessId).first())
            invite.role = "admin"
            try await invite.update(on: h.db)

            try await CreatePlatformWP6Schema.migrateRoles(on: h.db)
            try await CreatePlatformWP6Schema.migrateRoles(on: h.db)
            let roles = try await OrgMembershipRecord.query(on: h.db).all().map(\.role)
            XCTAssertEqual(Set(roles), ["owner", "org_admin", "messaging_operator"])
            XCTAssertEqual(roles.filter { $0 == "owner" }.count, 1, "owners are unchanged")
            let migrated = try await XCTUnwrapAsync(await OrgInviteRecord.find(invite.id!, on: h.db))
            XCTAssertEqual(migrated.role, "org_admin")
            // The migrated Organization Admin has exactly what the old admin had: keys and team, not owners.
            let migratedAdmin = try await h.dashLogin(admin).session
            let session = try XCTUnwrap(migratedAdmin)
            let status = try await h.get(session, "/dashboard/team")
            XCTAssertEqual(status, .ok)
        }
    }

    // MARK: Separation of duties (server side)

    func testSeparationOfDutiesIsEnforcedByTheServer() async throws {
        try await withHarness { h in
            let (owner, ownerAccount, businessId) = try await h.verifiedOwner()
            let (developer, _) = try await h.addMember(owner: owner, role: .developer, email: "dev@example.com")
            h.clock.advance(by: 60)
            try await h.dashReauth(owner, ownerAccount)
            let (security, _) = try await h.addMember(owner: owner, role: .securityAdmin, email: "sec@example.com")
            h.clock.advance(by: 60)
            try await h.dashReauth(owner, ownerAccount)
            let (admin, adminAccount) = try await h.addMember(owner: owner, role: .orgAdmin, email: "admin@example.com")

            try await h.entitle(businessId, [.transactionApprove])
            // A developer issues a key within the messaging scopes, but cannot widen it: the server refuses, whatever the form says.
            let ok = try await h.createKey(developer, name: "dev", scopes: ["interactions:write"])
            XCTAssertEqual(ok.status, .ok, ok.text)
            let widened = try await h.createKey(developer, name: "wide", scopes: ["interactions:write", "approvals:manage"])
            XCTAssertEqual(widened.status, .forbidden, widened.text)
            let widenedCapabilities = try await h.createKey(developer, name: "wide2", scopes: ["interactions:write"], extra: [("capabilities[]", "transaction.approve"), ("capabilitiesChosen", "1")])
            XCTAssertEqual(widenedCapabilities.status, .forbidden, widenedCapabilities.text)
            // A Security Admin can widen scope, but cannot grant roles (not even to themselves) or manage the team.
            let secKey = try await h.createKey(security, name: "sec", scopes: ["interactions:write"], extra: [("capabilities[]", "transaction.approve"), ("capabilitiesChosen", "1")])
            XCTAssertNotEqual(secKey.status, .forbidden, "a Security Admin may widen a key")
            let selfGrant = try await OrgMembershipRecord.query(on: h.db).filter(\.$role == "security_admin").first()!
            let escalate = try await h.formPost("/dashboard/team/members/\(selfGrant.id!.uuidString.lowercased())/role", security, [("role", "owner")])
            XCTAssertEqual(escalate.status, .forbidden)
            let invite = try await h.formPost("/dashboard/team/invite", security, [("email", "x@example.com"), ("role", "developer")])
            XCTAssertEqual(invite.status, .forbidden)
            // An Organization Admin runs the team but cannot create the roles that widen scope or hold the keys of the organization.
            for role in ["owner", "org_admin", "security_admin"] {
                let r = try await h.formPost("/dashboard/team/invite", admin, [("email", "\(role)@example.com"), ("role", role)])
                XCTAssertEqual(r.status, .forbidden, role)
            }
            h.clock.advance(by: 60)
            try await h.dashReauth(admin, adminAccount)
            let allowed = try await h.formPost("/dashboard/team/invite", admin, [("email", "analyst2@example.com"), ("role", "analyst")])
            XCTAssertEqual(allowed.status, .ok, allowed.text)
            // Nobody changes their own role.
            let own = try await OrgMembershipRecord.query(on: h.db).filter(\.$role == "org_admin").first()!
            let ownChange = try await h.formPost("/dashboard/team/members/\(own.id!.uuidString.lowercased())/role", admin, [("role", "owner")])
            XCTAssertTrue([.forbidden, .conflict].contains(ownChange.status), "\(ownChange.status)")
            let still = try await XCTUnwrapAsync(await OrgMembershipRecord.find(own.id!, on: h.db))
            XCTAssertEqual(still.role, "org_admin")
            _ = businessId
        }
    }

    // MARK: Step-up and privileged inactivity

    func testSensitiveActionsNeedAFreshPasskeyAndTheInactivityTimeoutApplies() async throws {
        try await withHarness { h in
            let (owner, account, businessId) = try await h.verifiedOwner()
            h.clock.advance(by: 20 * 60)
            let stale = try await h.createKey(owner)
            XCTAssertEqual(stale.status, .forbidden)
            XCTAssertTrue(stale.text.contains("Confirm with passkey"))
            let created = try await BusinessAPIKeyRecord.query(on: h.db).filter(\.$businessId == businessId).count()
            XCTAssertEqual(created, 0)
            try await h.dashReauth(owner, account)
            let ok = try await h.createKey(owner)
            XCTAssertEqual(ok.status, .ok, ok.text)

            // The organization shortens the privileged-inactivity timeout to 60 s: a fresh passkey does not help a console left idle.
            let timeout = try await h.formPost("/dashboard/security/network/inactivity", owner, [("seconds", "60")])
            XCTAssertEqual(timeout.status, .seeOther, timeout.text)
            try await h.dashReauth(owner, account)
            h.clock.advance(by: 120)
            let idle = try await h.createKey(owner, name: "idle")
            XCTAssertEqual(idle.status, .forbidden, "the console sat idle longer than the privileged timeout")
            try await h.dashReauth(owner, account)
            let active = try await h.createKey(owner, name: "active")
            XCTAssertEqual(active.status, .ok, active.text)
            // Revoking is protective: no step-up needed.
            h.clock.advance(by: 20 * 60)
            let record = try await XCTUnwrapAsync(await BusinessAPIKeyRecord.query(on: h.db).filter(\.$businessId == businessId).filter(\.$revokedAt == nil).first())
            let revoked = try await h.formPost("/dashboard/api-keys/\(record.id!.uuidString.lowercased())/revoke", owner)
            XCTAssertEqual(revoked.status, .seeOther)
            // The bounds of the timeout are enforced.
            try await h.dashReauth(owner, account)
            let tooLong = try await h.formPost("/dashboard/security/network/inactivity", owner, [("seconds", "86400")])
            XCTAssertNotEqual(tooLong.status, .seeOther)
        }
    }

    // MARK: Two-person approval

    func testTwoPersonApprovalForKeysAndRoleGrants() async throws {
        try await withHarness { h in
            let (owner, ownerAccount, businessId) = try await h.verifiedOwner()
            let (developer, developerAccount) = try await h.addMember(owner: owner, role: .developer, email: "dev@example.com")
            h.clock.advance(by: 60)
            try await h.dashReauth(owner, ownerAccount)
            let (admin, adminAccount) = try await h.addMember(owner: owner, role: .orgAdmin, email: "admin@example.com")
            h.clock.advance(by: 60)
            try await h.dashReauth(owner, ownerAccount)
            let on = try await h.formPost("/dashboard/security/approvals/two-person", owner, [("enabled", "1")])
            XCTAssertEqual(on.status, .seeOther, on.text)

            // The developer's request waits; no key exists and no secret was shown.
            let waiting = try await h.createKey(developer, name: "needs approval", scopes: ["interactions:write"])
            XCTAssertEqual(waiting.status, .seeOther, waiting.text)
            XCTAssertNil(waiting.secret)
            var keyCount = try await BusinessAPIKeyRecord.query(on: h.db).filter(\.$businessId == businessId).count()
            XCTAssertEqual(keyCount, 0)
            let change = try await XCTUnwrapAsync(await PendingChangeRecord.query(on: h.db).filter(\.$businessId == businessId).first())
            XCTAssertEqual(change.status, "pending")
            XCTAssertFalse(change.payloadJSON.contains("needs approval"), "the payload is sealed at rest")
            let changeId = change.id!.uuidString.lowercased()

            // The requester cannot approve their own request, and a role without the right cannot decide it.
            let own = try await h.formPost("/dashboard/security/approvals/\(changeId)/approve", developer)
            XCTAssertEqual(own.status, .forbidden)
            // Nor can the requester complete it before it is approved.
            let early = try await h.formPost("/dashboard/api-keys/approved/\(changeId)", developer)
            XCTAssertEqual(early.status, .forbidden)
            // A different person with the right approves; the requester alone completes it and sees the secret once.
            h.clock.advance(by: 60)
            try await h.dashReauth(admin, adminAccount)
            let approved = try await h.formPost("/dashboard/security/approvals/\(changeId)/approve", admin, [("note", "ok")])
            XCTAssertEqual(approved.status, .seeOther, approved.text)
            h.clock.advance(by: 60)
            try await h.dashReauth(developer, developerAccount)
            let someoneElse = try await h.formPost("/dashboard/api-keys/approved/\(changeId)", admin)
            XCTAssertEqual(someoneElse.status, .forbidden, "only the requester completes an approved key")
            let completed = try await h.formPost("/dashboard/api-keys/approved/\(changeId)", developer)
            XCTAssertEqual(completed.status, .ok, completed.text)
            let secret = try XCTUnwrap(h.shownSecret(completed.text))
            XCTAssertTrue(secret.hasPrefix("vdk_test_"))
            let again = try await h.formPost("/dashboard/api-keys/approved/\(changeId)", developer)
            XCTAssertNotEqual(again.status, .ok, "single use")
            keyCount = try await BusinessAPIKeyRecord.query(on: h.db).filter(\.$businessId == businessId).count()
            XCTAssertEqual(keyCount, 1)
            let actions = try await h.auditActions(businessId)
            XCTAssertTrue(actions.contains("approval.requested"))
            XCTAssertTrue(actions.contains("approval.approved"))
            XCTAssertTrue(actions.contains("apikey.created"))
            XCTAssertFalse(h.allMailText.contains(secret))

            // A role grant waits too, and is executed by the approver's decision, never by the requester's.
            h.clock.advance(by: 60)
            try await h.dashReauth(admin, adminAccount)
            let grant = try await h.formPost("/dashboard/team/invite", admin, [("email", "newanalyst@example.com"), ("role", "analyst")])
            XCTAssertTrue([.ok, .seeOther].contains(grant.status), grant.text)
            let invites = try await OrgInviteRecord.query(on: h.db).filter(\.$businessId == businessId).all()
            XCTAssertEqual(invites.filter { $0.role == "analyst" }.count, 0, "nothing is invited before a second person approves")
            let grantChange = try await XCTUnwrapAsync(await PendingChangeRecord.query(on: h.db).filter(\.$kind == "role_grant").first())
            let selfApprove = try await h.formPost("/dashboard/security/approvals/\(grantChange.id!.uuidString.lowercased())/approve", admin)
            XCTAssertEqual(selfApprove.status, .forbidden)
            h.clock.advance(by: 60)
            try await h.dashReauth(owner, ownerAccount)
            let ownerApproves = try await h.formPost("/dashboard/security/approvals/\(grantChange.id!.uuidString.lowercased())/approve", owner)
            XCTAssertEqual(ownerApproves.status, .seeOther, ownerApproves.text)
            let after = try await OrgInviteRecord.query(on: h.db).filter(\.$businessId == businessId).all()
            XCTAssertEqual(after.filter { $0.role == "analyst" }.count, 1)

            // Requests expire after 24 hours and cannot be approved late.
            h.clock.advance(by: 60)
            try await h.dashReauth(developer, developerAccount)
            _ = try await h.createKey(developer, name: "late", scopes: ["interactions:write"])
            let late = try await XCTUnwrapAsync(await PendingChangeRecord.query(on: h.db).filter(\.$status == "pending").first())
            h.clock.advance(by: 25 * 3600)
            let relogin = try await h.dashLogin(ownerAccount)
            let fresh = try XCTUnwrap(relogin.session) // the old session expired with the day
            let lateApproval = try await h.formPost("/dashboard/security/approvals/\(late.id!.uuidString.lowercased())/approve", fresh)
            XCTAssertNotEqual(lateApproval.status, .seeOther)
        }
    }
}
