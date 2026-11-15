import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Rendering input for screenshots of the profile-change and recovery pages (G20, G25): writes each page's HTML to `$CONSOLE_PAGES_DIR`.
/// Skipped unless that variable is set.
final class OpsPagesDump: XCTestCase {
    func testDumpProfileChangeAndRecoveryPages() async throws {
        guard let dir = ProcessInfo.processInfo.environment["CONSOLE_PAGES_DIR"] else { throw XCTSkip("CONSOLE_PAGES_DIR not set") }
        let root = URL(fileURLWithPath: dir, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try await withHarness { h in
            let (owner, account, businessId) = try await h.verifiedOwner(org: "Acme Roasters and Provisions")
            _ = try await h.makeBusiness(name: "Birch Bakery", handle: "birchbakery")
            _ = try await h.addMember(owner: owner, role: .analyst, email: "analyst@example.com", name: "Avery Analyst")
            let (dev, devAccount) = try await h.addMember(owner: owner, role: .developer, email: "dev@example.com", name: "Dana Developer")
            _ = dev
            _ = try await h.formPost("/dashboard/organization/profile", owner, [("displayName", "Acme Coffee Roasters"), ("handle", "acmecoffee")])
            let change = try await BusinessProfileChanges(db: h.db, ctx: h.ctx).open(businessId: businessId)!
            let (op1, _) = try await h.enrolledOperator("ops1@viadere.test", name: "Olive Operator")
            let (op2, _) = try await h.enrolledOperator("ops2@viadere.test", name: "Omar Operator")
            _ = try await h.formPost("/operator/profile-changes/\(change.id!.uuidString.lowercased())/approve", op1, [("note", "Registry name matches.")])
            // A recovery started by the owner for the developer, and an operator-path recovery for the owner of a second organization.
            let devMembership = try await OrgMembershipRecord.query(on: h.db).filter(\.$userId == devAccount.userId).first()!.id!
            _ = try await h.formPost("/dashboard/team/members/\(devMembership.uuidString.lowercased())/recover", owner, [("reason", "Dana lost her laptop and phone")])
            let (other, otherAccount, otherId) = try await h.verifiedOwner(email: "birch@example.com", org: "Cedar Cafe", handle: "cedarcafe")
            _ = other
            let otherMembership = try await OrgMembershipRecord.query(on: h.db).filter(\.$userId == otherAccount.userId).first()!.id!
            _ = try await h.formPost("/operator/recoveries", op1, [("businessId", otherId.uuidString.lowercased()), ("membershipId", otherMembership.uuidString.lowercased()),
                                                               ("reason", "Owner lost both devices; ticket SUP-1042")] + ConsoleRecoveryTests.checks)
            let recovery = try await ConsoleRecoveryRecord.query(on: h.db).filter(\.$businessId == otherId).first()!
            _ = account
            let pages: [(String, String)] = [
                ("organization-profile-change", try await h.page("/dashboard/organization", owner).text),
                ("team-recovery", try await h.page("/dashboard/team?m=recovery-started", owner).text),
                ("operator-profile-changes", try await h.page("/operator/profile-changes", op2).text),
                ("operator-profile-change", try await h.page("/operator/profile-changes/\(change.id!.uuidString.lowercased())", op2).text),
                ("operator-recoveries", try await h.page("/operator/recoveries?business=\(otherId.uuidString.lowercased())", op2).text),
                ("operator-recovery", try await h.page("/operator/recoveries/\(recovery.id!.uuidString.lowercased())", op2).text),
            ]
            for (name, html) in pages { try Data(html.utf8).write(to: root.appendingPathComponent(name + ".html")) }
        }
    }
}
