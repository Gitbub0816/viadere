import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

extension TestHarness {
    /// An enrolled operator with its own address (`makeOperator` returns the first operator row, so it cannot make a second one).
    func enrolledOperator(_ email: String, name: String = "Ops") async throws -> (session: DashSession, account: DashAccount) {
        let link = try await DashboardAuthService(db: db, ctx: ctx).createOperator(email: email, displayName: name)
        let token = String(link.split(separator: "/").last!)
        let begin = try await jsonPost("/operator/auth/enroll/begin", EnrollBeginBody(token: token))
        XCTAssertEqual(begin.status, .ok, begin.text)
        let options = try begin.json(PasskeyRegistrationOptions.self)
        let credentialId = SecureToken.generate(byteCount: 16)
        let publicKey = SecureToken.generate(byteCount: 32)
        let finish = try await jsonPost("/operator/auth/enroll/finish",
            PasskeyRegistrationFinishRequest(ceremonyId: options.ceremonyId, credential: registrationCredential(for: options, credentialId: credentialId, publicKey: publicKey)))
        XCTAssertEqual(finish.status, .ok, finish.text)
        let user = try await DashboardUserRecord.query(on: db).filter(\.$emailHash == DashboardAuthService(db: db, ctx: ctx).emailHash(email)).first()!
        return (DashSession(token: sessionCookie(finish, realm: .operator)!.value, realm: .operator),
                DashAccount(email: email, credentialId: credentialId, publicKey: publicKey, userId: user.id!, businessId: nil))
    }

    func auditActions() async throws -> [String] { try await AuditEventRecord.query(on: db).all().map(\.action) }
}

/// G20 (docs/SECURITY.md §2.111): profile changes after verification. Every test reproduces an exploit path first.
final class ProfileChangeTests: XCTestCase {
    static func directory(_ h: TestHarness, _ businessId: UUID) async throws -> BusinessSummary? {
        try await DirectoryService(db: h.db).summary(for: try await BusinessRecord.find(businessId, on: h.db)!)
    }

    func open(_ h: TestHarness, _ businessId: UUID) async throws -> BusinessProfileChangeRecord? {
        try await BusinessProfileChanges(db: h.db, ctx: h.ctx).open(businessId: businessId)
    }

    func testAPendingChangeIsInvisibleToCustomersUntilTwoDifferentOperatorsApprove() async throws {
        try await withHarness { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            let submitted = try await h.formPost("/dashboard/organization/profile", owner, [("displayName", "Acme Coffee House"), ("handle", "@acmecoffee"), ("website", "")])
            XCTAssertEqual(submitted.status, .seeOther, submitted.text)
            let change = try await XCTUnwrapAsync(try await open(h, businessId))
            XCTAssertEqual(change.status, "pending")
            // Customers (directory, handle lookup, search) still see the verified identity only.
            var summary = try await Self.directory(h, businessId)
            XCTAssertEqual(summary?.displayName, "Acme Roasters")
            XCTAssertEqual(summary?.handle?.value, "acmeroasters")
            try await eqNil(try await DirectoryService(db: h.db).verified(handle: BusinessHandle("acmecoffee")))
            let found = try await DirectoryService(db: h.db).search("Acme Coffee House", limit: 5)
            XCTAssertTrue(found.isEmpty)
            // The organization sees its pending change.
            let page = try await h.page("/dashboard/organization", owner)
            XCTAssertTrue(page.text.contains("Profile change under review"), page.text)

            let (op1, _) = try await h.enrolledOperator("ops1@viadere.test")
            let (op2, _) = try await h.enrolledOperator("ops2@viadere.test")
            let base = "/operator/profile-changes/\(change.id!.uuidString.lowercased())"
            try await eq(try await h.page(base, op1).status, .ok)
            try await eq(try await h.formPost("\(base)/approve", op1).status, .seeOther)
            // The same operator cannot give the second approval.
            let again = try await h.formPost("\(base)/approve", op1)
            XCTAssertEqual(again.status, .forbidden, again.text)
            summary = try await Self.directory(h, businessId)
            XCTAssertEqual(summary?.displayName, "Acme Roasters", "one approval never applies a change")
            // A different operator applies it.
            try await eq(try await h.formPost("\(base)/approve", op2).status, .seeOther)
            summary = try await Self.directory(h, businessId)
            XCTAssertEqual(summary?.displayName, "Acme Coffee House")
            XCTAssertEqual(summary?.handle?.value, "acmecoffee")
            // The old handle is retired, not freed: no lookup finds it, and it stays bound to this business.
            try await eqNil(try await DirectoryService(db: h.db).verified(handle: BusinessHandle("acmeroasters")))
            let retired = try await BusinessHandleRecord.query(on: h.db).filter(\.$handle == "acmeroasters").first()
            XCTAssertEqual(retired?.status, "retired")
            XCTAssertEqual(retired?.businessId, businessId)
            let actions = Set(try await h.auditActions())
            for action in ["business.profile_change_requested", "business.profile_change_first_approval", "business.profile_change_second_review_refused",
                           "business.profile_change_applied"] {
                XCTAssertTrue(actions.contains(action), action)
            }
        }
    }

    func testAnotherTenantCannotSeeOrCancelItAndAViewerCannotSubmit() async throws {
        try await withHarness { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            try await eq(try await h.formPost("/dashboard/organization/profile", owner, [("displayName", "Acme Coffee House")]).status, .seeOther)
            let change = try await XCTUnwrapAsync(try await open(h, businessId))
            let (other, _, otherId) = try await h.verifiedOwner(email: "birch@example.com", org: "Birch Bakery", handle: "birchbakery")
            // Business B sees nothing of A's change and cannot cancel it.
            let otherPage = try await h.page("/dashboard/organization", other)
            XCTAssertFalse(otherPage.text.contains("Acme Coffee House"))
            let cancel = try await h.formPost("/dashboard/organization/profile/\(change.id!.uuidString.lowercased())/cancel", other)
            XCTAssertEqual(cancel.status, .notFound, cancel.text)
            try await eq(try await open(h, businessId)?.status, "pending")
            // B's own submission changes only B.
            try await eq(try await h.formPost("/dashboard/organization/profile", other, [("displayName", "Birch Bread Company")]).status, .seeOther)
            try await eq(try await open(h, otherId)?.displayName, "Birch Bread Company")
            try await eq(try await open(h, businessId)?.displayName, "Acme Coffee House")
            // A read-only member of A (viewOrganization, not manageOrganization) cannot submit or cancel, and gets no form.
            let (auditor, _) = try await h.addMember(owner: owner, role: .auditor, email: "audit@example.com")
            let viewerPost = try await h.formPost("/dashboard/organization/profile", auditor, [("displayName", "Acme Coffee House Two")])
            XCTAssertEqual(viewerPost.status, .forbidden, viewerPost.text)
            let viewerCancel = try await h.formPost("/dashboard/organization/profile/\(change.id!.uuidString.lowercased())/cancel", auditor)
            XCTAssertEqual(viewerCancel.status, .forbidden, viewerCancel.text)
            let viewerPage = try await h.page("/dashboard/organization", auditor)
            XCTAssertEqual(viewerPage.status, .ok)
            XCTAssertFalse(viewerPage.text.contains("id=\"pc-name\""))
            // A pending organization (not verified) has no profile change at all.
            let (pending, _, _) = try await h.dashSignup(email: "new@example.com", org: "Cedar Cafe", handle: "cedarcafe")
            try await eq(try await h.formPost("/dashboard/organization/profile", pending, [("displayName", "Cedar Coffee")]).status, .forbidden)
            // The request itself needs a fresh passkey.
            h.clock.advance(by: h.ctx.config.dashboard.reauthWindow + 1)
            let stale = try await h.formPost("/dashboard/organization/profile/\(change.id!.uuidString.lowercased())/cancel", owner)
            XCTAssertEqual(stale.status, .seeOther, "cancelling is protective and needs no step-up")
            let restep = try await h.formPost("/dashboard/organization/profile", owner, [("displayName", "Acme Coffee House")])
            XCTAssertNotEqual(restep.status, .seeOther)
            try await eqNil(try await open(h, businessId))
        }
    }

    func testANameThatImpersonatesViadereOrAnotherVerifiedBusinessIsRefusedAtRequestAndAtApproval() async throws {
        try await withHarness { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            _ = try await h.makeBusiness(name: "Birch Bakery", handle: "birchbakery")
            for name in ["Viadere Payments", "V1adere Support", "Acme by V I A D E R E", "Birch Bakery Inc", "B1rch Bakery", "Birch Bakeryy", "birchbakery",
                         "Acme\u{202E}Roasters"] {
                let refused = try await h.formPost("/dashboard/organization/profile", owner, [("displayName", name)])
                XCTAssertEqual(refused.status, .unprocessableEntity, "\(name): \(refused.text.prefix(200))")
                try await eqNil(try await open(h, businessId))
            }
            // A clean name is accepted for review, but a business verified meanwhile with a confusable name makes the approval refuse it.
            try await eq(try await h.formPost("/dashboard/organization/profile", owner, [("displayName", "Juniper Coffee Roasters")]).status, .seeOther)
            let change = try await XCTUnwrapAsync(try await open(h, businessId))
            _ = try await h.makeBusiness(name: "Juniper Coffee Roaster", handle: "junipercoffee")
            let (op1, _) = try await h.enrolledOperator("ops1@viadere.test")
            let approve = try await h.formPost("/operator/profile-changes/\(change.id!.uuidString.lowercased())/approve", op1)
            XCTAssertEqual(approve.status, .unprocessableEntity, approve.text)
            let after = try await BusinessProfileChangeRecord.find(change.id!, on: h.db)
            XCTAssertEqual(after?.status, "refused")
            try await eq(try await Self.directory(h, businessId)?.displayName, "Acme Roasters")
            let refusedActions = try await h.auditActions()
            XCTAssertTrue(refusedActions.contains("business.profile_change_refused"))
            // The service refuses a Viadere look-alike at approval too (a row that bypassed the form).
            let forged = BusinessProfileChangeRecord()
            forged.id = UUID(); forged.businessId = businessId; forged.requestedBy = UUID(); forged.requestedAt = h.clock.now(); forged.status = "first_approved"
            forged.displayName = "Viadere Rewards"; forged.previousDisplayName = "Acme Roasters"; forged.firstReviewer = UUID()
            try await forged.create(on: h.db)
            do {
                _ = try await BusinessProfileChanges(db: h.db, ctx: h.ctx).approve(id: forged.id!, operatorId: UUID(), note: nil)
                XCTFail("a Viadere look-alike was applied")
            } catch {}
            try await eq(try await Self.directory(h, businessId)?.displayName, "Acme Roasters")
        }
    }

    func testAHandleCollisionOrARetiredHandleIsRefused() async throws {
        try await withHarness { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            let (other, _, otherId) = try await h.verifiedOwner(email: "birch@example.com", org: "Birch Bakery", handle: "birchbakery")
            for handle in ["birchbakery", "b1rchbakery", "BIRCHBAKERY", "viadere_shop", "admin"] {
                let refused = try await h.formPost("/dashboard/organization/profile", owner, [("handle", handle)])
                XCTAssertEqual(refused.status, .unprocessableEntity, "\(handle): \(refused.text.prefix(200))")
            }
            try await eqNil(try await open(h, businessId))
            // A changes its handle; its old one is retired.
            try await eq(try await h.formPost("/dashboard/organization/profile", owner, [("handle", "acmecoffee")]).status, .seeOther)
            let change = try await XCTUnwrapAsync(try await open(h, businessId))
            let service = BusinessProfileChanges(db: h.db, ctx: h.ctx)
            let (op1, op2) = (UUID(), UUID())
            _ = try await service.approve(id: change.id!, operatorId: op1, note: nil)
            try await eq(try await service.approve(id: change.id!, operatorId: op2, note: nil), .applied)
            // Nobody gets the retired handle, not even A again.
            let byOther = try await h.formPost("/dashboard/organization/profile", other, [("handle", "acmeroasters")])
            XCTAssertEqual(byOther.status, .unprocessableEntity, byOther.text)
            try await eqNil(try await open(h, otherId))
            let byOwner = try await h.formPost("/dashboard/organization/profile", owner, [("handle", "acmeroasters")])
            XCTAssertEqual(byOwner.status, .unprocessableEntity, byOwner.text)
            // A handle another business claims between request and approval is refused at approval.
            try await eq(try await h.formPost("/dashboard/organization/profile", other, [("handle", "birchbread")]).status, .seeOther)
            let pending = try await XCTUnwrapAsync(try await open(h, otherId))
            _ = try await h.makeBusiness(name: "Elm Market", handle: "birchbread")
            do { _ = try await service.approve(id: pending.id!, operatorId: op1, note: nil); XCTFail("approved a taken handle") } catch {}
            try await eq(try await BusinessProfileChangeRecord.find(pending.id!, on: h.db)?.status, "refused")
        }
    }

    func testOperatorApprovalWithoutTheSecondPersonIsRefusedAndTheWebsiteMustBeOnAVerifiedDomain() async throws {
        try await withHarness { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            // A website on a domain the organization has not verified is refused; on a verified one it is accepted.
            let unverified = try await h.formPost("/dashboard/organization/profile", owner, [("website", "https://acme-login.example.net")])
            XCTAssertEqual(unverified.status, .unprocessableEntity, unverified.text)
            let domain = BusinessDomainRecord()
            domain.id = UUID(); domain.businessId = businessId; domain.domain = "acme.example.com"; domain.token = "t"; domain.status = "verified"
            domain.createdBy = "test"; domain.failures = 0; domain.createdAt = h.clock.now(); domain.verifiedAt = h.clock.now()
            try await domain.create(on: h.db)
            try await eq(try await h.formPost("/dashboard/organization/profile", owner, [("website", "http://acme.example.com")]).status, .unprocessableEntity)
            try await eq(try await h.formPost("/dashboard/organization/profile", owner, [("website", "https://shop.acme.example.com/")]).status, .seeOther)
            let change = try await XCTUnwrapAsync(try await open(h, businessId))
            let service = BusinessProfileChanges(db: h.db, ctx: h.ctx)
            let op = UUID()
            try await eq(try await service.approve(id: change.id!, operatorId: op, note: nil), .firstApproval)
            do { _ = try await service.approve(id: change.id!, operatorId: op, note: nil); XCTFail("one operator approved twice") } catch let error as APIError {
                XCTAssertEqual(error.status, .forbidden)
            }
            try await eq(try await BusinessRecord.find(businessId, on: h.db)?.websiteURL, "https://acme.example.com")
            // A decline needs a reason and closes the change; the organization can ask again.
            do { try await service.reject(id: change.id!, operatorId: UUID(), note: "no"); XCTFail("decline without a reason") } catch {}
            try await service.reject(id: change.id!, operatorId: UUID(), note: "The website does not match the registry record.")
            try await eqNil(try await open(h, businessId))
            let page = try await h.page("/dashboard/organization", owner)
            XCTAssertTrue(page.text.contains("does not match the registry record"))
        }
    }

    func testNamePolicyUnits() {
        XCTAssertEqual(BusinessIdentityPolicy.skeleton("Acme Roasters, Inc."), BusinessIdentityPolicy.skeleton("ACME roasters"))
        XCTAssertTrue(BusinessIdentityPolicy.confusable(BusinessIdentityPolicy.skeleton("Аcme Roasters"), BusinessIdentityPolicy.skeleton("Acme Roasters")))
        XCTAssertFalse(BusinessIdentityPolicy.confusable(BusinessIdentityPolicy.skeleton("Joe's Coffee"), BusinessIdentityPolicy.skeleton("Coffee")))
        XCTAssertFalse(BusinessIdentityPolicy.confusable(BusinessIdentityPolicy.skeleton("Birch Bakery"), BusinessIdentityPolicy.skeleton("Larch Bakery Group")))
        XCTAssertEqual(BusinessIdentityPolicy.editDistance("kitten", "sitten", limit: 3), 1)
        XCTAssertNil(BusinessIdentityPolicy.nameIssue("Acme Roasters", others: []))
        XCTAssertNotNil(BusinessIdentityPolicy.nameIssue("Viadere", others: []))
    }
}

func eqNil<T>(_ value: @autoclosure () async throws -> T?, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) async throws {
    let resolved = try await value()
    XCTAssertNil(resolved, message, file: file, line: line)
}
