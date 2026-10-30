import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// WP-1.9 (FX-4 layer 1, O19 platform-wide reading): a healthcare-category business is refused, not routed into an extra review.
final class HealthcareRefusalTests: XCTestCase {
    private func expectRefusal(_ what: String, file: StaticString = #filePath, line: UInt = #line, _ body: () async throws -> Void) async {
        do {
            try await body()
            XCTFail("\(what) was accepted", file: file, line: line)
        } catch {}
    }

    func testSignupWithAHealthcareCategoryIsRefusedWithAPlainReason() async throws {
        try await withHarness { h in
            for category in ["healthcare", "medical", "pharmacy", "telehealth"] {
                let body = SignupBeginBody(email: "\(category)@clinic.example", displayName: "Pat", organizationName: "Clinic \(category)", category: category)
                let response = try await h.jsonPost("/dashboard/auth/signup/begin", body)
                XCTAssertEqual(response.status, .unprocessableEntity, "\(category): \(response.text)")
                XCTAssertTrue(response.text.contains("healthcare"), response.text)
            }
            // The sign-up form no longer offers the category.
            let form = try await h.request(.GET, "/dashboard/signup")
            XCTAssertFalse(form.text.contains("value=\"healthcare\""), "the category is not offered")
        }
    }

    func testAHealthcareApplicationCannotBeCreatedApprovedOrTakenLive() async throws {
        try await withHarness { h in
            let onboarding = BusinessOnboarding(db: h.db, ctx: h.ctx)
            await expectRefusal("a healthcare application") {
                _ = try await onboarding.createPending(businessId: UUID(), ownerId: UUID(), displayName: "Downtown Clinic", legalName: nil, category: .healthcare,
                                                      website: nil, requestedHandle: nil, description: nil)
            }
            // A record that predates the ban (created directly) still cannot be approved by an operator.
            let legacy = try await BusinessRegistry(db: h.db, ctx: h.ctx).register(displayName: "Old Clinic", handle: nil, category: .healthcare, status: .pending)
            let application = BusinessApplicationRecord()
            application.id = UUID()
            application.businessId = legacy.id!
            application.state = "pending"
            application.submittedAt = h.clock.now()
            try await application.create(on: h.db)
            await expectRefusal("an operator approval") {
                _ = try await onboarding.approve(businessId: legacy.id!, operatorId: UUID(), handleOverride: nil, note: nil)
            }
            let after = try await BusinessRecord.find(legacy.id!, on: h.db)
            XCTAssertEqual(after?.status, .pending)
            // The state machine cannot skip the refusal: a go-live request is blocked whatever else is done.
            let state = try await OnboardingService(db: h.db, ctx: h.ctx).state(businessId: legacy.id!)
            XCTAssertNotEqual(state.enhanced, .pending, "healthcare is not an 'additional review' path any more")
            XCTAssertTrue(state.categoryBanned)
            XCTAssertTrue(state.requestBlockers.contains(.categoryBanned))
            let complete = OnboardingState(domainVerified: true, legalEntity: .approved, identityVerified: true, contractsCurrent: true, sandboxKey: true,
                                           testCustomer: true, testEvent: true, securityContact: true, categoryBanned: true)
            XCTAssertThrowsError(try OnboardingStateMachine.apply(.goLiveRequested, to: complete))
            var requested = complete
            requested.goLive = .requested
            XCTAssertThrowsError(try OnboardingStateMachine.apply(.goLiveApproved, to: requested))
            XCTAssertThrowsError(try OnboardingStateMachine.apply(.identityVerified, to: complete))
            var cleared = complete
            cleared.categoryBanned = false
            XCTAssertNoThrow(try OnboardingStateMachine.apply(.goLiveRequested, to: cleared))
        }
    }

    func testAVerifiedHealthcareBusinessCannotBeGrantedEntitlements() async throws {
        try await withHarness { h in
            let clinic = try await BusinessRegistry(db: h.db, ctx: h.ctx).register(displayName: "Legacy Clinic", handle: nil, category: .healthcare, status: .verified)
            await expectRefusal("a tier grant") {
                try await EntitlementService(db: h.db, ctx: h.ctx).grant(businessId: clinic.id!, tier: .a, actor: .system("test"),
                                                                         justification: "Grant for a test that must be refused.")
            }
            let rows = try await BusinessEntitlementRecord.query(on: h.db).filter(\.$businessId == clinic.id!).count()
            XCTAssertEqual(rows, 0)
        }
    }

    func testReclassifyingIntoHealthcareRevokesEntitlementsAndSuspends() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Wellness Shop", handle: "wellnessshop")
            let world = try await h.readyConsumer()
            let relationship = try await h.connect(world, to: b)
            let pending = try await h.issue(b, relationship: relationship, payload: .confirm(ConfirmPayload(title: "Pickup")), purpose: .transactional)
            XCTAssertEqual(pending.status, .created, pending.text)
            let before = try await BusinessEntitlementRecord.query(on: h.db).filter(\.$businessId == b.record.id!).filter(\.$revokedAt == nil).count()
            XCTAssertGreaterThan(before, 0)
            try await BusinessOnboarding(db: h.db, ctx: h.ctx).reclassify(businessId: b.record.id!, category: "healthcare", operatorId: UUID(),
                                                                         note: "Legal entity is a licensed clinic.")
            let after = try await BusinessEntitlementRecord.query(on: h.db).filter(\.$businessId == b.record.id!).filter(\.$revokedAt == nil).count()
            XCTAssertEqual(after, 0)
            let record = try await BusinessRecord.find(b.record.id!, on: h.db)
            XCTAssertEqual(record?.status, .suspended)
            XCTAssertEqual(record?.category, "healthcare")
            // Its pending requests were cancelled; it can issue nothing more.
            let issued = try await h.issue(b, relationship: relationship, payload: .confirm(ConfirmPayload(title: "Again")), purpose: .transactional)
            XCTAssertNotEqual(issued.status, .created)
            // An operator cannot lift the suspension while the category stands.
            await expectRefusal("lifting the suspension") {
                try await BusinessOnboarding(db: h.db, ctx: h.ctx).unsuspend(businessId: b.record.id!, operatorId: UUID())
            }
            let state = try await OnboardingService(db: h.db, ctx: h.ctx).state(businessId: b.record.id!)
            XCTAssertTrue(state.categoryBanned)
            XCTAssertTrue(state.requestBlockers.contains(.categoryBanned))
            let audit = try await AuditEventRecord.query(on: h.db).filter(\.$action == "business.reclassified").count()
            XCTAssertEqual(audit, 1)
        }
    }
}
