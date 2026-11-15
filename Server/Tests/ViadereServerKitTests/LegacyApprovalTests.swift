import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Gate finding F2: the legacy `authorize` / high-risk `authenticate` path decides on relay status alone, so it is closed for live traffic
/// unless an operator granted the explicit, expiring legacy entitlement.
final class LegacyApprovalTests: XCTestCase {
    private func login(_ h: TestHarness) -> InteractionPayload {
        .authenticate(AuthenticatePayload(service: "Northwind portal", device: "Chrome on Mac", attemptedAt: h.clock.now()))
    }

    func testALiveBusinessWithoutTheLegacyEntitlementCannotIssueAnAuthorizeOrHighRiskAuthenticate() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank", legacyApproval: false)
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b)
            let authorize = try await h.issue(b, relationship: rel, payload: .authorize(.sample()))
            aeq(authorize.status, .forbidden, authorize.text)
            atrue(authorize.text.contains("legacy_approval_not_entitled"))
            let critical = try await h.issue(b, relationship: rel, payload: login(h), sensitivity: .critical)
            aeq(critical.status, .forbidden, critical.text)
            let high = try await h.issue(b, relationship: rel, payload: login(h), sensitivity: .high)
            aeq(high.status, .forbidden, high.text)
            // Low-risk authenticate and every other kind are unaffected.
            let low = try await h.issue(b, relationship: rel, payload: login(h), sensitivity: .standard)
            aeq(low.status, .created, low.text)
            atrue(try await h.approvalAudit("interaction.legacy_approval_refused").count >= 3)
        }
    }

    func testTheSandboxKeepsWorkingWithoutTheEntitlement() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank", live: false, legacyApproval: false)
            let rel = try await h.sandboxRelationship(b)
            let issued = try await h.issue(b, relationship: rel, payload: .authorize(.sample()))
            aeq(issued.status, .created, issued.text)
        }
    }

    func testTheEntitlementIsGrantedByAnOperatorWithAJustificationExpiresAndHasASunset() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank", legacyApproval: false)
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b)
            let service = EntitlementService(db: h.db, ctx: h.ctx)
            let actor = EntitlementActor.system("test")
            let id = b.record.id!
            // A justification and a bounded expiry are mandatory.
            do { _ = try await service.grantLegacyApproval(businessId: id, actor: actor, justification: "short", expiresAt: h.clock.now().addingTimeInterval(86_400)); XCTFail("justification") } catch {}
            do { _ = try await service.grantLegacyApproval(businessId: id, actor: actor, justification: "Migrating the bank to Approve v2 by Q2.", expiresAt: h.clock.now().addingTimeInterval(400 * 86_400)); XCTFail("too long") } catch {}
            do { _ = try await service.grantLegacyApproval(businessId: id, actor: actor, justification: "Migrating the bank to Approve v2 by Q2.", expiresAt: h.clock.now().addingTimeInterval(-60)); XCTFail("past") } catch {}
            aeq(try await h.issue(b, relationship: rel, payload: .authorize(.sample())).status, .forbidden)
            _ = try await service.grantLegacyApproval(businessId: id, actor: actor, justification: "Migrating the bank to Approve v2 by Q2.", expiresAt: h.clock.now().addingTimeInterval(7 * 86_400))
            aeq(try await h.issue(b, relationship: rel, payload: .authorize(.sample())).status, .created)
            atrue(try await h.approvalAudit("entitlement.legacy_approval_granted").count == 1)
            // An operator can withdraw it earlier...
            try await service.revokeLegacyApproval(businessId: id, actor: actor, justification: "Migration finished.")
            aeq(try await h.issue(b, relationship: rel, payload: .authorize(.sample())).status, .forbidden)
            // ...and a grant ends by itself.
            _ = try await service.grantLegacyApproval(businessId: id, actor: actor, justification: "Migrating the bank to Approve v2 by Q2.", expiresAt: h.clock.now().addingTimeInterval(7 * 86_400))
            aeq(try await h.issue(b, relationship: rel, payload: .authorize(.sample())).status, .created)
            h.clock.advance(by: 8 * 86_400)
            aeq(try await h.issue(b, relationship: rel, payload: .authorize(.sample())).status, .forbidden)
        }
    }

    func testNothingWorksAfterThePlatformSunset() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")   // fixture grant, expiring within 30 days
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b)
            aeq(try await h.issue(b, relationship: rel, payload: .authorize(.sample())).status, .created)
            h.clock.set(LegacyApproval.sunset.addingTimeInterval(60))
            aeq(try await h.issue(b, relationship: rel, payload: .authorize(.sample())).status, .forbidden, "the sunset closes the path whatever was granted")
            do { _ = try await EntitlementService(db: h.db, ctx: h.ctx).grantLegacyApproval(businessId: b.record.id!, actor: .system("test"),
                                                                                           justification: "Trying to extend past the sunset date.", expiresAt: h.clock.now().addingTimeInterval(86_400)); XCTFail("after sunset") } catch {}
        }
    }
}
