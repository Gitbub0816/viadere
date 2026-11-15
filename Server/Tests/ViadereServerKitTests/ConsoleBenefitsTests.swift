import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// G6 rewards, loyalty and Wallet pass pages (docs/SECURITY.md §2.109). Exploit paths first: a role that may only read acting, another tenant's
/// reward, pass or code reachable from the console, a value-changing action without a fresh passkey, a test-mode organization touching real
/// customers' value, a code used twice, and business-supplied text rendered as markup.
final class ConsoleBenefitsTests: XCTestCase {
    struct Tenant {
        var owner: DashSession
        var account: DashAccount
        var businessId: UUID
        var business: TestBusiness
        var consumer: TestConsumer
        var reward: Reward
        var code: String
        var passId: WalletPassID
        var scanCode: String
    }

    /// An organization from the console with a program, a member, a claimed coupon with an outstanding code and a loyalty card pass.
    static func tenant(_ h: TestHarness, email: String = "owner@example.com", org: String = "Acme Roasters", handle: String = "acmeroasters",
                       title: String = "Free coffee") async throws -> Tenant {
        let (owner, account, businessId) = try await h.verifiedOwner(email: email, org: org, handle: handle)
        let business = try await h.testBusiness(businessId)
        try await h.saveProgram(business)
        let consumer = try await h.readyConsumer()
        let relationship = try await h.connect(consumer, to: business)
        try await eq(try await h.enroll(consumer, business).status, .created)
        let reward = try await h.reward(business, title: title, kind: .coupon)
        _ = try await h.claim(consumer, reward.id)
        let redeemed = try await h.redeem(consumer, reward.id)
        XCTAssertEqual(redeemed.status, .created, redeemed.text)
        let code = try redeemed.json(RewardRedemption.self).redemptionCode
        let issued = try await h.businessPost(business, "/v1/business/wallet/passes", BusinessIssueWalletPassRequest(relationshipId: relationship.id, kind: .storeCard))
        XCTAssertEqual(issued.status, .created, issued.text)
        let pass = try issued.json(BusinessWalletPass.self)
        let mine = try await h.signed(consumer, .GET, "/v1/wallet/passes").json([WalletPassMetadata].self)
        let scan = try XCTUnwrap(mine.first { $0.id == pass.id }?.scanCode)
        return Tenant(owner: owner, account: account, businessId: businessId, business: business, consumer: consumer, reward: reward, code: code,
                      passId: pass.id, scanCode: scan)
    }

    private func id(_ uuid: UUID) -> String { uuid.uuidString.lowercased() }
    private func codeRow(_ h: TestHarness, _ t: Tenant) async throws -> RewardRedemptionRecord {
        try await XCTUnwrapAsync(await RewardRedemptionRecord.query(on: h.db).filter(\.$rewardId == t.reward.id.uuid).first())
    }

    func testTheRoleMatrixSeparatesReadingFromActing() async throws {
        XCTAssertEqual(DashboardPermission.manageBenefits.roles, [.owner, .orgAdmin, .messagingOperator])
        XCTAssertTrue(DashboardPermission.manageBenefits.roles.isSubset(of: DashboardPermission.viewBenefits.roles))
        XCTAssertTrue(DashboardPermission.viewBenefits.roles.contains(.auditor) && DashboardPermission.viewBenefits.roles.contains(.analyst))
        XCTAssertFalse(DashboardPermission.viewBenefits.roles.contains(.developer))
        XCTAssertEqual(DashboardPermission.replyConversations.roles, [.owner, .orgAdmin, .messagingOperator])
        XCTAssertTrue(DashboardPermission.replyConversations.roles.isSubset(of: DashboardPermission.viewConversations.roles))
        XCTAssertFalse(DashboardPermission.viewConversations.roles.contains(.analyst), "aggregate-only roles never read message bodies")
        try await withHarness { h in
            let t = try await Self.tenant(h)
            let analyst = try await h.addMember(owner: t.owner, role: .analyst, email: "analyst@example.com")
            let developer = try await h.addMember(owner: t.owner, role: .developer, email: "dev@example.com")
            let ops = try await h.addMember(owner: t.owner, role: .messagingOperator, email: "ops@example.com")
            // Reading: the analyst sees the pages without any action; the developer sees nothing.
            for path in ["/dashboard/benefits", "/dashboard/benefits/passes"] {
                let page = try await h.page(path, analyst.session)
                XCTAssertEqual(page.status, .ok, page.text)
                XCTAssertFalse(page.text.contains("/revoke\"") || page.text.contains("/void\""), path)
                try await eq(try await h.page(path, developer.session).status, .forbidden)
            }
            try await eq(try await h.page("/dashboard/benefits/check", analyst.session).status, .forbidden)
            for (path, form) in [("/dashboard/benefits/rewards/\(t.reward.id)/revoke", [(String, String)]()), ("/dashboard/benefits/passes/\(t.passId)/void", []),
                                 ("/dashboard/benefits/check", [("code", t.code)]),
                                 ("/dashboard/benefits/program", [("program_name", "X"), ("summary", "Y"), ("terms_version", "v2"), ("time_zone", "UTC")])] {
                try await eq(try await h.formPost(path, analyst.session, form).status, .forbidden)
                try await eq(try await h.formPost(path, developer.session, form).status, .forbidden)
            }
            try await eq(try await codeRow(h, t).status, "issued")
            // The operator acts (the sign-in was a fresh passkey assertion).
            let checked = try await h.formPost("/dashboard/benefits/check", ops.session, [("code", t.code)])
            XCTAssertEqual(checked.status, .ok, checked.text)
            XCTAssertTrue(checked.text.contains("Redeemed"))
            // A downgrade applies on the next request.
            try await OrgMembershipRecord.query(on: h.db).filter(\.$businessId == t.businessId).filter(\.$userId == ops.account.userId)
                .set(\.$role, to: OrgRole.developer.rawValue).update()
            try await eq(try await h.formPost("/dashboard/benefits/passes/\(t.passId)/void", ops.session).status, .forbidden)
            try await eq(try await h.page("/dashboard/benefits", ops.session).status, .forbidden)
        }
    }

    func testEveryRouteIsTenantIsolated() async throws {
        try await withHarness { h in
            let a = try await Self.tenant(h)
            let b = try await Self.tenant(h, email: "other@example.com", org: "Other Shop", handle: "othershop", title: "Other shop secret deal")
            let overview = try await h.page("/dashboard/benefits", a.owner)
            XCTAssertEqual(overview.status, .ok, overview.text)
            XCTAssertTrue(overview.text.contains("Free coffee"))
            XCTAssertFalse(overview.text.contains("Other shop secret deal"))
            XCTAssertFalse(overview.text.contains(id(b.reward.id.uuid)))
            let passes = try await h.page("/dashboard/benefits/passes", a.owner)
            XCTAssertTrue(passes.text.contains(id(a.passId.uuid)))
            XCTAssertFalse(passes.text.contains(id(b.passId.uuid)))
            // B's reward and pass ids are not found from A's console.
            try await eq(try await h.formPost("/dashboard/benefits/rewards/\(b.reward.id)/revoke", a.owner).status, .notFound)
            try await eq(try await h.formPost("/dashboard/benefits/passes/\(b.passId)/void", a.owner).status, .notFound)
            // B's redemption code and B's pass code are "not valid here", and stay usable by B.
            for code in [b.code, b.scanCode] {
                let checked = try await h.formPost("/dashboard/benefits/check", a.owner, [("code", code)])
                XCTAssertEqual(checked.status, .unprocessableEntity, checked.text)
                XCTAssertTrue(checked.text.contains("isn&#39;t valid here") || checked.text.contains("isn't valid here"), checked.text)
            }
            try await eq(try await codeRow(h, b).status, "issued")
            try await eq(try await RewardRecord.find(b.reward.id.uuid, on: h.db)?.status, "active")
            try await eq(try await WalletPassRecord.find(b.passId.uuid, on: h.db)?.voided, false)
            // A's program edit changes A's program only.
            let saved = try await h.formPost("/dashboard/benefits/program", a.owner, [("program_name", "Acme Club"), ("summary", "Points on every cup."),
                                                                                    ("terms_version", "v2"), ("time_zone", "America/Phoenix"), ("tiers", "Silver: 100\nGold: 500")])
            XCTAssertEqual(saved.status, .seeOther, saved.text)
            try await eq(try await LoyaltyProgramRecord.query(on: h.db).filter(\.$businessId == a.businessId).first()?.programName, "Acme Club")
            try await eq(try await LoyaltyProgramRecord.query(on: h.db).filter(\.$businessId == b.businessId).first()?.programName, "Other Shop Club")
            // The existing validation applies: an unknown time zone or a bad tier line is refused.
            try await eq(try await h.formPost("/dashboard/benefits/program", a.owner, [("program_name", "Acme Club"), ("summary", "S"), ("terms_version", "v2"),
                                                                                   ("time_zone", "Mars/Olympus")]).status, .unprocessableEntity)
            try await eq(try await h.formPost("/dashboard/benefits/program", a.owner, [("program_name", "Acme Club"), ("summary", "S"), ("terms_version", "v2"),
                                                                                   ("time_zone", "UTC"), ("tiers", "Gold")]).status, .unprocessableEntity)
        }
    }

    func testRevokeVoidAndConsumeNeedAFreshPasskeyAndAreAudited() async throws {
        try await withHarness { h in
            let t = try await Self.tenant(h)
            // The passkey assertion is older than the step-up window.
            try await DashboardSessionRecord.query(on: h.db).set(\.$reauthAt, to: h.clock.now().addingTimeInterval(-86_400)).update()
            for (path, form) in [("/dashboard/benefits/rewards/\(t.reward.id)/revoke", [(String, String)]()), ("/dashboard/benefits/passes/\(t.passId)/void", []),
                                 ("/dashboard/benefits/check", [("code", t.code)])] {
                let refused = try await h.formPost(path, t.owner, form)
                XCTAssertEqual(refused.status, .forbidden, path)
                XCTAssertTrue(refused.text.contains("Confirm it&#39;s you") || refused.text.contains("Confirm it's you"), refused.text)
            }
            try await eq(try await codeRow(h, t).status, "issued")
            try await eq(try await RewardRecord.find(t.reward.id.uuid, on: h.db)?.status, "active")
            try await eq(try await WalletPassRecord.find(t.passId.uuid, on: h.db)?.voided, false)
            // After a fresh passkey assertion each works once and is attributed to the person in the audit chain.
            try await eq(try await h.dashReauth(t.owner, t.account).status, .ok)
            try await eq(try await h.formPost("/dashboard/benefits/passes/\(t.passId)/void", t.owner).status, .seeOther)
            try await eq(try await h.formPost("/dashboard/benefits/rewards/\(t.reward.id)/revoke", t.owner).status, .seeOther)
            try await eq(try await WalletPassRecord.find(t.passId.uuid, on: h.db)?.voided, true)
            try await eq(try await RewardRecord.find(t.reward.id.uuid, on: h.db)?.status, "revoked")
            for action in ["wallet.pass_voided", "reward.revoked"] {
                let event = try await XCTUnwrapAsync(await AuditEventRecord.query(on: h.db).filter(\.$action == action).first())
                XCTAssertEqual(event.actorKind, AuditActor.Kind.business.rawValue, action)
                XCTAssertEqual(event.actorId, id(t.account.userId), action)
            }
            // A revoked reward's outstanding code no longer redeems.
            let after = try await h.formPost("/dashboard/benefits/check", t.owner, [("code", t.code)])
            XCTAssertEqual(after.status, .unprocessableEntity, after.text)
        }
    }

    func testConsumeIsSingleUse() async throws {
        try await withHarness { h in
            let t = try await Self.tenant(h)
            let first = try await h.formPost("/dashboard/benefits/check", t.owner, [("code", t.code), ("location", "store-12")])
            XCTAssertEqual(first.status, .ok, first.text)
            XCTAssertTrue(first.text.contains("Free coffee"))
            let ref = h.ctx.subjects.subjectRef(businessId: BusinessID(t.businessId), consumerId: t.consumer.id).rawValue
            XCTAssertTrue(first.text.contains(ref), "the customer appears as the business's own reference")
            XCTAssertFalse(first.text.contains(t.consumer.id.uuid.uuidString.lowercased()))
            // The same code again (even spelt differently), from the console or the API: already used.
            let again = try await h.formPost("/dashboard/benefits/check", t.owner, [("code", t.code.lowercased().replacingOccurrences(of: "-", with: " "))])
            XCTAssertEqual(again.status, .unprocessableEntity, again.text)
            XCTAssertTrue(again.text.contains("already used"), again.text)
            try await eq(try await h.consume(t.business, code: t.code).status, .conflict)
            try await eq(try await AuditEventRecord.query(on: h.db).filter(\.$action == "reward.redeemed").count(), 1)
            try await eq(try await codeRow(h, t).locationCode, "store-12")
            // A loyalty card scan reports the member; nothing is spent.
            let member = try await h.formPost("/dashboard/benefits/check", t.owner, [("code", t.scanCode)])
            XCTAssertEqual(member.status, .ok, member.text)
            XCTAssertTrue(member.text.contains("Loyalty member"), member.text)
            // A tampered pass code is not valid here.
            let forged = String(t.scanCode.dropLast()) + (t.scanCode.hasSuffix("A") ? "B" : "A")
            try await eq(try await h.formPost("/dashboard/benefits/check", t.owner, [("code", forged)]).status, .unprocessableEntity)
        }
    }

    func testATestModeOrganizationCannotChangeOrRedeemLiveValue() async throws {
        try await withHarness { h in
            let t = try await Self.tenant(h)
            // Production access is not (or no longer) approved: the console acts in test mode, like a test key.
            try await BusinessOnboardingRecord.query(on: h.db).filter(\.$businessId == t.businessId).set(\.$goLiveStatus, to: OnboardingGoLive.requested.rawValue).update()
            let overview = try await h.page("/dashboard/benefits", t.owner)
            XCTAssertEqual(overview.status, .ok, overview.text)
            XCTAssertTrue(overview.text.contains("Test mode"))
            XCTAssertFalse(overview.text.contains("Save program"), "no program editor in test mode")
            try await eq(try await h.formPost("/dashboard/benefits/program", t.owner, [("program_name", "Hijacked"), ("summary", "S"), ("terms_version", "v9"),
                                                                                   ("time_zone", "UTC")]).status, .forbidden)
            // A real customer's code and pass are not valid here; the reward and pass cannot be revoked or voided.
            for code in [t.code, t.scanCode] { try await eq(try await h.formPost("/dashboard/benefits/check", t.owner, [("code", code)]).status, .unprocessableEntity) }
            try await eq(try await h.formPost("/dashboard/benefits/rewards/\(t.reward.id)/revoke", t.owner).status, .notFound)
            // Pass management is live-only, exactly like a test key (`Sandbox.requireLive`): refused before any lookup.
            try await eq(try await h.formPost("/dashboard/benefits/passes/\(t.passId)/void", t.owner).status, .forbidden)
            try await isFalse(try await h.page("/dashboard/benefits/passes", t.owner).text.contains(id(t.passId.uuid)))
            try await eq(try await codeRow(h, t).status, "issued")
            try await eq(try await RewardRecord.find(t.reward.id.uuid, on: h.db)?.status, "active")
            try await eq(try await LoyaltyProgramRecord.query(on: h.db).filter(\.$businessId == t.businessId).first()?.programName, "Acme Roasters Club")
        }
    }

    func testBusinessTextIsEscaped() async throws {
        try await withHarness { h in
            let t = try await Self.tenant(h, title: "<script>alert(1)</script> Free")
            let saved = try await h.formPost("/dashboard/benefits/program", t.owner, [("program_name", "<img src=x onerror=alert(2)>"), ("summary", "<b>bold</b>"),
                                                                                    ("terms_version", "v2"), ("time_zone", "UTC")])
            XCTAssertEqual(saved.status, .seeOther, saved.text)
            let page = try await h.page("/dashboard/benefits", t.owner).text
            XCTAssertFalse(page.contains("<script>alert(1)"))
            XCTAssertFalse(page.contains("<img src=x"))
            XCTAssertFalse(page.contains("<b>bold</b>"))
            XCTAssertTrue(page.contains("&lt;script&gt;alert(1)&lt;/script&gt; Free"))
            XCTAssertTrue(page.contains("&lt;b&gt;bold&lt;/b&gt;"))
            let checked = try await h.formPost("/dashboard/benefits/check", t.owner, [("code", t.code)])
            XCTAssertFalse(checked.text.contains("<script>alert(1)"))
        }
    }
}
