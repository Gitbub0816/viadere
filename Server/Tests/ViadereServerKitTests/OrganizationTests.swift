import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// WP-1.1, WP-1.5, WP-1.7 security tests (plan 5.4): cross-tenant leakage in All views (D3.T1), selector manipulation (D3.T2), revoked
/// businesses (D3.T8), expired items, mute and block, delegates, keyset paging and incremental sync.
final class OrganizationTests: XCTestCase {
    private func alerts(_ h: TestHarness, _ consumer: TestConsumer, _ query: String = "") async throws -> AlertPage {
        let response = try await h.signed(consumer, .GET, "/v1/alerts" + query)
        XCTAssertEqual(response.status, .ok, response.text)
        return try response.json(AlertPage.self)
    }

    // MARK: D3.T1 cross-tenant leakage in All views

    func testAllViewsNeverShowAnotherTenantsRowsOrABusinessTheCustomerLeft() async throws {
        try await withHarness { h in
            let world = try await TenantWorld.build(h)
            for name in ["alice", "bob", "sam"] { try await LeakageMatrix.assertNoLeak(world, consumer: name) }
            // Alice's All view holds exactly her shop and bank items (and nothing of the gym she left).
            let page = try await alerts(h, world.alice)
            XCTAssertEqual(Set(page.items.compactMap(\.business?.id)), [world.shop.id, world.bank.id])
            XCTAssertEqual(page.items.count, 5)
        }
    }

    // MARK: D3.T2 selector manipulation

    func testABusinessFilterOutsideTheCallersConnectionsIsNotFoundEverywhere() async throws {
        try await withHarness { h in
            let world = try await TenantWorld.build(h)
            for business in [world.cafe.id, world.stranger.id, BusinessID()] {
                for path in LeakageMatrix.businessScoped(business) {
                    let response = try await h.signed(world.alice, .GET, path)
                    XCTAssertEqual(response.status, .notFound, "\(path): \(response.text)")
                }
                let put = try await h.signed(world.alice, .PUT, "/v1/businesses/\(business)/preferences", body: try ViadereJSON.encode(BusinessPreferencesUpdate(favorite: true)))
                XCTAssertEqual(put.status, .notFound, put.text)
            }
            // A malformed filter is a validation error, not a silent All view.
            let malformed = try await h.signed(world.alice, .GET, "/v1/alerts?business_id=not-a-uuid")
            XCTAssertEqual(malformed.status, .unprocessableEntity, malformed.text)
            // A business the customer left is no longer a valid filter for All-view lists either.
            let left = try await h.signed(world.alice, .GET, "/v1/alerts?business_id=\(world.dropped.id)")
            XCTAssertEqual(left.status, .notFound, left.text)
            // The selected business narrows the list to that business only.
            let shopOnly = try await alerts(h, world.alice, "?business_id=\(world.shop.id)")
            XCTAssertFalse(shopOnly.items.isEmpty)
            XCTAssertTrue(shopOnly.items.allSatisfy { $0.business?.id == world.shop.id })
        }
    }

    func testADelegateSeesOnlyGrantedPurposesAndBusinesses() async throws {
        try await withHarness { h in
            let world = try await TenantWorld.build(h)
            let page = try await alerts(h, world.sam)
            XCTAssertFalse(page.items.isEmpty)
            XCTAssertTrue(page.items.allSatisfy { $0.business?.id == world.shop.id && $0.purpose == .transactional }, "\(page.items.map(\.title))")
            XCTAssertFalse(page.items.contains { $0.alertId == AlertIdentifier.make(.interaction, world.interactions["alice/shop/security"]!.uuid) })
            // The grant's business is a valid filter for the delegate; Alice's bank is not.
            let shop = try await h.signed(world.sam, .GET, "/v1/alerts?business_id=\(world.shop.id)")
            XCTAssertEqual(shop.status, .ok, shop.text)
            let bank = try await h.signed(world.sam, .GET, "/v1/alerts?business_id=\(world.bank.id)")
            XCTAssertEqual(bank.status, .notFound, bank.text)
        }
    }

    // MARK: D3.T8 revoked or suspended businesses; expiry

    func testItemsOfASuspendedBusinessAreNeverActionable() async throws {
        try await withHarness { h in
            let world = try await TenantWorld.build(h)
            // Flip the status directly (a race with the suspension's own cancellation): the read model must not offer the action anyway.
            try await BusinessRecord.query(on: h.db).filter(\.$id == world.bank.id.uuid).set(\.$verificationStatus, to: VerificationStatus.suspended.rawValue).update()
            let page = try await alerts(h, world.alice, "?status=pending")
            let bankItems = page.items.filter { $0.business?.id == world.bank.id }
            XCTAssertFalse(bankItems.isEmpty)
            XCTAssertTrue(bankItems.allSatisfy { !$0.actionable && !$0.isActionable(at: h.clock.now()) })
            XCTAssertTrue(page.items.filter { $0.business?.id == world.shop.id && $0.actionRequired }.allSatisfy(\.actionable))
        }
    }

    func testExpiredItemsAreNeverReturnedAsPendingOrActionable() async throws {
        try await withHarness { h in
            let world = try await TenantWorld.build(h)
            let short = try await world.issueConfirm(world.shop, world.rel("alice", "shop"), title: "Quick one", ttl: 60)
            let id = AlertIdentifier.make(.interaction, short.uuid)
            let before = try await alerts(h, world.alice, "?status=pending")
            XCTAssertTrue(before.items.contains { $0.alertId == id && $0.actionable })
            h.clock.advance(by: 61)
            let after = try await alerts(h, world.alice, "?status=pending")
            XCTAssertFalse(after.items.contains { $0.alertId == id })
            let expired = try await alerts(h, world.alice, "?status=expired").items.first { $0.alertId == id }
            XCTAssertEqual(expired?.status, .expired)
            XCTAssertEqual(expired?.actionable, false)
            let all = try await alerts(h, world.alice).items.first { $0.alertId == id }
            XCTAssertEqual(all?.status, .expired)
            XCTAssertEqual(all?.actionable, false)
        }
    }

    // MARK: Paging, incremental sync, seen state

    func testKeysetPagesAreStableAndSinceReturnsChangedItems() async throws {
        try await withHarness { h in
            let world = try await TenantWorld.build(h)
            for i in 0..<6 {
                h.clock.advance(by: 1)
                try await world.issueConfirm(world.bank, world.rel("alice", "bank"), title: "Paged \(i)")
            }
            var seen: [String] = []
            var cursor: String?
            var pages = 0
            repeat {
                let page = try await alerts(h, world.alice, "?limit=4" + (cursor.map { "&cursor=\($0)" } ?? ""))
                seen += page.items.map(\.alertId)
                cursor = page.nextCursor
                pages += 1
            } while cursor != nil && pages < 10
            XCTAssertEqual(seen.count, 11)
            XCTAssertEqual(Set(seen).count, seen.count, "no duplicates across pages")
            let first = try await alerts(h, world.alice)
            XCTAssertEqual(first.items.map(\.createdAt), first.items.map(\.createdAt).sorted(by: >))

            // Answer one request; an incremental sync returns it as completed, and nothing else.
            h.clock.advance(by: 5)
            let token = first.syncToken
            h.clock.advance(by: 5)
            let target = world.interactions["alice/shop/confirm"]!
            let interaction = try await h.consumerInteraction(world.alice, id: target)
            let decided = try await h.decide(world.alice, id: target, signed: try await h.decision(world.alice, interaction: interaction, decision: .confirm))
            XCTAssertEqual(decided.status, .ok, decided.text)
            let delta = try await alerts(h, world.alice, "?since=\(token)")
            XCTAssertEqual(delta.items.map(\.alertId), [AlertIdentifier.make(.interaction, target.uuid)])
            XCTAssertEqual(delta.items.first?.status, .completed)
            XCTAssertEqual(delta.items.first?.actionable, false)
        }
    }

    func testSeenStateIsPerAccountAndFiltersUnread() async throws {
        try await withHarness { h in
            let world = try await TenantWorld.build(h)
            let page = try await alerts(h, world.alice)
            XCTAssertTrue(page.items.allSatisfy(\.unread))
            let mark = Array(page.items.prefix(2).map(\.alertId))
            let seen = try await h.signedPost(world.alice, "/v1/alerts/seen", AlertSeenRequest(alertIds: mark))
            XCTAssertEqual(seen.status, .ok, seen.text)
            let unread = try await alerts(h, world.alice, "?unread=1")
            XCTAssertEqual(unread.items.count, page.items.count - 2)
            XCTAssertFalse(unread.items.contains { mark.contains($0.alertId) })
            // Sam sees the same shop items, still unread for him (seen state is per viewer).
            let samShop = try await alerts(h, world.sam)
            XCTAssertTrue(samShop.items.allSatisfy(\.unread))
            let bad = try await h.signedPost(world.alice, "/v1/alerts/seen", AlertSeenRequest(alertIds: ["interaction:'; DROP TABLE alert_seen; --"]))
            XCTAssertEqual(bad.status, .unprocessableEntity, bad.text)
        }
    }

    func testApproveRequestsAndSecurityNoticesAppearAsAlerts() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            let (created, _) = try await h.createRequest(f)
            XCTAssertEqual(created.status, .created, created.text)
            let page = try await alerts(h, f.phone.consumer, "?status=pending")
            let approval = try XCTUnwrap(page.items.first { $0.source == .approveRequest })
            XCTAssertEqual(approval.category, .approval)
            XCTAssertEqual(approval.target?.kind, .approveDelivery)
            XCTAssertTrue(approval.actionable)
            // The push and the list name the same record with the same event id.
            let device = try await h.pendingRequests(f.phone.consumer)
            XCTAssertEqual(device.first?.alert?.eventId, approval.eventId)
            XCTAssertEqual(device.first?.id.uuidString.lowercased(), approval.target?.id)
            // Account notices (the enrollment created some) are Viadere's own: no business, purpose security.
            let all = try await alerts(h, f.phone.consumer)
            XCTAssertTrue(all.items.filter { $0.source == .securityNotice }.allSatisfy { $0.business == nil && $0.purpose == .security })
            // A business filter never shows Viadere's account notices.
            let filtered = try await alerts(h, f.phone.consumer, "?business_id=\(f.business.id)")
            XCTAssertFalse(filtered.items.contains { $0.source == .securityNotice })
        }
    }

    // MARK: WP-1.5 mute and block

    func testMuteChangesInterruptionOnlyAndNeverTouchesSecurity() async throws {
        try await withHarness { h in
            let world = try await TenantWorld.build(h)
            let token = try await h.signedPost(world.alice, "/v1/push/apns-token",
                                               APNsTokenRegistration(token: String(repeating: "ab", count: 32), environment: .sandbox, bundleId: "com.viadere.app"))
            XCTAssertTrue([.ok, .created, .noContent].contains(token.status), token.text)
            let put = try await h.signed(world.alice, .PUT, "/v1/businesses/\(world.shop.id)/preferences",
                                         body: try ViadereJSON.encode(BusinessPreferencesUpdate(muteLevel: .allNonEssential)))
            XCTAssertEqual(put.status, .ok, put.text)
            XCTAssertEqual(try put.json(BusinessPreferences.self).muteLevel, .allNonEssential)
            let before = h.push.sent.count
            let signIn = try await world.issueSignIn(world.shop, world.rel("alice", "shop"))
            let update = try await world.issueStatus(world.shop, world.rel("alice", "shop"), title: "Your order shipped")
            let pushes = h.push.sent.dropFirst(before)
            let securityPush = pushes.first { $0.interactionId == signIn.description }
            let updatePush = pushes.first { $0.interactionId == update.description }
            XCTAssertNotNil(securityPush)
            XCTAssertNotEqual(securityPush?.interruptionLevel, "passive", "mute never silences a security request")
            XCTAssertEqual(updatePush?.interruptionLevel, "passive", "a muted informational update arrives quietly")
            // Muted items stay in Alerts.
            let page = try await alerts(h, world.alice)
            XCTAssertTrue(page.items.contains { $0.alertId == AlertIdentifier.make(.interaction, signIn.uuid) })
            XCTAssertTrue(page.items.contains { $0.alertId == AlertIdentifier.make(.interaction, update.uuid) })
            // A timed mute must end in the future and within a year.
            let past = try await h.signed(world.alice, .PUT, "/v1/businesses/\(world.shop.id)/preferences",
                                          body: try ViadereJSON.encode(BusinessPreferencesUpdate(muteLevel: .promotional, muteUntil: h.clock.now().addingTimeInterval(-1))))
            XCTAssertEqual(past.status, .unprocessableEntity, past.text)
        }
    }

    func testBlockEndsTheConnectionAndRefusesReconnectUntilUnblocked() async throws {
        try await withHarness { h in
            let world = try await TenantWorld.build(h)
            let pending = world.interactions["alice/bank/confirm"]!
            let block = try await h.signed(world.alice, .PUT, "/v1/businesses/\(world.bank.id)/preferences",
                                           body: try ViadereJSON.encode(BusinessPreferencesUpdate(blocked: true)))
            XCTAssertEqual(block.status, .ok, block.text)
            XCTAssertTrue(try block.json(BusinessPreferences.self).blocked)
            // Disconnect semantics: pending requests cancelled, nothing new can be delivered.
            let record = try await InteractionRecord.find(pending.uuid, on: h.db)
            XCTAssertEqual(record?.status, InteractionStatus.cancelled.rawValue)
            let issued = try await h.issue(world.bank, relationship: world.rel("alice", "bank"), payload: .confirm(ConfirmPayload(title: "Still there?")), purpose: .transactional)
            XCTAssertNotEqual(issued.status, .created, issued.text)
            // The customer cannot reconnect by accident while blocked.
            let reconnect = try await h.signedPost(world.alice, APIRoutes.relationshipConnect.template, ConnectRequest(businessId: world.bank.id, source: .code))
            XCTAssertEqual(reconnect.status, .conflict, reconnect.text)
            // Block survives in the directory; unblocking does not reconnect.
            let directory = try await h.signed(world.alice, .GET, "/v1/businesses").json([ConnectedBusiness].self)
            let entry = try XCTUnwrap(directory.first { $0.business.id == world.bank.id })
            XCTAssertTrue(entry.preferences.blocked)
            XCTAssertEqual(entry.status, .disconnected)
            let unblock = try await h.signed(world.alice, .PUT, "/v1/businesses/\(world.bank.id)/preferences",
                                             body: try ViadereJSON.encode(BusinessPreferencesUpdate(blocked: false)))
            XCTAssertEqual(unblock.status, .ok, unblock.text)
            let again = try await h.signedPost(world.alice, APIRoutes.relationshipConnect.template, ConnectRequest(businessId: world.bank.id, source: .code))
            XCTAssertTrue([.ok, .created].contains(again.status), again.text)
            // Bob's connection with the same bank is untouched.
            let bobs = try await alerts(h, world.bob, "?business_id=\(world.bank.id)")
            XCTAssertTrue(bobs.items.contains { $0.actionable })
        }
    }

    func testFavoritesOrderTheDirectoryAndPreferencesArePerAccount() async throws {
        try await withHarness { h in
            let world = try await TenantWorld.build(h)
            let fav = try await h.signed(world.alice, .PUT, "/v1/businesses/\(world.bank.id)/preferences",
                                         body: try ViadereJSON.encode(BusinessPreferencesUpdate(favorite: true)))
            XCTAssertEqual(fav.status, .ok, fav.text)
            let directory = try await h.signed(world.alice, .GET, "/v1/businesses").json([ConnectedBusiness].self)
            XCTAssertEqual(directory.first?.business.id, world.bank.id)
            XCTAssertFalse(directory.contains { $0.business.id == world.cafe.id || $0.business.id == world.stranger.id })
            let bobs = try await h.signed(world.bob, .GET, "/v1/businesses/\(world.bank.id)/preferences").json(BusinessPreferences.self)
            XCTAssertFalse(bobs.favorite)
            let empty = try await h.signed(world.alice, .PUT, "/v1/businesses/\(world.bank.id)/preferences", body: Data("{}".utf8))
            XCTAssertEqual(empty.status, .unprocessableEntity, empty.text)
        }
    }

    // MARK: Benefits and conversations

    func testBenefitsAndConversationsHonorTheSelectedBusiness() async throws {
        try await withHarness { h in
            let world = try await TenantWorld.build(h)
            for (business, title) in [(world.shop, "Free coffee"), (world.bank, "Fee waiver"), (world.cafe, "Muffin")] {
                let issued = try await h.businessPost(business, APIRoutes.businessIssueReward.template,
                                                      IssueRewardRequest(title: title, kind: .coupon, validUntil: h.clock.now().addingTimeInterval(86_400), idempotencyKey: UUID().uuidString))
                XCTAssertEqual(issued.status, .created, issued.text)
            }
            let all = try await h.signed(world.alice, .GET, "/v1/benefits").json(RewardsOverview.self)
            XCTAssertEqual(Set(all.rewards.map(\.reward.title)), ["Free coffee", "Fee waiver"])
            let shop = try await h.signed(world.alice, .GET, "/v1/benefits?business_id=\(world.shop.id)&filter=available").json(RewardsOverview.self)
            XCTAssertEqual(shop.rewards.map(\.reward.title), ["Free coffee"])
            let bad = try await h.signed(world.alice, .GET, "/v1/benefits?filter=everything")
            XCTAssertEqual(bad.status, .unprocessableEntity, bad.text)

            let started = try await h.signedPost(world.alice, APIRoutes.conversationStart.template, StartConversationRequest(businessId: world.shop.id))
            XCTAssertEqual(started.status, .ok, started.text)
            let session = try started.json(ConversationSummary.self)
            _ = try await h.signedPost(world.alice, APIRoutes.conversationStart.template, StartConversationRequest(businessId: world.bank.id))
            let filtered = try await h.signed(world.alice, .GET, "/v1/conversations?business_id=\(world.shop.id)").json([ConversationSummary].self)
            XCTAssertEqual(filtered.map(\.business.id), [world.shop.id])
            let archived = try await h.signed(world.alice, .PUT, "/v1/conversations/\(session.id)/state", body: try ViadereJSON.encode(ConversationStateUpdate(archived: true)))
            XCTAssertEqual(archived.status, .ok, archived.text)
            let visible = try await h.signed(world.alice, .GET, "/v1/conversations").json([ConversationSummary].self)
            XCTAssertFalse(visible.contains { $0.id == session.id })
            let withArchived = try await h.signed(world.alice, .GET, "/v1/conversations?archived=1").json([ConversationSummary].self)
            XCTAssertEqual(withArchived.first { $0.id == session.id }?.archived, true)
            // Bob cannot archive Alice's thread.
            let foreign = try await h.signed(world.bob, .PUT, "/v1/conversations/\(session.id)/state", body: try ViadereJSON.encode(ConversationStateUpdate(muted: true)))
            XCTAssertEqual(foreign.status, .notFound, foreign.text)
        }
    }
}
