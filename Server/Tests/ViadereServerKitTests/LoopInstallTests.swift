import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Installable Loops (SECURITY.md §2.98 "Installed Loops"): what an install grants (this Loop, nothing else), what the business can see from
/// an install-only customer (answers only: no relationship, no subjectRef, no profile), the directory's reviewed-data-only rule, and abuse
/// controls (rate, cap, rollout, kill switches, blocks).
final class LoopInstallTests: XCTestCase {
    /// Global enablement only (an install records the business authorization itself).
    func enableLoops(_ h: TestHarness, _ consumer: TestConsumer) async throws {
        let text = LoopConsentCatalog.current
        var answers: [String: String] = [:]
        for check in text.checks { answers[check.id] = check.correctOptionId }
        let response = try await h.signed(consumer, .PUT, "/v1/loops/consent",
                                          body: try ViadereJSON.encode(LoopGlobalConsentRequest(textVersion: text.version, textDigest: text.digest, answers: answers, agree: true)))
        XCTAssertEqual(response.status, .ok, response.text)
    }

    func install(_ h: TestHarness, _ consumer: TestConsumer, _ loop: UUID, mode: LoopInstallMode = .installOnly, source: LoopInstallSource = .directory,
                 digest: String? = nil, agree: Bool = true) async throws -> HTTPResult {
        let text = LoopConsentCatalog.current
        return try await h.signed(consumer, .PUT, "/v1/loops/installed/\(loop.uuidString.lowercased())", body: try ViadereJSON.encode(
            LoopInstallRequest(mode: mode, source: source, textVersion: text.version, textDigest: digest ?? text.digest, agree: agree)))
    }

    func list(_ world: LoopWorld, _ publication: LoopPublicationRecord, category: LoopDirectoryCategory = .foodAndDrink, featured: Bool = false) async throws {
        try await LoopInstallService(db: world.h.db, ctx: world.h.ctx).setListing(publicationId: publication.id!, category: category, listed: true,
                                                                                    featured: featured, operatorId: world.reviewer1, reason: "Checked for the directory.")
    }

    func testAnInstallOnlyCustomerStartsTheLoopWithoutAnyRelationshipAndTheBusinessSeesOnlyTheAnswers() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            let publication = try await world.publish()
            try await list(world, publication, featured: true)
            // Another reviewed Loop of the same business, not installed: an install never opens the business's other Loops.
            let other = try await world.publish(LoopFixtures.pickup(title: "Order a cake", key: "cake"))
            let carol = try await h.readyConsumer(name: "Carol")
            try await enableLoops(h, carol)

            // Browse: the listed Loop, featured, with reviewed text only.
            let page = try await h.signed(carol, .GET, "/v1/loops/directory").json(LoopDirectoryPage.self)
            XCTAssertEqual(page.entries.map(\.loopId), [LoopDefinitionID(publication.definitionId)], "only the operator-listed Loop is browsable")
            XCTAssertEqual(page.featured.map(\.loopId), [LoopDefinitionID(publication.definitionId)])
            XCTAssertEqual(page.categories, [.foodAndDrink])
            let entry = try XCTUnwrap(page.entries.first)
            XCTAssertEqual(entry.title, "Schedule your pickup")
            XCTAssertFalse(entry.installed)
            XCTAssertFalse(entry.connected)
            XCTAssertEqual(entry.business.id, world.business.id)
            // Search and category filters.
            try await eq(try await h.signed(carol, .GET, "/v1/loops/directory?q=PICKUP").json(LoopDirectoryPage.self).entries.count, 1)
            try await eq(try await h.signed(carol, .GET, "/v1/loops/directory?q=corner").json(LoopDirectoryPage.self).entries.count, 1, "business names match")
            try await eq(try await h.signed(carol, .GET, "/v1/loops/directory?q=zzz").json(LoopDirectoryPage.self).entries.count, 0)
            try await eq(try await h.signed(carol, .GET, "/v1/loops/directory?category=travel").json(LoopDirectoryPage.self).entries.count, 0)
            try await eq(try await h.signed(carol, .GET, "/v1/loops/directory?category=medical").status, .unprocessableEntity)
            try await eq(try await h.signed(carol, .GET, "/v1/loops/directory?q=\(String(repeating: "a", count: 61))").status, .unprocessableEntity)
            // A business page lists every visible Loop of that business, listed or not.
            let businessPage = try await h.signed(carol, .GET, "/v1/loops/directory?business_id=\(world.business.id)").json(LoopDirectoryPage.self)
            XCTAssertEqual(Set(businessPage.entries.map(\.loopId)), [LoopDefinitionID(publication.definitionId), LoopDefinitionID(other.definitionId)])
            XCTAssertTrue(businessPage.featured.isEmpty)

            // Detail: the device gets the signed manifest and the reviewed definition and verifies them itself.
            let detail = try await h.signed(carol, .GET, "/v1/loops/directory/\(publication.definitionId.uuidString.lowercased())").json(LoopDirectoryDetail.self)
            let keys = try await h.signed(carol, .GET, "/v1/loops/keys").json(LoopPublicationKeySet.self).keys.compactMap(\.pinned)
            let manifest = try LoopPublicationManifest.verify(detail.manifest, keys: keys, now: h.clock.now())
            let definition = try XCTUnwrap(LoopDefinition.parse(detail.definition).definition)
            XCTAssertEqual(manifest.definitionHash, try definition.definitionHash())
            XCTAssertEqual(LoopPermissions.derive(definition, business: entry.business.displayName, connected: false).first?.fields, ["Time"])

            // Not connected: the Loop is not startable before installing.
            try await eq(try await world.start(carol, publication).status, .notFound)
            // Install only.
            let installed = try await install(h, carol, publication.definitionId)
            XCTAssertEqual(installed.status, .ok, installed.text)
            let result = try installed.json(LoopInstallResult.self)
            XCTAssertEqual(result.installed.mode, .installOnly)
            XCTAssertFalse(result.installed.connected)
            XCTAssertTrue(result.installed.isStartable)
            XCTAssertTrue(result.consent.businesses.contains { $0.businessId == world.business.id && $0.current }, "the install records the business authorization")
            // No relationship of any kind, so no subjectRef, no webhook, no messaging and no profile access for the business.
            try await eq(try await RelationshipRecord.query(on: h.db).filter(\.$consumerId == carol.id.uuid).count(), 0)
            try await eq(try await AuditEventRecord.query(on: h.db).filter(\.$action == "relationship.connected").filter(\.$consumerId == carol.id.uuid).count(), 0)
            try await isTrue(try await AuditEventRecord.query(on: h.db).filter(\.$action == "loop.installed").count() == 1)
            XCTAssertEqual(h.ctx.metrics.value(.loopInstalled), 1)

            // Startable now; the instance records the install, not a relationship.
            let available = try await h.signed(carol, .GET, "/v1/loops/available").json([LoopSummary].self)
            XCTAssertEqual(available.map(\.publicationId), [LoopPublicationID(publication.id!)], "only the installed Loop")
            XCTAssertEqual(available.first?.installed, true)
            XCTAssertEqual(available.first?.loopId, LoopDefinitionID(publication.definitionId))
            let view = try await world.instance(carol, publication)
            let record = try await LoopInstanceRecord.find(view.id.uuid, on: h.db)!
            XCTAssertEqual(record.relationshipId, LoopInstanceRecord.noRelationship)
            XCTAssertNotNil(record.installId)
            // The business's other Loop stays closed.
            try await eq(try await world.start(carol, other).status, .notFound)
            try await isTrue(try await world.refusals("relationship_inactive") >= 1)

            // The answers reach the hosted inbox; that is all the business gets.
            _ = try await world.submitPickup(carol, view.id)
            try await world.drain(.loopDelivery)
            let item = try await XCTUnwrapAsync(try await InboxItemRecord.query(on: h.db).filter(\.$instanceId == view.id.uuid).first())
            let detailForStaff = try await LoopInbox(db: h.db, ctx: h.ctx).open(itemId: item.id!, businessId: world.business.id.uuid, staffId: UUID())
            XCTAssertEqual(detailForStaff.answers.map(\.value), ["Morning"])
            // Its brand manifest (the icon) is readable without a connection.
            try await isTrue(try await h.signed(carol, .GET, "/v1/businesses/\(world.business.id)/brand").status != .notFound)

            // Your Loops lists it with the open instance.
            let mine = try await h.signed(carol, .GET, "/v1/loops/installed").json([InstalledLoop].self)
            XCTAssertEqual(mine.map(\.loopId), [LoopDefinitionID(publication.definitionId)])
            XCTAssertEqual(mine.first?.openInstances, [view.id])
            let reinstalled = try await install(h, carol, publication.definitionId)
            XCTAssertEqual(reinstalled.status, .ok, "installing again is idempotent")
            try await eq(try await LoopInstallRecord.query(on: h.db).count(), 1)
        }
    }

    func testInstallNeedsTheGlobalEducationAndTheCurrentTextAndRefusesWhatTheCustomerCannotSee() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            let publication = try await world.publish()
            let carol = try await h.readyConsumer(name: "Carol")
            try await eq(try await install(h, carol, publication.definitionId).status, .conflict)
            try await enableLoops(h, carol)
            try await eq(try await install(h, carol, publication.definitionId, digest: "sha256:" + String(repeating: "0", count: 64)).status, .unprocessableEntity)
            try await eq(try await install(h, carol, publication.definitionId, agree: false).status, .unprocessableEntity)
            try await eq(try await install(h, carol, UUID()).status, .notFound)
            // A Loop still in review is invisible.
            let pending = try await world.submit(LoopFixtures.pickup(title: "New pickup", key: "pending"))
            XCTAssertEqual(pending.stateValue, .inReview)
            try await eq(try await install(h, carol, pending.definitionId).status, .notFound)
            try await eq(try await h.signed(carol, .GET, "/v1/loops/directory/\(pending.definitionId.uuidString.lowercased())").status, .notFound)
            // Outside the rollout: invisible until allow-listed.
            try await world.publications.setRollout(publicationId: publication.id!, percent: 0, operatorId: world.reviewer1, reason: "Pause the rollout.")
            try await eq(try await install(h, carol, publication.definitionId).status, .notFound)
            try await world.publications.allowList(publicationId: publication.id!, consumerId: carol.id.uuid, operatorId: world.reviewer1)
            try await eq(try await install(h, carol, publication.definitionId).status, .ok)
            try await eq(try await RelationshipRecord.query(on: h.db).filter(\.$consumerId == carol.id.uuid).count(), 0)
            // Nothing was recorded by the refused attempts.
            try await eq(try await LoopInstallRecord.query(on: h.db).count(), 1)
        }
    }

    func testInstallAndConnectRunsTheNormalConnect() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            let publication = try await world.publish()
            let carol = try await h.readyConsumer(name: "Carol")
            try await enableLoops(h, carol)
            let response = try await install(h, carol, publication.definitionId, mode: .installAndConnect, source: .link)
            XCTAssertEqual(response.status, .ok, response.text)
            let result = try response.json(LoopInstallResult.self)
            XCTAssertTrue(result.installed.connected)
            XCTAssertEqual(result.installed.mode, .installAndConnect)
            let relationship = try await XCTUnwrapAsync(try await RelationshipRecord.query(on: h.db).filter(\.$consumerId == carol.id.uuid).first())
            XCTAssertEqual(relationship.status, "active")
            XCTAssertEqual(relationship.source, ConnectSource.link.rawValue)
            try await eq(try await AuditEventRecord.query(on: h.db).filter(\.$action == "relationship.connected").filter(\.$consumerId == carol.id.uuid).count(), 1)
            // A connected instance records the relationship as before.
            let view = try await world.instance(carol, publication)
            let record = try await LoopInstanceRecord.find(view.id.uuid, on: h.db)!
            XCTAssertEqual(record.relationshipId, relationship.id)
            XCTAssertNil(record.installId)
            // Disconnecting keeps the install: the Loop keeps working install-only.
            let disconnected = try await h.signed(carol, .DELETE, "/v1/relationships/\(relationship.id!.uuidString.lowercased())")
            XCTAssertTrue([.ok, .noContent].contains(disconnected.status), disconnected.text)
            let after = try await h.signed(carol, .GET, "/v1/loops/installed").json([InstalledLoop].self)
            XCTAssertEqual(after.first?.connected, false)
            try await eq(try await world.start(carol, publication).status, .created)
        }
    }

    func testUninstallCancelsOpenInstancesAndEndsTheAuthorizationItSupported() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            let publication = try await world.publish()
            let carol = try await h.readyConsumer(name: "Carol")
            try await enableLoops(h, carol)
            try await eq(try await install(h, carol, publication.definitionId).status, .ok)
            let view = try await world.instance(carol, publication)
            let removed = try await h.signed(carol, .DELETE, "/v1/loops/installed/\(publication.definitionId.uuidString.lowercased())")
            XCTAssertEqual(removed.status, .ok, removed.text)
            XCTAssertEqual(try removed.json([InstalledLoop].self), [])
            try await eq(try await LoopInstanceRecord.find(view.id.uuid, on: h.db)?.stateValue, .cancelled)
            let consent = try await h.signed(carol, .GET, "/v1/loops/consent").json(LoopConsentStatus.self)
            XCTAssertFalse(consent.businesses.contains { $0.businessId == world.business.id }, "the install was the only basis for the authorization")
            try await eq(try await world.act(carol, view.id, step: "s1", action: "next", inputs: ["slot": .string("am")]).status, .notFound)
            try await eq(try await world.start(carol, publication).status, .notFound)
            try await eq(try await h.signed(carol, .DELETE, "/v1/loops/installed/\(publication.definitionId.uuidString.lowercased())").status, .notFound)
            // A connected customer keeps the business authorization after uninstalling.
            try await eq(try await install(h, world.alice, publication.definitionId).status, .ok)
            try await eq(try await h.signed(world.alice, .DELETE, "/v1/loops/installed/\(publication.definitionId.uuidString.lowercased())").status, .ok)
            let alice = try await h.signed(world.alice, .GET, "/v1/loops/consent").json(LoopConsentStatus.self)
            XCTAssertTrue(alice.businesses.contains { $0.businessId == world.business.id })
            try await isTrue(try await AuditEventRecord.query(on: h.db).filter(\.$action == "loop.uninstalled").count() == 2)
        }
    }

    func testKillSwitchesSuspensionAndBlocksStillApplyToInstalledLoops() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            let publication = try await world.publish()
            // Alice is connected (LoopWorld); she installs too, then blocks the business: the block uninstalls its Loops.
            try await eq(try await install(h, world.alice, publication.definitionId).status, .ok)
            let carol = try await h.readyConsumer(name: "Carol")
            try await enableLoops(h, carol)
            try await eq(try await install(h, carol, publication.definitionId).status, .ok)
            let view = try await world.instance(carol, publication)
            // Per-Loop kill switch: suspended publications pause installed instances too.
            try await world.publications.setStatus(publicationId: publication.id!, to: .suspended, operatorId: world.reviewer1, reason: "Investigating reports.")
            try await eq(try await world.act(carol, view.id, step: "s1", action: "next", inputs: ["slot": .string("am")]).status, .conflict)
            try await isTrue(try await h.signed(carol, .GET, "/v1/loops/instances/\(view.id)").json(LoopInstanceView.self).paused)
            try await isTrue(try await h.signed(carol, .GET, "/v1/loops/directory?business_id=\(world.business.id)").json(LoopDirectoryPage.self).entries.isEmpty)
            let mine = try await h.signed(carol, .GET, "/v1/loops/installed").json([InstalledLoop].self)
            XCTAssertNil(mine.first?.publicationId, "listed, but not startable while suspended")
            try await world.publications.setStatus(publicationId: publication.id!, to: .active, operatorId: world.reviewer1, reason: "Resolved.")
            // Business switch.
            try await world.publications.setBusinessSwitch(businessId: world.business.id.uuid, on: true, operatorId: world.reviewer1, reason: "Pause everything.")
            try await eq(try await world.start(carol, publication).status, .conflict)
            try await world.publications.setBusinessSwitch(businessId: world.business.id.uuid, on: false, operatorId: world.reviewer1, reason: "Resume.")
            // Block (needs the connection, as blocking does today).
            let blocked = try await h.signed(world.alice, .PUT, "/v1/businesses/\(world.business.id)/preferences",
                                             body: try ViadereJSON.encode(BusinessPreferencesUpdate(blocked: true)))
            XCTAssertEqual(blocked.status, .ok, blocked.text)
            try await eq(try await h.signed(world.alice, .GET, "/v1/loops/installed").json([InstalledLoop].self).count, 0)
            try await eq(try await install(h, world.alice, publication.definitionId).status, .notFound)
            try await eq(try await world.start(world.alice, publication).status, .notFound)
        }
    }

    func testDirectoryListingIsAnOperatorDecisionWithLoopReviewer() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            let publication = try await world.publish()
            let outsider = try await LoopWorld.operatorId(h, "no-permission@viadere.test")
            let service = LoopInstallService(db: h.db, ctx: h.ctx)
            do {
                try await service.setListing(publicationId: publication.id!, category: .shopping, listed: true, featured: true, operatorId: outsider, reason: "x")
                XCTFail("an operator without loop_reviewer cannot list a Loop")
            } catch let error as APIError { XCTAssertEqual(error.status, .forbidden) }
            do {
                try await service.setListing(publicationId: publication.id!, category: LoopDirectoryCategory(rawValue: "health"), listed: true, featured: false,
                                             operatorId: world.reviewer1, reason: "x")
                XCTFail("unknown category")
            } catch let error as APIError { XCTAssertEqual(error.status, .unprocessableEntity) }
            try await service.setListing(publicationId: publication.id!, category: .shopping, listed: false, featured: true, operatorId: world.reviewer1, reason: "Not yet.")
            let row = try await XCTUnwrapAsync(try await LoopDirectoryListingRecord.query(on: h.db).first())
            XCTAssertFalse(row.featured, "an unlisted Loop is never featured")
            try await isTrue(try await AuditEventRecord.query(on: h.db).filter(\.$action == "loop.directory_listing_changed").count() == 1)
            // The operator console form needs a fresh passkey assertion and the permission.
            let (op, account) = try await h.makeOperator()
            try await eq(try await h.dashReauth(op, account).status, .ok)
            let form = try await h.formPost("/operator/loops/publications/\(publication.id!.uuidString.lowercased())/listing", op,
                                            [("category", "food_and_drink"), ("listed", "on"), ("reason", "Directory check.")])
            XCTAssertEqual(form.status, .forbidden, "ops@viadere.test has no loop_reviewer yet")
            try await OperatorPermissions(db: h.db, ctx: h.ctx).set(email: "ops@viadere.test", permission: .loopReviewer, granted: true)
            try await eq(try await h.formPost("/operator/loops/publications/\(publication.id!.uuidString.lowercased())/listing", op,
                                              [("category", "food_and_drink"), ("listed", "on"), ("reason", "Directory check.")]).status, .seeOther)
            let listed = try await LoopDirectoryListingRecord.query(on: h.db).first()
            XCTAssertEqual(listed?.category, "food_and_drink")
            XCTAssertEqual(listed?.listed, true)
        }
    }

    func testInstallsAreRateLimitedAndCappedPerAccount() async throws {
        try await withHarness({ config in
            config.loops.maxInstalledPerAccount = 1
            config.loops.installRate = .perHour(3, burst: 3)
        }) { h in
            let world = try await LoopWorld.build(h)
            let first = try await world.publish()
            let second = try await world.publish(LoopFixtures.pickup(title: "Order a cake", key: "cake"))
            let carol = try await h.readyConsumer(name: "Carol")
            try await enableLoops(h, carol)
            try await eq(try await install(h, carol, first.definitionId).status, .ok)
            try await eq(try await install(h, carol, second.definitionId).status, .conflict)
            try await eq(try await install(h, carol, first.definitionId).status, .ok, "re-installing an installed Loop is not a new one")
            try await eq(try await install(h, carol, first.definitionId).status, .tooManyRequests)
        }
    }

    func testTheInstallLinkLandingNamesOnlyFullyLaunchedLoopsAndTheAppSiteAssociationCoversIt() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            let publication = try await world.publish()
            let path = "/lp/\(publication.definitionId.uuidString.lowercased())"
            let launched = try await h.request(.GET, path)
            XCTAssertEqual(launched.status, .ok)
            XCTAssertTrue(launched.text.contains("Schedule your pickup"))
            XCTAssertTrue(launched.text.contains("Corner Bakery"))
            try await world.publications.setRollout(publicationId: publication.id!, percent: 10, operatorId: world.reviewer1, reason: "Slow down.")
            let partial = try await h.request(.GET, path)
            XCTAssertEqual(partial.status, .ok)
            XCTAssertFalse(partial.text.contains("Schedule your pickup"), "a Loop still rolling out is not named to anyone with the link")
            try await isTrue(try await !h.request(.GET, "/lp/\(UUID().uuidString.lowercased())").text.contains("Built by"))
            try await eq(try await h.request(.GET, "/lp/not-a-uuid").status, .notFound)
            let aasa = try await h.request(.GET, "/.well-known/apple-app-site-association")
            XCTAssertTrue(aasa.text.contains("\"/lp/*\""))
        }
    }
}

/// `XCTUnwrap` for an async expression.
func XCTUnwrapAsync<T>(_ expression: @autoclosure () async throws -> T?, file: StaticString = #filePath, line: UInt = #line) async throws -> T {
    let value = try await expression()
    return try XCTUnwrap(value, file: file, line: line)
}
