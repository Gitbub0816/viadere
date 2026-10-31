@preconcurrency import Crypto
import Fluent
import Foundation
import NIOHTTP1
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Wallet completion (docs/WALLET.md): signed pass codes and business validation, the business pass API, operational updates,
/// voiding on disconnect and cancellation, localization and relevance, and what a pass may contain. Every security property here
/// was written as a failing exploit test first.
final class WalletBusinessTests: XCTestCase {
    private struct Scene {
        var business: TestBusiness
        var consumer: TestConsumer
        var relationship: Relationship
    }

    private func scene(_ h: TestHarness, name: String = "Juniper Coffee", handle: String = "junipercoffee") async throws -> Scene {
        let business = try await h.makeBusiness(name: name, handle: handle)
        try await h.saveProgram(business)
        let consumer = try await h.readyConsumer()
        let relationship = try await h.connect(consumer, to: business)
        return Scene(business: business, consumer: consumer, relationship: relationship)
    }

    private func consumerIssue(_ h: TestHarness, _ s: Scene, kind: WalletPassKind = .storeCard, rewardId: RewardID? = nil,
                               interactionId: InteractionID? = nil) async throws -> WalletPassMetadata {
        let response = try await h.signedPost(s.consumer, "/v1/wallet/passes", WalletPassIssueRequest(kind: kind, businessId: s.business.id, rewardId: rewardId,
                                                                                                    interactionId: interactionId))
        XCTAssertTrue([.created, .ok].contains(response.status), response.text)
        return try response.json(WalletPassMetadata.self)
    }

    private func scan(_ h: TestHarness, _ b: TestBusiness, _ code: String, key: String? = nil) async throws -> HTTPResult {
        try await h.businessPost(b, "/v1/business/wallet/scan", WalletScanRequest(code: code), key: key)
    }

    private func download(_ h: TestHarness, _ s: Scene, _ id: WalletPassID) async throws -> PKPassContents {
        let response = try await h.signed(s.consumer, .GET, "/v1/wallet/passes/\(id)")
        XCTAssertEqual(response.status, .ok, response.text)
        return try PKPassContents(response.body)
    }

    private func record(_ h: TestHarness, _ id: WalletPassID) async throws -> WalletPassRecord {
        try await WalletPassRecord.find(id.uuid, on: h.db).unwrap()
    }

    private func ticket(_ h: TestHarness, _ s: Scene, validFrom: Date? = nil, validUntil: Date? = nil, startsAt: Date? = nil) async throws -> InteractionID {
        let payload = TicketPayload(title: "Jazz Night", ticketType: "event", holderName: "Samantha Holder", validFrom: validFrom ?? h.clock.now(),
                                    validUntil: validUntil ?? h.clock.now().addingTimeInterval(5 * 86_400), venue: "Orpheum Theatre", seat: "Row F · Seat 12",
                                    startsAt: startsAt ?? h.clock.now().addingTimeInterval(3 * 86_400))
        let issued = try await h.issue(s.business, relationship: s.relationship, payload: .ticket(payload), purpose: .transactional, ttl: 86_400)
        XCTAssertEqual(issued.status, .created, issued.text)
        return try issued.json(Interaction.self).id
    }

    private func testKey(_ h: TestHarness, _ b: TestBusiness) async throws -> String {
        try await BusinessAPIKeys.issue(businessId: b.record.id!, name: "test", live: false, scopes: BusinessAPIKeys.Scope.all,
                                        capabilities: Capability.operational, now: h.clock.now(), on: h.db).key
    }

    private func errorDetails(_ result: HTTPResult) throws -> [String: String]? {
        try ViadereJSON.decode(APIErrorResponse.self, from: result.body).error.details
    }

    // MARK: Signed presentation codes

    func testThePassQRIsASignedCodeAndForgedAlteredOrForeignCodesAreAllTheSame404() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            try await h.enroll(s.consumer, s.business)
            try await h.adjustPoints(s.business, s.relationship, 40)
            let metadata = try await consumerIssue(h, s)
            let code = try XCTUnwrap(metadata.scanCode, "the holder sees the same code the pass shows")
            XCTAssertTrue(WalletScanCode.isWellFormed(code))
            // The pass's QR is that code, not the serial number (the PassKit lookup key) and nothing about the person.
            let pass = try await download(h, s, metadata.id)
            let barcode = try XCTUnwrap((pass.passJSON["barcodes"] as? [[String: Any]])?.first)
            XCTAssertEqual(barcode["message"] as? String, code)
            XCTAssertEqual(barcode["format"] as? String, "PKBarcodeFormatQR")
            XCTAssertNil(barcode["altText"])
            XCTAssertFalse(code.contains(metadata.serialNumber))

            // A genuine code identifies the member to their own business.
            let accepted = try await scan(h, s.business, code)
            XCTAssertEqual(accepted.status, .ok, accepted.text)
            let result = try accepted.json(WalletScanResult.self)
            XCTAssertEqual(result.outcome, .member)
            XCTAssertEqual(result.pointsBalance, 40)
            XCTAssertEqual(result.relationshipId, s.relationship.id)
            XCTAssertEqual(result.passId, metadata.id)

            // Exploit attempts: every one is the same 404, so nothing distinguishes "almost right" from garbage.
            let body = try XCTUnwrap(Base64URL.decode(String(code.dropFirst(WalletScanCode.prefix.count))))
            var flippedTag = body
            flippedTag[flippedTag.count - 1] ^= 0x01
            var otherPass = body
            otherPass[0] ^= 0x01
            var bumpedGeneration = body
            bumpedGeneration[19] = 1
            let wrongKey = SymmetricKey(data: Data(repeating: 0x5A, count: 32))
            let payload = Data(body.prefix(20))
            let foreignTag = Data(HMAC<SHA256>.authenticationCode(for: Data("wallet-scan-v1\n".utf8) + payload, using: wrongKey)).prefix(16)
            let attempts = [
                WalletScanCode.prefix + Base64URL.encode(flippedTag),
                WalletScanCode.prefix + Base64URL.encode(otherPass),
                WalletScanCode.prefix + Base64URL.encode(bumpedGeneration),
                WalletScanCode.prefix + Base64URL.encode(payload + foreignTag),
                String(code.dropLast()),
                metadata.serialNumber,
                "K7M2Q-9XPB4",
                "",
                String(repeating: "A", count: 4000),
            ]
            var bodies = Set<String>()
            for attempt in attempts {
                let response = try await scan(h, s.business, attempt)
                XCTAssertEqual(response.status, .notFound, attempt.prefix(20) + "…")
                bodies.insert(try ViadereJSON.decode(APIErrorResponse.self, from: response.body).error.message)
            }
            XCTAssertEqual(bodies.count, 1, "one indistinguishable refusal: \(bodies)")

            // Another business scanning this pass learns nothing either.
            let rival = try await h.makeBusiness(name: "Rival Roasters", handle: "rivalroasters")
            let foreign = try await scan(h, rival, code)
            XCTAssertEqual(foreign.status, .notFound)
            XCTAssertEqual(try ViadereJSON.decode(APIErrorResponse.self, from: foreign.body).error.message, bodies.first)
            // A test-mode key of the right business never matches a real pass.
            try await eq(try await scan(h, s.business, code, key: try await testKey(h, s.business)).status, .notFound)
        }
    }

    func testScanningIsRateLimitedPerBusinessSoCodesCannotBeGuessedAtVolume() async throws {
        try await withHarness({ $0.rateLimits.walletScan = .perMinute(5, burst: 5) }) { h in
            let s = try await scene(h)
            var statuses: [HTTPStatus] = []
            for index in 0..<8 {
                let guess = WalletScanCode.prefix + Base64URL.encode(Data((0..<36).map { UInt8(($0 + index) & 0xFF) }))
                statuses.append(try await scan(h, s.business, guess).status)
            }
            XCTAssertEqual(statuses.prefix(5).allSatisfy { $0 == .notFound }, true, "\(statuses)")
            XCTAssertTrue(statuses.suffix(3).allSatisfy { $0 == .tooManyRequests }, "\(statuses)")
        }
    }

    func testRotatingTheCodeKillsAPhotographedQRAndPushesTheNewOne() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            try await h.enroll(s.consumer, s.business)
            let metadata = try await consumerIssue(h, s)
            let old = try XCTUnwrap(metadata.scanCode)
            try await eq(try await scan(h, s.business, old).status, .ok)
            let before = try await WalletPushOutboxRecord.query(on: h.db).count()
            let rotated = try await h.business(s.business, .PATCH, "/v1/business/wallet/passes/\(metadata.id)",
                                               body: try ViadereJSON.encode(UpdateWalletPassRequest(rotateScanCode: true)))
            XCTAssertEqual(rotated.status, .ok, rotated.text)
            let after = try await WalletPushOutboxRecord.query(on: h.db).count()
            XCTAssertEqual(after, before + 1, "the new code is pushed to the customer's devices")
            // The screenshot of the old QR is now worthless; the pass and the app carry the new one.
            try await eq(try await scan(h, s.business, old).status, .notFound)
            let refreshed = try await h.signed(s.consumer, .GET, "/v1/wallet/passes").json([WalletPassMetadata].self)
            let fresh = try XCTUnwrap(refreshed.first?.scanCode)
            XCTAssertNotEqual(fresh, old)
            let refreshedPass = try await download(h, s, metadata.id)
            let barcode = try XCTUnwrap((refreshedPass.passJSON["barcodes"] as? [[String: Any]])?.first)
            XCTAssertEqual(barcode["message"] as? String, fresh)
            try await eq(try await scan(h, s.business, fresh).status, .ok)
        }
    }

    // MARK: Coupons and tickets

    func testACouponPassRedeemsExactlyOnceEvenUnderConcurrentScansAndReplaysAreRefused() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            // Not claimed in the app: presenting the pass is the customer's act of using it.
            let reward = try await h.reward(s.business, title: "Free pastry", kind: .coupon, relationship: s.relationship)
            let metadata = try await consumerIssue(h, s, kind: .coupon, rewardId: reward.id)
            let code = try XCTUnwrap(metadata.scanCode)
            let results = try await withThrowingTaskGroup(of: HTTPResult.self) { group in
                let business = s.business
                for _ in 0..<4 { group.addTask { try await h.businessPost(business, "/v1/business/wallet/scan", WalletScanRequest(code: code)) } }
                var out: [HTTPResult] = []
                for try await result in group { out.append(result) }
                return out
            }
            XCTAssertEqual(results.filter { $0.status == .ok }.count, 1, "\(results.map(\.status))")
            XCTAssertTrue(results.allSatisfy { [.ok, .conflict, .gone].contains($0.status) }, "\(results.map(\.status))")
            let won = try XCTUnwrap(results.first { $0.status == .ok }).json(WalletScanResult.self)
            XCTAssertEqual(won.outcome, .redeemed)
            XCTAssertEqual(won.title, "Free pastry")
            let receipt = try XCTUnwrap(won.redemption)
            XCTAssertEqual(receipt.rewardId, reward.id)
            XCTAssertNotEqual(receipt.consumerReference, s.consumer.id, "a per-business pseudonym, never the consumer id")
            let consumed = try await RewardRedemptionRecord.query(on: h.db).filter(\.$status == "consumed").count()
            XCTAssertEqual(consumed, 1)
            // The spent coupon's pass is void: a replay of the same QR (a screenshot, a second till) is refused.
            let pass = try await record(h, metadata.id)
            XCTAssertTrue(pass.voided)
            try await eq(try await scan(h, s.business, code).status, .gone)
            try await eq(try await h.signed(s.consumer, .GET, "/v1/wallet/passes/\(metadata.id)").status, .gone)
            let listed = try await h.signed(s.consumer, .GET, "/v1/wallet/passes").json([WalletPassMetadata].self)
            XCTAssertNil(listed.first?.scanCode, "a void pass has no code to show")
        }
    }

    func testAnExpiredCouponPassIsRefused() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            let reward = try await h.reward(s.business, title: "Weekend deal", kind: .coupon, relationship: s.relationship,
                                            validUntil: h.clock.now().addingTimeInterval(3600))
            let issued = try await consumerIssue(h, s, kind: .coupon, rewardId: reward.id)
            let code = try XCTUnwrap(issued.scanCode)
            h.clock.advance(by: 7200)
            let response = try await scan(h, s.business, code)
            XCTAssertEqual(response.status, .gone, response.text)
            let redemptions = try await RewardRedemptionRecord.query(on: h.db).count()
            XCTAssertEqual(redemptions, 0)
        }
    }

    func testATicketChecksInOnceInsideItsValidityWindow() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            let opens = h.clock.now().addingTimeInterval(3600)
            let ticketId = try await ticket(h, s, validFrom: opens, validUntil: opens.addingTimeInterval(6 * 3600), startsAt: opens.addingTimeInterval(1800))
            let metadata = try await consumerIssue(h, s, kind: .eventTicket, interactionId: ticketId)
            let code = try XCTUnwrap(metadata.scanCode)
            // A second ticket whose window closes before these doors open.
            let other = try await consumerIssue(h, s, kind: .eventTicket, interactionId: try await ticket(h, s, validUntil: h.clock.now().addingTimeInterval(1800),
                                                                                                                  startsAt: h.clock.now()))
            // Doors are not open yet.
            let early = try await scan(h, s.business, code)
            XCTAssertEqual(early.status, .conflict)
            XCTAssertEqual(try errorDetails(early)?["state"], "notYetValid")
            h.clock.advance(by: 3700)
            let entry = try await scan(h, s.business, code)
            XCTAssertEqual(entry.status, .ok, entry.text)
            let result = try entry.json(WalletScanResult.self)
            XCTAssertEqual(result.outcome, .checkedIn)
            XCTAssertEqual(result.title, "Jazz Night")
            // Single entry: the second scan (a copied QR at another door) says when it was used.
            let checkedInAt = h.clock.now()
            h.clock.advance(by: 60)
            let again = try await scan(h, s.business, code)
            XCTAssertEqual(again.status, .conflict)
            XCTAssertEqual(try errorDetails(again)?["usedAt"], ViadereDate.format(checkedInAt))
            // The pass updates to show it (as Wallet will fetch it), and the business list shows when.
            let content = try PKPassContents(try await WalletService(db: h.db, ctx: h.ctx).pkpass(for: try await record(h, metadata.id)))
            let auxiliary = try XCTUnwrap((content.passJSON["eventTicket"] as? [String: Any])?["auxiliaryFields"] as? [[String: Any]])
            XCTAssertTrue(auxiliary.contains { $0["key"] as? String == "entry" && $0["value"] as? String == "Checked in" })
            let listed = try await h.business(s.business, .GET, "/v1/business/wallet/passes").json([BusinessWalletPass].self)
            XCTAssertEqual(listed.first { $0.id == metadata.id }?.usedAt, checkedInAt)
            // After the window: expired, even for a ticket never used.
            try await eq(try await scan(h, s.business, try XCTUnwrap(other.scanCode)).status, .gone)
        }
    }

    // MARK: Business pass API

    func testBusinessIssuesListsUpdatesAndVoidsPassesOnlyForItsOwnLiveCustomers() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            try await h.enroll(s.consumer, s.business)
            let ticketId = try await ticket(h, s)
            let request = BusinessIssueWalletPassRequest(relationshipId: s.relationship.id, kind: .eventTicket, interactionId: ticketId)
            let created = try await h.businessPost(s.business, "/v1/business/wallet/passes", request)
            XCTAssertEqual(created.status, .created, created.text)
            let pass = try created.json(BusinessWalletPass.self)
            XCTAssertEqual(pass.issuedBy, .business)
            XCTAssertEqual(pass.relationshipId, s.relationship.id)
            XCTAssertEqual(pass.interactionId, ticketId)
            try await eq(try await h.businessPost(s.business, "/v1/business/wallet/passes", request).status, .ok, "one pass per subject")
            // By subject reference too.
            let bySubject = try await h.businessPost(s.business, "/v1/business/wallet/passes",
                                                     BusinessIssueWalletPassRequest(subjectRef: pass.subjectRef, kind: .storeCard))
            XCTAssertEqual(bySubject.status, .created, bySubject.text)
            // The customer sees it in the app, with its code, ready to add to Wallet.
            let mine = try await h.signed(s.consumer, .GET, "/v1/wallet/passes").json([WalletPassMetadata].self)
            XCTAssertEqual(Set(mine.map(\.id)), [pass.id, try bySubject.json(BusinessWalletPass.self).id])
            XCTAssertTrue(mine.allSatisfy { $0.scanCode != nil })
            // The business list never says whether (or where) the customer added it.
            let listedRaw = try await h.business(s.business, .GET, "/v1/business/wallet/passes")
            XCTAssertEqual(listedRaw.status, .ok)
            XCTAssertFalse(listedRaw.text.contains("device"), listedRaw.text)
            XCTAssertFalse(listedRaw.text.contains("pushToken"))
            XCTAssertFalse(listedRaw.text.contains("VQ1."), "the business never receives the holder's code")
            XCTAssertFalse(listedRaw.text.contains(s.consumer.id.description))

            // A schedule change: the pass shows it with Wallet's change notice, and is pushed.
            let newStart = h.clock.now().addingTimeInterval(4 * 86_400)
            let updated = try await h.business(s.business, .PATCH, "/v1/business/wallet/passes/\(pass.id)",
                                               body: try ViadereJSON.encode(UpdateWalletPassRequest(venue: "Hall B", startsAt: newStart)))
            XCTAssertEqual(updated.status, .ok, updated.text)
            let content = try await download(h, s, pass.id)
            let style = try XCTUnwrap(content.passJSON["eventTicket"] as? [String: Any])
            let venue = try XCTUnwrap((style["secondaryFields"] as? [[String: Any]])?.first { $0["key"] as? String == "venue" })
            XCTAssertEqual(venue["value"] as? String, "Hall B")
            XCTAssertEqual(venue["changeMessage"] as? String, "Venue changed to %@")
            let starts = try XCTUnwrap((style["auxiliaryFields"] as? [[String: Any]])?.first { $0["key"] as? String == "starts" })
            XCTAssertEqual(starts["value"] as? String, PassDescriptor.wallet(newStart))
            XCTAssertEqual(content.passJSON["relevantDate"] as? String, PassDescriptor.wallet(newStart))
            // Validation: only operational fields, bounded, on passes that have them.
            try await eq(try await h.business(s.business, .PATCH, "/v1/business/wallet/passes/\(pass.id)",
                                              body: try ViadereJSON.encode(UpdateWalletPassRequest(venue: String(repeating: "x", count: 81)))).status, .unprocessableEntity)
            try await eq(try await h.business(s.business, .PATCH, "/v1/business/wallet/passes/\(pass.id)",
                                              body: try ViadereJSON.encode(UpdateWalletPassRequest(venue: "Free drinks!\nVisit us"))).status, .unprocessableEntity)
            try await eq(try await h.business(s.business, .PATCH, "/v1/business/wallet/passes/\(pass.id)", body: Data("{}".utf8)).status, .unprocessableEntity)
            let storeCardId = try bySubject.json(BusinessWalletPass.self).id
            try await eq(try await h.business(s.business, .PATCH, "/v1/business/wallet/passes/\(storeCardId)",
                                              body: try ViadereJSON.encode(UpdateWalletPassRequest(venue: "Hall B"))).status, .conflict)

            // Tenant isolation: another business can neither see, update, void nor issue for this customer.
            let rival = try await h.makeBusiness(name: "Rival Roasters", handle: "rivalroasters")
            try await eq(try await h.business(rival, .POST, "/v1/business/wallet/passes/\(pass.id)/void").status, .notFound)
            try await eq(try await h.business(rival, .PATCH, "/v1/business/wallet/passes/\(pass.id)",
                                              body: try ViadereJSON.encode(UpdateWalletPassRequest(rotateScanCode: true))).status, .notFound)
            try await eq(try await h.businessPost(rival, "/v1/business/wallet/passes", request).status, .notFound)
            let rivalList = try await h.business(rival, .GET, "/v1/business/wallet/passes").json([BusinessWalletPass].self)
            XCTAssertEqual(rivalList.count, 0)
            // Scope and capability like every business API.
            let noScope = try await h.makeBusiness(name: "Scoped Shop", handle: "scopedshop", scopes: [BusinessAPIKeys.Scope.rewardsWrite])
            try await eq(try await h.business(noScope, .GET, "/v1/business/wallet/passes").status, .forbidden)
            try await eq(try await h.request(.GET, "/v1/business/wallet/passes").status, .unauthorized)

            // Void: final, the code stops at once, the customer's Wallet updates.
            let code = try XCTUnwrap(mine.first { $0.id == pass.id }?.scanCode)
            let voided = try await h.business(s.business, .POST, "/v1/business/wallet/passes/\(pass.id)/void")
            XCTAssertEqual(voided.status, .ok, voided.text)
            XCTAssertTrue(try voided.json(BusinessWalletPass.self).voided)
            try await eq(try await scan(h, s.business, code).status, .gone)
            try await eq(try await h.business(s.business, .PATCH, "/v1/business/wallet/passes/\(pass.id)",
                                              body: try ViadereJSON.encode(UpdateWalletPassRequest(rotateScanCode: true))).status, .gone)
            let audit = try await AuditEventRecord.query(on: h.db).filter(\.$action ~~ ["wallet.pass_issued", "wallet.pass_updated", "wallet.pass_voided"]).count()
            XCTAssertGreaterThanOrEqual(audit, 4)
        }
    }

    func testTestModeKeysNeverProduceOrTouchARealPass() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            try await h.enroll(s.consumer, s.business)
            let key = try await testKey(h, s.business)
            let live = try await consumerIssue(h, s)
            // Issuing with a test key: refused before anything is created, for a live or a sandbox relationship.
            let refused = try await h.businessPost(s.business, "/v1/business/wallet/passes",
                                                   BusinessIssueWalletPassRequest(relationshipId: s.relationship.id, kind: .storeCard), key: key)
            XCTAssertEqual(refused.status, .forbidden, refused.text)
            let sandbox = try await h.business(s.business, .POST, "/v1/business/sandbox/relationships", key: key).json(SandboxRelationship.self)
            try await eq(try await h.businessPost(s.business, "/v1/business/wallet/passes",
                                                  BusinessIssueWalletPassRequest(relationshipId: sandbox.relationshipId, kind: .storeCard), key: key).status, .forbidden)
            // A reward created with a test key for a sandbox customer never comes with a pass, even when asked.
            let reward = try await h.businessPost(s.business, "/v1/business/rewards",
                                                  IssueRewardRequest(relationshipId: sandbox.relationshipId, title: "Test offer", kind: .coupon, issueWalletPass: true,
                                                                     idempotencyKey: "t-1"), key: key, idempotencyKey: "t-1")
            XCTAssertEqual(reward.status, .created, reward.text)
            let passes = try await WalletPassRecord.query(on: h.db).count()
            XCTAssertEqual(passes, 1, "only the live customer's own pass exists")
            // A test key can't list, void, update or scan real passes.
            let testList = try await h.business(s.business, .GET, "/v1/business/wallet/passes", key: key).json([BusinessWalletPass].self)
            XCTAssertEqual(testList.count, 0)
            try await eq(try await h.business(s.business, .POST, "/v1/business/wallet/passes/\(live.id)/void", key: key).status, .forbidden)
            try await eq(try await h.business(s.business, .PATCH, "/v1/business/wallet/passes/\(live.id)",
                                              body: try ViadereJSON.encode(UpdateWalletPassRequest(rotateScanCode: true)), key: key).status, .forbidden)
            try await eq(try await scan(h, s.business, try XCTUnwrap(live.scanCode), key: key).status, .notFound)
            let liveRecord = try await record(h, live.id)
            XCTAssertFalse(liveRecord.voided)
            XCTAssertEqual(h.signer.signedManifests.count, 0, "nothing was signed for a test key")
        }
    }

    func testUpdatesArePerPassRateLimitedSoPassesAreNoNotificationChannel() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            let pass = try await h.businessPost(s.business, "/v1/business/wallet/passes",
                                                BusinessIssueWalletPassRequest(relationshipId: s.relationship.id, kind: .eventTicket,
                                                                               interactionId: try await ticket(h, s))).json(BusinessWalletPass.self)
            var statuses: [HTTPStatus] = []
            for index in 0..<8 {
                statuses.append(try await h.business(s.business, .PATCH, "/v1/business/wallet/passes/\(pass.id)",
                                                     body: try ViadereJSON.encode(UpdateWalletPassRequest(seat: "Seat \(index)"))).status)
            }
            XCTAssertEqual(statuses.filter { $0 == .ok }.count, 6, "\(statuses)")
            XCTAssertEqual(statuses.suffix(2), [.tooManyRequests, .tooManyRequests])
            // No field of any pass carries a change notice except the operational ones.
            let content = try await download(h, s, pass.id)
            let style = try XCTUnwrap(content.passJSON["eventTicket"] as? [String: Any])
            let all = ["primaryFields", "secondaryFields", "auxiliaryFields", "backFields"].flatMap { (style[$0] as? [[String: Any]]) ?? [] }
            let noticed = Set(all.filter { $0["changeMessage"] != nil }.compactMap { $0["key"] as? String })
            XCTAssertEqual(noticed, ["venue", "seat", "starts"])
        }
    }

    // MARK: Lifecycle

    func testDisconnectingVoidsTheBusinesssPassesAndCancellingATicketVoidsItsPass() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            try await h.enroll(s.consumer, s.business)
            let card = try await consumerIssue(h, s)
            let ticketId = try await ticket(h, s)
            let ticketPass = try await consumerIssue(h, s, kind: .eventTicket, interactionId: ticketId)
            // The business cancels the ticket: its pass is void and pushed; the loyalty card is untouched.
            try await eq(try await h.business(s.business, .POST, "/v1/business/interactions/\(ticketId)/cancel").status, .ok)
            let ticketRecord = try await record(h, ticketPass.id)
            XCTAssertTrue(ticketRecord.voided)
            let cardBefore = try await record(h, card.id)
            XCTAssertFalse(cardBefore.voided)
            try await eq(try await scan(h, s.business, try XCTUnwrap(ticketPass.scanCode)).status, .gone)
            // The customer disconnects: every pass of that business is void and its code is refused.
            try await eq(try await h.signed(s.consumer, .DELETE, "/v1/relationships/\(s.relationship.id)").status, .ok)
            let cardAfter = try await record(h, card.id)
            XCTAssertTrue(cardAfter.voided)
            try await eq(try await scan(h, s.business, try XCTUnwrap(card.scanCode)).status, .notFound)
            let queued = try await WalletPushOutboxRecord.query(on: h.db).filter(\.$passId == card.id.uuid).count()
            XCTAssertGreaterThanOrEqual(queued, 1, "Wallet is told to refresh the voided card")
        }
    }

    func testUpdatesReachOnlyDevicesRegisteredForThatPass() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            try await h.enroll(s.consumer, s.business)
            let card = try await record(h, try await consumerIssue(h, s).id)
            let ticketPass = try await record(h, try await consumerIssue(h, s, kind: .eventTicket, interactionId: try await ticket(h, s)).id)
            let token = WalletService(db: h.db, ctx: h.ctx).authenticationToken(id: card.id!, salt: card.authSalt)
            let body = try ViadereJSON.encode(["pushToken": String(repeating: "ab", count: 32)])
            try await eq(try await h.request(.POST, "/wallet/v1/devices/phone-1/registrations/\(card.passTypeIdentifier)/\(card.serialNumber)",
                                             headers: ["Authorization": "ApplePass \(token)"], body: body).status, .created)
            // The ticket pass changes: nothing is pushed (no device registered it) and the card's device is not told about it.
            _ = try await h.business(s.business, .PATCH, "/v1/business/wallet/passes/\(ticketPass.id!)",
                                     body: try ViadereJSON.encode(UpdateWalletPassRequest(venue: "Hall C")))
            try await h.runJobs()
            XCTAssertEqual(h.passPush.sent.count, 0)
            let serials = try await h.request(.GET, "/wallet/v1/devices/phone-1/registrations/\(card.passTypeIdentifier)")
            XCTAssertFalse(serials.text.contains(ticketPass.serialNumber), serials.text)
            // The card's token can't be used to register for, or fetch, the ticket pass.
            try await eq(try await h.request(.POST, "/wallet/v1/devices/phone-1/registrations/\(card.passTypeIdentifier)/\(ticketPass.serialNumber)",
                                             headers: ["Authorization": "ApplePass \(token)"], body: body).status, .unauthorized)
            try await eq(try await h.request(.GET, "/wallet/v1/passes/\(card.passTypeIdentifier)/\(ticketPass.serialNumber)",
                                             headers: ["Authorization": "ApplePass \(token)"]).status, .unauthorized)
        }
    }

    // MARK: Content, localization, relevance

    func testPassContentNeverIncludesMoreThanTheCustomerSees() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            try await h.enroll(s.consumer, s.business, reference: "MEMBER-SECRET-4242")
            try await h.adjustPoints(s.business, s.relationship, 150)
            let card = try await consumerIssue(h, s)
            let ticketPass = try await consumerIssue(h, s, kind: .eventTicket, interactionId: try await ticket(h, s))
            for metadata in [card, ticketPass] {
                let content = try await download(h, s, metadata.id)
                let allowedTopLevel: Set<String> = ["formatVersion", "passTypeIdentifier", "teamIdentifier", "serialNumber", "organizationName", "description",
                                                    "authenticationToken", "webServiceURL", "backgroundColor", "foregroundColor", "labelColor", "logoText",
                                                    "sharingProhibited", "barcodes", "relevantDate", "relevantDates", "expirationDate", "voided",
                                                    "storeCard", "coupon", "eventTicket", "boardingPass", "generic"]
                XCTAssertEqual(Set(content.passJSON.keys).subtracting(allowedTopLevel), [], "no userInfo, nfc, locations or other channels")
                XCTAssertEqual(content.passJSON["sharingProhibited"] as? Bool, true)
                let text = String(decoding: try XCTUnwrap(content.files["pass.json"]), as: UTF8.self)
                for secret in ["MEMBER-SECRET", "4242", s.consumer.id.description, s.relationship.id.description, "Samantha", "Holder",
                               s.consumer.id.uuid.uuidString.lowercased()] {
                    XCTAssertFalse(text.contains(secret), "pass.json leaks \(secret)")
                }
                // The QR names only the pass (16-byte id ‖ generation ‖ tag).
                let code = try XCTUnwrap(metadata.scanCode)
                let bytes = try XCTUnwrap(Base64URL.decode(String(code.dropFirst(WalletScanCode.prefix.count))))
                XCTAssertEqual(Data(bytes.prefix(16)), withUnsafeBytes(of: metadata.id.uuid.uuid) { Data($0) })
            }
            // Rewards and loyalty responses embed pass metadata without the code.
            let overview = try await h.overview(s.consumer)
            XCTAssertNil(overview.accounts.first?.walletPass?.scanCode)
            XCTAssertNotNil(overview.accounts.first?.walletPass)
        }
    }

    func testPassesAreLocalizedHaveRelevanceIntervalsAndCarryTheConfigurableBetaNote() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            let starts = h.clock.now().addingTimeInterval(3 * 86_400)
            let until = starts.addingTimeInterval(3 * 3600)
            let metadata = try await consumerIssue(h, s, kind: .eventTicket, interactionId: try await ticket(h, s, validUntil: until, startsAt: starts))
            let content = try await download(h, s, metadata.id)
            XCTAssertEqual(Set(content.files.keys), ["pass.json", "manifest.json", "signature", "icon.png", "icon@2x.png", "icon@3x.png",
                                                     "en.lproj/pass.strings", "es.lproj/pass.strings", "fr.lproj/pass.strings"])
            // Every localization is in the signed manifest.
            for name in ["en.lproj/pass.strings", "es.lproj/pass.strings", "fr.lproj/pass.strings"] {
                XCTAssertEqual(content.manifest[name], content.sha1(name), name)
                let data = try XCTUnwrap(content.files[name])
                XCTAssertEqual(data.prefix(2), Data([0xFF, 0xFE]), "UTF-16LE with a byte-order mark")
            }
            let french = try XCTUnwrap(String(data: try XCTUnwrap(content.files["fr.lproj/pass.strings"]), encoding: .utf16))
            XCTAssertTrue(french.contains(#""VENUE" = "LIEU";"#), french)
            XCTAssertTrue(french.contains(#""Venue changed to %@" = "Nouveau lieu : %@";"#))
            // Labels in pass.json are the English keys, so an unlisted language still reads well.
            let style = try XCTUnwrap(content.passJSON["eventTicket"] as? [String: Any])
            XCTAssertEqual((style["primaryFields"] as? [[String: Any]])?.first?["label"] as? String, "EVENT")
            // iOS 18 relevance interval next to the iOS 17 date.
            let dates = try XCTUnwrap(content.passJSON["relevantDates"] as? [[String: String]])
            XCTAssertEqual(dates, [["startDate": PassDescriptor.wallet(starts), "endDate": PassDescriptor.wallet(until)]])
            XCTAssertEqual(content.passJSON["relevantDate"] as? String, PassDescriptor.wallet(starts))
            XCTAssertNil(content.passJSON["locations"], "no location relevance until businesses publish their places")
            let back = try XCTUnwrap(style["backFields"] as? [[String: Any]])
            XCTAssertEqual(back.first { $0["key"] as? String == "beta" }?["value"] as? String, PassStrings.beta)
        }
        try await withHarness({ $0.walletBetaLabel = false }) { h in
            let s = try await scene(h)
            try await h.enroll(s.consumer, s.business)
            let content = try await download(h, s, try await consumerIssue(h, s).id)
            let back = try XCTUnwrap((content.passJSON["storeCard"] as? [String: Any])?["backFields"] as? [[String: Any]])
            XCTAssertNil(back.first { $0["key"] as? String == "beta" }, "the owner turned the beta note off")
        }
    }

    func testBetaLabelEnvironmentIsStrict() throws {
        var config = ServerConfig.testing()
        try config.applyPassEnvironment(["WALLET_BETA_LABEL": "false"])
        XCTAssertFalse(config.walletBetaLabel)
        try config.applyPassEnvironment(["WALLET_BETA_LABEL": "true"])
        XCTAssertTrue(config.walletBetaLabel)
        XCTAssertThrowsError(try config.applyPassEnvironment(["WALLET_BETA_LABEL": "maybe"]))
        var untouched = ServerConfig.testing()
        try untouched.applyPassEnvironment([:])
        XCTAssertTrue(untouched.walletBetaLabel, "on by default")
    }
}
