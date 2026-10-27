import Fluent
import Foundation
import NIOHTTP1
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

final class RewardFlowTests: XCTestCase {
    private let phoenix = "America/Phoenix"

    /// Long-lived sessions so tests can move the clock across days without re-authenticating.
    private func harness(_ body: (TestHarness) async throws -> Void) async throws {
        try await withHarness({ $0.accessTokenTTL = 90 * 86_400 }, body)
    }

    private struct Scene {
        var business: TestBusiness
        var consumer: TestConsumer
        var relationship: Relationship
    }

    private func scene(_ h: TestHarness, program: Bool = true, tz: String = "America/Phoenix") async throws -> Scene {
        let business = try await h.makeBusiness(name: "Juniper Coffee", handle: "junipercoffee")
        if program { try await h.saveProgram(business, timeZone: tz) }
        let consumer = try await h.readyConsumer()
        let relationship = try await h.connect(consumer, to: business)
        return Scene(business: business, consumer: consumer, relationship: relationship)
    }

    // MARK: Eligibility over HTTP

    func testTuesdayRewardIsEvaluatedByTheServerInTheBusinessTimeZone() async throws {
        try await harness { h in
            let s = try await scene(h)
            let reward = try await h.reward(s.business, title: "Free coffee on Tuesdays",
                                            recurrence: RewardRecurrence(weekdays: [2], perDayLimit: 1, timeZone: phoenix))
            // Monday evening in Phoenix (already Tuesday in UTC): not today.
            h.setClock("2027-01-18 20:00", phoenix)
            var entry = try await h.entry(s.consumer, reward.id)
            XCTAssertEqual(entry.eligibility.state, .notToday)
            XCTAssertEqual(entry.eligibility.nextAction, .none)
            XCTAssertEqual(entry.eligibility.nextEligibleAt, TestHarness.date("2027-01-19 00:00", phoenix))
            XCTAssertEqual(entry.eligibility.checkedAt, h.clock.now(), "the verdict carries the server's clock")
            XCTAssertEqual(entry.reward.recurrence?.weekdays, [2])
            let early = try await h.redeem(s.consumer, reward.id)
            XCTAssertEqual(early.status, .conflict, "redeem re-checks eligibility")
            // Tuesday morning in Phoenix.
            h.setClock("2027-01-19 09:00", phoenix)
            entry = try await h.entry(s.consumer, reward.id)
            XCTAssertEqual(entry.eligibility.state, .eligible)
            XCTAssertEqual(entry.eligibility.nextAction, .redeem)
            XCTAssertEqual(entry.kind, .perk)
            XCTAssertEqual(entry.reward.status, .available)
        }
    }

    func testOverviewShowsAccountsTiersAndOnlyConnectedBusinessesRewards() async throws {
        try await harness { h in
            let s = try await scene(h)
            let other = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            try await h.saveProgram(other)
            let hidden = try await h.reward(other, title: "Lounge pass")
            let shown = try await h.reward(s.business, title: "Free coffee")
            try await h.enroll(s.consumer, s.business, reference: "MEMBER-4821")
            try await h.adjustPoints(s.business, s.relationship, 120)
            let overview = try await h.overview(s.consumer)
            XCTAssertEqual(overview.rewards.map(\.id), [shown.id])
            XCTAssertFalse(overview.rewards.map(\.id).contains(hidden.id))
            let account = try XCTUnwrap(overview.accounts.first)
            XCTAssertEqual(account.business.id, s.business.id)
            XCTAssertEqual(account.pointsBalance, 120)
            XCTAssertEqual(account.statusName, "Silver")
            XCTAssertEqual(account.nextStatusName, "Gold")
            XCTAssertEqual(account.pointsToNextStatus, 380)
            XCTAssertEqual(account.memberReference, "••4821")
            // The program view: terms, account and rewards; unconnected consumers see no rewards and no account.
            let program = try await h.signed(s.consumer, .GET, "/v1/loyalty/\(s.business.id)").json(LoyaltyProgramOverview.self)
            XCTAssertEqual(program.termsVersion, "v1")
            XCTAssertEqual(program.account?.pointsBalance, 120)
            XCTAssertEqual(program.rewards.count, 1)
            let stranger = try await h.readyConsumer(name: "Stranger")
            let strangerView = try await h.signed(stranger, .GET, "/v1/loyalty/\(s.business.id)").json(LoyaltyProgramOverview.self)
            XCTAssertNil(strangerView.account)
            XCTAssertTrue(strangerView.rewards.isEmpty)
            // No program → 404 (the app hides the feature).
            let bare = try await h.makeBusiness(name: "Bare Bones", handle: "barebones")
            try await eq(try await h.signed(s.consumer, .GET, "/v1/loyalty/\(bare.id)").status, .notFound)
        }
    }

    // MARK: Claim

    func testCouponsAreClaimedBeforeTheyAreRedeemed() async throws {
        try await harness { h in
            let s = try await scene(h)
            let coupon = try await h.reward(s.business, title: "10% off", kind: .coupon)
            var entry = try await h.entry(s.consumer, coupon.id)
            XCTAssertEqual(entry.eligibility.nextAction, .claim)
            XCTAssertNil(entry.claimedAt)
            // Redeeming an unclaimed coupon is refused.
            let early = try await h.redeem(s.consumer, coupon.id)
            XCTAssertEqual(early.status, .conflict)
            let claimed = try await h.claim(s.consumer, coupon.id)
            XCTAssertEqual(claimed.status, .ok, claimed.text)
            entry = try claimed.json(RewardEntry.self)
            XCTAssertNotNil(entry.claimedAt)
            XCTAssertEqual(entry.eligibility.nextAction, .redeem)
            // A second tap is a harmless no-op.
            let again = try await h.claim(s.consumer, coupon.id)
            XCTAssertEqual(again.status, .ok)
            XCTAssertEqual(try again.json(RewardEntry.self).claimedAt, entry.claimedAt)
            let claims = try await RewardClaimRecord.query(on: h.db).count()
            XCTAssertEqual(claims, 1)
            // Perks need no claim, so claiming one is "not claimable".
            let perk = try await h.reward(s.business, title: "Free refill", kind: .perk)
            try await eq(try await h.claim(s.consumer, perk.id).status, .conflict)
            // Redeem now works.
            try await eq(try await h.redeem(s.consumer, coupon.id).status, .created)
        }
    }

    func testClaimsAreScopedToTheConsumerAndTheirConnection() async throws {
        try await harness { h in
            let s = try await scene(h)
            let mine = try await h.reward(s.business, title: "Just for you", kind: .coupon, relationship: s.relationship)
            let other = try await h.readyConsumer(name: "Other")
            _ = try await h.connect(other, to: s.business)
            // Another connected consumer can neither see, claim nor redeem a reward issued to someone else: always 404.
            let flag130 = try await h.overview(other).rewards.map(\.id).contains(mine.id)
            XCTAssertFalse(flag130)
            try await eq(try await h.claim(other, mine.id).status, .notFound)
            try await eq(try await h.redeem(other, mine.id).status, .notFound)
            // An unconnected consumer cannot touch even a program-wide reward.
            let open = try await h.reward(s.business, title: "For members", kind: .coupon)
            let stranger = try await h.readyConsumer(name: "Stranger")
            try await eq(try await h.claim(stranger, open.id).status, .notFound)
            try await eq(try await h.redeem(stranger, open.id).status, .notFound)
            // After disconnecting, access ends.
            let gone = try await h.signed(s.consumer, .DELETE, "/v1/relationships/\(s.relationship.id)")
            XCTAssertEqual(gone.status, .ok)
            try await eq(try await h.claim(s.consumer, open.id).status, .notFound)
        }
    }

    // MARK: Redemption codes

    func testRedemptionReservesTheDailyLimitAndReleasesItWhenTheCodeExpires() async throws {
        try await harness { h in
            let s = try await scene(h)
            let reward = try await h.reward(s.business, recurrence: RewardRecurrence(weekdays: [2], perDayLimit: 1, timeZone: phoenix))
            h.setClock("2027-01-19 09:00", phoenix)
            let issued = try await h.redeem(s.consumer, reward.id, location: "till-2")
            XCTAssertEqual(issued.status, .created, issued.text)
            let redemption = try issued.json(RewardRedemption.self)
            XCTAssertEqual(redemption.validForSeconds, 120)
            XCTAssertEqual(redemption.serverTime, h.clock.now())
            XCTAssertEqual(redemption.expiresAt, h.clock.now().addingTimeInterval(120))
            XCTAssertEqual(redemption.reward.id, reward.id)
            XCTAssertNotNil(RewardsService.normalizeCode(redemption.redemptionCode))
            XCTAssertEqual(redemption.redemptionCode.count, 11)
            // The code is never stored: only a keyed hash.
            let row = try await RewardRedemptionRecord.query(on: h.db).first().unwrap()
            XCTAssertEqual(row.codeHash.count, 64)
            XCTAssertFalse(row.codeHash.contains(redemption.redemptionCode.replacingOccurrences(of: "-", with: "").lowercased()))
            XCTAssertEqual(row.windowKey, "2027-01-19")
            XCTAssertEqual(row.slot, 1)
            // The reservation counts immediately: the limit is reached and a second code is refused.
            let held = try await h.entry(s.consumer, reward.id)
            XCTAssertEqual(held.eligibility.state, .limitReached)
            XCTAssertEqual(held.eligibility.nextEligibleAt, TestHarness.date("2027-01-26 00:00", phoenix))
            let second = try await h.redeem(s.consumer, reward.id)
            XCTAssertEqual(second.status, .conflict)
            XCTAssertEqual(second.errorCode, .conflict)
            // The code expires unused: the reservation is released and the person can ask again.
            h.clock.advance(by: 121)
            let eligible = try await h.entry(s.consumer, reward.id)
            XCTAssertEqual(eligible.eligibility.state, .eligible, "an expired code no longer counts")
            try await h.runJobs()
            let released = try await RewardRedemptionRecord.query(on: h.db).filter(\.$id == row.id!).first().unwrap()
            XCTAssertEqual(released.status, "expired")
            XCTAssertNil(released.slot, "the slot is free again")
            let third = try await h.redeem(s.consumer, reward.id)
            XCTAssertEqual(third.status, .created, third.text)
            // A consumed code keeps the day's slot: after use, the limit stays reached all day.
            let code = try third.json(RewardRedemption.self).redemptionCode
            let used = try await h.consume(s.business, code: code)
            XCTAssertEqual(used.status, .ok, used.text)
            h.clock.advance(by: 600)
            try await h.runJobs()
            try await eq(try await h.entry(s.consumer, reward.id).eligibility.state, .limitReached)
            try await eq(try await h.redeem(s.consumer, reward.id).status, .conflict)
            // Tomorrow is not a Tuesday; next Tuesday it is available again.
            h.setClock("2027-01-26 09:00", phoenix)
            try await eq(try await h.entry(s.consumer, reward.id).eligibility.state, .eligible)
        }
    }

    func testEveryDayRewardWithAHigherLimitHandsOutThatManyCodes() async throws {
        try await harness { h in
            let s = try await scene(h)
            let reward = try await h.reward(s.business, recurrence: RewardRecurrence(weekdays: [1, 2, 3, 4, 5, 6, 7], perDayLimit: 2, timeZone: phoenix))
            try await eq(try await h.redeem(s.consumer, reward.id).status, .created)
            try await eq(try await h.redeem(s.consumer, reward.id).status, .created)
            try await eq(try await h.redeem(s.consumer, reward.id).status, .conflict)
            let slots = try await RewardRedemptionRecord.query(on: h.db).all().compactMap(\.slot).sorted()
            XCTAssertEqual(slots, [1, 2])
        }
    }

    func testConcurrentRedemptionsOfASingleUseRewardIssueExactlyOneCode() async throws {
        try await harness { h in
            let s = try await scene(h)
            let reward = try await h.reward(s.business, kind: .perk)
            let statuses = try await withThrowingTaskGroup(of: HTTPStatus.self) { group in
                for _ in 0..<4 { group.addTask { try await h.redeem(s.consumer, reward.id).status } }
                var out: [HTTPStatus] = []
                for try await status in group { out.append(status) }
                return out
            }
            XCTAssertEqual(statuses.filter { $0 == .created }.count, 1, "\(statuses)")
            XCTAssertEqual(statuses.filter { $0 == .conflict }.count, 3, "\(statuses)")
            let rows = try await RewardRedemptionRecord.query(on: h.db).count()
            XCTAssertEqual(rows, 1)
        }
    }

    func testConsumingACodeIsSingleUseAndRaceSafe() async throws {
        try await harness { h in
            let s = try await scene(h)
            let reward = try await h.reward(s.business, kind: .coupon)
            _ = try await h.claim(s.consumer, reward.id)
            let code = try await h.redeem(s.consumer, reward.id).json(RewardRedemption.self).redemptionCode
            // Two tills validate the same code at once: exactly one wins.
            let results = try await withThrowingTaskGroup(of: HTTPResult.self) { group in
                group.addTask { try await h.consume(s.business, code: code) }
                group.addTask { try await h.consume(s.business, code: code.lowercased().replacingOccurrences(of: "-", with: " ")) }
                var out: [HTTPResult] = []
                for try await result in group { out.append(result) }
                return out
            }
            XCTAssertEqual(results.filter { $0.status == .ok }.count, 1, "\(results.map(\.status))")
            XCTAssertEqual(results.filter { $0.status == .conflict }.count, 1, "\(results.map(\.status))")
            let receipt = try XCTUnwrap(results.first { $0.status == .ok }).json(RedemptionReceipt.self)
            XCTAssertEqual(receipt.rewardId, reward.id)
            XCTAssertEqual(receipt.rewardTitle, "Free coffee")
            XCTAssertEqual(receipt.kind, .coupon)
            XCTAssertEqual(receipt.redeemedAt, h.clock.now())
            // The business sees a per-business pseudonym, never the consumer id.
            XCTAssertNotEqual(receipt.consumerReference, s.consumer.id)
            XCTAssertEqual(receipt.consumerReference, h.ctx.hasher.consumerReference(businessId: s.business.id, consumerId: s.consumer.id))
            // Later attempts say "already used" and report when.
            let again = try await h.consume(s.business, code: code)
            XCTAssertEqual(again.status, .conflict)
            let details = try ViadereJSON.decode(APIErrorResponse.self, from: again.body).error.details
            XCTAssertEqual(details?["redeemedAt"], ViadereDate.format(h.clock.now()))
            // A spent coupon is redeemed for good.
            let entry = try await h.entry(s.consumer, reward.id)
            XCTAssertEqual(entry.eligibility.state, .redeemed)
            XCTAssertEqual(entry.reward.status, .redeemed)
            XCTAssertEqual(entry.reward.redeemedAt, h.clock.now())
            try await eq(try await h.redeem(s.consumer, reward.id).status, .conflict)
        }
    }

    func testExpiredUnknownMalformedAndForeignCodesAreRefusedWithoutDetail() async throws {
        try await harness { h in
            let s = try await scene(h)
            let rival = try await h.makeBusiness(name: "Rival Roasters", handle: "rivalroasters")
            let reward = try await h.reward(s.business)
            let code = try await h.redeem(s.consumer, reward.id).json(RewardRedemption.self).redemptionCode
            // Another business learns nothing: indistinguishable from an unknown code, and the code stays valid for its owner.
            try await eq(try await h.consume(rival, code: code).status, .notFound)
            try await eq(try await h.consume(s.business, code: "ZZZZZ-ZZZZZ").status, .notFound)
            for malformed in ["", "short", "ABCDE-FGHJK-MORE", "ünïcode-12345", String(repeating: "A", count: 500)] {
                try await eq(try await h.consume(s.business, code: malformed).status, .notFound, malformed)
            }
            try await eq(try await h.consume(s.business, code: code, location: String(repeating: "x", count: 100)).status, .unprocessableEntity)
            // Expired: 410, even if the sweep hasn't run yet; nothing is consumed.
            h.clock.advance(by: 121)
            let late = try await h.consume(s.business, code: code)
            XCTAssertEqual(late.status, .gone)
            let row = try await RewardRedemptionRecord.query(on: h.db).first().unwrap()
            XCTAssertEqual(row.status, "expired")
            XCTAssertNil(row.consumedAt)
            // The boundary: valid up to (not including) expiry.
            let fresh = try await h.redeem(s.consumer, reward.id).json(RewardRedemption.self)
            h.clock.advance(by: 119)
            try await eq(try await h.consume(s.business, code: fresh.redemptionCode).status, .ok)
        }
    }

    func testRevokingARewardInvalidatesOutstandingCodesAndReturnsPoints() async throws {
        try await harness { h in
            let s = try await scene(h)
            try await h.enroll(s.consumer, s.business)
            try await h.adjustPoints(s.business, s.relationship, 300)
            let reward = try await h.reward(s.business, title: "Pastry", kind: .pointsReward, pointsCost: 200)
            let code = try await h.redeem(s.consumer, reward.id).json(RewardRedemption.self).redemptionCode
            try await eq(try await h.overview(s.consumer).accounts.first?.pointsBalance, 100, "points are held while the code is live")
            let revoked = try await h.business(s.business, .POST, "/v1/business/rewards/\(reward.id)/revoke", body: Data("{}".utf8))
            XCTAssertEqual(revoked.status, .ok, revoked.text)
            XCTAssertEqual(try revoked.json(Reward.self).status, .revoked)
            try await eq(try await h.business(s.business, .POST, "/v1/business/rewards/\(reward.id)/revoke", body: Data("{}".utf8)).status, .ok, "idempotent")
            try await eq(try await h.consume(s.business, code: code).status, .gone)
            try await eq(try await h.overview(s.consumer).accounts.first?.pointsBalance, 300, "held points come back")
            // History stays visible only to people who used it.
            let flag308 = try await h.overview(s.consumer).rewards.contains { $0.id == reward.id && $0.eligibility.state == .revoked }
            XCTAssertTrue(flag308)
            let newcomer = try await h.readyConsumer(name: "Newcomer")
            _ = try await h.connect(newcomer, to: s.business)
            let flag312 = try await h.overview(newcomer).rewards.contains { $0.id == reward.id }
            XCTAssertFalse(flag312)
        }
    }

    // MARK: Points

    func testPointsRewardsHoldPointsOnIssueAndReturnThemOnExpiry() async throws {
        try await harness { h in
            let s = try await scene(h)
            let reward = try await h.reward(s.business, title: "Free bag of beans", kind: .pointsReward, pointsCost: 150)
            // Not enrolled and no points: shortfall is the whole price.
            var entry = try await h.entry(s.consumer, reward.id)
            XCTAssertEqual(entry.eligibility.state, .insufficientPoints)
            XCTAssertEqual(entry.eligibility.pointsShortfall, 150)
            XCTAssertEqual(entry.pointsCost, 150)
            try await eq(try await h.redeem(s.consumer, reward.id).status, .conflict)
            // Adjustments need an enrolled member.
            try await eq(try await h.adjustPoints(s.business, s.relationship, 100).status, .conflict)
            try await h.enroll(s.consumer, s.business)
            try await eq(try await h.adjustPoints(s.business, s.relationship, 100).status, .ok)
            entry = try await h.entry(s.consumer, reward.id)
            XCTAssertEqual(entry.eligibility.pointsShortfall, 50)
            try await eq(try await h.adjustPoints(s.business, s.relationship, 60).status, .ok)
            let balance = { try await h.overview(s.consumer).accounts.first?.pointsBalance }
            try await eq(try await balance(), 160)
            // Redeem: points are held immediately.
            let issued = try await h.redeem(s.consumer, reward.id)
            XCTAssertEqual(issued.status, .created, issued.text)
            try await eq(try await balance(), 10)
            try await eq(try await h.entry(s.consumer, reward.id).eligibility.state, .insufficientPoints)
            // Unused code expires: points return.
            h.clock.advance(by: 125)
            try await h.runJobs()
            try await eq(try await balance(), 160)
            // Used code: points are spent for good.
            let code = try await h.redeem(s.consumer, reward.id).json(RewardRedemption.self).redemptionCode
            let receipt = try await h.consume(s.business, code: code).json(RedemptionReceipt.self)
            XCTAssertEqual(receipt.pointsSpent, 150)
            h.clock.advance(by: 300)
            try await h.runJobs()
            try await eq(try await balance(), 10)
        }
    }

    func testConcurrentPointsRedemptionsCannotOverspend() async throws {
        try await harness { h in
            let s = try await scene(h)
            try await h.enroll(s.consumer, s.business)
            try await h.adjustPoints(s.business, s.relationship, 250)
            let reward = try await h.reward(s.business, kind: .pointsReward, pointsCost: 100)
            let statuses = try await withThrowingTaskGroup(of: HTTPStatus.self) { group in
                for _ in 0..<5 { group.addTask { try await h.redeem(s.consumer, reward.id).status } }
                var out: [HTTPStatus] = []
                for try await status in group { out.append(status) }
                return out
            }
            XCTAssertEqual(statuses.filter { $0 == .created }.count, 2, "\(statuses)")
            let balance = try await h.overview(s.consumer).accounts.first?.pointsBalance
            XCTAssertEqual(balance, 50)
        }
    }

    func testPointAdjustmentsAreIdempotentValidatedAndNeverNegative() async throws {
        try await harness { h in
            let s = try await scene(h)
            try await h.enroll(s.consumer, s.business)
            let first = try await h.adjustPoints(s.business, s.relationship, 40, key: "pts-1")
            XCTAssertEqual(try first.json(LoyaltyPointsResult.self).applied, true)
            let replay = try await h.adjustPoints(s.business, s.relationship, 40, key: "pts-1")
            let replayed = try replay.json(LoyaltyPointsResult.self)
            XCTAssertEqual(replay.status, .ok)
            XCTAssertFalse(replayed.applied)
            XCTAssertEqual(replayed.pointsBalance, 40, "applied once")
            try await eq(try await h.adjustPoints(s.business, s.relationship, 41, key: "pts-1").errorCode, .idempotencyConflict)
            try await eq(try await h.adjustPoints(s.business, s.relationship, -41).status, .conflict, "cannot go below zero")
            try await eq(try await h.adjustPoints(s.business, s.relationship, 0).status, .unprocessableEntity)
            try await eq(try await h.adjustPoints(s.business, s.relationship, 2_000_000).status, .unprocessableEntity)
            try await eq(try await h.adjustPoints(s.business, s.relationship, -40).status, .ok)
            let ledger = try await LoyaltyLedgerRecord.query(on: h.db).count()
            XCTAssertEqual(ledger, 2)
            let body = AdjustLoyaltyPointsRequest(relationshipId: s.relationship.id, delta: 1, reason: "bad reason!", idempotencyKey: "k")
            try await eq(try await h.businessPost(s.business, "/v1/business/loyalty/points", body).status, .unprocessableEntity)
        }
    }

    // MARK: Enrollment

    func testEnrollmentChecksTermsConnectionAndProtectsTheMemberReference() async throws {
        try await harness { h in
            let s = try await scene(h)
            try await eq(try await h.enroll(s.consumer, s.business, terms: "v0").status, .conflict)
            try await eq(try await h.enroll(s.consumer, s.business, terms: "v0").errorCode, .conflict)
            let joined = try await h.enroll(s.consumer, s.business, reference: "ACCT-77123456")
            XCTAssertEqual(joined.status, .created, joined.text)
            let account = try joined.json(LoyaltyAccount.self)
            XCTAssertEqual(account.pointsBalance, 0)
            XCTAssertEqual(account.memberReference, "••3456")
            XCTAssertEqual(account.programName, "Juniper Coffee Club")
            // The raw reference is encrypted at rest and never returned.
            XCTAssertFalse(joined.text.contains("ACCT-77123456"))
            let record = try await LoyaltyAccountRecord.query(on: h.db).first().unwrap()
            XCTAssertFalse(try XCTUnwrap(record.memberReferenceCiphertext).contains("77123456"))
            XCTAssertEqual(try h.ctx.cipher.openString(try XCTUnwrap(record.memberReferenceCiphertext), context: "loyalty_accounts.member_reference"), "ACCT-77123456")
            // Joining twice is the same account.
            try await eq(try await h.enroll(s.consumer, s.business).status, .ok)
            let members = try await LoyaltyAccountRecord.query(on: h.db).count()
            XCTAssertEqual(members, 1)
            // A stale app after the business changes its terms is refused.
            try await h.saveProgram(s.business, terms: "v2")
            let other = try await h.readyConsumer(name: "Other")
            _ = try await h.connect(other, to: s.business)
            try await eq(try await h.enroll(other, s.business, terms: "v1").status, .conflict)
            try await eq(try await h.enroll(other, s.business, terms: "v2").status, .created)
            // Not connected: connect first.
            let stranger = try await h.readyConsumer(name: "Stranger")
            try await eq(try await h.enroll(stranger, s.business, terms: "v2").status, .conflict)
            // No program: 404.
            let bare = try await h.makeBusiness(name: "Bare Bones", handle: "barebones")
            _ = try await h.connect(other, to: bare)
            try await eq(try await h.enroll(other, bare).status, .notFound)
            // Over-long references are rejected.
            let long = try await h.signedPost(stranger, "/v1/loyalty/\(s.business.id)/enroll", LoyaltyEnrollRequest(existingMemberReference: String(repeating: "9", count: 80), acceptedTermsVersion: "v2"))
            XCTAssertNotEqual(long.status, .created)
        }
    }

    func testDeletingAnAccountErasesTheMemberReferenceAndEndsCodes() async throws {
        try await harness { h in
            let s = try await scene(h)
            try await h.enroll(s.consumer, s.business, reference: "ACCT-9999")
            let reward = try await h.reward(s.business)
            let code = try await h.redeem(s.consumer, reward.id).json(RewardRedemption.self).redemptionCode
            let gone = try await h.signed(s.consumer, .DELETE, "/v1/account")
            XCTAssertEqual(gone.status, .ok, gone.text)
            let record = try await LoyaltyAccountRecord.query(on: h.db).first().unwrap()
            XCTAssertNil(record.memberReferenceCiphertext)
            XCTAssertNil(record.memberReferenceMasked)
            try await eq(try await h.consume(s.business, code: code).status, .gone)
        }
    }

    // MARK: Business API: validation, idempotency, tenancy

    func testRewardCreationIsValidatedAndIdempotent() async throws {
        try await harness { h in
            let s = try await scene(h)
            func create(_ request: IssueRewardRequest) async throws -> HTTPResult { try await h.createReward(s.business, request) }
            let good = IssueRewardRequest(title: "Free coffee", kind: .perk, idempotencyKey: "r-1")
            let first = try await create(good)
            XCTAssertEqual(first.status, .created)
            let replay = try await create(good)
            XCTAssertEqual(replay.status, .ok)
            XCTAssertEqual(try replay.json(Reward.self).id, try first.json(Reward.self).id)
            var changed = good
            changed.title = "Different"
            try await eq(try await create(changed).errorCode, .idempotencyConflict)
            let header = try await h.businessPost(s.business, "/v1/business/rewards", good, idempotencyKey: "other")
            XCTAssertEqual(header.status, .badRequest)
            let now = h.clock.now()
            let bad: [(IssueRewardRequest, String)] = [
                (IssueRewardRequest(title: "  ", idempotencyKey: "b1"), "blank title"),
                (IssueRewardRequest(title: String(repeating: "x", count: 81), idempotencyKey: "b2"), "long title"),
                (IssueRewardRequest(title: "Points", kind: .pointsReward, idempotencyKey: "b3"), "points reward without a cost"),
                (IssueRewardRequest(title: "Points", kind: .pointsReward, pointsCost: 0, idempotencyKey: "b4"), "zero cost"),
                (IssueRewardRequest(title: "Past", validUntil: now.addingTimeInterval(-60), idempotencyKey: "b5"), "already ended"),
                (IssueRewardRequest(title: "Backwards", validFrom: now.addingTimeInterval(100), validUntil: now.addingTimeInterval(50), idempotencyKey: "b6"), "until before from"),
                (IssueRewardRequest(title: "Zone", recurrence: RewardRecurrence(weekdays: [2], perDayLimit: 1, timeZone: "Mars/Olympus"), idempotencyKey: "b7"), "bad zone"),
                (IssueRewardRequest(title: "Day", recurrence: RewardRecurrence(weekdays: [8], perDayLimit: 1, timeZone: "UTC"), idempotencyKey: "b8"), "bad weekday"),
                (IssueRewardRequest(title: "Empty", recurrence: RewardRecurrence(weekdays: [], perDayLimit: 1, timeZone: "UTC"), idempotencyKey: "b9"), "no weekdays"),
                (IssueRewardRequest(title: "Limit", recurrence: RewardRecurrence(weekdays: [1], perDayLimit: 0, timeZone: "UTC"), idempotencyKey: "b10"), "zero limit"),
                (IssueRewardRequest(title: "Key", idempotencyKey: ""), "no key"),
            ]
            for (request, why) in bad {
                let response = try await h.businessPost(s.business, "/v1/business/rewards", request)
                XCTAssertEqual(response.status, .unprocessableEntity, "\(why): \(response.text)")
            }
            // A points reward needs a program.
            let noProgram = try await h.makeBusiness(name: "No Program", handle: "noprogram")
            try await eq(try await h.createReward(noProgram, IssueRewardRequest(title: "Points", kind: .pointsReward, pointsCost: 10, idempotencyKey: "p")).status, .conflict)
            // Targeted rewards must reference one of the business's own active relationships.
            let other = try await h.makeBusiness(name: "Other Cafe", handle: "othercafe")
            let foreign = try await h.createReward(other, IssueRewardRequest(relationshipId: s.relationship.id, title: "Steal", idempotencyKey: "t"))
            XCTAssertEqual(foreign.status, .notFound, "another business's relationship is a plain 404")
        }
    }

    func testEveryNewBusinessEndpointIsTenantIsolatedAndScoped() async throws {
        try await harness { h in
            let a = try await scene(h)
            let b = try await h.makeBusiness(name: "Rival Roasters", handle: "rivalroasters")
            try await h.saveProgram(b, timeZone: "America/Chicago", terms: "rival-1")
            // Programs are per business.
            let programA = try await h.business(a.business, .GET, "/v1/business/loyalty/program").json(BusinessLoyaltyProgram.self)
            let programB = try await h.business(b, .GET, "/v1/business/loyalty/program").json(BusinessLoyaltyProgram.self)
            XCTAssertEqual(programA.programName, "Juniper Coffee Club")
            XCTAssertEqual(programB.programName, "Rival Roasters Club")
            XCTAssertEqual(programB.termsVersion, "rival-1")
            let noProgram = try await h.makeBusiness(name: "Quiet Shop", handle: "quietshop")
            try await eq(try await h.business(noProgram, .GET, "/v1/business/loyalty/program").status, .notFound)
            // Rewards: B cannot list, revoke, or read A's.
            let reward = try await h.reward(a.business)
            let listB = try await h.business(b, .GET, "/v1/business/rewards").json([Reward].self)
            XCTAssertTrue(listB.isEmpty)
            let listA = try await h.business(a.business, .GET, "/v1/business/rewards").json([Reward].self)
            XCTAssertEqual(listA.map(\.id), [reward.id])
            try await eq(try await h.business(b, .POST, "/v1/business/rewards/\(reward.id)/revoke", body: Data("{}".utf8)).status, .notFound)
            // Points: B cannot adjust A's member, even though the relationship id is valid.
            try await h.enroll(a.consumer, a.business)
            try await eq(try await h.adjustPoints(b, a.relationship, 500).status, .notFound)
            try await eq(try await h.overview(a.consumer).accounts.first?.pointsBalance, 0)
            // Redemption codes: B cannot consume A's code, and A's code survives the attempt.
            let code = try await h.redeem(a.consumer, reward.id).json(RewardRedemption.self).redemptionCode
            try await eq(try await h.consume(b, code: code).status, .notFound)
            try await eq(try await h.consume(a.business, code: code).status, .ok)
            // Idempotency keys are per business.
            let key = "shared-key"
            try await eq(try await h.createReward(a.business, IssueRewardRequest(title: "A", idempotencyKey: key)).status, .created)
            try await eq(try await h.createReward(b, IssueRewardRequest(title: "B", idempotencyKey: key)).status, .created)
            // Scope: a key without rewards:write is refused on every endpoint; an unauthenticated call is a 401.
            let narrow = try await h.makeBusiness(name: "Narrow Keys", handle: "narrowkeys", scopes: [BusinessAPIKeys.Scope.interactionsRead])
            for (method, path) in [(NIOHTTP1.HTTPMethod.GET, "/v1/business/rewards"), (.GET, "/v1/business/loyalty/program"), (.POST, "/v1/business/loyalty/points"),
                                   (.POST, "/v1/business/redemptions/consume"), (.PUT, "/v1/business/loyalty/program"), (.POST, "/v1/business/rewards"),
                                   (.POST, "/v1/business/rewards/\(reward.id)/revoke")] {
                let body: Data? = method == .GET ? nil : Data("{}".utf8)
                try await eq(try await h.business(narrow, method, path, body: body).status, .forbidden, path)
                let anonymous = try await h.request(method, path, body: body)
                XCTAssertEqual(anonymous.status, .unauthorized, path)
            }
            // The audit chain recorded the business actions and still verifies.
            let chain = try await AuditService.verifyChain(on: h.db)
            XCTAssertTrue(chain.valid)
        }
    }

    func testRedemptionRateLimitsBoundCodeGuessing() async throws {
        try await withHarness({ $0.accessTokenTTL = 90 * 86_400; $0.rateLimits.redemptionConsume = .perMinute(3, burst: 3); $0.rateLimits.rewardRedeem = .perMinute(2, burst: 2) }) { h in
            let s = try await scene(h)
            let reward = try await h.reward(s.business, recurrence: RewardRecurrence(weekdays: [1, 2, 3, 4, 5, 6, 7], perDayLimit: 20, timeZone: phoenix))
            for _ in 0..<3 { try await eq(try await h.consume(s.business, code: "ABCDE-FGHJK").status, .notFound) }
            let limited = try await h.consume(s.business, code: "ABCDE-FGHJK")
            XCTAssertEqual(limited.status, .tooManyRequests)
            XCTAssertNotNil(limited.headers.first(name: "Retry-After"))
            // Another business has its own budget.
            let other = try await h.makeBusiness(name: "Other Cafe", handle: "othercafe")
            try await eq(try await h.consume(other, code: "ABCDE-FGHJK").status, .notFound)
            // Consumers asking for codes are limited too.
            try await eq(try await h.redeem(s.consumer, reward.id).status, .created)
            try await eq(try await h.redeem(s.consumer, reward.id).status, .created)
            try await eq(try await h.redeem(s.consumer, reward.id).status, .tooManyRequests)
        }
    }

    func testRedemptionsAreReportedByWebhookAndMetered() async throws {
        try await harness { h in
            let s = try await scene(h)
            let hook = try await h.businessPost(s.business, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://hooks.example.com/v")!, events: [.rewardRedeemed]))
            XCTAssertEqual(hook.status, .created, hook.text)
            let reward = try await h.reward(s.business)
            let code = try await h.redeem(s.consumer, reward.id).json(RewardRedemption.self).redemptionCode
            try await eq(try await h.consume(s.business, code: code).status, .ok)
            try await h.runJobs()
            let delivered = h.webhooks.received
            XCTAssertEqual(delivered.count, 1)
            let event = try ViadereJSON.decode(WebhookEvent.self, from: delivered[0].body)
            XCTAssertEqual(event.type, .rewardRedeemed)
            XCTAssertEqual(try event.decodeData(RedemptionReceipt.self).rewardId, reward.id)
            XCTAssertFalse(String(decoding: delivered[0].body, as: UTF8.self).contains(s.consumer.id.description), "pseudonymous")
            let totals = try await UsageMeter.totals(businessId: s.business.id.uuid, from: .distantPast, to: .distantFuture, on: h.db)
            XCTAssertEqual(totals.redemptions, 1)
            XCTAssertEqual(totals.interactions, 0, "redemptions are not billed as interactions")
        }
    }

    func testCodesAndMemberReferencesNeverAppearInAuditOrLogs() async throws {
        try await harness { h in
            let s = try await scene(h)
            try await h.enroll(s.consumer, s.business, reference: "ACCT-SECRET-1")
            let reward = try await h.reward(s.business)
            let code = try await h.redeem(s.consumer, reward.id).json(RewardRedemption.self).redemptionCode
            _ = try await h.consume(s.business, code: code)
            let events = try await AuditEventRecord.query(on: h.db).all()
            XCTAssertTrue(events.contains { $0.action == "reward.redemption_issued" })
            XCTAssertTrue(events.contains { $0.action == "reward.redeemed" })
            for event in events {
                XCTAssertFalse(event.metadataJSON.contains(code))
                XCTAssertFalse(event.metadataJSON.contains("SECRET"))
            }
            XCTAssertEqual(LogRedactor.redact("redeemed \(code) ok"), "redeemed [redacted-code] ok")
            XCTAssertEqual(LogRedactor.redact("invite K7M2-9QXP now"), "invite [redacted-code] now")
            XCTAssertEqual(RequestLoggingMiddleware.safePath("/wallet/v1/passes/pass.com.viadere.test/VP-abc"), "/wallet/v1/passes/:id/:id")
            XCTAssertEqual(RequestLoggingMiddleware.safePath("/wallet/v1/devices/dev1/registrations/pass.x/VP-abc"), "/wallet/v1/devices/:id/registrations/:id/:id")
        }
    }
}

extension Optional {
    func unwrap(file: StaticString = #filePath, line: UInt = #line) throws -> Wrapped {
        try XCTUnwrap(self, file: file, line: line)
    }
}
