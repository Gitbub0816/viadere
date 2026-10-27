import Foundation
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// The eligibility verdict is a pure function of server-side facts and the server clock.
final class RewardEligibilityTests: XCTestCase {
    private func zone(_ id: String) -> TimeZone { TimeZone(identifier: id)! }

    private func facts(kind: RewardKind = .perk, weekdays: [Int] = [], zone id: String = "America/Phoenix", perDay: Int? = nil, cost: Int? = nil,
                       validFrom: Date? = nil, validUntil: Date? = nil, claimed: Bool = false, usage: Int = 0, redeemed: Bool = false,
                       balance: Int? = nil, revoked: Bool = false, held: Date? = nil) -> RewardFacts {
        RewardFacts(kind: kind, revoked: revoked, validFrom: validFrom, validUntil: validUntil, weekdays: weekdays, timeZone: zone(id), perDayLimit: perDay,
                    pointsCost: cost, claimedAt: claimed ? Date(timeIntervalSince1970: 1) : nil, lifetimeRedeemed: redeemed, usageInWindow: usage,
                    earliestHeldCodeExpiry: held, pointsBalance: balance)
    }

    private func at(_ text: String, _ zone: String) -> Date { TestHarness.date(text, zone) }

    // MARK: Recurrence in the business's zone

    func testTuesdayRewardFollowsTheBusinessTimeZoneNotTheClientsOrUTC() {
        // 2027-01-12 is a Tuesday. This one instant is Monday evening in Phoenix and Tuesday afternoon in Auckland.
        let instant = Date(timeIntervalSince1970: 1_799_719_200)   // 2027-01-12T02:00:00Z
        XCTAssertEqual(RewardEligibilityEvaluator.isoWeekday(instant, in: zone("America/Phoenix")), 1)
        XCTAssertEqual(RewardEligibilityEvaluator.isoWeekday(instant, in: zone("Pacific/Auckland")), 2)
        XCTAssertEqual(RewardEligibilityEvaluator.isoWeekday(instant, in: zone("UTC")), 2)

        let phoenix = RewardEligibilityEvaluator.evaluate(facts(weekdays: [2], zone: "America/Phoenix"), now: instant)
        XCTAssertEqual(phoenix.state, .notToday)
        XCTAssertEqual(phoenix.nextAction, .none)
        XCTAssertEqual(phoenix.nextEligibleAt, at("2027-01-12 00:00", "America/Phoenix"), "next Tuesday starts at Phoenix midnight")

        let auckland = RewardEligibilityEvaluator.evaluate(facts(weekdays: [2], zone: "Pacific/Auckland"), now: instant)
        XCTAssertEqual(auckland.state, .eligible)
        XCTAssertEqual(auckland.nextAction, .redeem)
        XCTAssertEqual(auckland.checkedAt, instant)
    }

    func testMidnightBoundaryIsExactInTheBusinessZone() {
        let f = facts(weekdays: [2], zone: "America/Phoenix")
        XCTAssertEqual(RewardEligibilityEvaluator.evaluate(f, now: at("2027-01-11 23:59", "America/Phoenix")).state, .notToday)
        XCTAssertEqual(RewardEligibilityEvaluator.evaluate(f, now: at("2027-01-12 00:00", "America/Phoenix")).state, .eligible)
        XCTAssertEqual(RewardEligibilityEvaluator.evaluate(f, now: at("2027-01-12 23:59", "America/Phoenix")).state, .eligible)
        XCTAssertEqual(RewardEligibilityEvaluator.evaluate(f, now: at("2027-01-13 00:00", "America/Phoenix")).state, .notToday)
    }

    func testDaylightSavingDaysAreNotAssumedToBe24Hours() {
        let ny = "America/New_York"
        // Spring forward 2027-03-14 (a 23-hour Sunday). The next Monday starts at 00:00 EDT, not 24h after Sunday 00:00 EST.
        let sunday = at("2027-03-14 20:00", ny)
        let verdict = RewardEligibilityEvaluator.evaluate(facts(weekdays: [1], zone: ny), now: sunday)
        XCTAssertEqual(verdict.state, .notToday)
        XCTAssertEqual(verdict.nextEligibleAt, at("2027-03-15 00:00", ny))
        XCTAssertEqual(verdict.nextEligibleAt, Date(timeIntervalSince1970: at("2027-03-14 00:00", ny).timeIntervalSince1970 + 23 * 3600))
        // Fall back 2027-11-07 (a 25-hour Sunday): the repeated 01:30 is one local day with one day key and one limit window.
        let first = Date(timeIntervalSince1970: at("2027-11-07 00:00", ny).timeIntervalSince1970 + 1.5 * 3600)       // 01:30 EDT
        let second = Date(timeIntervalSince1970: first.timeIntervalSince1970 + 3600)                                 // 01:30 EST
        XCTAssertEqual(RewardEligibilityEvaluator.dayKey(first, in: zone(ny)), "2027-11-07")
        XCTAssertEqual(RewardEligibilityEvaluator.dayKey(second, in: zone(ny)), "2027-11-07")
        XCTAssertEqual(RewardEligibilityEvaluator.dayKey(at("2027-11-07 23:30", ny), in: zone(ny)), "2027-11-07")
        XCTAssertEqual(RewardEligibilityEvaluator.dayKey(at("2027-11-08 00:00", ny), in: zone(ny)), "2027-11-08")
        let next = try? XCTUnwrap(RewardEligibilityEvaluator.startOfNextDay(after: second, in: zone(ny)))
        XCTAssertEqual(next, at("2027-11-08 00:00", ny))
        XCTAssertEqual(next!.timeIntervalSince(at("2027-11-07 00:00", ny)), 25 * 3600)
    }

    func testDayKeyDiffersBetweenZonesForTheSameInstant() {
        let instant = at("2027-01-12 23:30", "America/Los_Angeles")
        XCTAssertEqual(RewardEligibilityEvaluator.dayKey(instant, in: zone("America/Los_Angeles")), "2027-01-12")
        XCTAssertEqual(RewardEligibilityEvaluator.dayKey(instant, in: zone("Europe/London")), "2027-01-13")
    }

    func testNextEligibleDoesNotPassTheEndOfValidity() {
        let now = at("2027-01-12 12:00", "America/Phoenix")                              // Tuesday
        let f = facts(weekdays: [2], perDay: 1, validUntil: at("2027-01-15 00:00", "America/Phoenix"), usage: 1)
        let verdict = RewardEligibilityEvaluator.evaluate(f, now: now)
        XCTAssertEqual(verdict.state, .limitReached)
        XCTAssertNil(verdict.nextEligibleAt, "the next Tuesday is after the reward ends")
    }

    // MARK: Limits

    func testPerDayLimitCountsCodesAndFreesAtLocalMidnight() {
        let now = at("2027-01-12 10:00", "America/Phoenix")
        let two = facts(weekdays: [2], perDay: 2, usage: 1)
        XCTAssertEqual(RewardEligibilityEvaluator.evaluate(two, now: now).state, .eligible)
        var used = two
        used.usageInWindow = 2
        let limited = RewardEligibilityEvaluator.evaluate(used, now: now)
        XCTAssertEqual(limited.state, .limitReached)
        XCTAssertEqual(limited.nextAction, .none)
        XCTAssertEqual(limited.nextEligibleAt, at("2027-01-19 00:00", "America/Phoenix"))
        // A daily (every weekday) reward is back tomorrow.
        let daily = RewardEligibilityEvaluator.evaluate(facts(weekdays: [1, 2, 3, 4, 5, 6, 7], perDay: 1, usage: 1), now: now)
        XCTAssertEqual(daily.nextEligibleAt, at("2027-01-13 00:00", "America/Phoenix"))
    }

    func testCouponsAreClaimedThenRedeemedOnceForever() {
        let now = at("2027-01-12 10:00", "UTC")
        XCTAssertEqual(RewardEligibilityEvaluator.evaluate(facts(kind: .coupon, zone: "UTC"), now: now).nextAction, .claim)
        XCTAssertEqual(RewardEligibilityEvaluator.evaluate(facts(kind: .coupon, zone: "UTC", claimed: true), now: now).nextAction, .redeem)
        XCTAssertEqual(RewardEligibilityEvaluator.evaluate(facts(kind: .perk, zone: "UTC"), now: now).nextAction, .redeem, "perks need no claim")
        let held = now.addingTimeInterval(90)
        let pending = RewardEligibilityEvaluator.evaluate(facts(kind: .coupon, zone: "UTC", claimed: true, usage: 1, held: held), now: now)
        XCTAssertEqual(pending.state, .limitReached, "an unexpired code holds the single use")
        XCTAssertEqual(pending.nextEligibleAt, held, "…and frees up when it expires")
        XCTAssertEqual(RewardEligibilityEvaluator.evaluate(facts(kind: .coupon, zone: "UTC", claimed: true, redeemed: true), now: now).state, .redeemed)
    }

    func testPointsRewardsReportTheShortfall() {
        let now = at("2027-01-12 10:00", "UTC")
        let short = RewardEligibilityEvaluator.evaluate(facts(kind: .pointsReward, zone: "UTC", cost: 500, balance: 320), now: now)
        XCTAssertEqual(short.state, .insufficientPoints)
        XCTAssertEqual(short.pointsShortfall, 180)
        XCTAssertEqual(short.nextAction, .none)
        XCTAssertEqual(RewardEligibilityEvaluator.evaluate(facts(kind: .pointsReward, zone: "UTC", cost: 500, balance: nil), now: now).pointsShortfall, 500, "no account = 0 points")
        let enough = RewardEligibilityEvaluator.evaluate(facts(kind: .pointsReward, zone: "UTC", cost: 500, balance: 500), now: now)
        XCTAssertEqual(enough.state, .eligible)
        XCTAssertEqual(enough.nextAction, .redeem)
        XCTAssertNil(enough.pointsShortfall)
        // Points rewards can be redeemed repeatedly: usage never limits them without an explicit per-day limit.
        XCTAssertEqual(RewardEligibilityEvaluator.evaluate(facts(kind: .pointsReward, zone: "UTC", cost: 10, usage: 5, balance: 100), now: now).state, .eligible)
    }

    // MARK: Validity and revocation

    func testValidityWindowRevocationAndPrecedence() {
        let now = at("2027-01-12 10:00", "America/Phoenix")                              // Tuesday
        let future = RewardEligibilityEvaluator.evaluate(facts(validFrom: at("2027-01-14 00:00", "America/Phoenix")), now: now)
        XCTAssertEqual(future.state, .notYetValid)
        XCTAssertEqual(future.nextEligibleAt, at("2027-01-14 00:00", "America/Phoenix"))
        // With a Tuesday rule the first moment is the following Tuesday, not the start of validity.
        let recurring = RewardEligibilityEvaluator.evaluate(facts(weekdays: [2], validFrom: at("2027-01-14 00:00", "America/Phoenix")), now: now)
        XCTAssertEqual(recurring.nextEligibleAt, at("2027-01-19 00:00", "America/Phoenix"))
        XCTAssertEqual(RewardEligibilityEvaluator.evaluate(facts(validUntil: now), now: now).state, .expired, "validUntil is exclusive")
        XCTAssertEqual(RewardEligibilityEvaluator.evaluate(facts(validUntil: now.addingTimeInterval(1)), now: now).state, .eligible)
        XCTAssertEqual(RewardEligibilityEvaluator.evaluate(facts(redeemed: true, revoked: true), now: now).state, .revoked, "revocation wins")
        XCTAssertEqual(RewardEligibilityEvaluator.evaluate(facts(validUntil: now.addingTimeInterval(-1), redeemed: true), now: now).state, .redeemed)
    }

    func testCodeFormatAndNormalization() {
        for _ in 0..<50 {
            let code = RewardsService.generateCode()
            XCTAssertEqual(code.count, 11)
            XCTAssertNotNil(RewardsService.normalizeCode(code))
            XCTAssertEqual(RewardsService.normalizeCode(code.lowercased().replacingOccurrences(of: "-", with: " ")), RewardsService.normalizeCode(code))
        }
        XCTAssertEqual(RewardsService.normalizeCode("ioL0O-11abc"), "1010011ABC", "look-alikes fold")
        XCTAssertNil(RewardsService.normalizeCode("ABCDE-FGHJ"), "too short")
        XCTAssertNil(RewardsService.normalizeCode("ABCDE-FGHJKU"), "too long")
        XCTAssertNil(RewardsService.normalizeCode("ABCDE-FGHJ!"), "outside the alphabet")
        XCTAssertNil(RewardsService.normalizeCode("UUUUU-UUUUU"), "U is not in the alphabet")
        XCTAssertEqual(Set((0..<200).map { _ in RewardsService.generateCode() }).count, 200, "no repeats")
    }
}
