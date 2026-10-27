import Testing
import Foundation
import ViadereCore
@testable import ViadereKit

@Suite("Rewards eligibility display")
struct RewardDisplayTests {
    private func entry(state: RewardEligibility.State, action: RewardEligibility.Action = .none, recurrence: RewardRecurrence? = nil,
                       checkedAt: Date = tuesdayNoon, next: Date? = nil, short: Int? = nil) -> RewardEntry {
        let reward = Reward(id: RewardID(), business: PreviewData.juniperCoffee, title: "Free coffee", status: .available, recurrence: recurrence)
        return RewardEntry(reward: reward, kind: .perk,
                           eligibility: RewardEligibility(state: state, nextAction: action, checkedAt: checkedAt, nextEligibleAt: next, pointsShortfall: short))
    }

    @Test func recurrenceCopyDescribesTheRule() {
        #expect(RewardCopy.recurrence(RewardRecurrence(weekdays: [2], timeZone: "America/Phoenix")) == "Every Tuesday")
        #expect(RewardCopy.recurrence(RewardRecurrence(weekdays: [1, 2, 3, 4, 5], timeZone: "UTC")) == "Weekdays")
        #expect(RewardCopy.recurrence(RewardRecurrence(weekdays: [6, 7], timeZone: "UTC")) == "Weekends")
        #expect(RewardCopy.recurrence(RewardRecurrence(weekdays: [1, 3, 5], timeZone: "UTC")) == "Mon, Wed and Fri")
        #expect(RewardCopy.recurrence(RewardRecurrence(weekdays: [2], perDayLimit: 2, timeZone: "UTC")) == "Every Tuesday · up to 2 a day")
        #expect(RewardCopy.recurrence(RewardRecurrence(weekdays: [], timeZone: "UTC")) == "")
    }

    @Test func actionComesOnlyFromTheServerVerdict() {
        let now = tuesdayNoon
        let eligible = RewardRowPresentation(entry(state: .eligible, action: .redeem), now: now, fetchedAt: now)
        #expect(eligible.action == .redeem && eligible.actionTitle == "Use now" && eligible.tone == .available)
        let claim = RewardRowPresentation(entry(state: .eligible, action: .claim), now: now, fetchedAt: now)
        #expect(claim.actionTitle == "Claim")
        for state in RewardEligibility.State.allCases where state != .eligible {
            let p = RewardRowPresentation(entry(state: state, action: .redeem), now: now, fetchedAt: now)
            #expect(p.action == .none, "\(state) must never offer an action")
        }
    }

    @Test func clientNeverSecondGuessesTheServerWithTheRecurrenceRule() {
        // The rule says Tuesdays only, but the clock says Wednesday and the server says eligible (e.g. a time-zone
        // difference or a one-off exception). The client follows the server.
        let recurrence = RewardRecurrence(weekdays: [2], timeZone: "America/Phoenix")
        let e = entry(state: .eligible, action: .redeem, recurrence: recurrence)
        #expect(!recurrence.isEligible(on: wednesdayNoon))
        let p = RewardRowPresentation(e, now: wednesdayNoon, fetchedAt: wednesdayNoon)
        #expect(p.action == .redeem)
        // ...and the reverse: the rule says today works, the server says no.
        let denied = entry(state: .limitReached, recurrence: recurrence)
        #expect(RewardRowPresentation(denied, now: tuesdayNoon, fetchedAt: tuesdayNoon).action == .none)
    }

    @Test func staleVerdictsAreRefreshedBeforeOfferingAnAction() {
        let e = entry(state: .eligible, action: .redeem)
        let stale = RewardRowPresentation(e, now: tuesdayNoon.addingTimeInterval(600), fetchedAt: tuesdayNoon)
        #expect(stale.needsRefresh && stale.action == .none)
        let fresh = RewardRowPresentation(e, now: tuesdayNoon.addingTimeInterval(60), fetchedAt: tuesdayNoon)
        #expect(!fresh.needsRefresh && fresh.action == .redeem)
        // a device clock that is far *behind* the fetch time doesn't hide the action either
        #expect(RewardRowPresentation(e, now: tuesdayNoon.addingTimeInterval(-3_600), fetchedAt: tuesdayNoon).action == .redeem)
    }

    @Test func statusLinesAreCalm() {
        let next = tuesdayNoon.addingTimeInterval(86_400)
        let zone = TimeZone(identifier: "America/Phoenix") ?? .current
        #expect(RewardRowPresentation(entry(state: .notToday, next: next), now: tuesdayNoon, fetchedAt: tuesdayNoon, timeZone: zone).statusLine.hasPrefix("Next available"))
        #expect(RewardRowPresentation(entry(state: .insufficientPoints, short: 260), now: tuesdayNoon, fetchedAt: tuesdayNoon).statusLine == "260 points to go")
        #expect(RewardRowPresentation(entry(state: .expired), now: tuesdayNoon, fetchedAt: tuesdayNoon).tone == .finished)
        #expect(RewardRowPresentation(entry(state: .limitReached), now: tuesdayNoon, fetchedAt: tuesdayNoon).statusLine == "Used for now")
    }

    @Test func unknownServerStatesDegradeSafely() throws {
        let json = #"{"state":"quantum_superposition","nextAction":"teleport","checkedAt":"2026-10-27T18:00:00.000Z"}"#
        let decoded = try ViadereJSON.decode(RewardEligibility.self, from: Data(json.utf8))
        #expect(decoded.state == .unavailable && decoded.nextAction == .none)
    }

    @Test func pointsFormatting() {
        #expect(RewardCopy.points(1) == "1 point")
        #expect(RewardCopy.points(260) == "260 points")
    }
}

@Suite("Rewards flows")
@MainActor
struct RewardFlowTests {
    @Test func aggregatedOverviewIsOrderedByServerVerdict() async throws {
        let (services, _) = await p3World()
        let model = RewardsViewModel(services: services)
        await model.load()
        #expect(model.phase == .loaded)
        #expect(model.accounts.count == 2)
        let ready = try #require(model.sections.first { $0.kind == .available })
        #expect(ready.entries.contains { $0.reward.title == "Free coffee on Tuesdays" })
        let waiting = try #require(model.sections.first { $0.kind == .waiting })
        #expect(waiting.entries.contains { $0.reward.title == "Birthday drink" })
        #expect(model.sections.first { $0.kind == .finished }?.entries.first?.reward.title == "Welcome cookie")
    }

    @Test func tuesdayRewardIsNotOfferedOnWednesday() async throws {
        let (services, _) = await p3World(now: wednesdayNoon)
        let model = RewardsViewModel(services: services)
        await model.load()
        let coffee = try #require(model.overview.rewards.first { $0.reward.title == "Free coffee on Tuesdays" })
        #expect(coffee.eligibility.state == .notToday)
        #expect(model.presentation(for: coffee).action == .none)
        #expect(coffee.eligibility.nextEligibleAt != nil)
    }

    @Test func claimThenRedeemWithServerSideChecks() async throws {
        let (services, _) = await p3World()
        let model = RewardsViewModel(services: services)
        await model.load()
        let pastry = try #require(model.overview.rewards.first { $0.reward.title == "Pastry with any drink" })
        #expect(pastry.eligibility.nextAction == .claim)
        await model.claim(pastry)
        let claimed = try #require(model.entry(pastry.id))
        #expect(claimed.claimedAt != nil && claimed.eligibility.nextAction == .redeem)
        #expect(model.message?.hasPrefix("Claimed") == true)
    }

    @Test func serverRefusesAClaimThatIsNoLongerValid() async throws {
        let (services, api) = await p3World()
        let model = RewardsViewModel(services: services)
        await model.load()
        let pastry = try #require(model.overview.rewards.first { $0.reward.title == "Pastry with any drink" })
        _ = try await api.claimReward(pastry.id)   // claimed elsewhere first
        await model.claim(pastry)                  // second claim: the server says no
        #expect(model.message?.contains("isn't available") == true)
        // the list was refreshed to the server's current verdict
        #expect(model.entry(pastry.id)?.eligibility.nextAction == .redeem)
    }

    @Test func redemptionCodeLifecycleCountdownAndWipe() async throws {
        let (services, _) = await p3World()
        let rewards = RewardsViewModel(services: services)
        await rewards.load()
        let coffee = try #require(rewards.overview.rewards.first { $0.reward.title == "Free coffee on Tuesdays" })
        let redemption = rewards.redemption(for: coffee)
        #expect(redemption.visibleCode == nil)
        await redemption.start()
        #expect(redemption.phase == .active)
        let code = try #require(redemption.visibleCode)
        #expect(code.count == 8 && redemption.qrPayload == code)
        #expect(redemption.displayCode?.contains(" ") == true)
        #expect(redemption.countdownLabel == "2:00")
        #expect(redemption.fraction == 1)
        redemption.tick(tuesdayNoon.addingTimeInterval(60))
        #expect(redemption.countdownLabel == "1:00" && redemption.fraction == 0.5)
        // recording hides the code, ending the recording brings it back
        redemption.isScreenBeingCaptured = true
        #expect(redemption.visibleCode == nil && redemption.qrPayload == nil)
        redemption.isScreenBeingCaptured = false
        #expect(redemption.visibleCode == code)
        // a screenshot is noted but doesn't break the flow
        redemption.noteScreenshot()
        #expect(redemption.screenshotTaken && redemption.phase == .active)
        // expiry wipes the code
        redemption.tick(tuesdayNoon.addingTimeInterval(121))
        #expect(redemption.phase == .expired && redemption.visibleCode == nil && redemption.canRequestAgain)
    }

    @Test func leavingTheScreenForgetsTheCode() async throws {
        let (services, _) = await p3World()
        let rewards = RewardsViewModel(services: services)
        await rewards.load()
        let coffee = try #require(rewards.overview.rewards.first { $0.reward.title == "Free coffee on Tuesdays" })
        let redemption = rewards.redemption(for: coffee)
        await redemption.start()
        #expect(redemption.visibleCode != nil)
        redemption.invalidate()
        #expect(redemption.visibleCode == nil && redemption.codeForSecureCopy == nil && redemption.phase == .expired)
        redemption.noteScreenshot()
        #expect(!redemption.screenshotTaken)   // nothing to protect any more
    }

    @Test func secondRedemptionOnTheSameDayIsRefusedByTheServer() async throws {
        let (services, _) = await p3World()
        let rewards = RewardsViewModel(services: services)
        await rewards.load()
        let coffee = try #require(rewards.overview.rewards.first { $0.reward.title == "Free coffee on Tuesdays" })
        let first = rewards.redemption(for: coffee)
        await first.start()
        #expect(first.phase == .active)
        // the screen still holds the old "eligible" verdict (e.g. a second device): the server is authoritative
        let second = rewards.redemption(for: coffee)
        await second.start()
        guard case .refused = second.phase else { Issue.record("expected the server to refuse, got \(second.phase)"); return }
        #expect(second.visibleCode == nil)
    }

    @Test func nothingIsRequestedForRewardsTheServerDidNotMarkEligible() async throws {
        let (services, api) = await p3World(now: wednesdayNoon)
        let rewards = RewardsViewModel(services: services)
        await rewards.load()
        let coffee = try #require(rewards.overview.rewards.first { $0.reward.title == "Free coffee on Tuesdays" })
        let redemption = rewards.redemption(for: coffee)
        await redemption.start()
        guard case .refused = redemption.phase else { Issue.record("expected refused"); return }
        // and the server's own check agrees
        await #expect(throws: APIError.self) { _ = try await api.redeemReward(coffee.id, RedeemRewardRequest()) }
    }

    @Test func pointsRewardShowsTheServersShortfall() async throws {
        let (services, _) = await p3World()
        let rewards = RewardsViewModel(services: services)
        await rewards.load()
        let beans = try #require(rewards.overview.rewards.first { $0.reward.title == "Free bag of beans" })
        #expect(beans.eligibility.state == .insufficientPoints && beans.eligibility.pointsShortfall == 260)
        #expect(rewards.presentation(for: beans).statusLine == "260 points to go")
    }

    @Test func enrollmentFromBusinessDetail() async throws {
        let (services, _) = await p3World()
        let model = BusinessRewardsViewModel(business: PreviewData.lumenTheater, services: services)
        await model.load()
        #expect(model.phase == .loaded && !model.isEnrolled)
        #expect(model.rewards.first?.reward.title == "Intermission drink")
        let ok = await model.enroll(existingMemberReference: "  LC-99-4410 ")
        #expect(ok && model.isEnrolled)
        #expect(model.account?.memberReference == "••4410")
        #expect(model.account?.pointsBalance == 320)   // linked an existing membership
    }

    @Test func businessWithoutAProgramHidesTheSection() async throws {
        let (services, _) = await p3World()
        let model = BusinessRewardsViewModel(business: PreviewData.lindenDental, services: services)
        await model.load()
        #expect(model.phase == .noProgram)
    }

    @Test func staleTermsAreRejectedByTheServer() async throws {
        let (_, api) = await p3World()
        await #expect(throws: APIError.self) {
            _ = try await api.enrollLoyalty(business: PreviewData.lumenTheater.id, LoyaltyEnrollRequest(acceptedTermsVersion: "2019-01"))
        }
    }

    @Test func codeFormatting() {
        #expect(RedemptionCodeFormat.display("K7M29QXP") == "K7M2 9QXP")
        #expect(RedemptionCodeFormat.display("AB") == "AB")
        #expect(RedemptionCodeFormat.spoken("K7M2") == "K 7 M 2")
    }
}
