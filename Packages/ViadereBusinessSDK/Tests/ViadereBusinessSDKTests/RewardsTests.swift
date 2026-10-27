import Foundation
import Testing
import ViadereCore
@testable import ViadereBusinessSDK

@Suite("Rewards and redemption")
struct RewardsTests {
    private func reward(_ title: String = "Free coffee") -> Reward {
        Reward(id: RewardID(), business: BusinessSummary(id: BusinessID(), displayName: "Juniper", handle: BusinessHandle(parsing: "juniper"),
                                                         code: BusinessCode.generate(), verificationStatus: .verified),
               title: title, status: .available)
    }

    @Test func createRewardSendsTheIdempotencyKeyAndReportsReplays() async throws {
        let transport = MockTransport()
        let client = try Fixtures.client(transport)
        let request = IssueRewardRequest(title: "Free coffee", kind: .perk, recurrence: RewardRecurrence(weekdays: [2], perDayLimit: 1, timeZone: "America/Phoenix"),
                                         idempotencyKey: "reward-tuesday")
        try transport.enqueue(status: 201, json: reward())
        let created = try await client.createReward(request)
        #expect(created.wasCreated)
        try transport.enqueue(status: 200, json: reward())
        #expect(try await client.createReward(request).wasCreated == false)
        let sent = try #require(transport.requests.first)
        #expect(sent.method == "POST" && sent.url.path == "/v1/business/rewards")
        #expect(sent.headers["Idempotency-Key"] == "reward-tuesday")
        #expect(try ViadereJSON.decode(IssueRewardRequest.self, from: #require(sent.body)) == request)
    }

    @Test func programPointsListAndRevokeUseTheCatalog() async throws {
        let transport = MockTransport()
        let client = try Fixtures.client(transport)
        let program = BusinessLoyaltyProgram(programName: "Juniper Club", summary: "Earn points", termsVersion: "v1", timeZone: "America/Phoenix",
                                             tiers: [LoyaltyTier(name: "Silver", minimumPoints: 100)], memberCount: 3, updatedAt: Fixtures.now)
        try transport.enqueue(status: 200, json: program)
        _ = try await client.saveLoyaltyProgram(UpsertLoyaltyProgramRequest(programName: "Juniper Club", summary: "Earn points", termsVersion: "v1",
                                                                            timeZone: "America/Phoenix", tiers: program.tiers))
        try transport.enqueue(status: 200, json: program)
        #expect(try await client.loyaltyProgram().memberCount == 3)
        let relationship = RelationshipID()
        try transport.enqueue(status: 200, json: LoyaltyPointsResult(relationshipId: relationship, pointsBalance: 25, applied: true))
        let result = try await client.adjustPoints(AdjustLoyaltyPointsRequest(relationshipId: relationship, delta: 25, reason: "purchase", idempotencyKey: "pts-1"))
        #expect(result.pointsBalance == 25)
        try transport.enqueue(status: 200, json: [reward()])
        #expect(try await client.listRewards().count == 1)
        let id = RewardID()
        try transport.enqueue(status: 200, json: reward())
        _ = try await client.revokeReward(id: id)
        let calls = transport.requests.map { "\($0.method) \($0.url.path)" }
        #expect(calls == ["PUT /v1/business/loyalty/program", "GET /v1/business/loyalty/program", "POST /v1/business/loyalty/points",
                          "GET /v1/business/rewards", "POST /v1/business/rewards/\(id)/revoke"])
        #expect(transport.requests[2].headers["Idempotency-Key"] == "pts-1")
    }

    @Test func consumingACodeIsAtomicOnTheServerAndNeverRetriedBlindly() async throws {
        let transport = MockTransport()
        let client = try Fixtures.client(transport)
        let receipt = RedemptionReceipt(redemptionId: RedemptionID(), rewardId: RewardID(), rewardTitle: "Free coffee", kind: .perk,
                                        consumerReference: ConsumerID(), redeemedAt: Fixtures.now, locationCode: "till-2")
        try transport.enqueue(status: 200, json: receipt)
        let consumed = try await client.consumeRedemption(code: "abcde-fghjk", locationCode: "till-2")
        #expect(consumed == receipt)
        let body = try ViadereJSON.decode(ConsumeRedemptionRequest.self, from: #require(transport.requests[0].body))
        #expect(body.code == "abcde-fghjk" && body.locationCode == "till-2")
        #expect(transport.requests[0].headers["Idempotency-Key"] == nil)
        // A 500 is not retried: a repeat after a lost response would report "already used".
        try transport.enqueue(status: 500, json: Fixtures.errorBody(.internalError))
        await #expect(throws: ViadereAPIError.self) { try await client.consumeRedemption(code: "ABCDE-FGHJK") }
        #expect(transport.requests.count == 2)
        // A used code surfaces as a typed 409.
        try transport.enqueue(status: 409, json: Fixtures.errorBody(.conflict, "This code was already used."))
        do {
            _ = try await client.consumeRedemption(code: "ABCDE-FGHJK")
            Issue.record("expected an error")
        } catch let error as ViadereAPIError {
            #expect(error.status == 409 && error.code == .conflict)
        }
    }
}
