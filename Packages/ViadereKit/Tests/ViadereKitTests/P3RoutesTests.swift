import Testing
import Foundation
import ViadereCore
@testable import ViadereKit

@Suite("P3 routes over HTTP")
struct P3RouteTests {
    @Test func routesAreDeviceSignedAndPathsMatchTheContract() async throws {
        let env = try await ClientEnv()
        let transport = FakeTransport { request, _ in
            if request.url.path.hasPrefix("/v1/wallet/passes/") { return HTTPResponse(status: 200, headers: ["content-type": "application/vnd.apple.pkpass"], body: Data([0x50, 0x4B, 0x03, 0x04])) }
            if request.url.path == "/v1/rewards/overview" { return json(#"{"accounts":[],"rewards":[]}"#) }
            if request.url.path == "/v1/household" { return json(#"{"given":[],"received":[]}"#) }
            return json("[]")
        }
        let (client, _) = env.client(transport: transport)
        let api = LiveViadereAPI(client: client)
        let passId = WalletPassID()
        let delegationId = DelegationID()

        _ = try await api.rewardsOverview()
        _ = try await api.walletPasses()
        let bytes = try await api.walletPass(passId)
        #expect(bytes == Data([0x50, 0x4B, 0x03, 0x04]))
        _ = try await api.household()
        _ = try await api.householdAudit()
        _ = try await api.acknowledgments()
        try await api.revokeDelegation(delegationId)

        let seen = transport.requests.map { "\($0.method) \($0.url.path)" }
        #expect(seen == ["GET /v1/rewards/overview", "GET /v1/wallet/passes", "GET /v1/wallet/passes/\(passId)", "GET /v1/household",
                         "GET /v1/household/audit", "GET /v1/acknowledgments", "DELETE /v1/delegations/\(delegationId)"])
        // every one is a device-signed bearer request
        for request in transport.requests {
            #expect(request.headers["Authorization"] == "Bearer tok-1")
            #expect(request.headers[ViadereHeader.signature] != nil)
        }
    }

    @Test func claimAndRedeemAreSignedPosts() async throws {
        let env = try await ClientEnv()
        let transport = FakeTransport { _, _ in json("{}") }
        let (client, _) = env.client(transport: transport)
        let api = LiveViadereAPI(client: client)
        let id = RewardID()
        _ = try? await api.claimReward(id)
        _ = try? await api.redeemReward(id, RedeemRewardRequest(locationCode: "PHX-01"))
        let requests = transport.requests
        #expect(requests.map(\.method.rawValue) == ["POST", "POST"])
        let paths: [String] = requests.map { pathAndQuery($0.url) }
        #expect(paths == ["/v1/rewards/\(id)/claim", "/v1/rewards/\(id)/redeem"])
        #expect(requests.allSatisfy { $0.headers[ViadereHeader.signature] != nil })
    }

    @Test func missingServerSupportReadsAsNotFound() async throws {
        let env = try await ClientEnv()
        let transport = FakeTransport { _, _ in json(404, errorBody("not_found")) }
        let (client, _) = env.client(transport: transport)
        let api = LiveViadereAPI(client: client)
        do {
            _ = try await api.rewardsOverview()
            Issue.record("expected 404")
        } catch let error as APIError {
            #expect(error.code == .notFound)
        }
    }

    @Test func remainingP3CallsUseTheCoreCatalog() async throws {
        let env = try await ClientEnv()
        let transport = FakeTransport { request, _ in
            if request.url.path == "/v1/sessions" {
                return json(#"[{"id":"7b1d3c7e-0d3a-4d3e-9d4b-1f3f4c2a9a10","createdAt":"2026-10-27T12:00:00.000Z","expiresAt":"2026-11-27T12:00:00.000Z","current":true}]"#)
            }
            return json("{}")
        }
        let (client, _) = env.client(transport: transport)
        let api = LiveViadereAPI(client: client)
        let business = BusinessID()
        let sessions = try await api.sessions()
        #expect(sessions.count == 1 && sessions[0].isCurrent && sessions[0].id == "7b1d3c7e-0d3a-4d3e-9d4b-1f3f4c2a9a10")
        _ = try? await api.loyaltyProgram(business: business)
        _ = try? await api.enrollLoyalty(business: business, LoyaltyEnrollRequest(acceptedTermsVersion: "v1"))
        _ = try? await api.previewDelegationInvitation(code: "K7M2-9QXP")
        _ = try? await api.acceptDelegationInvitation(code: "K7M2-9QXP")
        let seen = transport.requests.map { "\($0.method) \($0.url.path)" }
        #expect(seen == ["GET /v1/sessions", "GET /v1/loyalty/\(business)", "POST /v1/loyalty/\(business)/enroll",
                         "POST /v1/household/invitations/preview", "POST /v1/household/invitations/accept"])
        // the Kit and Core agree on one definition of every P3 route
        #expect(APIRoutes.rewardsOverview.auth == .deviceSignedBearer)
        #expect(APIRoutes.household.auth == .deviceSignedBearer)
    }
}
