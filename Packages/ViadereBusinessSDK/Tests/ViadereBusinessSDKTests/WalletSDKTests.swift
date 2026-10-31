import Foundation
import Testing
import ViadereCore
@testable import ViadereBusinessSDK

@Suite("Wallet passes")
struct WalletSDKTests {
    private func pass(voided: Bool = false) -> BusinessWalletPass {
        BusinessWalletPass(id: WalletPassID(), kind: .eventTicket, relationshipId: RelationshipID(), issuedBy: .business, voided: voided,
                           createdAt: Fixtures.now, updatedAt: Fixtures.now)
    }

    @Test func issueListUpdateAndVoidUseTheCatalog() async throws {
        let transport = MockTransport()
        let client = try Fixtures.client(transport)
        let issued = pass()
        try transport.enqueue(status: 201, json: issued)
        let request = BusinessIssueWalletPassRequest(relationshipId: issued.relationshipId, kind: .eventTicket, interactionId: InteractionID())
        #expect(try await client.issueWalletPass(request).wasCreated)
        try transport.enqueue(status: 200, json: issued)
        #expect(try await client.issueWalletPass(request).wasCreated == false)
        try transport.enqueue(status: 200, json: [issued])
        #expect(try await client.listWalletPasses(limit: 999).count == 1)
        try transport.enqueue(status: 200, json: issued)
        _ = try await client.updateWalletPass(id: issued.id, UpdateWalletPassRequest(venue: "Hall B"))
        try transport.enqueue(status: 200, json: pass(voided: true))
        #expect(try await client.voidWalletPass(id: issued.id).voided)
        let calls = transport.requests.map { "\($0.method) \($0.url.path)" }
        #expect(calls == ["POST /v1/business/wallet/passes", "POST /v1/business/wallet/passes", "GET /v1/business/wallet/passes",
                          "PATCH /v1/business/wallet/passes/\(issued.id)", "POST /v1/business/wallet/passes/\(issued.id)/void"])
        #expect(transport.requests[2].url.query == "limit=200", "the limit is clamped to the server's maximum")
        #expect(try ViadereJSON.decode(UpdateWalletPassRequest.self, from: #require(transport.requests[3].body)).venue == "Hall B")
    }

    @Test func scanningIsNeverRetriedAndGarbageNeverLeavesTheDevice() async throws {
        let transport = MockTransport()
        let client = try Fixtures.client(transport)
        // Malformed input: refused locally, no request.
        await #expect(throws: ViadereAPIError.self) { try await client.scanWalletPass(code: "K7M2Q-9XPB4") }
        #expect(transport.requests.isEmpty)
        let code = WalletScanCode.prefix + String(repeating: "A", count: 48)
        let result = WalletScanResult(outcome: .checkedIn, passId: WalletPassID(), kind: .eventTicket, relationshipId: RelationshipID(), scannedAt: Fixtures.now)
        try transport.enqueue(status: 200, json: result)
        #expect(try await client.scanWalletPass(code: " \(code)\n", locationCode: "door-1") == result)
        let body = try ViadereJSON.decode(WalletScanRequest.self, from: #require(transport.requests[0].body))
        #expect(body.code == code && body.locationCode == "door-1")
        // A 500 is not retried: a repeat after a lost response would report "already used".
        try transport.enqueue(status: 500, json: Fixtures.errorBody(.internalError))
        await #expect(throws: ViadereAPIError.self) { try await client.scanWalletPass(code: code) }
        #expect(transport.requests.count == 2)
    }
}
