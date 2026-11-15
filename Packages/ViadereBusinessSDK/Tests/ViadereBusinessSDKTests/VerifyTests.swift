import Foundation
import Testing
import ViadereCore
@testable import ViadereBusinessSDK

@Suite("Verification requests")
struct VerifyClientTests {
    @Test func createGetAndRetrieveUseTheCatalogPathsAndTheIdempotencyKey() async throws {
        let transport = MockTransport()
        let client = try Fixtures.client(transport)
        let id = VerificationRequestID()
        let ref = VerificationResultRef.generate()
        let subject = CapabilityTests.ref
        let resource = VerificationRequestResource(requestId: id, capability: .ageMinimum, subjectRef: subject, purposeCode: "age_restricted_access", status: .pending,
                                                   createdAt: Fixtures.now, expiresAt: Fixtures.now.addingTimeInterval(180))
        try transport.enqueue(status: 201, json: resource)
        let created = try await client.createVerificationRequest(
            CreateVerificationRequest(subjectRef: subject, capability: .ageMinimum, parameters: ["years": .integer(18)], purposeCode: "age_restricted_access",
                                      callbackId: "5d1b2a60-0000-4000-8000-000000000001", expiresInSeconds: 180), idempotencyKey: "verify-1")
        #expect(created.wasCreated && created.request.requestId == id)
        let sent = try #require(transport.requests.first)
        #expect(sent.method == "POST" && sent.url.path == "/v1/verification-requests")
        #expect(sent.headers["Idempotency-Key"] == "verify-1")
        let body = String(decoding: try #require(sent.body), as: UTF8.self)
        #expect(body.contains("\"subject_ref\"") && body.contains("\"purpose_code\"") && body.contains("\"callback_id\"") && !body.contains("http"))

        var done = resource
        done.status = .completed
        done.resultRef = ref
        try transport.enqueue(status: 200, json: done)
        let fetched = try await client.verificationRequest(id: id)
        #expect(fetched.resultRef == ref)
        #expect(transport.requests[1].url.path == "/v1/verification-requests/\(id)")

        let result = VerificationResult(resultRef: ref, requestId: id, capability: .ageMinimum, subjectRef: subject, parameters: ["years": .integer(18)], createdAt: Fixtures.now,
                                        outcome: .verified, result: ["meets_threshold": .bool(true)])
        try transport.enqueue(status: 200, json: result)
        let retrieved = try await client.verificationResult(ref: ref)
        #expect(retrieved.outcome == .verified && retrieved.result["meets_threshold"] == .bool(true))
        #expect(transport.requests[2].url.path == "/v1/verification-results/\(ref)")
    }

    @Test func aSecondRetrievalIsGoneAndNotRetried() async throws {
        let transport = MockTransport()
        try transport.enqueue(status: 410, json: APIErrorResponse(code: .gone, message: "This result was already retrieved or has expired.", requestId: "req_1", details: nil))
        let client = try Fixtures.client(transport)
        await #expect(throws: ViadereAPIError.self) { try await client.verificationResult(ref: .generate()) }
        #expect(transport.requests.count == 1)
    }
}
