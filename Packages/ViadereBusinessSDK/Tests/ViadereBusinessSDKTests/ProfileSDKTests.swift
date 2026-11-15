import Foundation
import Testing
import ViadereCore
@testable import ViadereBusinessSDK

@Suite("Customer profiles")
struct ProfileSDKTests {
    @Test func requestGetAndReadUseTheCatalogPathsAndTheIdempotencyKey() async throws {
        let transport = MockTransport()
        let client = try Fixtures.client(transport)
        let subject = CapabilityTests.ref
        let id = ProfileRequestID()
        let resource = ProfileRequestResource(id: id, subjectRef: subject, fieldKeys: ["contact.email"], purpose: "Receipts", status: .pending, approvedKeys: nil,
                                              livemode: true, createdAt: Fixtures.now, expiresAt: Fixtures.now.addingTimeInterval(3600), answeredAt: nil)
        try transport.enqueue(status: 201, json: resource)
        let created = try await client.createProfileRequest(CreateProfileRequest(subjectRef: subject, fieldKeys: ["contact.email"], purpose: "Receipts"),
                                                           idempotencyKey: "profile-1")
        #expect(created.wasCreated && created.request.id == id)
        #expect(transport.requests[0].method == "POST" && transport.requests[0].url.path == "/v1/business/profile-requests")
        #expect(transport.requests[0].headers["Idempotency-Key"] == "profile-1")
        try transport.enqueue(status: 200, json: resource)
        _ = try await client.profileRequest(id: id)
        #expect(transport.requests[1].url.path == "/v1/business/profile-requests/\(id)")
        let view = BusinessProfileView(subjectRef: subject, publicName: "Jane D.", fields: [BusinessProfileField(key: "contact.email", entry: nil, value: .text("a@b.co"))],
                                       grantedWithoutValue: [], livemode: true)
        try transport.enqueue(status: 200, json: view)
        let read = try await client.profile(subjectRef: subject)
        #expect(read.publicName == "Jane D." && read.fields.count == 1)
        #expect(transport.requests[2].url.path == "/v1/business/profiles/\(subject.rawValue)")
    }

    @Test func profileWebhooksCarryKeysOnly() throws {
        let payload = ProfileAccessEvent(subjectRef: CapabilityTests.ref, fieldKeys: ["contact.email"], requestId: nil, occurredAt: Fixtures.now)
        let event = WebhookEvent(id: WebhookDeliveryID(), type: .profileAccessRevoked, createdAt: Fixtures.now, businessId: BusinessID(),
                                 data: try ViadereJSON.decode(JSONValue.self, from: ViadereJSON.encode(payload)))
        #expect(try event.profileAccessEvent()?.fieldKeys == ["contact.email"])
        if case .other = try event.typed() {} else { Issue.record("profile events stay .other") }
    }
}
