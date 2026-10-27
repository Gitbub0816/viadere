import Crypto
import Foundation
import Testing
import ViadereCore
@testable import ViadereBusinessSDK

@Suite("Capabilities and subject references")
struct CapabilityTests {
    static let ref = SubjectRefDeriver(key: SymmetricKey(data: Data(repeating: 9, count: 32))).subjectRef(businessId: BusinessID(), consumerId: ConsumerID())

    @Test func capabilitiesUseTheCatalogPathAndDecode() async throws {
        let transport = MockTransport()
        let response = BusinessCapabilitiesResponse(businessId: BusinessID(), environment: .test, tiers: [.m], entitlements: Capability.messaging,
                                                    keyScopes: Capability.messaging, effective: Capability.messaging, catalog: CapabilityCatalog.definitions)
        try transport.enqueue(status: 200, json: response)
        let result = try await Fixtures.client(transport).capabilities()
        #expect(result == response)
        let sent = try #require(transport.requests.first)
        #expect(sent.method == "GET" && sent.url.path == "/v1/business/capabilities")
        #expect(sent.headers["Authorization"] == "Bearer \(Fixtures.key)")
        // A messaging-only key does not list the approval or verification capabilities as effective.
        #expect(!result.effective.contains(.transactionApprove) && !result.effective.contains(.ageMinimum))
    }

    @Test func capabilityDenialsAreTypedAndNotRetried() async throws {
        let transport = MockTransport()
        let body = APIErrorResponse(code: .insufficientScope, message: "This API key does not carry the capability this request needs.",
                                    requestId: "req_1", details: ["capability": "transaction.approve", "reason": "insufficient_scope"])
        try transport.enqueue(status: 403, json: body)
        let client = try Fixtures.client(transport)
        let request = IssueInteractionRequest(relationshipId: Fixtures.relationship, purpose: .security, payload: .authorize(AuthorizePayload(actionDescription: "Pay")),
                                              ttlSeconds: 120, idempotencyKey: "pay-1")
        do {
            _ = try await client.issueInteraction(request)
            Issue.record("expected a denial")
        } catch let error as ViadereAPIError {
            #expect(error.status == 403 && error.code == .insufficientScope)
            #expect(error.isCapabilityDenied && !error.isRetryable)
            #expect(error.deniedCapability == .transactionApprove)
        }
        #expect(transport.requests.count == 1, "a capability denial is not retried")
    }

    @Test func requestsCanAddressACustomerBySubjectRefAlone() async throws {
        let transport = MockTransport()
        let request = BusinessSendMessageRequest(subjectRef: Self.ref, body: "Your order shipped", idempotencyKey: "msg-1")
        try transport.enqueue(status: 201, json: ConversationMessage(id: MessageID(), sessionId: SessionID(), businessId: BusinessID(), direction: .businessToConsumer,
                                                                    attribution: MessageAttribution(senderType: .business, displayName: "Northwind"),
                                                                    body: "Your order shipped", channel: .inApp, createdAt: Fixtures.now, deliveryStatus: .queued))
        _ = try await Fixtures.client(transport).sendMessage(request)
        let sent = String(decoding: try #require(transport.requests.first?.body), as: UTF8.self)
        #expect(sent.contains("\"subjectRef\":\"\(Self.ref.rawValue)\""))
        #expect(!sent.contains("relationshipId"), "the placeholder relationship id is never sent")
    }

    @Test func webhookEventsCarryTheSubjectRef() throws {
        let event = RelationshipEvent(relationshipId: Fixtures.relationship, subjectRef: Self.ref, source: .code, occurredAt: Fixtures.now)
        let decoded = try ViadereJSON.decode(RelationshipEvent.self, from: ViadereJSON.encode(event))
        #expect(decoded.subjectRef == Self.ref)
        // Events from before subject_ref existed still decode.
        let legacy = try ViadereJSON.decode(RelationshipEvent.self, from: Data(#"{"relationshipId":"\#(Fixtures.relationship)","occurredAt":"2027-01-15T08:00:00Z"}"#.utf8))
        #expect(legacy.subjectRef == nil)
    }
}
