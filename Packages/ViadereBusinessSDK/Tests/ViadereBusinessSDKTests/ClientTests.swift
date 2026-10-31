import Foundation
import Testing
import ViadereCore
@testable import ViadereBusinessSDK

@Suite("Business client")
struct ClientTests {
    @Test func issuingAnInteractionSendsAuthIdempotencyKeyAndTheCanonicalBody() async throws {
        let transport = MockTransport()
        let request = Fixtures.confirm()
        try transport.enqueue(status: 201, json: Fixtures.interaction(from: request))
        let client = try Fixtures.client(transport)
        let issued = try await client.issueInteraction(request)
        #expect(issued.wasCreated)
        #expect(issued.interaction.kind == .confirm)
        let sent = try #require(transport.requests.first)
        #expect(sent.method == "POST")
        #expect(sent.url.absoluteString == "https://viadere.com/v1/business/interactions")
        #expect(sent.headers["Authorization"] == "Bearer \(Fixtures.key)")
        #expect(sent.headers["Idempotency-Key"] == "order-1042-confirm")
        #expect(sent.headers["Content-Type"] == "application/json")
        #expect(sent.headers["User-Agent"]?.hasPrefix("ViadereBusinessSDK/") == true)
        // The body is exactly what ViadereJSON produces for the DTO (so signatures and idempotency hashes are stable).
        #expect(sent.body == (try ViadereJSON.encode(request)))
        let decoded = try ViadereJSON.decode(IssueInteractionRequest.self, from: try #require(sent.body))
        #expect(decoded == request)
    }

    @Test func sandboxRelationshipsUseTheCatalogPathAndDecodeTheResult() async throws {
        let transport = MockTransport()
        let sandbox = SandboxRelationship(relationshipId: RelationshipID(), createdAt: Fixtures.now)
        try transport.enqueue(status: 201, json: sandbox)
        let created = try await Fixtures.client(transport).createSandboxRelationship()
        #expect(created == sandbox)
        let sent = try #require(transport.requests.first)
        #expect(sent.method == "POST" && sent.url.path == "/v1/business/sandbox/relationships")
    }

    @Test func aBusinessOutcomeNeverCarriesTheRawSignedDecision() throws {
        let outcome = InteractionOutcome(interactionId: InteractionID(), businessId: BusinessID(), status: .approved, decision: .approve,
                                         assurance: .biometric, decidedAt: Fixtures.now, deviceRef: "pseudonym",
                                         verification: DecisionVerification(keyPurpose: .approvalBiometric, contextBound: true,
                                                                            verifiedAt: Fixtures.now, evidenceRef: "ref"))
        let decoded = try ViadereJSON.decode(InteractionOutcome.self, from: ViadereJSON.encode(outcome))
        #expect(decoded.signedDecision == nil && decoded.deviceRef == "pseudonym" && decoded.verification?.contextBound == true)
    }

    @Test func aRecognizedIdempotencyKeyIsReportedAsNotCreated() async throws {
        let transport = MockTransport()
        let request = Fixtures.confirm()
        try transport.enqueue(status: 200, json: Fixtures.interaction(from: request))
        let issued = try await Fixtures.client(transport).issueInteraction(request)
        #expect(!issued.wasCreated)
    }

    @Test func invalidIdempotencyKeysAreRejectedBeforeAnythingIsSent() async throws {
        let transport = MockTransport()
        let client = try Fixtures.client(transport)
        for bad in ["", "has space", "emoji-😀", String(repeating: "a", count: 129), "new\nline"] {
            await #expect(throws: ViadereAPIError.self) { try await client.issueInteraction(Fixtures.confirm(key: bad)) }
        }
        #expect(transport.requests.isEmpty)
    }

    @Test func outcomeCancelMessageStatusAndWebhookCallsUseTheCatalogPaths() async throws {
        let transport = MockTransport()
        let client = try Fixtures.client(transport)
        let id = InteractionID()
        let outcome = InteractionOutcome(interactionId: id, businessId: BusinessID(), status: .confirmed, decision: .confirm, channel: .nativePush, decidedAt: Fixtures.now)
        try transport.enqueue(status: 200, json: outcome)
        let fetched = try await client.interactionOutcome(id: id)
        #expect(fetched.status == .confirmed)
        try transport.enqueue(status: 200, json: outcome)
        _ = try await client.cancelInteraction(id: id)
        let message = ConversationMessage(id: MessageID(), sessionId: SessionID(), businessId: BusinessID(), direction: .businessToConsumer,
                                          attribution: MessageAttribution(senderType: .business, displayName: "Northwind"), body: "Hi", channel: .sms,
                                          createdAt: Fixtures.now, deliveryStatus: .queued)
        try transport.enqueue(status: 201, json: message)
        _ = try await client.sendMessage(BusinessSendMessageRequest(relationshipId: Fixtures.relationship, body: "Hi", idempotencyKey: "msg-1"))
        let status = Fixtures.interaction(from: Fixtures.confirm())
        try transport.enqueue(status: 201, json: status)
        _ = try await client.updateStatus(BusinessStatusUpdateRequest(relationshipId: Fixtures.relationship, purpose: .transactional, status: StatusPayload(title: "Out for delivery"),
                                                                       activityKey: "order-1", idempotencyKey: "status-1"))
        let subscription = WebhookSubscription(id: WebhookSubscriptionID(), url: URL(string: "https://example.com/h")!, events: [.interactionDecided], active: true, createdAt: Fixtures.now)
        try transport.enqueue(status: 200, json: [subscription])
        let listed = try await client.listWebhooks()
        #expect(listed.count == 1)
        try transport.enqueue(status: 201, json: WebhookSecretResponse(subscription: subscription, secret: "whsec_abc"))
        let created = try await client.createWebhook(url: URL(string: "https://example.com/h")!, events: [.interactionDecided])
        #expect(created.secret == "whsec_abc")
        try transport.enqueue(status: 200, json: EmptyBody())
        try await client.deleteWebhook(id: subscription.id)
        try transport.enqueue(status: 200, json: WebhookSecretResponse(subscription: subscription, secret: "whsec_new"))
        let rotated = try await client.rotateWebhookSecret(id: subscription.id)
        #expect(rotated.secret == "whsec_new")
        let calls = transport.requests.map { "\($0.method) \($0.url.path)" }
        #expect(calls == [
            "GET /v1/business/interactions/\(id)", "POST /v1/business/interactions/\(id)/cancel", "POST /v1/business/messages", "POST /v1/business/statuses",
            "GET /v1/business/webhooks", "POST /v1/business/webhooks", "DELETE /v1/business/webhooks/\(subscription.id)", "POST /v1/business/webhooks/\(subscription.id)/rotate-secret",
        ])
        #expect(transport.requests[2].headers["Idempotency-Key"] == "msg-1")
        #expect(transport.requests[3].headers["Idempotency-Key"] == "status-1")
        #expect(transport.requests[0].headers["Idempotency-Key"] == nil)
        #expect(transport.requests[0].body == nil)
    }

    @Test func everyBusinessRouteInTheCatalogIsCoveredByTheClient() {
        let business = APIRoutes.all.filter { $0.auth == .businessAPIKey }.map(\.name)
        let covered: Set<String> = ["business.interactions.issue", "business.interactions.outcome", "business.interactions.cancel", "business.messages.send",
                                    "business.statuses.update", "business.webhooks.list", "business.webhooks.create", "business.webhooks.delete", "business.webhooks.rotate",
                                    "business.rewards.issue", "business.rewards.list", "business.rewards.revoke", "business.loyalty.program.get",
                                    "business.loyalty.program.put", "business.loyalty.points", "business.redemptions.consume",
                                    "business.sandbox.relationships.create", "business.capabilities.get",
                                    "business.verification.requests.create", "business.verification.requests.get", "business.verification.results.get",
                                    "business.approve.enrollments.create", "business.approve.enrollments.get", "business.approve.enrollments.confirm", "business.approve.enrollments.cancel",
                                    "business.approve.keys.list", "business.approve.keys.revoke", "business.approve.requests.create", "business.approve.requests.get",
                                    "business.approve.requests.cancel", "business.approve.results.get", "business.approve.freeze", "business.approve.freezes.get",
                                    "business.keyDirectory.publish", "business.keyDirectory.entries",
                                    "business.webhooks.verify", "business.webhooks.test", "business.webhooks.pause", "business.webhooks.resume",
                                    "business.approve.settings.get", "business.approve.settings.put",
                                    "business.linkSessions.create", "business.linkSessions.get", "business.linkSessions.confirm", "business.linkSessions.cancel",
                                    "business.wallet.passes.issue", "business.wallet.passes.list", "business.wallet.passes.update", "business.wallet.passes.void",
                                    "business.wallet.scan",
                                    "business.profileRequests.create", "business.profileRequests.get", "business.profiles.get"]

        #expect(Set(business).subtracting(covered).isEmpty)
    }

    // MARK: Errors

    @Test func apiErrorsCarryTheStableCodeMessageAndRequestId() async throws {
        let transport = MockTransport()
        try transport.enqueue(status: 403, json: Fixtures.errorBody(.consentRequired, "The consumer has not consented.", requestId: "req-abc"))
        let client = try Fixtures.client(transport)
        do {
            _ = try await client.issueInteraction(Fixtures.confirm())
            Issue.record("expected an error")
        } catch let error as ViadereAPIError {
            #expect(error.status == 403)
            #expect(error.code == .consentRequired)
            #expect(error.requestId == "req-abc")
            #expect(error.message == "The consumer has not consented.")
            #expect(!error.isRetryable)
            #expect(!error.description.contains(Fixtures.key))
        }
        #expect(transport.requests.count == 1, "client errors are never retried")
    }

    @Test func nonJSONErrorBodiesBecomeAGenericErrorWithoutEchoingTheBody() async throws {
        let transport = MockTransport()
        transport.enqueue(status: 502, raw: "<html>Bad gateway secret-internal-detail</html>", headers: ["X-Request-Id": "req-9"])
        transport.enqueue(status: 502, raw: "<html>again</html>")
        transport.enqueue(status: 502, raw: "<html>again</html>")
        let client = try Fixtures.client(transport)
        do {
            _ = try await client.listWebhooks()
            Issue.record("expected an error")
        } catch let error as ViadereAPIError {
            #expect(error.status == 502)
            #expect(error.code == nil)
            #expect(!error.message.contains("secret-internal-detail"))
        }
    }

    // MARK: Retries

    @Test func rateLimitsAreRetriedAfterTheServersRetryAfter() async throws {
        let transport = MockTransport()
        let sleeps = RecordedSleeps()
        let request = Fixtures.confirm()
        try transport.enqueue(status: 429, json: Fixtures.errorBody(.rateLimited), headers: ["Retry-After": "7"])
        try transport.enqueue(status: 429, json: Fixtures.errorBody(.rateLimited), headers: ["Retry-After": "120"])
        try transport.enqueue(status: 201, json: Fixtures.interaction(from: request))
        let client = try Fixtures.client(transport, sleeps: sleeps)
        let issued = try await client.issueInteraction(request)
        #expect(issued.wasCreated)
        #expect(transport.requests.count == 3)
        #expect(transport.requests.allSatisfy { $0.headers["Idempotency-Key"] == "order-1042-confirm" }, "every retry reuses the same key")
        #expect(transport.requests.map(\.body).dropFirst().allSatisfy { $0 == transport.requests[0].body })
        #expect(sleeps.delays == [7, 30], "Retry-After honoured and capped at maxDelay")
    }

    @Test func serverErrorsAndNetworkFailuresRetryWithBackoffThenGiveUp() async throws {
        let transport = MockTransport()
        let sleeps = RecordedSleeps()
        transport.enqueue(.failure(NetworkDown()))
        try transport.enqueue(status: 503, json: Fixtures.errorBody(.unavailable))
        transport.enqueue(.failure(NetworkDown()))
        let client = try Fixtures.client(transport, sleeps: sleeps)
        await #expect(throws: ViadereSDKError.transport("NetworkDown")) { try await client.listWebhooks() }
        #expect(transport.requests.count == 3)
        #expect(sleeps.delays.count == 2)
        #expect(sleeps.delays[0] <= 0.5 && sleeps.delays[1] <= 1.0, "exponential backoff with jitter")
    }

    @Test func webhookCreateAndRotateAreRetriedWithTheSameIdempotencyKeyOnEveryAttempt() async throws {
        let transport = MockTransport()
        for _ in 0..<3 { try transport.enqueue(status: 500, json: Fixtures.errorBody(.internalError)) }
        let client = try Fixtures.client(transport)
        // The server requires an Idempotency-Key on create, so a retry can no longer create two endpoints: every attempt carries the same key.
        await #expect(throws: ViadereAPIError.self) { try await client.createWebhook(url: URL(string: "https://example.com/h")!, events: [.interactionDecided]) }
        let createKeys = Set(transport.requests.map { $0.headers[ViadereHeader.idempotencyKey] ?? "" })
        #expect(transport.requests.count == 3)
        #expect(createKeys.count == 1 && createKeys.first?.isEmpty == false)
        // Rotation too (a retry with a new key could rotate twice and lose the first secret), and a different call gets a different key.
        for _ in 0..<3 { try transport.enqueue(status: 500, json: Fixtures.errorBody(.internalError)) }
        await #expect(throws: ViadereAPIError.self) { try await client.rotateWebhookSecret(id: WebhookSubscriptionID()) }
        let rotateKeys = Set(transport.requests.dropFirst(3).map { $0.headers[ViadereHeader.idempotencyKey] ?? "" })
        #expect(transport.requests.count == 6)
        #expect(rotateKeys.count == 1 && rotateKeys.first?.isEmpty == false && rotateKeys != createKeys)
        // A caller can pin the key (a deterministic key derived from its own object).
        let cancelled = InteractionOutcome(interactionId: InteractionID(), businessId: BusinessID(), status: .cancelled, decidedAt: Fixtures.now)
        try transport.enqueue(status: 200, json: cancelled)
        _ = try await client.cancelInteraction(id: cancelled.interactionId, idempotencyKey: "cancel-order-17")
        #expect(transport.requests.last?.headers[ViadereHeader.idempotencyKey] == "cancel-order-17")
    }

    @Test func retriesCanBeDisabled() async throws {
        let transport = MockTransport()
        try transport.enqueue(status: 500, json: Fixtures.errorBody(.internalError))
        let client = try Fixtures.client(transport, retry: .none)
        await #expect(throws: ViadereAPIError.self) { try await client.listWebhooks() }
        #expect(transport.requests.count == 1)
    }

    // MARK: Safety

    @Test func theAPIKeyIsValidatedAndNeverPrinted() throws {
        for bad in ["", "vdk_live_", "sk_live_0123456789abcdef0123", "vda_0123456789abcdefghijklmnopqrstuvwxyz", "vdk_test_ has space 0123456789", String(repeating: "x", count: 100)] {
            #expect(throws: ViadereSDKError.invalidAPIKey) { try ViadereBusinessClient(apiKey: bad, transport: MockTransport()) }
        }
        let client = try Fixtures.client(MockTransport())
        #expect(!client.description.contains(Fixtures.key))
        #expect(!client.debugDescription.contains(Fixtures.key))
        #expect(!"\(client)".contains(Fixtures.key))
        #expect(client.description.contains("•••DEFG"))
        #expect(!client.isLive)
        #expect(try ViadereBusinessClient(apiKey: "vdk_live_" + String(repeating: "a", count: 43), transport: MockTransport()).isLive)
    }

    @Test func onlyHTTPSBaseURLsAreAcceptedExceptLoopbackForDevelopment() throws {
        for bad in ["http://viadere.com", "ftp://viadere.com", "https://user:pw@viadere.com", "viadere.com", "http://example.com"] {
            #expect(throws: ViadereSDKError.insecureBaseURL, "\(bad)") { try Fixtures.client(MockTransport(), baseURL: URL(string: bad)!) }
        }
        #expect(throws: Never.self) { try Fixtures.client(MockTransport(), baseURL: URL(string: "https://sandbox.viadere.com")!) }
        #expect(throws: Never.self) { try Fixtures.client(MockTransport(), baseURL: URL(string: "http://localhost:8080")!) }
    }

    @Test func malformedSuccessBodiesSurfaceAsDecodingErrors() async throws {
        let transport = MockTransport()
        transport.enqueue(status: 200, raw: "{\"not\":\"an array\"}")
        let client = try Fixtures.client(transport)
        await #expect(throws: ViadereSDKError.decodingFailed("Array<WebhookSubscription>")) { try await client.listWebhooks() }
    }

    @Test func pathParametersAreEncodedByTheCatalog() async throws {
        let transport = MockTransport()
        try transport.enqueue(status: 200, json: EmptyBody())
        let client = try Fixtures.client(transport)
        try await client.deleteWebhook(id: WebhookSubscriptionID())
        #expect(transport.requests[0].url.path.hasPrefix("/v1/business/webhooks/"))
    }
}
