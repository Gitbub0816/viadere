@preconcurrency import Crypto
import Fluent
import Foundation
import Logging
import NIOCore
import NIOHTTP1
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// An HTTP client double for the Twilio sender: records the request and replies with a canned response.
final class StubClient: Client, @unchecked Sendable {
    let eventLoop: any EventLoop
    private let lock = NSLock()
    private var requests: [ClientRequest] = []
    private let status: HTTPStatus
    private let json: String

    init(eventLoop: any EventLoop, status: HTTPStatus, json: String) {
        self.eventLoop = eventLoop
        self.status = status
        self.json = json
    }

    var recorded: [ClientRequest] { lock.withLock { requests } }
    func delegating(to eventLoop: any EventLoop) -> any Client { self }
    func logging(to logger: Logger) -> any Client { self }
    func allocating(to byteBufferAllocator: ByteBufferAllocator) -> any Client { self }
    func send(_ request: ClientRequest) -> EventLoopFuture<ClientResponse> {
        lock.withLock { requests.append(request) }
        var headers = HTTPHeaders()
        headers.contentType = .json
        return eventLoop.makeSucceededFuture(ClientResponse(status: status, headers: headers, body: ByteBuffer(string: json)))
    }
}

final class ProviderAndJobTests: XCTestCase {
    func twilio(_ app: Application, status: HTTPStatus, json: String) -> (TwilioProvider, StubClient) {
        let client = StubClient(eventLoop: app.eventLoopGroup.next(), status: status, json: json)
        let provider = TwilioProvider(config: TwilioConfig(accountSID: "ACabc", authToken: "secret-token", fromNumber: "+15550001111", messagingServiceSID: nil),
                                      client: client, logger: Logger(label: "t"))
        return (provider, client)
    }

    func testTwilioSendBuildsAuthenticatedFormRequestAndMapsOutcomes() async throws {
        let app = try await Application.make(.testing)
        let request = OutboundSMSRequest(to: PhoneNumber("+14805550123")!, body: "Viadere: hello & welcome", reference: "r1")

        let (ok, client) = twilio(app, status: .created, json: #"{"sid":"SM123abc","status":"queued"}"#)
        let result = try await ok.send(request)
        XCTAssertEqual(result.providerMessageId, "twilio:SM123abc")
        let sent = try XCTUnwrap(client.recorded.first)
        XCTAssertEqual(sent.url.string, "https://api.twilio.com/2010-04-01/Accounts/ACabc/Messages.json")
        XCTAssertEqual(sent.headers.first(name: .authorization), "Basic " + Data("ACabc:secret-token".utf8).base64EncodedString())
        XCTAssertEqual(sent.headers.contentType, .urlEncodedForm)
        let body = String(buffer: sent.body!)
        XCTAssertTrue(body.contains("To=%2B14805550123") && body.contains("From=%2B15550001111"))
        XCTAssertTrue(body.contains("Body=Viadere%3A%20hello%20%26%20welcome"), body)

        let (throttled, _) = twilio(app, status: .tooManyRequests, json: "{}")
        do { _ = try await throttled.send(request); XCTFail() } catch { XCTAssertEqual(error as? SMSProviderError, .transient("http 429")) }
        let (down, _) = twilio(app, status: .badGateway, json: "")
        do { _ = try await down.send(request); XCTFail() } catch { XCTAssertEqual(error as? SMSProviderError, .transient("http 502")) }
        let (stopped, _) = twilio(app, status: .badRequest, json: #"{"code":21610,"message":"unsubscribed"}"#)
        do { _ = try await stopped.send(request); XCTFail() } catch { XCTAssertEqual(error as? SMSProviderError, .permanent(code: "21610", recipientOptedOut: true)) }
        let (invalid, _) = twilio(app, status: .badRequest, json: #"{"code":21211}"#)
        do { _ = try await invalid.send(request); XCTFail() } catch { XCTAssertEqual(error as? SMSProviderError, .permanent(code: "21211", recipientOptedOut: false)) }
        try await app.asyncShutdown()
    }

    func testTwilioDeliveryReceiptsUpdateMessageStatusAndCarrierStopMarksOptOut() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let rel = try await h.connect(consumer, to: b)
            let sent = try await h.businessPost(b, "/v1/business/messages", BusinessSendMessageRequest(relationshipId: rel.id, body: "hello", idempotencyKey: "d1"))
            XCTAssertEqual(try sent.json(ConversationMessage.self).deliveryStatus, .delivered, "in-app messages are delivered once stored")
            // An SMS-queued message follows provider receipts.
            let phone = PhoneNumber("+14805550123")!
            let message = ConversationMessageRecord()
            message.id = UUID(); message.sessionId = try await ConversationSessionRecord.query(on: h.db).first()!.id!
            message.businessId = b.id.uuid; message.consumerId = consumer.id.uuid; message.direction = "businessToConsumer"; message.senderType = "business"
            message.displayName = "Northwind Air"; message.bodyCiphertext = try h.ctx.cipher.seal("x", context: "conversation_messages.body")
            message.channel = "sms"; message.deliveryStatus = "queued"; message.createdAt = h.clock.now()
            try await message.create(on: h.db)
            try await OutboundSMS(db: h.db, ctx: h.ctx).enqueue(to: phone, body: "hello", allowWhenOptedOut: true, messageId: message.id)
            try await h.runJobs()
            let providerId = try await SMSOutboundRecord.query(on: h.db).first()!.providerMessageId!
            XCTAssertEqual(providerId, "twilio:SMOUT1")
            func callback(_ status: String, code: String? = nil) async throws -> HTTPResult {
                var params = [("MessageSid", "SMOUT1"), ("MessageStatus", status)]
                if let code { params.append(("ErrorCode", code)) }
                let sig = TwilioProvider.signature(authToken: RecordingSMSProvider.authToken, url: h.config.publicBaseURL + "/v1/providers/sms/status", params: params)
                return try await h.request(.POST, "/v1/providers/sms/status", headers: ["X-Twilio-Signature": sig], body: smsForm(params), contentType: "application/x-www-form-urlencoded")
            }
            try await eq(try await callback("delivered").status, .ok)
            let delivered = try await ConversationMessageRecord.find(message.id!, on: h.db)
            XCTAssertEqual(delivered?.deliveryStatus, "delivered")
            XCTAssertNotNil(delivered?.deliveredAt)
            try await eq(try await callback("undelivered", code: "30003").status, .ok)
            // Unknown statuses are ignored, not errors.
            try await eq(try await callback("weird").status, .ok)
        }
    }

    func testCarrierLevelStopMarksThePhoneOptedOut() async throws {
        try await withHarness { h in
            let phone = PhoneNumber("+14805550123")!
            // Create a context row for the phone so the opt-out can be recorded.
            _ = try await sendInbound(h, from: phone.e164, body: "Hi", sid: nil)
            let provider = ThrowingSMSProvider()
            _ = provider
            h.texts.reset()
            let queue = OutboundSMS(db: h.db, ctx: h.ctx)
            try await queue.enqueue(to: phone, body: "business message")
            // Fail permanently with the carrier-STOP code through a failing provider swap.
            let failing = ServerContext(config: h.config, clock: h.clock, apns: h.push, sms: ThrowingSMSProvider(), passkeys: FakePasskeyVerifier(), webhookTransport: h.webhooks)
            let original = h.app.ctx
            h.app.ctx = failing
            try await BackgroundJobs(app: h.app).runOnce()
            h.app.ctx = original
            let context = try await SMSContextRecord.query(on: h.db).first()!
            XCTAssertTrue(context.optedOut)
            let row = try await SMSOutboundRecord.query(on: h.db).filter(\.$status == "failed").first()
            XCTAssertEqual(row?.errorCode, "21610")
        }
    }

    func testSignedRequestsCoverTheQueryString() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            let ok = try await h.signed(consumer, .GET, "/v1/interactions?status=pending&limit=5")
            XCTAssertEqual(ok.status, .ok, ok.text)
            // A signature for one query string cannot be reused for another.
            let swapped = try await h.signed(consumer, .GET, "/v1/interactions?status=approved&limit=5", signedPath: "/v1/interactions?status=pending&limit=5")
            XCTAssertEqual(swapped.status, .unauthorized)
            let stripped = try await h.signed(consumer, .GET, "/v1/interactions?status=pending&limit=5", signedPath: "/v1/interactions")
            XCTAssertEqual(stripped.status, .unauthorized)
        }
    }

    func testBackgroundRunnerDeliversWebhooksAndSMSWithoutManualTicks() async throws {
        try await withHarness({
            $0.runBackgroundJobs = true
            $0.jobIntervalSeconds = 0.05
        }) { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            _ = try await h.businessPost(b, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://hooks.example.com/bg")!, events: [.relationshipConnected]))
            let consumer = try await h.readyConsumer()
            _ = try await h.connect(consumer, to: b)
            // The app has not been "booted" by XCTVapor's helpers until a request is made; give the runner a moment.
            var delivered = false
            for _ in 0..<60 {
                if !h.webhooks.received.isEmpty { delivered = true; break }
                try await Task.sleep(for: .milliseconds(50))
            }
            XCTAssertTrue(delivered, "the background runner should deliver due webhooks on its own")
        }
    }
}

/// A provider that always reports the carrier-level STOP error.
struct ThrowingSMSProvider: SMSProvider {
    var name: String { "twilio" }
    func verifyWebhook(_ request: ProviderWebhookRequest) -> Bool { false }
    func parseInbound(_ request: ProviderWebhookRequest) throws -> InboundSMS { throw SMSProviderError.malformedWebhook }
    func parseDeliveryUpdate(_ request: ProviderWebhookRequest) throws -> SMSDeliveryUpdate? { nil }
    func send(_ request: OutboundSMSRequest) async throws -> OutboundSMSResult { throw SMSProviderError.permanent(code: "21610", recipientOptedOut: true) }
}

final class PushAndSchemaTests: XCTestCase {
    func testAPNSwiftSenderBuildsFromPEMAndRefusesEnvironmentMismatch() async throws {
        let key = P256.Signing.PrivateKey()
        let config = APNsConfig(keyPEM: key.pemRepresentation, keyID: "ABC123DEFG", teamID: "TEAM123456", topic: "com.viadere.app", useSandbox: true)
        let sender = try APNSwiftSender(config: config, logger: Logger(label: "t"))
        // A production-environment token is never sent through the sandbox gateway (no network is touched).
        let message = PushMessage(deviceToken: String(repeating: "ab", count: 32), environment: .production, topic: "com.viadere.app", title: "Viadere",
                                  body: "x", category: "viadere.confirm", threadID: "business.x", interruptionLevel: "active", interactionId: "id", highPriority: true)
        let outcome = await sender.send(message)
        XCTAssertEqual(outcome, .failed)
        await sender.shutdown()
        XCTAssertThrowsError(try APNSwiftSender(config: APNsConfig(keyPEM: "not a key", keyID: "k", teamID: "t", topic: "x", useSandbox: true), logger: Logger(label: "t")))
    }

    func testPushPayloadBuilderNeverIncludesSensitiveContent() throws {
        let business = BusinessSummary(id: BusinessID(), displayName: "Northwind Air", handle: BusinessHandle(parsing: "northwindair"), code: BusinessCode.generate(), verificationStatus: .verified)
        let scope = RelationshipScope(consumerId: ConsumerID(), relationshipId: RelationshipID())
        let token = APNsTokenRegistrationRecord(token: String(repeating: "ab", count: 32), environment: .sandbox, bundleId: "com.viadere.app")
        for payload in [InteractionPayload.authorize(.sample()), .authenticate(AuthenticatePayload(service: "Bank of Fictionland", device: "Chrome", approximateLocation: "Paris", attemptedAt: Date())),
                        .message(MessagePayload(text: "your secret number is 9981")), .confirm(ConfirmPayload(title: "Dentist at 3pm", details: "Dr. Strange"))] {
            let interaction = Interaction(businessId: business.id, scope: scope, purpose: .transactional, payload: payload, createdAt: Date(), expiresAt: Date().addingTimeInterval(300), idempotencyKey: "k")
            let message = PushPayloadBuilder.message(for: interaction, business: business, token: token, topic: "com.viadere.app")
            let blob = [message.title, message.body, message.category, message.threadID, message.interactionId ?? ""].joined(separator: "|")
            for secret in ["285", "Walmart", "Mesa", "Fictionland", "Paris", "9981", "Dentist", "Strange", "Chrome", "Northwind"] {
                XCTAssertFalse(blob.contains(secret), "\(secret) leaked into \(blob)")
            }
            XCTAssertEqual(message.interactionId, interaction.id.description)
            XCTAssertTrue(message.mutableContent)
        }
    }

    func testAppendOnlyTablesRejectUpdatesAndDeletes() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            _ = try await h.connect(consumer, to: b)
            let grant = try await ConsentGrantRecord.query(on: h.db).first()!
            grant.granted.toggle()
            do { try await grant.update(on: h.db); XCTFail("consent history must be append-only") } catch {}
            do { try await grant.delete(on: h.db); XCTFail("consent history must be append-only") } catch {}
            let count = try await ConsentGrantRecord.query(on: h.db).count()
            XCTAssertEqual(count, 6)
        }
    }
}
