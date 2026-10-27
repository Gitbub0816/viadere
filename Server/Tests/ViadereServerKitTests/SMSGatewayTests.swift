@preconcurrency import Crypto
import Fluent
import Foundation
import ViadereCore
import struct ViadereCore.Page
import XCTest
@testable import ViadereServerKit

final class SMSGatewayTests: XCTestCase {
    let phone = "+14805550123"
    let inboundPath = "/v1/providers/sms/inbound"

    // MARK: Helpers

    func form(_ params: [(String, String)]) -> Data { smsForm(params) }

    @discardableResult
    func inbound(_ h: TestHarness, from: String? = nil, body: String, sid: String? = nil, signature: String? = nil, signAs: String? = nil) async throws -> HTTPResult {
        try await sendInbound(h, from: from ?? phone, body: body, sid: sid, signature: signature, signAs: signAs)
    }

    /// Sends an SMS from the phone, runs the queue, and returns the Viadere replies produced.
    @discardableResult
    func say(_ h: TestHarness, _ text: String, from: String? = nil, sid: String? = nil) async throws -> [String] {
        let before = h.texts.sent.count
        let response = try await inbound(h, from: from, body: text, sid: sid)
        XCTAssertEqual(response.status, .ok, response.text)
        try await h.runJobs()
        return h.texts.sent.dropFirst(before).map(\.body)
    }

    func linkPhone(_ h: TestHarness, _ consumer: TestConsumer, phone number: String? = nil) async throws {
        let e164 = PhoneNumber(number ?? phone)!
        let link = try PhoneLinkRecord(consumerId: consumer.id.uuid, phone: e164, hasher: h.ctx.hasher, cipher: h.ctx.cipher, now: h.clock.now())
        link.state = "verified"
        link.verifiedPhoneHash = h.ctx.hasher.phoneHash(e164)
        link.verifiedAt = h.clock.now()
        try await link.create(on: h.db)
    }

    func subscribeMessages(_ h: TestHarness, _ b: TestBusiness) async throws {
        let response = try await h.businessPost(b, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://hooks.example.com/\(b.id)")!, events: [.messageReceived]))
        XCTAssertEqual(response.status, .created, response.text)
    }

    func forwarded(_ h: TestHarness, to b: TestBusiness) throws -> [MessageReceivedPayload] {
        try h.webhooks.received.filter { $0.url.path.hasSuffix(b.id.description) }.map {
            try ViadereJSON.decode(WebhookEvent.self, from: $0.body).decodeData(MessageReceivedPayload.self)
        }
    }

    func extractToken(in text: String, prefix: String) -> String? {
        guard let range = text.range(of: "https://viadere.com/\(prefix)/") else { return nil }
        let rest = text[range.upperBound...]
        return String(rest.prefix { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" })
    }

    // MARK: Provider adapter

    func testTwilioSignatureMatchesKnownVector() {
        // Twilio's documented scheme (URL + sorted name/value pairs, HMAC-SHA1, base64) with the vector from its
        // request-validation example; the expected value was computed independently with Python's hmac module.
        let signature = TwilioProvider.signature(
            authToken: "12345", url: "https://mycompany.com/myapp.php?foo=1&bar=2",
            params: [("CallSid", "CA1234567890ABCDE"), ("Caller", "+12349013030"), ("Digits", "1234"), ("From", "+12349013030"), ("To", "+18005551212")])
        XCTAssertEqual(signature, "0/KCTR6DLpKmkAf8muzZqo1nDgQ=")
    }

    func testInvalidOrMissingProviderSignatureIsRejectedAndNothingIsProcessed() async throws {
        try await withHarness { h in
            for bad in ["AAAA", "", String(repeating: "A", count: 28), "0/KCTR6DLpKmkAf8muzZqo1nDgQ="] {
                let response = try await inbound(h, body: "Hi", signature: bad)
                XCTAssertEqual(response.status, .forbidden, "signature \(bad)")
            }
            // Missing header entirely.
            let params = [("MessageSid", "SMmissing"), ("From", phone), ("Body", "Hi")]
            let missing = try await h.request(.POST, inboundPath, body: form(params), contentType: "application/x-www-form-urlencoded")
            XCTAssertEqual(missing.status, .forbidden)
            // Signature computed for different content (body tampered in transit).
            let tampered = try await inbound(h, body: "Hi", signAs: "Hello")
            XCTAssertEqual(tampered.status, .forbidden)
            // Signature for another URL.
            let otherURL = TwilioProvider.signature(authToken: RecordingSMSProvider.authToken, url: "https://evil.example/v1/providers/sms/inbound", params: params)
            let wrongHost = try await h.request(.POST, inboundPath, headers: ["X-Twilio-Signature": otherURL], body: form(params), contentType: "application/x-www-form-urlencoded")
            XCTAssertEqual(wrongHost.status, .forbidden)
            let processed = try await ProcessedProviderMessageRecord.query(on: h.db).count()
            let contexts = try await SMSContextRecord.query(on: h.db).count()
            XCTAssertEqual(processed, 0)
            XCTAssertEqual(contexts, 0)
            XCTAssertTrue(h.texts.sent.isEmpty)
            let denied = try await AuditEventRecord.query(on: h.db).filter(\.$action == "gateway.webhook_rejected").count()
            XCTAssertGreaterThanOrEqual(denied, 5)
            // The status callback endpoint is protected the same way.
            let status = try await h.request(.POST, "/v1/providers/sms/status", headers: ["X-Twilio-Signature": "nope"], body: form([("MessageSid", "SMx"), ("MessageStatus", "delivered")]), contentType: "application/x-www-form-urlencoded")
            XCTAssertEqual(status.status, .forbidden)
        }
    }

    func testMalformedProviderPayloadsAreRejectedSafely() async throws {
        try await withHarness { h in
            let url = h.config.publicBaseURL + inboundPath
            for params in [[("MessageSid", "SM1"), ("From", "not-a-number"), ("Body", "x")], [("From", phone), ("Body", "x")],
                           [("MessageSid", "SM2 evil"), ("From", phone), ("Body", "x")]] as [[(String, String)]] {
                let signature = TwilioProvider.signature(authToken: RecordingSMSProvider.authToken, url: url, params: params)
                let response = try await h.request(.POST, inboundPath, headers: ["X-Twilio-Signature": signature], body: form(params), contentType: "application/x-www-form-urlencoded")
                XCTAssertEqual(response.status, .badRequest)
            }
            // An inbound body is capped and control characters cannot break the engine.
            let huge = String(repeating: "A", count: 5000)
            let response = try await inbound(h, body: huge)
            XCTAssertEqual(response.status, .ok)
        }
    }

    // MARK: End to end

    func testHiMenuSearchConfirmConnectedAndNumbersForwardWhileConnected() async throws {
        try await withHarness { h in
            let airline = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            try await linkPhone(h, consumer)
            try await subscribeMessages(h, airline)

            let menu = try await say(h, "Hi")
            XCTAssertEqual(menu.count, 1)
            XCTAssertTrue(menu[0].contains("1.") && menu[0].contains("4."), menu[0])
            let confirm = try await say(h, "Northwind Air")
            XCTAssertTrue(confirm[0].contains("Northwind Air") && confirm[0].contains(airline.summary.code.display), confirm[0])
            let connected = try await say(h, "1")
            XCTAssertTrue(connected.joined().contains("Connected to Northwind Air"), connected.joined())
            // A relationship and session now exist, created by the gateway for the linked consumer.
            let relationships = try await h.signed(consumer, .GET, "/v1/relationships").json([Relationship].self)
            XCTAssertEqual(relationships.map(\.business.id), [airline.id])
            XCTAssertEqual(relationships[0].source, .sms)

            // "4" is an ordinary message while connected — never a menu choice.
            let reply = try await say(h, "4")
            XCTAssertTrue(reply.isEmpty, "no menu reply while connected: \(reply)")
            try await h.runJobs()
            let received = try forwarded(h, to: airline)
            XCTAssertEqual(received.map(\.text), ["4"])
            XCTAssertEqual(received[0].channel, .sms)
            XCTAssertFalse(String(decoding: h.webhooks.received.last!.body, as: UTF8.self).contains(phone), "the business never receives the phone number")
            XCTAssertFalse(String(decoding: h.webhooks.received.last!.body, as: UTF8.self).contains(consumer.id.description))

            // The business replies in the same session; it arrives attributed in the same SMS thread.
            let sessionId = received[0].sessionId
            let sent = try await h.businessPost(airline, "/v1/business/messages", BusinessSendMessageRequest(relationshipId: received[0].relationshipId, sessionId: sessionId, body: "Your order 4 has shipped", agentName: "Sam", idempotencyKey: "r1"))
            XCTAssertEqual(sent.status, .created, sent.text)
            try await h.runJobs()
            let last = h.texts.sent.last!
            XCTAssertEqual(last.to, phone)
            XCTAssertTrue(last.body.hasPrefix("[Northwind Air]: "), last.body)
            XCTAssertTrue(last.body.contains("Your order 4 has shipped"))
            // The in-app history has both directions with verified attribution.
            let conversation = try await h.signed(consumer, .GET, "/v1/conversations/\(sessionId)/messages").json(Page<ConversationMessage>.self)
            XCTAssertEqual(Set(conversation.items.map(\.direction)), [.consumerToBusiness, .businessToConsumer])
            // Message bodies are encrypted at rest.
            let stored = try await ConversationMessageRecord.query(on: h.db).all()
            XCTAssertTrue(stored.allSatisfy { !$0.bodyCiphertext.contains("shipped") && $0.bodyCiphertext.hasPrefix("v1.") })
        }
    }

    func testSwitchingFromAirlineToHotelNeverLeaksAcrossTenants() async throws {
        try await withHarness { h in
            let airline = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let hotel = try await h.makeBusiness(name: "Harbor Hotel", handle: "harborhotel")
            let consumer = try await h.readyConsumer()
            try await linkPhone(h, consumer)
            try await subscribeMessages(h, airline)
            try await subscribeMessages(h, hotel)

            _ = try await say(h, "Hi")
            _ = try await say(h, "@northwindair")
            _ = try await say(h, "1")
            _ = try await say(h, "My booking reference is XK92LP")
            try await h.runJobs()
            let airlineMessages = try forwarded(h, to: airline)
            XCTAssertEqual(airlineMessages.map(\.text), ["My booking reference is XK92LP"])

            // Addressing a different business asks for confirmation and sends NOTHING to the current one.
            let prompt = try await say(h, "@harborhotel Do you have a room tonight?")
            XCTAssertTrue(prompt.joined().contains("Harbor Hotel"), prompt.joined())
            try await h.runJobs()
            XCTAssertEqual(try forwarded(h, to: airline).count, 1)
            XCTAssertTrue(try forwarded(h, to: hotel).isEmpty)
            // After explicit confirmation the held message goes to the hotel only.
            _ = try await say(h, "1")
            try await h.runJobs()
            XCTAssertEqual(try forwarded(h, to: hotel).map(\.text), ["Do you have a room tonight?"])
            XCTAssertEqual(try forwarded(h, to: airline).count, 1)
            _ = try await say(h, "Late check-in please")
            try await h.runJobs()
            XCTAssertEqual(try forwarded(h, to: hotel).map(\.text), ["Do you have a room tonight?", "Late check-in please"])
            XCTAssertEqual(try forwarded(h, to: airline).count, 1)

            // The old session is closed: an airline reply is held in history and never shown in this thread.
            let airlineSession = airlineMessages[0]
            let before = h.texts.sent.count
            let late = try await h.businessPost(airline, "/v1/business/messages", BusinessSendMessageRequest(relationshipId: airlineSession.relationshipId, sessionId: airlineSession.sessionId, body: "Gate changed to B12", idempotencyKey: "late1"))
            XCTAssertEqual(late.status, .created, late.text)
            try await h.runJobs()
            XCTAssertEqual(h.texts.sent.count, before, "airline text must not reach the hotel thread")
            XCTAssertFalse(h.texts.sent.contains { $0.body.contains("Gate changed") })
            // The hotel reply is delivered, attributed to the hotel.
            let hotelSession = try forwarded(h, to: hotel)[0]
            _ = try await h.businessPost(hotel, "/v1/business/messages", BusinessSendMessageRequest(relationshipId: hotelSession.relationshipId, sessionId: hotelSession.sessionId, body: "Yes, room 204", idempotencyKey: "h1"))
            try await h.runJobs()
            XCTAssertEqual(h.texts.sent.last?.body, "[Harbor Hotel]: Yes, room 204")
            // Histories are separate per business.
            let conversations = try await h.signed(consumer, .GET, "/v1/conversations").json([ConversationSummary].self)
            XCTAssertEqual(Set(conversations.map(\.business.id)), [airline.id, hotel.id])
            for conversation in conversations {
                let page = try await h.signed(consumer, .GET, "/v1/conversations/\(conversation.id)/messages").json(Page<ConversationMessage>.self)
                XCTAssertTrue(page.items.allSatisfy { $0.businessId == conversation.business.id })
                let joined = page.items.map(\.body).joined()
                if conversation.business.id == hotel.id { XCTAssertFalse(joined.contains("XK92LP") || joined.contains("B12")) }
            }
        }
    }

    func testStopHelpStartCompliance() async throws {
        try await withHarness { h in
            let airline = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            try await linkPhone(h, consumer)
            try await subscribeMessages(h, airline)
            _ = try await say(h, "@northwindair")
            _ = try await say(h, "1")
            _ = try await say(h, "hello")
            try await h.runJobs()
            let session = try forwarded(h, to: airline)[0]

            // A business reply is queued, then the user texts STOP before it is sent.
            _ = try await h.businessPost(airline, "/v1/business/messages", BusinessSendMessageRequest(relationshipId: session.relationshipId, sessionId: session.sessionId, body: "Pre-stop reply", idempotencyKey: "p1"))
            let before = h.texts.sent.count
            let stop = try await inbound(h, body: "STOP")
            XCTAssertEqual(stop.status, .ok)
            try await h.runJobs()
            let sentAfterStop = h.texts.sent.dropFirst(before).map(\.body)
            XCTAssertEqual(sentAfterStop, [GatewayCopy.optOutConfirmation], "only the STOP confirmation goes out; the queued business reply is cancelled")
            let ctxRecord = try await SMSContextRecord.query(on: h.db).first()!
            XCTAssertTrue(ctxRecord.optedOut)
            let consent = try await SMSConsentEventRecord.query(on: h.db).all()
            XCTAssertEqual(consent.map(\.optedOut), [true])

            // Everything else is silently dropped, business replies are held, HELP is still answered.
            let silent = try await say(h, "anyone there?")
            XCTAssertTrue(silent.isEmpty)
            let count = h.texts.sent.count
            _ = try await h.businessPost(airline, "/v1/business/messages", BusinessSendMessageRequest(relationshipId: session.relationshipId, sessionId: session.sessionId, body: "Are you there?", idempotencyKey: "p2"))
            try await h.runJobs()
            XCTAssertEqual(h.texts.sent.count, count)
            try await eq(try await say(h, "HELP"), [GatewayCopy.help])
                        // START resubscribes.
            let start = try await say(h, "START")
            XCTAssertTrue(start.joined().contains("resubscribed"), start.joined())
            let after = try await SMSContextRecord.query(on: h.db).first()!
            XCTAssertFalse(after.optedOut)
        }
    }

    func testDuplicateProviderWebhookIsProcessedExactlyOnce() async throws {
        try await withHarness { h in
            let airline = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            try await linkPhone(h, consumer)
            try await subscribeMessages(h, airline)
            _ = try await say(h, "@northwindair")
            _ = try await say(h, "1")
            let first = try await inbound(h, body: "order 1234", sid: "SMDUPLICATE0001")
            let second = try await inbound(h, body: "order 1234", sid: "SMDUPLICATE0001")
            let third = try await inbound(h, body: "order 1234", sid: "SMDUPLICATE0001")
            XCTAssertEqual([first.status, second.status, third.status], [.ok, .ok, .ok])
            try await h.runJobs()
            XCTAssertEqual(try forwarded(h, to: airline).map(\.text), ["order 1234"])
            let markers = try await ProcessedProviderMessageRecord.query(on: h.db).filter(\.$providerMessageId == "twilio:SMDUPLICATE0001").count()
            XCTAssertEqual(markers, 1)
            // Concurrent duplicates also collapse to one.
            let sid = "SMCONCURRENT0002"
            let results = try await withThrowingTaskGroup(of: UInt.self) { group -> [UInt] in
                for _ in 0..<4 { group.addTask { try await sendInbound(h, from: "+14805550123", body: "ping", sid: sid).status.code } }
                var out: [UInt] = []
                for try await code in group { out.append(code) }
                return out
            }
            XCTAssertTrue(results.allSatisfy { $0 == 200 })
            try await h.runJobs()
            XCTAssertEqual(try forwarded(h, to: airline).map(\.text), ["order 1234", "ping"])
        }
    }

    func testUnlinkedNumberBrowsesButMustLinkBeforeRoutingThenLinkTokenFlow() async throws {
        try await withHarness { h in
            let airline = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            try await subscribeMessages(h, airline)
            var consumer = try await h.registerConsumer()
            consumer = try await h.enrollDevice(consumer)

            _ = try await say(h, "Hi")
            _ = try await say(h, "Northwind")
            let linkPrompt = try await say(h, "1")
            XCTAssertTrue(linkPrompt.joined().contains("link your account"), linkPrompt.joined())
            let linkSMS = linkPrompt.first { $0.contains("/l/") }!
            let token = extractToken(in: linkSMS, prefix: "l")!
            XCTAssertEqual(token.count, 43)
            XCTAssertTrue(try forwarded(h, to: airline).isEmpty, "nothing is routed before linking")
            // The token is stored hashed only.
            let records = try await LinkTokenRecord.query(on: h.db).all()
            XCTAssertEqual(records.count, 1)
            XCTAssertEqual(records[0].tokenHash, SecureToken.hash(token))
            XCTAssertNotEqual(records[0].tokenHash, token)
            // The link SMS body is wiped after sending.
            let outbound = try await SMSOutboundRecord.query(on: h.db).filter(\.$sensitive == true).all()
            XCTAssertFalse(outbound.isEmpty)
            for row in outbound { XCTAssertEqual(try h.ctx.cipher.openString(row.bodyCiphertext, context: "sms_outbound.body"), "[removed]") }

            // The landing page is minimal, strict-CSP, and does not consume the token.
            let page = try await h.request(.GET, "/l/\(token)")
            XCTAssertEqual(page.status, .ok)
            let csp = page.headers.first(name: "Content-Security-Policy") ?? ""
            XCTAssertTrue(csp.contains("default-src 'none'") && csp.contains("frame-ancestors 'none'") && csp.contains("'sha256-"), csp)
            XCTAssertFalse(csp.contains("unsafe-inline") || csp.contains("script-src"))
            XCTAssertEqual(page.headers.first(name: "Referrer-Policy"), "no-referrer")
            XCTAssertEqual(page.headers.first(name: "Cache-Control"), "no-store")
            XCTAssertFalse(page.text.contains("<script"))
            XCTAssertFalse(page.text.contains(String(phone.suffix(4))), "the page does not reveal the phone number")
            try await eq(try await h.request(.GET, "/l/\(token)").status, .ok)
            try await eq(try await h.request(.GET, "/l/\(SecureToken.generate())").status, .notFound)

            // Redemption needs an authenticated consumer AND explicit phone confirmation.
            let unauthenticated = try await h.post("/v1/sms/link-tokens/redeem", SMSLinkRedeemRequest(token: token, confirmPhoneLast4: "0123"))
            XCTAssertEqual(unauthenticated.status, .unauthorized)
            let auth = ["Authorization": "Bearer \(consumer.token)"]
            let wrong = try await h.post("/v1/sms/link-tokens/redeem", SMSLinkRedeemRequest(token: token, confirmPhoneLast4: "9999"), headers: auth)
            XCTAssertEqual(wrong.status, .forbidden)
            let redeemed = try await h.post("/v1/sms/link-tokens/redeem", SMSLinkRedeemRequest(token: token, confirmPhoneLast4: "0123"), headers: auth)
            XCTAssertEqual(redeemed.status, .ok, redeemed.text)
            let link = try redeemed.json(PhoneLink.self)
            XCTAssertFalse(link.maskedPhone.contains("48055501"), link.maskedPhone)
            XCTAssertTrue(link.maskedPhone.hasSuffix("0123"))
            // Replay fails — for the same user and for anybody else.
            let replay = try await h.post("/v1/sms/link-tokens/redeem", SMSLinkRedeemRequest(token: token, confirmPhoneLast4: "0123"), headers: auth)
            XCTAssertEqual(replay.status, .gone)
            let mallory = try await h.registerConsumer(name: "Mallory")
            let stolen = try await h.post("/v1/sms/link-tokens/redeem", SMSLinkRedeemRequest(token: token, confirmPhoneLast4: "0123"), headers: ["Authorization": "Bearer \(mallory.token)"])
            XCTAssertEqual(stolen.status, .gone)
            try await h.runJobs()
            let confirmation = h.texts.sent.map(\.body)
            XCTAssertTrue(confirmation.contains { $0.contains("now linked") }, confirmation.joined(separator: "|"))
            // The destination chosen before linking survives; confirming connects and routing works.
            XCTAssertTrue(confirmation.last?.contains("Connect to Northwind Air") ?? false, confirmation.last ?? "")
            _ = try await say(h, "1")
            _ = try await say(h, "hello after link")
            try await h.runJobs()
            XCTAssertEqual(try forwarded(h, to: airline).map(\.text), ["hello after link"])
        }
    }

    func testLinkTokenExpiresAndWrongConfirmationsBurnIt() async throws {
        try await withHarness { h in
            _ = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            func requestLink(from number: String) async throws -> String {
                _ = try await say(h, "Hi", from: number)
                _ = try await say(h, "Northwind", from: number)
                let sms = try await say(h, "1", from: number)
                return extractToken(in: sms.first { $0.contains("/l/") }!, prefix: "l")!
            }
            // Expiry (15 minutes), on the web page and at redemption.
            let first = try await requestLink(from: "+14805550111")
            h.clock.advance(by: 16 * 60)
            try await eq(try await h.request(.GET, "/l/\(first)").status, .gone)
            let fresh = try await h.registerConsumer(name: "Fresh")
            let expired = try await h.post("/v1/sms/link-tokens/redeem", SMSLinkRedeemRequest(token: first, confirmPhoneLast4: "0111"), headers: ["Authorization": "Bearer \(fresh.token)"])
            XCTAssertEqual(expired.status, .gone)
            // Brute-forcing the last four digits burns the token after five wrong tries.
            let second = try await requestLink(from: "+14805550222")
            for guess in ["0000", "0001", "0002", "0003", "0004"] {
                let wrong = try await h.post("/v1/sms/link-tokens/redeem", SMSLinkRedeemRequest(token: second, confirmPhoneLast4: guess), headers: ["Authorization": "Bearer \(fresh.token)"])
                XCTAssertTrue([403, 429].contains(wrong.status.code), "\(wrong.status)")
                h.clock.advance(by: 10)
            }
            let right = try await h.post("/v1/sms/link-tokens/redeem", SMSLinkRedeemRequest(token: second, confirmPhoneLast4: "0222"), headers: ["Authorization": "Bearer \(fresh.token)"])
            XCTAssertEqual(right.status, .gone, "token is burned after repeated wrong confirmations")
            // A new link text revokes the previous token.
            let auth = ["Authorization": "Bearer \(try await h.registerConsumer(name: "Late").token)"]
            let a = try await requestLink(from: "+14805550333")
            _ = try await say(h, "MENU", from: "+14805550333")
            _ = try await say(h, "Northwind", from: "+14805550333")
            let sms = try await say(h, "1", from: "+14805550333")
            if let b = sms.first(where: { $0.contains("/l/") }).flatMap({ extractToken(in: $0, prefix: "l") }) {
                XCTAssertNotEqual(a, b)
                try await eq(try await h.post("/v1/sms/link-tokens/redeem", SMSLinkRedeemRequest(token: a, confirmPhoneLast4: "0333"), headers: auth).status, .gone)
            }
        }
    }

    func testSecureHandoffLinkIsSingleUseBoundToTheConsumerAndPageIsMinimal() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            try await linkPhone(h, consumer)
            _ = try await say(h, "Hi")
            let handoff = try await say(h, "3")
            let sms = handoff.first { $0.contains("/h/") }!
            let token = extractToken(in: sms, prefix: "h")!
            let page = try await h.request(.GET, "/h/\(token)")
            XCTAssertEqual(page.status, .ok)
            XCTAssertTrue(page.headers.first(name: "Content-Security-Policy")?.contains("default-src 'none'") ?? false)
            // Only the consumer the phone belongs to can redeem it, once.
            let other = try await h.readyConsumer(name: "Other")
            try await eq(try await h.signedPost(other, "/v1/handoff/redeem", HandoffRedeemRequest(token: token)).status, .forbidden)
            let ok = try await h.signedPost(consumer, "/v1/handoff/redeem", HandoffRedeemRequest(token: token))
            XCTAssertEqual(ok.status, .ok, ok.text)
            XCTAssertEqual(try ok.json(HandoffRedeemResponse.self).purpose, .accountHelp)
            try await eq(try await h.signedPost(consumer, "/v1/handoff/redeem", HandoffRedeemRequest(token: token)).status, .gone)
            try await eq(try await h.request(.GET, "/h/\(token)").status, .gone)
            // 10-minute TTL.
            let again = try await say(h, "3")
            let second = extractToken(in: again.first { $0.contains("/h/") }!, prefix: "h")!
            h.clock.advance(by: 11 * 60)
            try await eq(try await h.signedPost(consumer, "/v1/handoff/redeem", HandoffRedeemRequest(token: second)).status, .gone)
        }
    }

    func testPerPhoneRateLimitDropsFloodsSilently() async throws {
        try await withHarness({ $0.rateLimits.smsInboundPerPhone = RateRule(capacity: 3, perMinute: 1) }) { h in
            for i in 0..<6 {
                let response = try await inbound(h, body: "Hi \(i)")
                XCTAssertEqual(response.status, .ok)
            }
            let processed = try await ProcessedProviderMessageRecord.query(on: h.db).count()
            XCTAssertEqual(processed, 3)
            let limited = try await AuditEventRecord.query(on: h.db).filter(\.$action == "gateway.rate_limited").count()
            XCTAssertEqual(limited, 3)
            // Another number is unaffected.
            try await eq(try await inbound(h, from: "+14805550999", body: "Hi").status, .ok)
            let after = try await ProcessedProviderMessageRecord.query(on: h.db).count()
            XCTAssertEqual(after, 4)
        }
    }

    func testGlobalRateLimitApplies() async throws {
        try await withHarness({ $0.rateLimits.smsInboundGlobal = RateRule(capacity: 2, perMinute: 1) }) { h in
            for i in 0..<4 { _ = try await inbound(h, from: "+1480555010\(i)", body: "Hi") }
            let processed = try await ProcessedProviderMessageRecord.query(on: h.db).count()
            XCTAssertEqual(processed, 2)
        }
    }

    func testOutboundQueueRetriesWithBackoffAndKeepsOrdering() async throws {
        try await withHarness { h in
            let airline = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            try await linkPhone(h, consumer)
            _ = try await say(h, "@northwindair")
            _ = try await say(h, "1")
            let queue = OutboundSMS(db: h.db, ctx: h.ctx)
            let target = PhoneNumber(phone)!
            try await queue.enqueue(to: target, body: "first")
            try await queue.enqueue(to: target, body: "second")
            try await queue.enqueue(to: target, body: "third")
            let base = h.texts.sent.count
            h.texts.failNext(1)
            try await h.runJobs()
            XCTAssertEqual(h.texts.sent.count, base, "the failing head blocks later messages (ordering)")
            try await h.runJobs()
            XCTAssertEqual(h.texts.sent.count, base, "backoff: not retried immediately")
            h.clock.advance(by: 16)
            try await h.runJobs()
            XCTAssertEqual(h.texts.sent.dropFirst(base).map(\.body), ["first", "second", "third"])
            _ = airline
        }
    }

    func testPermanentlyFailingMessagesDoNotBlockTheQueueForever() async throws {
        try await withHarness { h in
            let queue = OutboundSMS(db: h.db, ctx: h.ctx)
            let target = PhoneNumber(phone)!
            try await queue.enqueue(to: target, body: "poison", allowWhenOptedOut: true)
            try await queue.enqueue(to: target, body: "next", allowWhenOptedOut: true)
            h.texts.failNext(100)
            for _ in 0..<OutboundSMS.maxAttempts + 1 {
                try await h.runJobs()
                h.clock.advance(by: 3600)
            }
            let rows = try await SMSOutboundRecord.query(on: h.db).sort(\.$seq).all()
            XCTAssertEqual(rows.first?.status, "failed")
            h.texts.failNext(0)
            try await h.runJobs()
            XCTAssertEqual(h.texts.sent.map(\.body), ["next"])
        }
    }

    func testOptInOutAndConsentStateAreBoundToThePhoneNotTheBusiness() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            try await linkPhone(h, consumer)
            _ = try await say(h, "Hi")
            _ = try await say(h, "STOP")
            // A fresh STOP from an unrelated number leaves other threads alone.
            _ = try await say(h, "Hi", from: "+14805550888")
            let contexts = try await SMSContextRecord.query(on: h.db).all()
            XCTAssertEqual(contexts.count, 2)
            XCTAssertEqual(contexts.filter(\.optedOut).count, 1)
        }
    }

    func testGatewayAuditNeverContainsFullPhoneNumbersOrMessageText() async throws {
        try await withHarness { h in
            let airline = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            try await linkPhone(h, consumer)
            _ = try await say(h, "@northwindair")
            _ = try await say(h, "1")
            _ = try await say(h, "my secret message about invoice 99887")
            let events = try await AuditEventRecord.query(on: h.db).all()
            XCTAssertFalse(events.isEmpty)
            for event in events {
                let blob = [event.actorId, event.metadataJSON, event.subjectId].compactMap { $0 }.joined()
                XCTAssertFalse(blob.contains("14805550123"), event.action)
                XCTAssertFalse(blob.contains("99887"), event.action)
                XCTAssertFalse(blob.contains("secret message"), event.action)
            }
            let verification = try await AuditService.verifyChain(on: h.db)
            XCTAssertTrue(verification.valid)
            _ = airline
        }
    }

    func testPhoneOTPLinkFlowIsHashedAttemptLimitedAndRateLimited() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            let target = PhoneNumber("+14805550177")!
            func start() async throws -> HTTPResult { try await h.signedPost(consumer, "/v1/phone-links/start", PhoneLinkStartRequest(phone: target)) }
            func lastCode() -> String? {
                h.texts.sent.last.flatMap { sms in sms.body.split(separator: " ").first { $0.count == 7 && $0.hasSuffix(".") ? true : $0.count == 6 && $0.allSatisfy(\.isNumber) } }
                    .map { String($0.filter(\.isNumber)) }
            }
            let started = try await start()
            XCTAssertEqual(started.status, .ok, started.text)
            let linkId = try started.json(PhoneLinkStartResponse.self).phoneLinkId
            try await h.runJobs()
            let code = lastCode()!
            XCTAssertEqual(code.count, 6)
            // The code is stored only as a keyed hash; the SMS body is wiped after sending.
            let row = try await PhoneLinkRecord.find(linkId.uuid, on: h.db)!
            XCTAssertNotEqual(row.otpHash, code)
            XCTAssertEqual(row.otpHash?.count, 64)
            XCTAssertFalse(row.phoneCiphertext.contains("4805550177"))
            let wiped = try await SMSOutboundRecord.query(on: h.db).first()!
            XCTAssertEqual(try h.ctx.cipher.openString(wiped.bodyCiphertext, context: "sms_outbound.body"), "[removed]")
            // Wrong codes are counted; the right one is refused once the attempt limit is hit.
            let wrong = code == "000000" ? "111111" : "000000"
            for _ in 0..<5 {
                let response = try await h.signedPost(consumer, "/v1/phone-links/verify", PhoneLinkVerifyRequest(phoneLinkId: linkId, code: wrong))
                XCTAssertEqual(response.status, .forbidden)
                h.clock.advance(by: 10)
            }
            let locked = try await h.signedPost(consumer, "/v1/phone-links/verify", PhoneLinkVerifyRequest(phoneLinkId: linkId, code: code))
            XCTAssertEqual(locked.status, .forbidden)
            // A new code works once; another consumer cannot use it.
            let second = try await start()
            let secondId = try second.json(PhoneLinkStartResponse.self).phoneLinkId
            try await h.runJobs()
            let fresh = lastCode()!
            let other = try await h.readyConsumer(name: "Other")
            try await eq(try await h.signedPost(other, "/v1/phone-links/verify", PhoneLinkVerifyRequest(phoneLinkId: secondId, code: fresh)).status, .notFound)
            let verified = try await h.signedPost(consumer, "/v1/phone-links/verify", PhoneLinkVerifyRequest(phoneLinkId: secondId, code: fresh))
            XCTAssertEqual(verified.status, .ok, verified.text)
            XCTAssertTrue(try verified.json(PhoneLink.self).maskedPhone.hasSuffix("0177"))
            try await eq(try await h.signedPost(consumer, "/v1/phone-links/verify", PhoneLinkVerifyRequest(phoneLinkId: secondId, code: fresh)).status, .notFound)
            // Texting from the verified number now reaches a linked account.
            let hello = try await say(h, "Hi", from: "+14805550177")
            XCTAssertFalse(hello.isEmpty)
            let context = try await SMSContextRecord.query(on: h.db).first()!
            XCTAssertEqual(context.consumerId, consumer.id.uuid)
        }
    }

    func testOTPStartIsRateLimitedPerPhone() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            let target = PhoneNumber("+14805550166")!
            var statuses: [UInt] = []
            for _ in 0..<5 {
                statuses.append(try await h.signedPost(consumer, "/v1/phone-links/start", PhoneLinkStartRequest(phone: target)).status.code)
            }
            XCTAssertEqual(statuses, [200, 200, 200, 429, 429])
        }
    }
}


func smsForm(_ params: [(String, String)]) -> Data {
    func enc(_ s: String) -> String { s.addingPercentEncoding(withAllowedCharacters: CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")) ?? "" }
    return Data(params.map { enc($0.0) + "=" + enc($0.1) }.joined(separator: "&").utf8)
}

func sendInbound(_ h: TestHarness, from: String, body: String, sid: String?, signature: String? = nil, signAs: String? = nil) async throws -> HTTPResult {
    let path = "/v1/providers/sms/inbound"
    let params: [(String, String)] = [("MessageSid", sid ?? "SM" + SecureToken.generate(byteCount: 12).filter(\.isLetter)), ("From", from),
                                      ("To", "+15550001111"), ("Body", body)]
    let url = h.config.publicBaseURL + path
    let valid = TwilioProvider.signature(authToken: RecordingSMSProvider.authToken, url: url, params: signAs == nil ? params : [("Body", signAs!)])
    let header = signature.map { $0 == "<valid>" ? valid : $0 } ?? valid
    return try await h.request(.POST, path, headers: ["X-Twilio-Signature": header], body: smsForm(params), contentType: "application/x-www-form-urlencoded")
}
