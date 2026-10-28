@preconcurrency import Crypto
import Foundation
import Logging
import NIOConcurrencyHelpers
import NIOCore
import NIOHTTP1
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// An HTTP client double that answers with fixed headers (MailerSend returns the message id in a header, with an empty body).
private final class HeaderStubClient: Client, @unchecked Sendable {
    let eventLoop: any EventLoop
    let status: HTTPStatus
    let headers: HTTPHeaders
    let requests = NIOLockedValueBox<[ClientRequest]>([])

    init(eventLoop: any EventLoop, status: HTTPStatus, headers: HTTPHeaders = [:]) {
        self.eventLoop = eventLoop
        self.status = status
        self.headers = headers
    }

    func delegating(to eventLoop: any EventLoop) -> any Client { self }
    func logging(to logger: Logger) -> any Client { self }
    func allocating(to byteBufferAllocator: ByteBufferAllocator) -> any Client { self }
    func send(_ request: ClientRequest) -> EventLoopFuture<ClientResponse> {
        requests.withLockedValue { $0.append(request) }
        return eventLoop.makeSucceededFuture(ClientResponse(status: status, headers: headers, body: nil))
    }
}

final class MailerSendProviderTests: XCTestCase {
    let config = MailerSendSMSConfig(apiToken: "mlsn.token", fromNumber: "+15550001111",
                                     inboundSecret: "inbound-secret-0123456789", statusSecret: "status-secret-0123456789")

    func webhook(_ json: String, route: ProviderWebhookRequest.Route, secret: String?) -> ProviderWebhookRequest {
        let body = Data(json.utf8)
        return ProviderWebhookRequest(url: "https://api.example/v1/providers/sms/inbound", route: route,
                                      signature: secret.map { MailerSendSMSProvider.signature(secret: $0, body: body) }, body: body, receivedAt: Date())
    }

    func testTheSignatureIsHexHMACSHA256OfTheRawBody() {
        // RFC 4231 test case 2.
        XCTAssertEqual(MailerSendSMSProvider.signature(secret: "Jefe", body: Data("what do ya want for nothing?".utf8)),
                       "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    }

    func testWebhooksAreCheckedOnlyAgainstTheirOwnRoutesSecret() {
        let provider = MailerSendSMSProvider(config: config, client: nil)
        let json = #"{"data":{"id":"abc123","from":"+14805550123","text":"MENU"}}"#
        XCTAssertTrue(provider.verifyWebhook(webhook(json, route: .inbound, secret: config.inboundSecret)))
        XCTAssertTrue(provider.verifyWebhook(webhook(json, route: .status, secret: config.statusSecret)))
        // A request signed for one route is refused on the other.
        XCTAssertFalse(provider.verifyWebhook(webhook(json, route: .status, secret: config.inboundSecret)))
        XCTAssertFalse(provider.verifyWebhook(webhook(json, route: .inbound, secret: config.statusSecret)))
        // Unsigned, wrongly signed, tampered, and MailerSend's public test secret.
        XCTAssertFalse(provider.verifyWebhook(webhook(json, route: .inbound, secret: nil)))
        XCTAssertFalse(provider.verifyWebhook(webhook(json, route: .inbound, secret: "test_Am3L1GuOIc4blLUuHqAPxxwkZaJyEk8G")))
        var tampered = webhook(json, route: .inbound, secret: config.inboundSecret)
        tampered.body = Data(json.replacingOccurrences(of: "MENU", with: "STOP").utf8)
        XCTAssertFalse(provider.verifyWebhook(tampered))
        var upper = webhook(json, route: .inbound, secret: config.inboundSecret)
        upper.signature = upper.signature?.uppercased()
        XCTAssertTrue(provider.verifyWebhook(upper), "hex case does not matter")
        XCTAssertEqual(provider.signatureHeader, "Signature")
    }

    func testInboundParsingAcceptsTheWrappedAndFlatShapesAndRejectsGarbage() throws {
        let provider = MailerSendSMSProvider(config: config, client: nil)
        let wrapped = try provider.parseInbound(webhook(#"{"type":"sms.inbound","data":{"id":"6244233a","from":"+14805550123","to":"+15550001111","text":"MENU"}}"#,
                                                        route: .inbound, secret: nil))
        XCTAssertEqual(wrapped.providerMessageId, "mailersend:6244233a")
        XCTAssertEqual(wrapped.from.e164, "+14805550123")
        XCTAssertEqual(wrapped.text, "MENU")
        // Without an id, the id is derived from the body: a replay of the same signed body deduplicates.
        let flat = webhook(#"{"from":"+14805550123","text":"8"}"#, route: .inbound, secret: nil)
        let first = try provider.parseInbound(flat)
        XCTAssertEqual(try provider.parseInbound(flat).providerMessageId, first.providerMessageId)
        XCTAssertTrue(first.providerMessageId.hasPrefix("mailersend:h"))
        for bad in [#"{"text":"hi"}"#, #"{"from":"not a number","text":"hi"}"#, "not json",
                    #"{"data":{"id":"bad id!","from":"+14805550123","text":"x"}}"#] {
            XCTAssertThrowsError(try provider.parseInbound(webhook(bad, route: .inbound, secret: nil)), bad)
        }
        let long = try provider.parseInbound(webhook(#"{"from":"+14805550123","text":"\#(String(repeating: "a", count: 5000))"}"#, route: .inbound, secret: nil))
        XCTAssertEqual(long.text.count, 1600)
    }

    func testDeliveryEventsMapToStatuses() throws {
        let provider = MailerSendSMSProvider(config: config, client: nil)
        func update(_ type: String) throws -> SMSDeliveryUpdate? {
            try provider.parseDeliveryUpdate(webhook(#"{"type":"\#(type)","data":{"sms_message_id":"m1","status":"x","sms":{"id":"m1","error_type":"carrier"}}}"#,
                                                     route: .status, secret: nil))
        }
        XCTAssertEqual(try update("sms.delivered"), SMSDeliveryUpdate(providerMessageId: "mailersend:m1", status: .delivered, errorCode: "carrier"))
        XCTAssertEqual(try update("sms.failed")?.status, .failed)
        XCTAssertEqual(try update("sms.sent")?.status, .sent)
        XCTAssertNil(try update("webhook.test"))
        XCTAssertThrowsError(try provider.parseDeliveryUpdate(webhook(#"{"data":{}}"#, route: .status, secret: nil)))
    }

    func testSendPostsTheDocumentedRequestAndMapsOutcomes() async throws {
        let app = try await Application.make(.testing)
        let loop = app.eventLoopGroup.next()
        let request = OutboundSMSRequest(to: PhoneNumber("+14805550123")!, body: "Viadere: {code} & welcome", reference: "r1")

        let ok = HeaderStubClient(eventLoop: loop, status: .accepted, headers: ["X-SMS-Message-Id": "6244233a7e19"])
        let result = try await MailerSendSMSProvider(config: config, client: ok).send(request)
        XCTAssertEqual(result.providerMessageId, "mailersend:6244233a7e19")
        let sent = try XCTUnwrap(ok.requests.withLockedValue { $0.first })
        XCTAssertEqual(sent.url.string, "https://api.mailersend.com/v1/sms")
        XCTAssertEqual(sent.headers.first(name: .authorization), "Bearer mlsn.token")
        var body = try XCTUnwrap(sent.body)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(body.readBytes(length: body.readableBytes) ?? [])) as? [String: Any])
        XCTAssertEqual(json["from"] as? String, "+15550001111")
        XCTAssertEqual(json["to"] as? [String], ["+14805550123"])
        XCTAssertEqual(json["text"] as? String, "Viadere: (code) & welcome", "curly braces are not allowed by MailerSend")

        func outcome(_ status: HTTPStatus, headers: HTTPHeaders = [:]) async -> SMSProviderError? {
            do { _ = try await MailerSendSMSProvider(config: config, client: HeaderStubClient(eventLoop: loop, status: status, headers: headers)).send(request) }
            catch { return error as? SMSProviderError }
            return nil
        }
        let throttled = await outcome(.tooManyRequests)
        XCTAssertEqual(throttled, .transient("http 429"))
        let down = await outcome(.badGateway)
        XCTAssertEqual(down, .transient("http 502"))
        let invalid = await outcome(.unprocessableEntity)
        XCTAssertEqual(invalid, .permanent(code: "http422", recipientOptedOut: false))
        let noID = await outcome(.accepted)
        XCTAssertEqual(noID, .transient("malformed response"))
        try await app.asyncShutdown()
    }

    func testTheEmailSenderSpeaksMailerSendWhenConfigured() async throws {
        let app = try await Application.make(.testing)
        let client = HeaderStubClient(eventLoop: app.eventLoopGroup.next(), status: .accepted)
        var email = EmailConfig(apiURL: URL(string: "https://api.mailersend.com/v1/email")!, apiKey: "mlsn.mail", fromAddress: "Viadere Staging <no-reply@viadere.cksites.dev>")
        email.format = .mailersend
        try await HTTPEmailSender(config: email, client: client).send(EmailMessage(to: "a@b.co", subject: "Hi", text: "Body", kind: "x"))
        let sent = try XCTUnwrap(client.requests.withLockedValue { $0.first })
        XCTAssertEqual(sent.headers.first(name: .authorization), "Bearer mlsn.mail")
        var body = try XCTUnwrap(sent.body)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(body.readBytes(length: body.readableBytes) ?? [])) as? [String: Any])
        XCTAssertEqual(json["from"] as? [String: String], ["email": "no-reply@viadere.cksites.dev", "name": "Viadere Staging"])
        XCTAssertEqual(json["to"] as? [[String: String]], [["email": "a@b.co"]])
        XCTAssertEqual(json["subject"] as? String, "Hi")
        XCTAssertEqual(json["text"] as? String, "Body")
        XCTAssertEqual(HTTPEmailSender.address("no-reply@x.dev").email, "no-reply@x.dev")
        XCTAssertNil(HTTPEmailSender.address("no-reply@x.dev").name)
        try await app.asyncShutdown()
    }

    func testStrictConfigurationAcceptsMailerSendAndRefusesWeakOrMissingValues() throws {
        var env = PlatformGateOpsTests.productionEnvironment("staging")
        env["TWILIO_ACCOUNT_SID"] = nil
        env["TWILIO_AUTH_TOKEN"] = nil
        env["TWILIO_FROM_NUMBER"] = nil
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(env), "staging needs an SMS provider")
        env["SMS_PROVIDER"] = "mailersend"
        env["MAILERSEND_SMS_API_TOKEN"] = "mlsn.token"
        env["MAILERSEND_SMS_FROM_NUMBER"] = "+1 (555) 000-1111"
        env["MAILERSEND_SMS_INBOUND_SECRET"] = "inbound-secret-0123456789"
        env["MAILERSEND_SMS_WEBHOOK_SECRET"] = "status-secret-0123456789"
        env["EMAIL_API_FORMAT"] = "mailersend"
        let config = try ServerConfig.fromEnvironment(env)
        XCTAssertNil(config.twilio)
        XCTAssertEqual(config.mailerSendSMS?.fromNumber, "+15550001111")
        XCTAssertEqual(config.email?.format, .mailersend)

        var short = env
        short["MAILERSEND_SMS_INBOUND_SECRET"] = "short"
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(short))
        var same = env
        same["MAILERSEND_SMS_WEBHOOK_SECRET"] = env["MAILERSEND_SMS_INBOUND_SECRET"]
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(same), "one secret for both routes is refused")
        var missing = env
        missing["MAILERSEND_SMS_WEBHOOK_SECRET"] = nil
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(missing))
        var unknown = env
        unknown["SMS_PROVIDER"] = "carrier-pigeon"
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(unknown))
        var badFormat = env
        badFormat["EMAIL_API_FORMAT"] = "xml"
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(badFormat))
    }
}
