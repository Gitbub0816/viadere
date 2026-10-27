@preconcurrency import Crypto
import Fluent
import Foundation
import ViadereCore
import Vapor
import XCTest
@testable import ViadereServerKit

/// A scripted RCS provider API: capability lookups and sends, recorded for assertions.
final class ScriptedRCSHTTP: RCSHTTPClient, @unchecked Sendable {
    private let lock = NSLock()
    private var log: [RCSHTTPRequest] = []
    private var capabilityStatus: [String: Int] = [:]
    private var defaultCapability = 200
    private var sendStatuses: [Int] = []
    private var counter = 0

    var requests: [RCSHTTPRequest] { lock.withLock { log } }
    var capabilityChecks: [RCSHTTPRequest] { requests.filter { $0.method == "GET" } }
    var sends: [RCSHTTPRequest] { requests.filter { $0.method == "POST" } }

    func setCapability(_ status: Int, for phone: String? = nil) {
        lock.withLock {
            if let phone { capabilityStatus[phone] = status } else { defaultCapability = status }
        }
    }

    func queueSendStatuses(_ statuses: [Int]) { lock.withLock { sendStatuses = statuses } }

    func send(_ request: RCSHTTPRequest) async throws -> RCSHTTPResponse {
        lock.withLock {
            log.append(request)
            if request.method == "GET" {
                let parts = request.url.path.split(separator: "/")
                let phone = parts.count >= 2 ? String(parts[parts.count - 2]) : ""
                let status = capabilityStatus[phone] ?? defaultCapability
                if status == 200 { return RCSHTTPResponse(status: 200, body: Data("{\"features\":[\"RICHCARD_STANDALONE\",\"ACTION_OPEN_URL\"]}".utf8)) }
                return RCSHTTPResponse(status: status)
            }
            counter += 1
            let status = sendStatuses.isEmpty ? 200 : sendStatuses.removeFirst()
            return RCSHTTPResponse(status: status, body: Data("{\"messageId\":\"prov-\(counter)\"}".utf8))
        }
    }
}

struct RCSFixture {
    static let secretBytes = Data(repeating: 0x5A, count: 32)
    static let config = RCSConfig(baseURL: URL(string: "https://rcs.provider.test/v1")!, apiToken: "provider-token-123", webhookSecret: secretBytes, agentId: "viadere-agent")
    static var secret: String { Base64URL.encode(secretBytes) }
    static let phone = "+14805550123"
}

extension TestHarness {
    /// Links a verified phone to a consumer (what the OTP / link-token flow produces).
    func linkVerifiedPhone(_ consumer: TestConsumer, phone number: String = RCSFixture.phone) async throws {
        let e164 = PhoneNumber(number)!
        let link = try PhoneLinkRecord(consumerId: consumer.id.uuid, phone: e164, hasher: ctx.hasher, cipher: ctx.cipher, now: clock.now())
        link.state = "verified"
        link.verifiedPhoneHash = ctx.hasher.phoneHash(e164)
        link.verifiedAt = clock.now()
        try await link.create(on: db)
    }

    /// A signed provider webhook.
    func rcsInbound(_ json: [String: Any], secret: String = RCSFixture.secret, at: Date? = nil, signature: String? = nil) async throws -> HTTPResult {
        let body = try JSONSerialization.data(withJSONObject: json, options: [.sortedKeys])
        let header = signature ?? WebhookSignature.header(secret: secret, body: body, now: at ?? clock.now())
        return try await request(.POST, "/v1/providers/rcs/inbound", headers: [GenericRBMProvider.signatureHeader: header], body: body)
    }

    func rcsTap(token: String, from phone: String = RCSFixture.phone, messageId: String = UUID().uuidString) async throws -> HTTPResult {
        try await rcsInbound(["messageId": messageId, "senderPhoneNumber": phone, "sendTime": ViadereDate.format(clock.now()),
                              "suggestionResponse": ["postbackData": token, "text": "tap"]])
    }

    func rcsText(_ text: String, from phone: String = RCSFixture.phone, messageId: String = UUID().uuidString) async throws -> HTTPResult {
        try await rcsInbound(["messageId": messageId, "senderPhoneNumber": phone, "sendTime": ViadereDate.format(clock.now()), "text": text])
    }

    func rcsSentMessages(_ http: ScriptedRCSHTTP) throws -> [[String: Any]] {
        try http.sends.map { try JSONSerialization.jsonObject(with: $0.body ?? Data()) as! [String: Any] }
    }

    func suggestions(in message: [String: Any]) -> [[String: Any]] {
        ((message["contentMessage"] as? [String: Any])?["suggestions"] as? [[String: Any]]) ?? []
    }

    func replyTokens(in message: [String: Any]) -> [(text: String, token: String)] {
        suggestions(in: message).compactMap { s in
            guard let reply = s["reply"] as? [String: Any], let text = reply["text"] as? String, let token = reply["postbackData"] as? String else { return nil }
            return (text, token)
        }
    }
}
