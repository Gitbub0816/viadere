@preconcurrency import Crypto
import Foundation
import Vapor
import ViadereCore

/// MailerSend SMS adapter (API v1, US/CA numbers).
///
/// * Sending: `POST https://api.mailersend.com/v1/sms` with `Authorization: Bearer <token>` and `{"from", "to": [..], "text"}`; `202`
///   carries the message id in `X-SMS-Message-Id`. The text may not contain curly braces (MailerSend's personalization syntax), so
///   they are replaced, and it is capped at 2,048 characters.
/// * Webhooks: MailerSend signs each request with `Signature` = hex(HMAC-SHA256(signing secret, raw body)). The status webhook
///   (`sms.sent` / `sms.delivered` / `sms.failed`) and the inbound route each have their own secret; a request is checked only
///   against the secret of the route it arrived on, in constant time. An unsigned request is refused (fail closed).
public struct MailerSendSMSProvider: SMSProvider {
    public let config: MailerSendSMSConfig
    private let client: (any Client)?

    public var name: String { "mailersend" }
    public var signatureHeader: String { "Signature" }

    static let maxTextLength = 2048

    public init(config: MailerSendSMSConfig, client: (any Client)?) {
        self.config = config
        self.client = client
    }

    // MARK: Signature

    /// Computes the expected signature (exposed for tests and tooling).
    public static func signature(secret: String, body: Data) -> String {
        let mac = HMAC<SHA256>.authenticationCode(for: body, using: SymmetricKey(data: Data(secret.utf8)))
        return Data(mac).map { String(format: "%02x", $0) }.joined()
    }

    public func verifyWebhook(_ request: ProviderWebhookRequest) -> Bool {
        guard let provided = request.signature?.lowercased(), provided.count == 64 else { return false }
        let secret = request.route == .inbound ? config.inboundSecret : config.statusSecret
        return ConstantTime.equals(provided, Self.signature(secret: secret, body: request.body))
    }

    // MARK: Parsing

    /// MailerSend wraps the event object in `data`; a top-level `from`/`text` is accepted too (the inbound forward shape is not
    /// fully documented). Without a provider id the message id is derived from the signed body, so a replay is still deduplicated.
    public func parseInbound(_ request: ProviderWebhookRequest) throws -> InboundSMS {
        guard let root = (try? JSONSerialization.jsonObject(with: request.body)) as? [String: Any] else { throw SMSProviderError.malformedWebhook }
        let object = (root["data"] as? [String: Any]) ?? root
        guard let from = (object["from"] as? String).flatMap(PhoneNumber.init) else { throw SMSProviderError.malformedWebhook }
        let id: String
        if let raw = (object["id"] as? String) ?? (object["sms_message_id"] as? String) {
            guard !raw.isEmpty, raw.count <= 64, raw.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }) else { throw SMSProviderError.malformedWebhook }
            id = raw
        } else {
            id = "h" + SHA256.hash(data: request.body).prefix(16).map { String(format: "%02x", $0) }.joined()
        }
        // The body is untrusted user text; it is capped here and again by the engine.
        let text = String(((object["text"] as? String) ?? "").prefix(1600))
        return InboundSMS(providerMessageId: "mailersend:" + id, from: from, text: text, receivedAt: request.receivedAt)
    }

    public func parseDeliveryUpdate(_ request: ProviderWebhookRequest) throws -> SMSDeliveryUpdate? {
        guard let root = (try? JSONSerialization.jsonObject(with: request.body)) as? [String: Any] else { throw SMSProviderError.malformedWebhook }
        guard let type = root["type"] as? String else { throw SMSProviderError.malformedWebhook }
        let mapped: SMSDeliveryUpdate.Status
        switch type {
        case "sms.delivered": mapped = .delivered
        case "sms.failed": mapped = .failed
        case "sms.sent": mapped = .sent
        default: return nil   // webhook.test and future events
        }
        let data = root["data"] as? [String: Any]
        let sms = data?["sms"] as? [String: Any]
        guard let id = (data?["sms_message_id"] as? String) ?? (sms?["id"] as? String), !id.isEmpty, id.count <= 64 else {
            throw SMSProviderError.malformedWebhook
        }
        let errorType = (sms?["error_type"] as? String).map { String($0.prefix(64)) }
        return SMSDeliveryUpdate(providerMessageId: "mailersend:" + id, status: mapped, errorCode: errorType)
    }

    // MARK: Sending

    struct Body: Encodable {
        var from: String
        var to: [String]
        var text: String
    }

    static func sanitize(_ text: String) -> String {
        String(text.replacingOccurrences(of: "{", with: "(").replacingOccurrences(of: "}", with: ")").prefix(maxTextLength))
    }

    public func send(_ request: OutboundSMSRequest) async throws -> OutboundSMSResult {
        guard let client else { throw SMSProviderError.transient("no http client") }
        let response: ClientResponse
        do {
            response = try await client.post(URI(string: "https://api.mailersend.com/v1/sms")) { clientRequest in
                clientRequest.headers.replaceOrAdd(name: .authorization, value: "Bearer \(config.apiToken)")
                clientRequest.headers.replaceOrAdd(name: .accept, value: "application/json")
                try clientRequest.content.encode(Body(from: config.fromNumber, to: [request.to.e164], text: Self.sanitize(request.body)), as: .json)
            }
        } catch {
            throw SMSProviderError.transient("network")
        }
        switch response.status.code {
        case 200..<300:
            guard let id = response.headers.first(name: "X-SMS-Message-Id"), !id.isEmpty, id.count <= 64 else {
                throw SMSProviderError.transient("malformed response")
            }
            return OutboundSMSResult(providerMessageId: "mailersend:" + id)
        case 429, 500..<600:
            throw SMSProviderError.transient("http \(response.status.code)")
        default:
            // 422: validation (invalid or unsubscribed number, number outside US/CA). MailerSend keeps its own STOP suppression list
            // and does not return a distinct code for it, so the gateway's own opt-out record stays the source of truth.
            throw SMSProviderError.permanent(code: "http\(response.status.code)", recipientOptedOut: false)
        }
    }
}
