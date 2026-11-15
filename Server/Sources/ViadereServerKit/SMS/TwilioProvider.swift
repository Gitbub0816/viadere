@preconcurrency import Crypto
import Foundation
import Vapor
import ViadereCore

/// Twilio-compatible adapter.
///
/// Inbound authenticity: `X-Twilio-Signature` = base64(HMAC-SHA1(authToken, url + for each POST parameter
/// sorted by name: name + value)), compared in constant time. (SHA-1 is mandated by Twilio's scheme; it is
/// used here only as an HMAC.)
public struct TwilioProvider: SMSProvider {
    public let config: TwilioConfig
    private let client: (any Client)?
    private let logger: Logger

    public var name: String { "twilio" }

    public init(config: TwilioConfig, client: (any Client)?, logger: Logger) {
        self.config = config
        self.client = client
        self.logger = logger
    }

    // MARK: Signature

    /// Computes the expected signature (exposed for tests and tooling).
    public static func signature(authToken: String, url: String, params: [(String, String)]) -> String {
        var message = url
        for (key, value) in params.sorted(by: { $0.0 == $1.0 ? $0.1 < $1.1 : $0.0 < $1.0 }) { message += key + value }
        let mac = HMAC<Insecure.SHA1>.authenticationCode(for: Data(message.utf8), using: SymmetricKey(data: Data(authToken.utf8)))
        return Data(mac).base64EncodedString()
    }

    public func verifyWebhook(_ request: ProviderWebhookRequest) -> Bool {
        guard let provided = request.signature, provided.count <= 128 else { return false }
        let expected = Self.signature(authToken: config.authToken, url: request.url, params: FormParams.parse(request.body))
        return ConstantTime.equals(provided, expected)
    }

    // MARK: Parsing

    public func parseInbound(_ request: ProviderWebhookRequest) throws -> InboundSMS {
        let params = Dictionary(FormParams.parse(request.body), uniquingKeysWith: { first, _ in first })
        guard let sid = params["MessageSid"] ?? params["SmsSid"], !sid.isEmpty, sid.count <= 64,
              sid.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }),
              let from = params["From"].flatMap(PhoneNumber.init) else { throw SMSProviderError.malformedWebhook }
        // The body is untrusted user text; it is capped here and again by the engine.
        let text = String((params["Body"] ?? "").prefix(1600))
        return InboundSMS(providerMessageId: "twilio:" + sid, from: from, text: text, receivedAt: request.receivedAt)
    }

    public func parseDeliveryUpdate(_ request: ProviderWebhookRequest) throws -> SMSDeliveryUpdate? {
        let params = Dictionary(FormParams.parse(request.body), uniquingKeysWith: { first, _ in first })
        guard let sid = params["MessageSid"] ?? params["SmsSid"], let status = params["MessageStatus"] ?? params["SmsStatus"] else {
            throw SMSProviderError.malformedWebhook
        }
        let mapped: SMSDeliveryUpdate.Status
        switch status {
        case "delivered": mapped = .delivered
        case "failed", "undelivered": mapped = .failed
        case "sent": mapped = .sent
        case "queued", "accepted", "sending": mapped = .queued
        default: return nil
        }
        return SMSDeliveryUpdate(providerMessageId: "twilio:" + sid, status: mapped, errorCode: params["ErrorCode"])
    }

    // MARK: Sending

    public func send(_ request: OutboundSMSRequest) async throws -> OutboundSMSResult {
        guard let client else { throw SMSProviderError.transient("no http client") }
        let uri = URI(string: "https://api.twilio.com/2010-04-01/Accounts/\(config.accountSID)/Messages.json")
        var form: [(String, String)] = [("To", request.to.e164), ("Body", request.body)]
        if let service = config.messagingServiceSID { form.append(("MessagingServiceSid", service)) } else { form.append(("From", config.fromNumber)) }
        let encoded = form.map { Self.formEncode($0.0) + "=" + Self.formEncode($0.1) }.joined(separator: "&")
        let credentials = Data("\(config.accountSID):\(config.authToken)".utf8).base64EncodedString()
        let response: ClientResponse
        do {
            response = try await client.post(uri) { clientRequest in
                clientRequest.headers.replaceOrAdd(name: .authorization, value: "Basic \(credentials)")
                clientRequest.headers.contentType = .urlEncodedForm
                clientRequest.body = ByteBuffer(string: encoded)
            }
        } catch {
            throw SMSProviderError.transient("network")
        }
        let bodyData = response.body.map { Data($0.readableBytesView) } ?? Data()
        let json = (try? JSONSerialization.jsonObject(with: bodyData)) as? [String: Any]
        switch response.status.code {
        case 200..<300:
            guard let sid = json?["sid"] as? String else { throw SMSProviderError.transient("malformed response") }
            return OutboundSMSResult(providerMessageId: "twilio:" + sid)
        case 429, 500..<600:
            throw SMSProviderError.transient("http \(response.status.code)")
        default:
            let code = (json?["code"] as? Int).map(String.init) ?? "http\(response.status.code)"
            // 21610: recipient replied STOP to the carrier-level opt-out; 21211/21614: invalid number.
            throw SMSProviderError.permanent(code: code, recipientOptedOut: code == "21610")
        }
    }

    private static func formEncode(_ value: String) -> String {
        var out = ""
        for byte in value.utf8 {
            switch byte {
            case UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "0")...UInt8(ascii: "9"),
                 UInt8(ascii: "-"), UInt8(ascii: "."), UInt8(ascii: "_"), UInt8(ascii: "~"):
                out.append(Character(Unicode.Scalar(byte)))
            default:
                out += String(format: "%%%02X", byte)
            }
        }
        return out
    }
}
