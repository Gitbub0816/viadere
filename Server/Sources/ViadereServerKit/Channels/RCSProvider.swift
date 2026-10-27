import Foundation
import Vapor
import ViadereCore

/// Provider-agnostic RCS Business Messaging transport: verified agent, capability lookup, rich sends and signed
/// inbound webhooks. Vendor adapters (Google RBM, an aggregator, a carrier hub) implement this; the router and
/// `RCSChannelAdapter` do not know which one is in use.
public protocol RCSProvider: Sendable {
    var name: String { get }
    /// Constant-time verification of the provider's webhook signature (including replay window).
    func verifyWebhook(_ request: ProviderWebhookRequest) -> Bool
    func parseInbound(_ request: ProviderWebhookRequest) throws -> [ChannelInboundEvent]
    /// Whether `phone` can receive RCS from our agent. Throws `ChannelError.transient` when unsure.
    func checkCapability(for phone: PhoneNumber) async throws -> Bool
    func send(_ message: OutboundChannelMessage, to phone: PhoneNumber, reference: String) async throws -> ChannelSendResult
}

/// Minimal HTTP seam so the generic provider is testable without a network.
public struct RCSHTTPRequest: Sendable {
    public var method: String
    public var url: URL
    public var headers: [String: String]
    public var body: Data?
}

public struct RCSHTTPResponse: Sendable {
    public var status: Int
    public var body: Data
    public init(status: Int, body: Data = Data()) {
        self.status = status
        self.body = body
    }
}

public protocol RCSHTTPClient: Sendable {
    func send(_ request: RCSHTTPRequest) async throws -> RCSHTTPResponse
}

/// Production HTTP client on Vapor's `Client`. Redirects are never followed (configured on the shared client).
public struct VaporRCSHTTPClient: RCSHTTPClient {
    let client: any Client

    public init(client: any Client) { self.client = client }

    public func send(_ request: RCSHTTPRequest) async throws -> RCSHTTPResponse {
        var headers = HTTPHeaders()
        for (name, value) in request.headers { headers.replaceOrAdd(name: name, value: value) }
        let uri = URI(string: request.url.absoluteString)
        let response = try await client.send(HTTPMethod(rawValue: request.method), headers: headers, to: uri) { outgoing in
            if let body = request.body { outgoing.body = ByteBuffer(data: body) }
        }
        let data = response.body.map { Data($0.readableBytesView) } ?? Data()
        return RCSHTTPResponse(status: Int(response.status.code), body: data)
    }
}

/// A generic, RBM-style REST + webhook adapter.
///
/// **Outbound** (`Authorization: Bearer {apiToken}`, JSON):
/// * `GET  {base}/phones/{e164}/capabilities` → `200 {"features":[…]}` (capable if non-empty) or `404` (not capable).
/// * `POST {base}/agentMessages` `{"agentId","to","messageId","contentMessage":{"text","suggestions":[
///   {"reply":{"text","postbackData"}} | {"action":{"text","openUrlAction":{"url"}}}]}}` → `{"messageId"}`.
///
/// **Inbound** (`X-RCS-Signature: t={unix},v1={hex HMAC-SHA256("{t}." + body)}`, key = the shared secret;
/// the timestamp window is 300 s and comparison is constant time — the same scheme as Viadere's own webhooks):
/// * `{"messageId","senderPhoneNumber","sendTime","text"}` — free text;
/// * `{"messageId","senderPhoneNumber","sendTime","suggestionResponse":{"postbackData","text"}}` — a suggestion tap;
/// * `{"eventType":"DELIVERED"|"READ"|"FAILED","messageId","senderPhoneNumber","sendTime","errorCode"}` — receipts.
public struct GenericRBMProvider: RCSProvider {
    public static let signatureHeader = "X-RCS-Signature"

    private let config: RCSConfig
    private let http: any RCSHTTPClient
    private let secret: String

    public init(config: RCSConfig, http: any RCSHTTPClient) {
        self.config = config
        self.http = http
        secret = Base64URL.encode(config.webhookSecret)
    }

    public var name: String { "rcs" }

    // MARK: Inbound

    public func verifyWebhook(_ request: ProviderWebhookRequest) -> Bool {
        guard let header = request.signature else { return false }
        return (try? WebhookSignature.verify(header: header, body: request.body, secrets: [secret], now: request.receivedAt)) != nil
    }

    private struct InboundBody: Decodable {
        struct SuggestionResponse: Decodable { var postbackData: String? }
        var messageId: String?
        var senderPhoneNumber: String?
        var sendTime: String?
        var text: String?
        var suggestionResponse: SuggestionResponse?
        var eventType: String?
        var errorCode: String?
    }

    public func parseInbound(_ request: ProviderWebhookRequest) throws -> [ChannelInboundEvent] {
        guard request.body.count <= 16 * 1024, let body = try? JSONDecoder().decode(InboundBody.self, from: request.body),
              let messageId = body.messageId, !messageId.isEmpty, messageId.count <= 128 else { throw ChannelError.permanent("malformed") }
        if let type = body.eventType?.uppercased() {
            let status: ChannelReceiptStatus
            switch type {
            case "DELIVERED": status = .delivered
            case "READ": status = .read
            case "FAILED", "UNDELIVERABLE": status = .failed
            default: return []
            }
            return [.receipt(providerMessageId: messageId, status: status, errorCode: body.errorCode.map { String($0.prefix(64)) })]
        }
        guard let rawPhone = body.senderPhoneNumber, let phone = PhoneNumber(rawPhone) else { throw ChannelError.permanent("malformed") }
        let received = body.sendTime.flatMap(ViadereDate.parse) ?? request.receivedAt
        if let data = body.suggestionResponse?.postbackData {
            guard data.count <= 256 else { throw ChannelError.permanent("malformed") }
            return [.postback(from: phone, data: data, messageId: messageId, receivedAt: received)]
        }
        if let text = body.text {
            return [.text(from: phone, text: String(text.prefix(1600)), messageId: messageId, receivedAt: received)]
        }
        return []
    }

    // MARK: Outbound

    private func headers() -> [String: String] {
        ["Authorization": "Bearer \(config.apiToken)", "Content-Type": "application/json", "Accept": "application/json",
         "User-Agent": "Viadere-RCS/1"]
    }

    public func checkCapability(for phone: PhoneNumber) async throws -> Bool {
        // E.164 (`+` and digits only, validated by `PhoneNumber`) is path-safe as is.
        let url = config.baseURL.appendingPathComponent("phones").appendingPathComponent(phone.e164).appendingPathComponent("capabilities")
        let response: RCSHTTPResponse
        do { response = try await http.send(RCSHTTPRequest(method: "GET", url: url, headers: headers(), body: nil)) } catch {
            throw ChannelError.transient("network")
        }
        switch response.status {
        case 200:
            struct Capabilities: Decodable { var features: [String]? }
            let features = (try? JSONDecoder().decode(Capabilities.self, from: response.body))?.features ?? []
            return !features.isEmpty
        case 404: return false
        default: throw ChannelError.transient("http_\(response.status)")
        }
    }

    public func send(_ message: OutboundChannelMessage, to phone: PhoneNumber, reference: String) async throws -> ChannelSendResult {
        var suggestions: [[String: Any]] = []
        for suggestion in message.suggestions.prefix(11) {
            switch suggestion.kind {
            case .reply:
                guard let token = suggestion.postbackToken else { continue }
                suggestions.append(["reply": ["text": suggestion.text, "postbackData": token]])
            case .openURL:
                guard let url = suggestion.url else { continue }
                suggestions.append(["action": ["text": suggestion.text, "openUrlAction": ["url": url.absoluteString]]])
            }
        }
        var content: [String: Any] = ["text": message.text]
        if !suggestions.isEmpty { content["suggestions"] = suggestions }
        let payload: [String: Any] = ["agentId": config.agentId, "to": phone.e164, "messageId": reference, "contentMessage": content]
        guard let body = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys, .withoutEscapingSlashes]) else {
            throw ChannelError.permanent("encode")
        }
        let url = config.baseURL.appendingPathComponent("agentMessages")
        let response: RCSHTTPResponse
        do { response = try await http.send(RCSHTTPRequest(method: "POST", url: url, headers: headers(), body: body)) } catch {
            throw ChannelError.transient("network")
        }
        switch response.status {
        case 200..<300:
            struct Sent: Decodable { var messageId: String? }
            let id = (try? JSONDecoder().decode(Sent.self, from: response.body))?.messageId ?? reference
            return ChannelSendResult(providerMessageId: String(id.prefix(128)))
        case 404, 409, 422: throw ChannelError.notCapable
        case 429, 500..<600: throw ChannelError.transient("http_\(response.status)")
        default: throw ChannelError.permanent("http_\(response.status)")
        }
    }
}

/// RCS as a `ChannelAdapter`. Disabled (and never selected) when no provider is configured.
public struct RCSChannelAdapter: ChannelAdapter {
    public let provider: (any RCSProvider)?

    public init(provider: (any RCSProvider)?) { self.provider = provider }

    public var channel: DeliveryChannel { .rcs }
    public var isEnabled: Bool { provider != nil }

    public func capability(for phone: PhoneNumber) async -> ChannelCapability {
        guard let provider else { return .incapable }
        do { return try await provider.checkCapability(for: phone) ? .capable : .incapable } catch { return .unknown }
    }

    /// Suggested replies and open-URL actions from `ChannelRenderer.rcs`. Reply targets are kept as typed
    /// `RCSPostbackTarget`s; the router swaps each for an opaque, signed, single-use token before sending.
    public func render(_ interaction: Interaction, business: BusinessSummary, handoffURL: URL?) -> ChannelRendering {
        let rendering = ChannelRenderer.rcs(interaction, business: business, handoffURL: handoffURL)
        var suggestions: [ChannelRendering.Suggestion] = []
        for suggestion in rendering.suggestions {
            switch suggestion.kind {
            case .reply:
                if let target = suggestion.target(forInteraction: interaction.id) {
                    suggestions.append(.init(text: suggestion.text, action: .reply(target)))
                }
            case .openURL:
                if let url = suggestion.url { suggestions.append(.init(text: suggestion.text, action: .openURL(url))) }
            }
        }
        return ChannelRendering(text: rendering.text, suggestions: suggestions, isSecureHandoff: rendering.isSecureHandoff)
    }

    public func send(_ message: OutboundChannelMessage, to phone: PhoneNumber, environment: ChannelEnvironment) async throws -> ChannelSendResult {
        guard let provider else { throw ChannelError.notEnabled }
        return try await provider.send(message, to: phone, reference: environment.reference)
    }

    public func verifyInbound(_ request: ProviderWebhookRequest) -> Bool { provider?.verifyWebhook(request) ?? false }

    public func parseInbound(_ request: ProviderWebhookRequest) throws -> [ChannelInboundEvent] {
        guard let provider else { throw ChannelError.notEnabled }
        return try provider.parseInbound(request)
    }
}
