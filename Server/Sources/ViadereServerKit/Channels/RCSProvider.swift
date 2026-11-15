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
///   With a rich form, `contentMessage` carries `richCard` instead of `text` (mutually exclusive in RBM):
///   `{"standaloneCard":{"cardOrientation":"VERTICAL","cardContent":{"title","description"?,"suggestions":[{"reply":…}]}}}` or
///   `{"carouselCard":{"cardWidth":"MEDIUM","cardContents":[…]}}` plus `"fallback"` (the plain text) and no message-level chips.
///   Cards carry no media and never an `openUrlAction`; a 4xx (not 429) answer to a rich send is resent once as plain text and chips.
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

    /// A rich card the transport refuses to encode (a URL suggestion, a missing token, too many suggestions or cards).
    struct RichCardRefused: Error {}

    /// The RBM `suggestions` array of the plain message: replies and (never produced by the renderer) open-URL actions.
    static func chipJSON(_ suggestions: [OutboundSuggestion]) -> [[String: Any]] {
        var out: [[String: Any]] = []
        for suggestion in suggestions.prefix(11) {
            switch suggestion.kind {
            case .reply:
                guard let token = suggestion.postbackToken else { continue }
                out.append(["reply": ["text": suggestion.text, "postbackData": token]])
            case .openURL:
                guard let url = suggestion.url else { continue }
                out.append(["action": ["text": suggestion.text, "openUrlAction": ["url": url.absoluteString]]])
            }
        }
        return out
    }

    /// One RBM `cardContent`: title, optional description, at most four reply suggestions and **no media**. Any suggestion that is not a
    /// reply with a token is refused (never an `openUrlAction` from card content, §2.89 decision 9).
    static func cardContentJSON(_ card: OutboundCard) throws -> [String: Any] {
        guard !card.title.isEmpty, card.suggestions.count <= ChannelRenderer.maxRCSCardSuggestions else { throw RichCardRefused() }
        var replies: [[String: Any]] = []
        for suggestion in card.suggestions {
            guard suggestion.kind == .reply, suggestion.url == nil, let token = suggestion.postbackToken else { throw RichCardRefused() }
            replies.append(["reply": ["text": suggestion.text, "postbackData": token]])
        }
        var content: [String: Any] = ["title": card.title]
        if let description = card.description { content["description"] = description }
        if !replies.isEmpty { content["suggestions"] = replies }
        return content
    }

    /// The RBM `contentMessage` for `message`: `richCard` (standalone or carousel) when the message has a rich form and it encodes,
    /// otherwise `text` with chips. `richCard` and `text` are mutually exclusive in RBM. A carousel carries no message-level chips (each
    /// card has its option's chip) and sets `fallback` to the plain text; a standalone card keeps the message's chips.
    static func contentJSON(_ message: OutboundChannelMessage, rich: Bool) -> (content: [String: Any], isRich: Bool) {
        let chips = chipJSON(message.suggestions)
        if rich, let carousel = message.carousel {
            if ChannelRenderer.rcsCarouselCards.contains(carousel.count), let cards = try? carousel.map(cardContentJSON) {
                return (["richCard": ["carouselCard": ["cardWidth": RCSCardWidth.medium.rawValue, "cardContents": cards]], "fallback": message.text], true)
            }
        } else if rich, let card = message.card, let content = try? cardContentJSON(card) {
            var out: [String: Any] = ["richCard": ["standaloneCard": ["cardOrientation": RCSCardOrientation.vertical.rawValue, "cardContent": content]]]
            if !chips.isEmpty { out["suggestions"] = chips }
            return (out, true)
        }
        var out: [String: Any] = ["text": message.text]
        if !chips.isEmpty { out["suggestions"] = chips }
        return (out, false)
    }

    public func send(_ message: OutboundChannelMessage, to phone: PhoneNumber, reference: String) async throws -> ChannelSendResult {
        let first = Self.contentJSON(message, rich: true)
        let response = try await post(first.content, to: phone, messageId: reference)
        // The provider refused the rich card (the phone or agent lacks the rich-card feature, or any other 4xx): resend the same message
        // as plain text and chips, with the same tokens. The SMS fallback rules then apply to the plain send exactly as before.
        if first.isRich, (400..<500).contains(response.status), response.status != 429 {
            let retry = reference + "-text"
            return try Self.result(try await post(Self.contentJSON(message, rich: false).content, to: phone, messageId: retry), reference: retry)
        }
        return try Self.result(response, reference: reference)
    }

    private func post(_ content: [String: Any], to phone: PhoneNumber, messageId: String) async throws -> RCSHTTPResponse {
        let payload: [String: Any] = ["agentId": config.agentId, "to": phone.e164, "messageId": messageId, "contentMessage": content]
        guard let body = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys, .withoutEscapingSlashes]) else {
            throw ChannelError.permanent("encode")
        }
        let url = config.baseURL.appendingPathComponent("agentMessages")
        do { return try await http.send(RCSHTTPRequest(method: "POST", url: url, headers: headers(), body: body)) } catch {
            throw ChannelError.transient("network")
        }
    }

    private static func result(_ response: RCSHTTPResponse, reference: String) throws -> ChannelSendResult {
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
    public func render(_ interaction: Interaction, business: BusinessSummary) -> ChannelRendering {
        Self.channelRendering(ChannelRenderer.rcs(interaction, business: business), interactionId: interaction.id)
    }

    /// Maps the Core rendering to the channel-neutral one. Chips and card suggestions map the same way (`.reply(target)` from
    /// `target(forInteraction:)`). A rich form is carried only if **every** card suggestion is a reply whose target parses for this
    /// interaction: a card with a URL suggestion (or anything else) is refused and only the plain message is sent.
    static func channelRendering(_ rendering: RCSRendering, interactionId: InteractionID) -> ChannelRendering {
        var suggestions: [ChannelRendering.Suggestion] = []
        for suggestion in rendering.suggestions {
            switch suggestion.kind {
            case .reply:
                if let target = suggestion.target(forInteraction: interactionId) {
                    suggestions.append(.init(text: suggestion.text, action: .reply(target)))
                }
            case .openURL:
                if let url = suggestion.url { suggestions.append(.init(text: suggestion.text, action: .openURL(url))) }
            }
        }
        func card(_ content: RCSCardContent) -> ChannelRendering.Card? {
            var replies: [ChannelRendering.Suggestion] = []
            for suggestion in content.suggestions {
                guard suggestion.kind == .reply, suggestion.url == nil, let target = suggestion.target(forInteraction: interactionId) else { return nil }
                replies.append(.init(text: suggestion.text, action: .reply(target)))
            }
            return ChannelRendering.Card(title: content.title, description: content.description, suggestions: replies)
        }
        var out = ChannelRendering(text: rendering.text, suggestions: suggestions, isSecureHandoff: rendering.isSecureHandoff)
        guard !rendering.isSecureHandoff else { return out }
        if let standalone = rendering.card { out.card = card(standalone.content) }
        if let carousel = rendering.carousel {
            let cards = carousel.cards.compactMap(card)
            if cards.count == carousel.cards.count { out.carousel = cards }
        }
        return out
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
