import Fluent
import Foundation
import ViadereCore

/// Whether a phone can receive a channel's rich features.
public enum ChannelCapability: Sendable, Equatable {
    case capable
    case incapable
    /// The provider could not tell (error, timeout). Treated as "try, then fall back".
    case unknown
}

/// One tappable element of an outbound rich message. Reply suggestions carry an **opaque token** — never an
/// interaction id, option id or decision — and open-URL suggestions carry a `/h/{token}` handoff link.
public struct OutboundSuggestion: Sendable, Equatable {
    public enum Kind: Sendable, Equatable { case reply, openURL }
    public var kind: Kind
    /// ≤ 25 characters.
    public var text: String
    public var postbackToken: String?
    public var url: URL?

    public static func reply(_ text: String, token: String) -> OutboundSuggestion {
        OutboundSuggestion(kind: .reply, text: text, postbackToken: token, url: nil)
    }
    public static func openURL(_ text: String, url: URL) -> OutboundSuggestion {
        OutboundSuggestion(kind: .openURL, text: text, postbackToken: nil, url: url)
    }
}

/// A message ready for a channel transport.
public struct OutboundChannelMessage: Sendable, Equatable {
    public var text: String
    public var suggestions: [OutboundSuggestion]
    public init(text: String, suggestions: [OutboundSuggestion] = []) {
        self.text = text
        self.suggestions = suggestions
    }
}

public struct ChannelSendResult: Sendable, Equatable {
    public var providerMessageId: String
    public init(providerMessageId: String) { self.providerMessageId = providerMessageId }
}

public enum ChannelError: Error, Sendable, Equatable {
    /// The adapter is switched off (no provider configured / feature flag off).
    case notEnabled
    /// The recipient cannot receive this channel; use the fallback.
    case notCapable
    /// The adapter is a placeholder with no sending implementation (Apple Messages for Business).
    case notImplemented
    case transient(String)
    case permanent(String)
}

/// Delivery receipt statuses reported by a rich-channel provider.
public enum ChannelReceiptStatus: String, Sendable, Equatable { case delivered, read, failed }

/// A verified, parsed inbound event from a channel provider.
public enum ChannelInboundEvent: Sendable, Equatable {
    /// Free text typed by the user.
    case text(from: PhoneNumber, text: String, messageId: String, receivedAt: Date)
    /// A tap on a suggested reply. `data` is the opaque token we sent; it is *not* authentication.
    case postback(from: PhoneNumber, data: String, messageId: String, receivedAt: Date)
    /// A receipt for a message we sent (`providerMessageId` is the id the provider returned from `send`).
    case receipt(providerMessageId: String, status: ChannelReceiptStatus, errorCode: String?)
}

/// What a transport needs from the server when sending (SMS uses the ordered, durable queue).
public struct ChannelEnvironment: Sendable {
    let db: any Database
    let ctx: ServerContext
    /// Stable reference of our outbox row, for provider correlation.
    let reference: String
    /// The message contains a secret (a handoff link) and must be wiped after sending.
    let sensitive: Bool
    /// Business the message is metered against / attributed to.
    let businessId: BusinessID?
}

/// A rich or plain messaging channel. SMS, RCS and (future) Apple Messages for Business all implement this so
/// the router can render a typed interaction, check capability, send and receive uniformly.
///
/// Invariants every adapter must preserve (the router and `ChannelRenderer` enforce them; adapters must not
/// weaken them):
/// * A security-sensitive interaction (`authenticate`, `authorize`, unknown kinds, or any interaction whose
///   `RequiredAssurance` exceeds `.channelReply`) is **never** rendered as an actionable reply. It becomes a
///   secure handoff link (`/h/{token}`).
/// * Replies on a text channel are unauthenticated (`ProvidedAssurance.unauthenticatedReply`).
public protocol ChannelAdapter: Sendable {
    var channel: DeliveryChannel { get }
    /// Master switch (configuration / feature flag). A disabled adapter is never selected.
    var isEnabled: Bool { get }
    func capability(for phone: PhoneNumber) async -> ChannelCapability
    /// Renders with `ChannelRenderer`. `handoffURL` is only non-nil when a secure handoff is needed.
    func render(_ interaction: Interaction, business: BusinessSummary, handoffURL: URL?) -> ChannelRendering
    func send(_ message: OutboundChannelMessage, to phone: PhoneNumber, environment: ChannelEnvironment) async throws -> ChannelSendResult
    /// Constant-time authenticity check of an inbound provider webhook.
    func verifyInbound(_ request: ProviderWebhookRequest) -> Bool
    func parseInbound(_ request: ProviderWebhookRequest) throws -> [ChannelInboundEvent]
}

/// Channel-neutral rendering: text plus suggestions whose reply targets stay **server-side**.
public struct ChannelRendering: Sendable, Equatable {
    public struct Suggestion: Sendable, Equatable {
        public enum Action: Sendable, Equatable {
            case reply(RCSPostbackTarget)
            case openURL(URL)
        }
        public var text: String
        public var action: Action
    }

    public var text: String
    public var suggestions: [Suggestion]
    public var isSecureHandoff: Bool
    /// Encoded length information for SMS metering (segments); 0 for non-SMS.
    public var smsSegments: Int

    public init(text: String, suggestions: [Suggestion] = [], isSecureHandoff: Bool, smsSegments: Int = 0) {
        self.text = text
        self.suggestions = suggestions
        self.isSecureHandoff = isSecureHandoff
        self.smsSegments = smsSegments
    }
}

/// The adapters available to the router.
public struct ChannelRegistry: Sendable {
    public let sms: any ChannelAdapter
    public let rcs: any ChannelAdapter
    public let appleMessagesForBusiness: any ChannelAdapter

    public init(sms: any ChannelAdapter, rcs: any ChannelAdapter, appleMessagesForBusiness: any ChannelAdapter) {
        self.sms = sms
        self.rcs = rcs
        self.appleMessagesForBusiness = appleMessagesForBusiness
    }

    public func adapter(for channel: DeliveryChannel) -> (any ChannelAdapter)? {
        switch channel {
        case .sms: sms
        case .rcs: rcs
        case .appleMessagesForBusiness: appleMessagesForBusiness
        default: nil
        }
    }
}

// MARK: - SMS

/// SMS as a `ChannelAdapter`. Sending goes through the ordered, retrying, STOP-aware `OutboundSMS` queue.
/// Numbered replies are *not* wired for interaction renderings (the gateway engine owns menu state), so any
/// interaction that needs an answer is rendered as a secure handoff — see `ChannelRouter.smsRendering`.
public struct SMSChannelAdapter: ChannelAdapter {
    private let provider: any SMSProvider

    public init(provider: any SMSProvider) { self.provider = provider }

    public var channel: DeliveryChannel { .sms }
    public var isEnabled: Bool { true }

    public func capability(for phone: PhoneNumber) async -> ChannelCapability { .capable }

    public func render(_ interaction: Interaction, business: BusinessSummary, handoffURL: URL?) -> ChannelRendering {
        let sms = ChannelRenderer.sms(interaction, business: business, handoffURL: handoffURL)
        return ChannelRendering(text: sms.body, suggestions: [], isSecureHandoff: sms.isSecureHandoff, smsSegments: sms.encoding.segments)
    }

    public func send(_ message: OutboundChannelMessage, to phone: PhoneNumber, environment: ChannelEnvironment) async throws -> ChannelSendResult {
        let row = try await OutboundSMS(db: environment.db, ctx: environment.ctx)
            .enqueue(to: phone, body: message.text, sensitive: environment.sensitive)
        return ChannelSendResult(providerMessageId: "sms-queue:" + (row.id?.uuidString.lowercased() ?? ""))
    }

    public func verifyInbound(_ request: ProviderWebhookRequest) -> Bool { provider.verifyWebhook(request) }

    public func parseInbound(_ request: ProviderWebhookRequest) throws -> [ChannelInboundEvent] {
        let sms = try provider.parseInbound(request)
        return [.text(from: sms.from, text: sms.text, messageId: sms.providerMessageId, receivedAt: sms.receivedAt)]
    }
}

// MARK: - Apple Messages for Business (placeholder)

/// **Placeholder only — no functional sending.**
///
/// Policy dependency (docs/COMPLETE-PRODUCT-SPEC.md §14, MESSAGING-GATEWAY-SPEC "Apple/RCS caveats"): Apple has
/// not approved or confirmed a single Viadere AMB identity as a switchboard for unrelated merchants, and AMB
/// requires an approved Messaging Service Provider. Until Apple's **written** approval of multi-merchant
/// brokerage is on file there must be no multi-merchant brokerage over AMB. This type therefore:
/// * is disabled unless `FEATURE_APPLE_MESSAGES_FOR_BUSINESS=true`, and even then
/// * reports every phone as `.incapable`, refuses to render actionable content, never sends, and
/// * rejects every inbound webhook.
/// Replacing it with a real adapter is a deliberate engineering step after the policy gate is cleared.
public struct AppleMessagesForBusinessAdapter: ChannelAdapter {
    public let flagEnabled: Bool

    public init(flagEnabled: Bool) { self.flagEnabled = flagEnabled }

    public var channel: DeliveryChannel { .appleMessagesForBusiness }
    /// Only meaningful for diagnostics; the router never selects this adapter (`capability` is always `.incapable`).
    public var isEnabled: Bool { flagEnabled }

    public func capability(for phone: PhoneNumber) async -> ChannelCapability { .incapable }

    public func render(_ interaction: Interaction, business: BusinessSummary, handoffURL: URL?) -> ChannelRendering {
        // Even the placeholder honours the no-downgrade rule: the only output is a handoff notice.
        ChannelRendering(text: "[\(SMSEncoding.field(business.displayName, maxLength: 40))]: Open the Viadere app to continue.",
                         suggestions: [], isSecureHandoff: true)
    }

    public func send(_ message: OutboundChannelMessage, to phone: PhoneNumber, environment: ChannelEnvironment) async throws -> ChannelSendResult {
        throw flagEnabled ? ChannelError.notImplemented : ChannelError.notEnabled
    }

    public func verifyInbound(_ request: ProviderWebhookRequest) -> Bool { false }
    public func parseInbound(_ request: ProviderWebhookRequest) throws -> [ChannelInboundEvent] { throw ChannelError.notImplemented }
}
