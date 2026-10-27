import Foundation

/// Message direction relative to the consumer.
public enum MessageDirection: String, Codable, Sendable {
    /// Consumer → business.
    case consumerToBusiness
    /// Business → consumer.
    case businessToConsumer
    /// Viadere system notice inside a conversation.
    case system
}

/// Who authored a message, as shown to the consumer.
public struct MessageAttribution: Codable, Sendable, Hashable {
    public enum SenderType: String, Codable, Sendable { case consumer, business, agent, automated, viadere }

    public var senderType: SenderType
    /// Display name (verified business name, or "You").
    public var displayName: String
    /// Optional agent name supplied by the business (≤ 40).
    public var agentName: String?

    public init(senderType: SenderType, displayName: String, agentName: String? = nil) {
        self.senderType = senderType
        self.displayName = displayName
        self.agentName = agentName
    }
}

/// Delivery status of a message.
public enum DeliveryStatus: String, Codable, Sendable {
    case queued, sent, delivered, read, failed
}

/// One message within a business-scoped conversation session.
public struct ConversationMessage: Codable, Sendable, Hashable, Identifiable {
    public var id: MessageID
    public var sessionId: SessionID
    public var businessId: BusinessID
    public var direction: MessageDirection
    public var attribution: MessageAttribution
    public var body: String
    public var channel: Channel
    public var createdAt: Date
    public var deliveredAt: Date?
    public var readAt: Date?
    public var deliveryStatus: DeliveryStatus
    /// Linked structured interaction, if any.
    public var interactionId: InteractionID?

    public init(id: MessageID, sessionId: SessionID, businessId: BusinessID, direction: MessageDirection,
                attribution: MessageAttribution, body: String, channel: Channel, createdAt: Date,
                deliveredAt: Date? = nil, readAt: Date? = nil, deliveryStatus: DeliveryStatus, interactionId: InteractionID? = nil) {
        self.id = id
        self.sessionId = sessionId
        self.businessId = businessId
        self.direction = direction
        self.attribution = attribution
        self.body = body
        self.channel = channel
        self.createdAt = createdAt
        self.deliveredAt = deliveredAt
        self.readAt = readAt
        self.deliveryStatus = deliveryStatus
        self.interactionId = interactionId
    }
}

/// A business-scoped conversation (one per business per consumer session).
public struct ConversationSummary: Codable, Sendable, Hashable, Identifiable {
    public enum State: String, Codable, Sendable { case open, parked, closed }

    public var id: SessionID
    public var business: BusinessSummary
    public var state: State
    public var lastMessagePreview: String?
    public var lastMessageAt: Date?
    public var unreadCount: Int

    public init(id: SessionID, business: BusinessSummary, state: State, lastMessagePreview: String? = nil,
                lastMessageAt: Date? = nil, unreadCount: Int = 0) {
        self.id = id
        self.business = business
        self.state = state
        self.lastMessagePreview = lastMessagePreview
        self.lastMessageAt = lastMessageAt
        self.unreadCount = unreadCount
    }
}
