import Foundation

/// An actionable item in the durable sense of spec v4 C5: **the server record is the source of truth**, a push is only a best-effort hint, and an
/// expired item is never actionable. Approval requests and link sessions carry one so the app can list, dedupe and age them without a separate
/// Alerts service (the Alerts pane itself is a later phase).
public struct AlertDescriptor: Codable, Sendable, Hashable {
    /// Stable server event id (`alr_…`), the same in every push and every fetch of this item: the app dedupes repeated pushes on it.
    public var eventId: String
    public var category: AlertCategory
    /// The issuer (the verified business the item is from).
    public var businessId: BusinessID
    public var urgency: AlertUrgency
    public var status: AlertStatus
    public var expiresAt: Date?
    /// The registered action this alert asks for (`ActionRegistry`), when there is one.
    public var action: ActionID?
    /// Derived on the server at the moment of the response: pending and not expired. The app re-checks the expiry with its own clock.
    public var actionable: Bool

    public init(eventId: String, category: AlertCategory, businessId: BusinessID, urgency: AlertUrgency, status: AlertStatus, expiresAt: Date?,
                action: ActionID?, now: Date) {
        self.eventId = eventId
        self.category = category
        self.businessId = businessId
        self.urgency = urgency
        self.status = status
        self.expiresAt = expiresAt
        self.action = action
        actionable = status == .pending && (expiresAt.map { $0 > now } ?? true)
    }

    /// Whether the app may still offer the action at `now` (never for an expired or finished item, whatever a push said).
    public func isActionable(at now: Date) -> Bool { actionable && status == .pending && (expiresAt.map { $0 > now } ?? true) }

    /// The event id of a server record: `alr_` + the first 32 hex characters of `SHA-256("VIADERE-ALERT-V1\n" ‖ kind ‖ "\n" ‖ id)`. Stable, opaque,
    /// and not the record id itself.
    public static func eventId(kind: String, id: UUID) -> String {
        "alr_" + String(SecureToken.sha256Hex(Data("VIADERE-ALERT-V1\n\(kind)\n\(id.uuidString.lowercased())".utf8)).prefix(32))
    }

    enum CodingKeys: String, CodingKey {
        case eventId = "event_id", category, businessId = "business_id", urgency, status, expiresAt = "expires_at", action, actionable
    }
}

public enum AlertCategory: String, Codable, Sendable, Hashable {
    case approval
    case linkConfirmation = "link_confirmation"
    case securityNotice = "security_notice"
    /// A business interaction that asks for an answer (confirm, choose, acknowledge, reply, sign-in, authorize).
    case request
    /// An informational business item (status update, reward, ticket).
    case update
    /// A first-party identity or age verification request (Verify).
    case verification
    case unknown

    public init(from decoder: any Decoder) throws {
        self = AlertCategory(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
    }
}

public enum AlertUrgency: String, Codable, Sendable, Hashable {
    case normal
    case timeSensitive = "time_sensitive"
    case critical
    case unknown

    public init(from decoder: any Decoder) throws {
        self = AlertUrgency(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
    }

    /// The urgency of an item of `risk`.
    public init(risk: ActionRisk) {
        switch risk {
        case .high: self = .critical
        case .medium: self = .timeSensitive
        case .low, .unknown: self = .normal
        }
    }
}

public enum AlertStatus: String, Codable, Sendable, Hashable {
    case pending, completed, expired, cancelled
    case unknown

    public init(from decoder: any Decoder) throws {
        self = AlertStatus(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
    }
}
