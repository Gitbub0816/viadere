import Foundation

/// Where an alert comes from (plan section 4.2: a read model over durable rows, not a table).
public enum AlertSource: String, Sendable, Codable, CaseIterable, Hashable {
    case interaction
    case approveRequest = "approve_request"
    case verification
    case securityNotice = "security_notice"
    case loopTask = "loop_task"
    /// A business asks for profile fields (docs/PROFILES.md).
    case profileRequest = "profile_request"
}

// `AlertStatus` is the durable alert status of `Models/Alert.swift` (unknown values decode as `.unknown`, which is never actionable).

/// Alert list filters (spec C5.2).
public enum AlertStatusFilter: String, Sendable, Codable, CaseIterable, Hashable {
    case pending, completed, expired
}

/// Benefits filters (spec C6.1).
public enum BenefitFilter: String, Sendable, Codable, CaseIterable, Hashable {
    case available, saved, redeemed, expired, eligible
}

/// One entry of the Alerts destination (spec D2.7). `alertId` is `"{source}:{id}"`, stable across pushes and syncs (dedupe key).
public struct AlertItem: Sendable, Hashable, Codable, Identifiable {
    public var id: String { alertId }
    public var alertId: String
    public var source: AlertSource
    public var businessId: BusinessID?
    public var purpose: InteractionPurpose
    public var status: AlertStatus
    public var expiresAt: Date?
    /// Whether answering it is a customer action (approve, verify, respond).
    public var actionRequired: Bool
    public var updatedAt: Date

    enum CodingKeys: String, CodingKey {
        case source, purpose, status
        case alertId = "alert_id"
        case businessId = "business_id"
        case expiresAt = "expires_at"
        case actionRequired = "action_required"
        case updatedAt = "updated_at"
    }

    public init(source: AlertSource, sourceId: String, businessId: BusinessID?, purpose: InteractionPurpose, status: AlertStatus, expiresAt: Date?,
                actionRequired: Bool, updatedAt: Date) {
        alertId = "\(source.rawValue):\(sourceId)"
        self.source = source
        self.businessId = businessId
        self.purpose = purpose
        self.status = status
        self.expiresAt = expiresAt
        self.actionRequired = actionRequired
        self.updatedAt = updatedAt
    }
}

/// Pure alert rules shared by the server read model and the app (spec C5.3–C5.6).
public enum AlertRules {
    /// Whether the item may show actions. **Expired items are never actionable**, whatever their stored status (a stale cache or a clock
    /// running ahead of the last sync cannot make them actionable); nor is anything from a business that is not verified.
    public static func isActionable(_ item: AlertItem, now: Date, businessStatus: VerificationStatus?) -> Bool {
        guard item.actionRequired, item.status == .pending else { return false }
        if let expiry = item.expiresAt, expiry <= now { return false }
        if item.businessId != nil, businessStatus != .verified { return false }
        return true
    }

    /// The status a list shows: a pending item whose expiry passed is shown as expired.
    public static func displayStatus(_ item: AlertItem, now: Date) -> AlertStatus {
        if item.status == .pending, let expiry = item.expiresAt, expiry <= now { return .expired }
        return item.status
    }

    /// Context and filter matching for one item (the server applies the same rule in SQL; the client re-checks cached items).
    public static func matches(_ item: AlertItem, context: OrganizationContext, status: AlertStatusFilter?, now: Date) -> Bool {
        if let business = context.businessFilter, item.businessId != business { return false }
        guard let status else { return true }
        switch (status, displayStatus(item, now: now)) {
        case (.pending, .pending), (.completed, .completed), (.expired, .expired): return true
        default: return false
        }
    }
}

/// Per-business mute (plan section 4.8 "Per-business settings"). Mute changes **interruption** only, never presence in Alerts, and can
/// never touch security, account-service or action-required items.
public enum MuteLevel: String, Sendable, Codable, CaseIterable, Hashable {
    case none
    case promotional
    case allNonEssential = "all_non_essential"
}

public enum MutePolicy {
    /// Whether a notification may be delivered silently because of mute.
    public static func silences(_ level: MuteLevel, purpose: InteractionPurpose, actionRequired: Bool) -> Bool {
        if !purpose.isRevocable || actionRequired { return false }
        switch level {
        case .none: return false
        case .promotional: return purpose == .marketing || purpose == .rewards
        case .allNonEssential: return purpose == .marketing || purpose == .rewards || purpose == .support || purpose == .transactional
        }
    }

    /// Mute never removes an item from the Alerts list.
    public static func hidesFromAlerts(_ level: MuteLevel) -> Bool { false }
}

/// Bounded seen-set of server event ids for push dedupe (spec C5.4). A repeated push for the same `alert_id` / event id is not presented
/// twice; the alert list, not the push, stays the source of truth (C5.6).
public struct SeenEventSet: Sendable, Hashable {
    public let capacity: Int
    private var order: [String] = []
    private var members: Set<String> = []

    public init(capacity: Int = 512) { self.capacity = max(1, capacity) }

    public var count: Int { members.count }

    public func contains(_ eventId: String) -> Bool { members.contains(eventId) }

    /// Records `eventId`. Returns `true` the first time (present the notification), `false` for a duplicate. Oldest ids are evicted
    /// first once `capacity` is reached.
    public mutating func insert(_ eventId: String) -> Bool {
        guard !eventId.isEmpty, eventId.utf8.count <= 256 else { return false }
        if members.contains(eventId) { return false }
        members.insert(eventId)
        order.append(eventId)
        if order.count > capacity {
            let evicted = order.removeFirst()
            members.remove(evicted)
        }
        return true
    }
}
