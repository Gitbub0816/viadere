import Foundation

/// Top-level destinations (spec C1.2; plan section 4.8 variant A, the recommended default pending the Phase 0 usability decision D6.1/O1).
public enum OrganizationDestination: String, Sendable, Codable, CaseIterable, Hashable {
    case messages, alerts, benefits, businesses
    /// Secondary (top-bar account button), not a tab, in variant A.
    case settings

    /// The stable primary bar. Never one tab per business (spec C8.1): this list does not depend on how many businesses exist.
    public static let primary: [OrganizationDestination] = [.messages, .alerts, .benefits, .businesses]
    public static let secondary: [OrganizationDestination] = [.settings]

    /// Whether the business selector filters this destination (Settings is global; per-business settings live on the business home).
    public var isFilteredByContext: Bool { self != .settings }
}

/// Segments of the Alerts destination: Activity lives under Alerts as "History" (variant A).
public enum AlertsSegment: String, Sendable, Codable, CaseIterable, Hashable {
    case needsYou = "needs_you"
    case history
}

/// The customer's business context: All (default) or one business (spec C1.2, C3.5). Client state, persisted locally for convenience and
/// sent only as a **filter**; the server validates it against the caller's relationships and answers `404` for any other business.
public enum OrganizationContext: Sendable, Hashable, Codable {
    case all
    case business(BusinessID)

    public static let `default` = OrganizationContext.all

    /// The `business_id` query filter, `nil` for All.
    public var businessFilter: BusinessID? {
        if case .business(let id) = self { return id }
        return nil
    }

    private enum CodingKeys: String, CodingKey { case scope, businessId = "business_id" }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        switch try c.decode(String.self, forKey: .scope) {
        case "all": self = .all
        case "business": self = .business(try c.decode(BusinessID.self, forKey: .businessId))
        default: self = .all
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .all: try c.encode("all", forKey: .scope)
        case .business(let id):
            try c.encode("business", forKey: .scope)
            try c.encode(id, forKey: .businessId)
        }
    }
}

/// What the screen shows right now: the saved context, plus an optional **temporary** business shown because a push, deep link, approval
/// or verification for another business was opened ("Showing {B}" banner with an explicit "Back to all", plan section 4.8, C9.7).
public struct OrganizationContextState: Sendable, Hashable {
    /// The user's chosen context. Only an explicit user selection changes it.
    public private(set) var saved: OrganizationContext
    /// A business shown without changing `saved`.
    public private(set) var temporary: BusinessID?
    /// While a security-sensitive flow (approval, verification, Loop confirmation) is open, the context does not change at all.
    public private(set) var sensitiveFlowOpen: Bool

    public init(saved: OrganizationContext = .default) {
        self.saved = saved
        temporary = nil
        sensitiveFlowOpen = false
    }

    /// The context lists are filtered by.
    public var effective: OrganizationContext { temporary.map(OrganizationContext.business) ?? saved }

    /// Whether the "Showing {business}" banner (with "Back to all") is visible.
    public var showsTemporaryBanner: Bool { temporary != nil }

    public enum ChangeResult: Sendable, Hashable {
        case changed
        /// Refused: a security-sensitive flow is open; the context never switches silently underneath it.
        case deferredSensitiveFlow
        /// Refused: the business is not one the customer is connected to (a deep link cannot select a foreign business).
        case notConnected
        case unchanged
    }

    /// An explicit user selection from the selector.
    public mutating func select(_ context: OrganizationContext, connected: Set<BusinessID>) -> ChangeResult {
        if sensitiveFlowOpen { return .deferredSensitiveFlow }
        if case .business(let id) = context, !connected.contains(id) { return .notConnected }
        if context == saved && temporary == nil { return .unchanged }
        saved = context
        temporary = nil
        return .changed
    }

    /// A push or deep link for `business` was opened. Shows it temporarily without rewriting the saved context.
    public mutating func open(itemFrom business: BusinessID, connected: Set<BusinessID>) -> ChangeResult {
        if sensitiveFlowOpen { return .deferredSensitiveFlow }
        guard connected.contains(business) else { return .notConnected }
        if saved == .business(business) {
            if temporary == nil { return .unchanged }
            temporary = nil
            return .changed
        }
        if temporary == business { return .unchanged }
        temporary = business
        return .changed
    }

    /// "Back to all" / dismissing the banner: drops the temporary business and returns to the saved context.
    public mutating func returnToSaved() -> ChangeResult {
        if sensitiveFlowOpen { return .deferredSensitiveFlow }
        guard temporary != nil else { return .unchanged }
        temporary = nil
        return .changed
    }

    /// The approval / verification sheet always shows its **own** issuing business, whatever the context (C9.7); opening it freezes the
    /// context until it closes.
    public mutating func beginSensitiveFlow() { sensitiveFlowOpen = true }
    public mutating func endSensitiveFlow() { sensitiveFlowOpen = false }

    /// A relationship ended: a context naming that business falls back to All.
    public mutating func businessDisconnected(_ business: BusinessID) {
        if saved == .business(business) { saved = .all }
        if temporary == business { temporary = nil }
    }
}
