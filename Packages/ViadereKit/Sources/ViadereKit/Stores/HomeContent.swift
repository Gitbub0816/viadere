import Foundation
import ViadereCore

/// What the calm home screen shows, in priority order: things that need the person, then what's in progress,
/// then recent businesses.
public struct HomeContent: Equatable, Sendable {
    public var pending: [InteractionEnvelope]
    public var statuses: [InteractionEnvelope]
    public var recent: [Relationship]

    public static let empty = HomeContent(pending: [], statuses: [], recent: [])
    public var isEmpty: Bool { pending.isEmpty && statuses.isEmpty && recent.isEmpty }

    public static func build(interactions: [InteractionEnvelope], relationships: [Relationship], now: Date,
                             recentLimit: Int = 6, statusLimit: Int = 3) -> HomeContent {
        let pending = interactions
            .filter { $0.status == .pending && !$0.interaction.isExpired(at: now) && isActionable($0.interaction.kind) }
            .sorted { lhs, rhs in
                let l = rank(lhs.interaction), r = rank(rhs.interaction)
                if l != r { return l > r }
                return lhs.interaction.expiresAt < rhs.interaction.expiresAt
            }
        let statuses = interactions
            .filter { envelope in
                guard case .status(let payload) = envelope.interaction.payload, !envelope.interaction.isExpired(at: now) else { return false }
                return !(payload.liveActivity?.isTerminal ?? true)
            }
            .sorted { $0.interaction.createdAt > $1.interaction.createdAt }
        var lastActivity: [BusinessID: Date] = [:]
        for envelope in interactions {
            lastActivity[envelope.business.id] = max(lastActivity[envelope.business.id] ?? .distantPast, envelope.interaction.createdAt)
        }
        let recent = relationships
            .filter { $0.status == .active }
            .sorted { (lastActivity[$0.business.id] ?? $0.connectedAt) > (lastActivity[$1.business.id] ?? $1.connectedAt) }
        return HomeContent(pending: pending, statuses: Array(statuses.prefix(statusLimit)), recent: Array(recent.prefix(recentLimit)))
    }

    static func isActionable(_ kind: InteractionKind) -> Bool {
        switch kind {
        case .authenticate, .authorize, .confirm, .choose, .acknowledge, .reply: true
        case .status, .reward, .ticket, .message, .unknown: false
        }
    }

    /// Security first, then Trust-Engine-clamped priority.
    static func rank(_ interaction: Interaction) -> Int {
        let base = interaction.kind.isSecuritySensitive ? 100 : 0
        switch interaction.effectivePriority {
        case .urgent: return base + 3
        case .high: return base + 2
        case .normal: return base + 1
        case .low: return base
        }
    }
}
