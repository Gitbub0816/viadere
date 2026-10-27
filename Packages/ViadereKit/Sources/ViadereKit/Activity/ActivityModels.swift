import Foundation
import ViadereCore

/// What an Activity item is about.
public enum ActivityCategory: String, Sendable, CaseIterable, Hashable {
    case order, delivery, appointment, travel, event, reservation, other

    public var title: String {
        switch self {
        case .order: "Order"
        case .delivery: "Delivery"
        case .appointment: "Appointment"
        case .travel: "Travel"
        case .event: "Event"
        case .reservation: "Reservation"
        case .other: "Update"
        }
    }

    public var symbol: String {
        switch self {
        case .order: "bag"
        case .delivery: "shippingbox"
        case .appointment: "calendar"
        case .travel: "airplane"
        case .event: "ticket"
        case .reservation: "bed.double"
        case .other: "bell"
        }
    }

    /// Filter chips on the Activity screen (reservations read as travel; other updates stay under All).
    public enum Filter: String, Sendable, CaseIterable, Hashable {
        case all, orders, appointments, travel, events
        public var title: String {
            switch self {
            case .all: "All"
            case .orders: "Orders"
            case .appointments: "Appointments"
            case .travel: "Travel"
            case .events: "Events"
            }
        }
        public func includes(_ category: ActivityCategory) -> Bool {
            switch self {
            case .all: true
            case .orders: category == .order || category == .delivery
            case .appointments: category == .appointment
            case .travel: category == .travel || category == .reservation
            case .events: category == .event
            }
        }
    }
}

/// Where an item sits in time.
public enum ActivityPhase: Int, Sendable, Comparable {
    /// Something is waiting on the person.
    case needsYou = 0
    /// Happening now (in progress, ticket valid today).
    case active = 1
    /// Scheduled for later.
    case upcoming = 2
    case past = 3

    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }
}

/// A button on an Activity item, derived from a pending interaction the business actually sent.
/// The app never invents actions: labels come from the business's `requestedActions`.
public struct ActivityAction: Identifiable, Sendable, Hashable {
    public enum Route: Sendable, Hashable {
        /// Safe to answer inline with a device-signed decision.
        case inline
        /// Changes money or identity (or is sensitive): opens the secure approval sheet.
        case secureSheet
    }

    public var id: String
    public var interactionId: InteractionID
    public var label: String
    public var decision: Decision
    public var selectedOptionIds: [String]?
    public var isPrimary: Bool
    public var route: Route
}

/// One thing in the person's life with a business (an order, an appointment, a trip, an event), merged from every
/// interaction that shares its correlation id.
public struct ActivityItem: Identifiable, Sendable, Hashable {
    public var id: String
    public var business: BusinessSummary
    public var category: ActivityCategory
    public var title: String
    public var subtitle: String?
    public var phase: ActivityPhase
    /// The date items sort by (start, event time, or latest update).
    public var date: Date
    /// Plain status words: "Preparing", "Delayed", "Check-in open", "Valid".
    public var statusText: String?
    public var isAlert: Bool
    public var progress: Double?
    public var live: LiveActivityStatus?
    /// The newest status/ticket/confirm interaction.
    public var latest: InteractionEnvelope
    /// Pending interactions the person can answer (confirm/cancel, choose a time, rebooking).
    public var pending: [InteractionEnvelope]
    public var actions: [ActivityAction]
    public var walletPassId: WalletPassID?
    public var venueNote: String?
}

public struct ActivityGroup: Identifiable, Sendable, Hashable {
    public var business: BusinessSummary
    public var items: [ActivityItem]
    public var id: BusinessID { business.id }
}

public struct ActivityContent: Sendable, Equatable {
    public var groups: [ActivityGroup]
    public static let empty = ActivityContent(groups: [])

    public var isEmpty: Bool { groups.isEmpty }
    public var allItems: [ActivityItem] { groups.flatMap(\.items) }
    public var needsYouCount: Int { allItems.filter { $0.phase == .needsYou }.count }

    public func filtered(_ filter: ActivityCategory.Filter, includePast: Bool = true) -> ActivityContent {
        let groups = groups.compactMap { group -> ActivityGroup? in
            let items = group.items.filter { filter.includes($0.category) && (includePast || $0.phase != .past) }
            return items.isEmpty ? nil : ActivityGroup(business: group.business, items: items)
        }
        return ActivityContent(groups: groups)
    }
}

extension ActivityGroup: Equatable {}
extension ActivityItem: Equatable {}

/// Builds the Activity feed. Pure: everything it needs is passed in.
public enum ActivityFeed {
    /// Interaction kinds that make up Activity. `choose` joins only as a pending action of an existing item.
    static func isActivityKind(_ kind: InteractionKind) -> Bool {
        switch kind {
        case .status, .ticket, .confirm: true
        default: false
        }
    }

    /// An answerable interaction (confirm/choose/authorize) that belongs with an item.
    static func isActionable(_ envelope: InteractionEnvelope, now: Date) -> Bool {
        guard envelope.status == .pending, !envelope.interaction.isExpired(at: now) else { return false }
        switch envelope.interaction.kind {
        case .confirm, .choose, .authorize: return true
        default: return false
        }
    }

    public static func build(interactions: [InteractionEnvelope], now: Date, pastWindow: TimeInterval = 14 * 86_400) -> ActivityContent {
        // Group by subject: the correlation id when the business supplied one, else the interaction itself.
        var buckets: [String: [InteractionEnvelope]] = [:]
        var order: [String] = []
        for envelope in interactions {
            let kind = envelope.interaction.kind
            guard isActivityKind(kind) || isActionable(envelope, now: now) else { continue }
            let key = envelope.interaction.correlationId.map { "\(envelope.business.id)|\($0)" } ?? "solo|\(envelope.id)"
            if buckets[key] == nil { order.append(key) }
            buckets[key, default: []].append(envelope)
        }

        var items: [ActivityItem] = []
        for key in order {
            guard let members = buckets[key], let item = makeItem(id: key, members: members, now: now) else { continue }
            if item.phase == .past, now.timeIntervalSince(item.date) > pastWindow { continue }
            items.append(item)
        }

        // Group by business: businesses with something that needs the person first, then by most recent item.
        var byBusiness: [BusinessID: [ActivityItem]] = [:]
        for item in items { byBusiness[item.business.id, default: []].append(item) }
        let groups = byBusiness.values.map { list -> ActivityGroup in
            ActivityGroup(business: list[0].business, items: list.sorted(by: itemOrder))
        }.sorted { lhs, rhs in
            let l = lhs.items.first, r = rhs.items.first
            let lp = l?.phase ?? .past, rp = r?.phase ?? .past
            if lp != rp { return lp < rp }
            return (l?.date ?? .distantPast) > (r?.date ?? .distantPast)
        }
        return ActivityContent(groups: groups)
    }

    /// Within a business: needs-you and active first, then upcoming (soonest first), then past (newest first).
    static func itemOrder(_ lhs: ActivityItem, _ rhs: ActivityItem) -> Bool {
        if lhs.phase != rhs.phase { return lhs.phase < rhs.phase }
        switch lhs.phase {
        case .upcoming: return lhs.date < rhs.date
        default: return lhs.date > rhs.date
        }
    }

    static func makeItem(id: String, members: [InteractionEnvelope], now: Date) -> ActivityItem? {
        let sorted = members.sorted { $0.interaction.createdAt > $1.interaction.createdAt }
        let pending = sorted.filter { isActionable($0, now: now) }
        let display = sorted.filter { isActivityKind($0.interaction.kind) }
        // Pick the headline interaction: newest status, else ticket, else confirm; fall back to the first actionable.
        let statusEnvelope = display.first { if case .status = $0.interaction.payload { return true } else { return false } }
        let ticketEnvelope = display.first { if case .ticket = $0.interaction.payload { return true } else { return false } }
        let confirmEnvelope = display.first { if case .confirm = $0.interaction.payload { return true } else { return false } }
        // Security approvals and uncorrelated questions live on Home; Activity only gathers the thing they belong to.
        guard let latest = statusEnvelope ?? ticketEnvelope ?? confirmEnvelope else { return nil }

        var live: LiveActivityStatus?
        var title = InteractionPresentation.headline(latest.interaction)
        var subtitle: String?
        var date = latest.interaction.createdAt
        var statusText: String?
        var alert = false
        var progress: Double?
        var category: ActivityCategory = .other
        var venue: String?

        if case .status(let payload) = latest.interaction.payload {
            subtitle = payload.body
            if let status = payload.liveActivity {
                live = status
                let presentation = LiveActivityPresentation(status: status, businessName: latest.business.displayName, now: now)
                statusText = presentation.detail
                alert = presentation.isAlert
                progress = presentation.progress
                switch status {
                case .order: category = .order
                case .delivery: category = .delivery
                case .flight: category = .travel
                case .appointment: category = .appointment
                }
                if let target = presentation.target { date = target }
            }
        }

        // A correlated ticket decides the category of status updates that carry no live activity, and lends its pass.
        let passId: WalletPassID?
        if case .ticket(let ticket)? = ticketEnvelope?.interaction.payload {
            passId = ticket.walletPassId
            let ticketCategory = Self.category(forTicketType: ticket.ticketType)
            if live == nil { category = ticketCategory }
            if statusEnvelope == nil || live == nil {
                if let from = ticket.validFrom { date = from }
            }
            if statusEnvelope == nil {
                title = ticket.title
                subtitle = ticket.holderName.map { "For \($0)" }
            } else if live == nil {
                // Schedule changes and venue notes ride on a status with no live activity.
                venue = statusEnvelope.flatMap { envelope -> String? in
                    if case .status(let p) = envelope.interaction.payload { return p.body }
                    return nil
                }
            }
        } else {
            passId = nil
        }
        if category == .other, case .confirm(let confirm)? = confirmEnvelope?.interaction.payload, confirm.scheduledAt != nil {
            category = .appointment
        }
        if case .confirm(let confirm) = latest.interaction.payload, let at = confirm.scheduledAt {
            date = at
            subtitle = confirm.details
        }

        // Phase.
        var phase: ActivityPhase
        if !pending.isEmpty {
            phase = .needsYou
        } else if let live {
            phase = live.isTerminal ? .past : .active
        } else if case .ticket(let ticket)? = ticketEnvelope?.interaction.payload {
            if let until = ticket.validUntil, until < now { phase = .past }
            else if let from = ticket.validFrom, from > now { phase = .upcoming }
            else { phase = .active }
        } else if latest.interaction.isExpired(at: now) || latest.status != .pending && latest.status != .delivered {
            phase = .past
        } else if date > now {
            phase = .upcoming
        } else {
            phase = .active
        }
        // A live item with nothing pending can still be upcoming (an appointment that's hours away).
        if phase == .active, let live, case .appointment(let a) = live, a.stage == .upcoming, a.startsAt.timeIntervalSince(now) > 3_600 { phase = .upcoming }

        if statusText == nil {
            switch phase {
            case .needsYou: statusText = "Needs you"
            case .upcoming: statusText = "Upcoming"
            case .active: statusText = category == .event ? "Valid" : nil
            case .past: statusText = "Done"
            }
        }

        let actions = pending.flatMap { makeActions(for: $0, category: category) }
        return ActivityItem(
            id: id, business: latest.business, category: category, title: title, subtitle: subtitle, phase: phase, date: date,
            statusText: statusText, isAlert: alert, progress: progress, live: live, latest: latest, pending: pending, actions: actions,
            walletPassId: passId, venueNote: venue)
    }

    static func category(forTicketType type: String) -> ActivityCategory {
        switch type.lowercased() {
        case "boarding_pass", "flight", "boarding": .travel
        case "event", "admission", "concert", "show": .event
        case "reservation", "hotel", "booking": .reservation
        default: .event
        }
    }

    // MARK: Actions

    static func makeActions(for envelope: InteractionEnvelope, category: ActivityCategory) -> [ActivityAction] {
        let interaction = envelope.interaction
        let route = ActivityActionRouter.route(for: interaction, category: category)
        func label(_ role: ActionRole, fallback: String) -> String {
            interaction.requestedActions.first { $0.role == role }?.label ?? fallback
        }
        let base = interaction.id.description
        switch interaction.payload {
        case .confirm:
            return [
                ActivityAction(id: base + ".confirm", interactionId: interaction.id, label: label(.confirm, fallback: "Confirm"),
                               decision: .confirm, selectedOptionIds: nil, isPrimary: true, route: route),
                ActivityAction(id: base + ".decline", interactionId: interaction.id, label: label(.decline, fallback: "Cancel"),
                               decision: .decline, selectedOptionIds: nil, isPrimary: false, route: route),
            ]
        case .choose(let choose) where !choose.allowsMultiple:
            return choose.options.map {
                ActivityAction(id: base + "." + $0.id, interactionId: interaction.id, label: $0.label, decision: .select,
                               selectedOptionIds: [$0.id], isPrimary: false, route: route)
            }
        case .authorize:
            // Money: one entry point, always the secure sheet.
            return [ActivityAction(id: base + ".review", interactionId: interaction.id,
                                   label: label(.approve, fallback: "Review"), decision: .approve, selectedOptionIds: nil,
                                   isPrimary: true, route: .secureSheet)]
        default:
            return [ActivityAction(id: base + ".open", interactionId: interaction.id, label: "Open", decision: .acknowledge,
                                   selectedOptionIds: nil, isPrimary: true, route: .secureSheet)]
        }
    }
}

/// Decides whether an action can be answered inline or must open the secure approval sheet.
public enum ActivityActionRouter {
    public static func route(for interaction: Interaction, category: ActivityCategory) -> ActivityAction.Route {
        // Money, identity, security and anything the Trust Engine treats as sensitive: secure sheet.
        if interaction.kind.isSecuritySensitive { return .secureSheet }
        if interaction.purpose == .security { return .secureSheet }
        if interaction.effectiveSensitivity >= .standard { return .secureSheet }
        // Travel prompts (rebooking, itinerary changes) can change what you pay or who is travelling.
        if category == .travel || category == .reservation { return .secureSheet }
        switch interaction.kind {
        case .confirm, .choose, .acknowledge: return .inline
        default: return .secureSheet
        }
    }
}

/// Which Activity items may start or update a Live Activity. Only genuinely ongoing, eligible statuses count:
/// never marketing, never a status the business marked expired, never one that is already finished.
public enum ActivityLiveEligibility {
    public static func candidates(from interactions: [InteractionEnvelope], now: Date) -> [InteractionEnvelope] {
        interactions.filter { envelope in
            guard case .status(let payload) = envelope.interaction.payload, let status = payload.liveActivity,
                  !status.isTerminal, !envelope.interaction.isExpired(at: now) else { return false }
            return LiveActivityPolicy.isEligible(purpose: envelope.interaction.purpose, status: status)
        }
    }
}
