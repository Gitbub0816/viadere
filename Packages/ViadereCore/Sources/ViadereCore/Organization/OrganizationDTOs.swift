import Foundation

// MARK: - Organization API wire types (WP-1.1; SECURITY.md §2.96). Consumer API: camelCase members like the rest of the consumer API.

/// What opening an alert does: the first-party flow that owns the item. The app never acts on an alert from the list itself; it opens the
/// issuing flow (approval sheet, Approve v2 sheet, verification sheet, security notice), which re-reads the item from the server.
public struct AlertTarget: Codable, Sendable, Hashable {
    public enum Kind: String, Codable, Sendable, Hashable {
        case interaction
        /// An Approve v2 request **delivered to the calling device** (the delivery id). Absent when this device holds no key for it.
        case approveDelivery = "approve_delivery"
        case verification
        case securityNotice = "security_notice"
        /// A Loop instance waiting for the customer (WP-3.9): open it with `GET /v1/loops/instances/{id}`.
        case loopInstance = "loop_instance"
        case unknown

        public init(from decoder: any Decoder) throws {
            self = Kind(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
        }
    }

    public var kind: Kind
    public var id: String

    public init(kind: Kind, id: String) {
        self.kind = kind
        self.id = id
    }
}

/// One row of `GET /v1/alerts` (spec C5, D2.7): the shared `AlertItem` read model plus what the list shows.
public struct AlertEntry: Codable, Sendable, Hashable, Identifiable {
    public var id: String { alertId }
    /// `"{source}:{source id}"`: stable across syncs (the keyset cursor and the seen-set use it).
    public var alertId: String
    /// The push event id of the same record (`alr_…`, `AlertDescriptor.eventId`): a push and a list row for one record dedupe on it.
    public var eventId: String
    public var source: AlertSource
    /// The issuer. `nil` for Viadere's own account notices.
    public var business: BusinessSummary?
    public var purpose: InteractionPurpose
    public var category: AlertCategory
    public var urgency: AlertUrgency
    /// The status the server computed **at response time** (a pending item past its expiry is `expired`).
    public var status: AlertStatus
    /// Sanitized, issuer-supplied headline (≤ 120); never security copy of Viadere's.
    public var title: String
    public var expiresAt: Date?
    /// Answering it is a customer action (approve, verify, respond).
    public var actionRequired: Bool
    /// The server's verdict at response time (`AlertRules.isActionable`). The app re-checks with its own clock before showing an action.
    public var actionable: Bool
    /// Not yet marked seen by this account (`POST /v1/alerts/seen`).
    public var unread: Bool
    public var createdAt: Date
    public var updatedAt: Date
    public var target: AlertTarget?

    public init(alertId: String, eventId: String, source: AlertSource, business: BusinessSummary?, purpose: InteractionPurpose, category: AlertCategory,
                urgency: AlertUrgency, status: AlertStatus, title: String, expiresAt: Date?, actionRequired: Bool, actionable: Bool, unread: Bool,
                createdAt: Date, updatedAt: Date, target: AlertTarget?) {
        self.alertId = alertId
        self.eventId = eventId
        self.source = source
        self.business = business
        self.purpose = purpose
        self.category = category
        self.urgency = urgency
        self.status = status
        self.title = title
        self.expiresAt = expiresAt
        self.actionRequired = actionRequired
        self.actionable = actionable
        self.unread = unread
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.target = target
    }

    /// The shared read model, for `AlertRules`.
    public var item: AlertItem {
        var item = AlertItem(source: source, sourceId: "", businessId: business?.id, purpose: purpose, status: status, expiresAt: expiresAt,
                             actionRequired: actionRequired, updatedAt: updatedAt)
        item.alertId = alertId
        return item
    }

    /// Whether the app may offer the action **now**: the server said so, the item is still pending by the device clock, and the issuer is
    /// verified. A stale cache or a push can never make an expired or finished item actionable.
    public func isActionable(at now: Date) -> Bool {
        actionable && target != nil && AlertRules.isActionable(item, now: now, businessStatus: business?.verificationStatus)
    }
}

/// `GET /v1/alerts` response.
public struct AlertPage: Codable, Sendable, Hashable {
    public var items: [AlertEntry]
    /// Opaque keyset cursor for the next (older) page; `nil` at the end. A page may hold fewer than `limit` items (the unread filter is
    /// applied after the keyset step); keep paging while it is present.
    public var nextCursor: String?
    /// Pass back as `since` for an incremental sync: the server's clock when this page was assembled.
    public var syncToken: String

    public init(items: [AlertEntry], nextCursor: String?, syncToken: String) {
        self.items = items
        self.nextCursor = nextCursor
        self.syncToken = syncToken
    }
}

/// The keyset position of an alert list: `(createdAt descending, alertId ascending)`. Creation time never changes, so a page boundary never
/// moves when an item is answered or expires.
public struct AlertCursor: Sendable, Hashable {
    public var createdAtMillis: Int64
    public var alertId: String

    public init(createdAt: Date, alertId: String) {
        createdAtMillis = Int64((createdAt.timeIntervalSince1970 * 1000).rounded(.down))
        self.alertId = alertId
    }

    public var createdAt: Date { Date(timeIntervalSince1970: Double(createdAtMillis) / 1000) }

    /// `base64url("v1|{millis}|{alertId}")`.
    public var encoded: String { Base64URL.encode(Data("v1|\(createdAtMillis)|\(alertId)".utf8)) }

    public init?(encoded: String) {
        guard encoded.utf8.count <= 256, let data = Base64URL.decode(encoded), let text = String(data: data, encoding: .utf8) else { return nil }
        let parts = text.split(separator: "|", omittingEmptySubsequences: false)
        guard parts.count == 3, parts[0] == "v1", let millis = Int64(parts[1]), millis >= 0, AlertIdentifier.isValid(String(parts[2])) else { return nil }
        createdAtMillis = millis
        alertId = String(parts[2])
    }

    /// Whether an item at (`createdAt`, `alertId`) comes **after** this cursor in list order.
    public func precedes(createdAt: Date, alertId other: String) -> Bool {
        let millis = Int64((createdAt.timeIntervalSince1970 * 1000).rounded(.down))
        if millis != createdAtMillis { return millis < createdAtMillis }
        return other > alertId
    }
}

/// Alert ids: `{source}:{lowercase UUID}`.
public enum AlertIdentifier {
    public static func make(_ source: AlertSource, _ id: UUID) -> String { "\(source.rawValue):\(id.uuidString.lowercased())" }

    public static func parse(_ raw: String) -> (source: AlertSource, id: UUID)? {
        guard raw.utf8.count <= 64, let colon = raw.firstIndex(of: ":") else { return nil }
        let rest = raw[raw.index(after: colon)...]
        guard let source = AlertSource(rawValue: String(raw[..<colon])), rest.count == 36, rest == rest.lowercased(), let id = UUID(uuidString: String(rest)) else {
            return nil
        }
        return (source, id)
    }

    public static func isValid(_ raw: String) -> Bool { parse(raw) != nil }
}

/// The query of `GET /v1/alerts` (spec C5.2; plan section 4.8). Built by the app, parsed strictly by the server.
public struct AlertQuery: Sendable, Hashable {
    public static let defaultLimit = 30
    public static let maxLimit = 50

    public var status: AlertStatusFilter?
    public var unreadOnly: Bool
    /// The selected business. The server accepts it only for a business the caller may see (`404` otherwise; never an existence oracle).
    public var businessId: BusinessID?
    public var cursor: AlertCursor?
    /// Incremental sync: only items created or changed after this instant (a previous page's `syncToken`).
    public var since: Date?
    public var limit: Int

    public init(status: AlertStatusFilter? = nil, unreadOnly: Bool = false, businessId: BusinessID? = nil, cursor: AlertCursor? = nil,
                since: Date? = nil, limit: Int = AlertQuery.defaultLimit) {
        self.status = status
        self.unreadOnly = unreadOnly
        self.businessId = businessId
        self.cursor = cursor
        self.since = since
        self.limit = min(max(limit, 1), Self.maxLimit)
    }

    public init(context: OrganizationContext, status: AlertStatusFilter? = nil, unreadOnly: Bool = false) {
        self.init(status: status, unreadOnly: unreadOnly, businessId: context.businessFilter)
    }

    public var queryItems: [(String, String)] {
        var out: [(String, String)] = []
        if let status { out.append(("status", status.rawValue)) }
        if unreadOnly { out.append(("unread", "1")) }
        if let businessId { out.append(("business_id", businessId.description)) }
        if let cursor { out.append(("cursor", cursor.encoded)) }
        if let since { out.append(("since", SyncToken.encode(since))) }
        if limit != Self.defaultLimit { out.append(("limit", String(limit))) }
        return out
    }

    public enum ParseError: Error, Equatable { case invalid(String) }

    /// Strict parse of the server's query parameters: unknown values are refused, never ignored.
    public static func parse(_ value: (String) -> String?) throws -> AlertQuery {
        var query = AlertQuery()
        if let raw = value("status") {
            guard let status = AlertStatusFilter(rawValue: raw) else { throw ParseError.invalid("status") }
            query.status = status
        }
        if let raw = value("unread") {
            switch raw {
            case "1", "true": query.unreadOnly = true
            case "0", "false": query.unreadOnly = false
            default: throw ParseError.invalid("unread")
            }
        }
        if let raw = value("business_id") {
            guard let id = UUID(uuidString: raw) else { throw ParseError.invalid("business_id") }
            query.businessId = BusinessID(id)
        }
        if let raw = value("cursor") {
            guard let cursor = AlertCursor(encoded: raw) else { throw ParseError.invalid("cursor") }
            query.cursor = cursor
        }
        if let raw = value("since") {
            guard let since = SyncToken.decode(raw) else { throw ParseError.invalid("since") }
            query.since = since
        }
        if let raw = value("limit") {
            guard let limit = Int(raw), (1...maxLimit).contains(limit) else { throw ParseError.invalid("limit") }
            query.limit = limit
        }
        return query
    }
}

/// Sync tokens: `base64url("s1|{unix milliseconds}")`.
public enum SyncToken {
    public static func encode(_ date: Date) -> String {
        Base64URL.encode(Data("s1|\(Int64((date.timeIntervalSince1970 * 1000).rounded(.down)))".utf8))
    }

    public static func decode(_ raw: String) -> Date? {
        guard raw.utf8.count <= 64, let data = Base64URL.decode(raw), let text = String(data: data, encoding: .utf8) else { return nil }
        let parts = text.split(separator: "|", omittingEmptySubsequences: false)
        guard parts.count == 2, parts[0] == "s1", let millis = Int64(parts[1]), millis >= 0 else { return nil }
        return Date(timeIntervalSince1970: Double(millis) / 1000)
    }
}

/// `POST /v1/alerts/seen`: marks alerts seen for **this account** (per viewer: household delegates see others' items).
public struct AlertSeenRequest: Codable, Sendable, Hashable {
    public static let maxIds = 100
    public var alertIds: [String]
    public init(alertIds: [String]) { self.alertIds = alertIds }

    public var isValid: Bool { !alertIds.isEmpty && alertIds.count <= Self.maxIds && alertIds.allSatisfy(AlertIdentifier.isValid) }
}

// MARK: - Benefits

/// Benefits filters (spec C6.1), shared by the server query and the app's local re-check. A reward the server says is revoked or expired is
/// never shown as available, whatever the device clock says.
public enum BenefitRules {
    public static func matches(_ entry: RewardEntry, filter: BenefitFilter?) -> Bool {
        let state = entry.eligibility.state
        let finished = entry.reward.status != .available || [.redeemed, .expired, .revoked].contains(state)
        switch filter {
        case nil: return true
        case .available: return !finished
        case .eligible: return !finished && state == .eligible
        case .saved: return !finished && entry.claimedAt != nil
        case .redeemed: return entry.reward.status == .redeemed || state == .redeemed
        case .expired: return entry.reward.status == .expired || entry.reward.status == .revoked || state == .expired || state == .revoked
        }
    }

    /// Display order: actionable first (eligible), then by the nearest expiry, then title. Deterministic, no learned ranking (spec C8.2).
    public static func sorted(_ entries: [RewardEntry]) -> [RewardEntry] {
        entries.sorted { a, b in
            let ae = a.eligibility.state == .eligible, be = b.eligibility.state == .eligible
            if ae != be { return ae }
            let au = a.reward.validUntil ?? .distantFuture, bu = b.reward.validUntil ?? .distantFuture
            if au != bu { return au < bu }
            if a.reward.title != b.reward.title { return a.reward.title < b.reward.title }
            return a.reward.id.description < b.reward.id.description
        }
    }
}

// MARK: - Businesses and per-business preferences

/// The customer's per-business settings (spec C7.2, D2 `BusinessPreference`; plan section 4.8). Mute changes how notifications interrupt,
/// never whether an item appears in Alerts, and never touches security, account-service or action-required items (`MutePolicy`).
public struct BusinessPreferences: Codable, Sendable, Hashable {
    public var businessId: BusinessID
    public var favorite: Bool
    public var muteLevel: MuteLevel
    /// When the mute ends (`nil`: until changed).
    public var muteUntil: Date?
    /// Blocked: the connection is ended and new connections or link sessions with this business are refused until unblocked.
    public var blocked: Bool
    public var updatedAt: Date?

    public init(businessId: BusinessID, favorite: Bool = false, muteLevel: MuteLevel = .none, muteUntil: Date? = nil, blocked: Bool = false,
                updatedAt: Date? = nil) {
        self.businessId = businessId
        self.favorite = favorite
        self.muteLevel = muteLevel
        self.muteUntil = muteUntil
        self.blocked = blocked
        self.updatedAt = updatedAt
    }

    /// The mute in force at `now` (an elapsed `muteUntil` means no mute).
    public func effectiveMute(at now: Date) -> MuteLevel {
        if let muteUntil, muteUntil <= now { return .none }
        return muteLevel
    }
}

/// `PUT /v1/businesses/{businessId}/preferences`. Absent members are unchanged. `muteUntil` applies only together with `muteLevel`.
public struct BusinessPreferencesUpdate: Codable, Sendable, Hashable {
    public var favorite: Bool?
    public var muteLevel: MuteLevel?
    public var muteUntil: Date?
    public var blocked: Bool?

    public init(favorite: Bool? = nil, muteLevel: MuteLevel? = nil, muteUntil: Date? = nil, blocked: Bool? = nil) {
        self.favorite = favorite
        self.muteLevel = muteLevel
        self.muteUntil = muteUntil
        self.blocked = blocked
    }

    /// The longest timed mute.
    public static let maxMuteDuration: TimeInterval = 366 * 86_400

    public var isEmpty: Bool { favorite == nil && muteLevel == nil && muteUntil == nil && blocked == nil }
}

/// One entry of the Businesses directory (`GET /v1/businesses`): a connection the customer has or had, with its preferences.
public struct ConnectedBusiness: Codable, Sendable, Hashable, Identifiable {
    public var id: BusinessID { business.id }
    public var business: BusinessSummary
    public var category: BusinessCategory?
    public var relationshipId: RelationshipID
    public var status: ConnectionStatus
    public var connectedAt: Date
    public var lastActivityAt: Date
    public var preferences: BusinessPreferences

    public init(business: BusinessSummary, category: BusinessCategory?, relationshipId: RelationshipID, status: ConnectionStatus, connectedAt: Date,
                lastActivityAt: Date, preferences: BusinessPreferences) {
        self.business = business
        self.category = category
        self.relationshipId = relationshipId
        self.status = status
        self.connectedAt = connectedAt
        self.lastActivityAt = lastActivityAt
        self.preferences = preferences
    }

    public var isActive: Bool { status == .active }
}

/// Directory ordering and search (spec C3, C8): favorites first (by name), then the rest by most recent activity; search is local, over
/// names and handles of the customer's own connections only (never a server-side cross-tenant search).
public enum BusinessDirectoryRules {
    public static func ordered(_ businesses: [ConnectedBusiness]) -> [ConnectedBusiness] {
        businesses.sorted { a, b in
            if a.isActive != b.isActive { return a.isActive }
            if a.preferences.favorite != b.preferences.favorite { return a.preferences.favorite }
            if a.preferences.favorite {
                let order = a.business.displayName.localizedCaseInsensitiveCompare(b.business.displayName)
                if order != .orderedSame { return order == .orderedAscending }
            } else if a.lastActivityAt != b.lastActivityAt {
                return a.lastActivityAt > b.lastActivityAt
            }
            return a.business.id.description < b.business.id.description
        }
    }

    /// Case- and diacritic-insensitive match on the display name or handle. An empty query matches everything.
    public static func matches(_ business: BusinessSummary, query: String) -> Bool {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: "@", with: "")
        guard !needle.isEmpty else { return true }
        let options: String.CompareOptions = [.caseInsensitive, .diacriticInsensitive]
        if business.displayName.range(of: needle, options: options) != nil { return true }
        if let handle = business.handle?.value, handle.range(of: needle, options: options) != nil { return true }
        return false
    }
}

// MARK: - Business surface (neutral business home, WP-1.6)

public struct SurfaceModule: Codable, Sendable, Hashable {
    public var module: String
    public var size: ModuleSize
    public init(module: String, size: ModuleSize) {
        self.module = module
        self.size = size
    }
}

/// `GET /v1/businesses/{businessId}/surface`: the module layout of a business home. Viadere owns the modules, their behavior, navigation and
/// all security copy; the business only chose which standard modules appear and in what order.
public struct BusinessSurfaceView: Codable, Sendable, Hashable {
    public var business: BusinessSummary
    public var template: String
    public var modules: [SurfaceModule]
    /// The published layout version, `0` for Viadere's default layout.
    public var version: Int

    public init(business: BusinessSummary, template: String, modules: [SurfaceModule], version: Int) {
        self.business = business
        self.template = template
        self.modules = modules
        self.version = version
    }
}

extension SurfaceLayout {
    /// The layout every business home has until the business publishes its own.
    public static let defaultBusinessHome = SurfaceLayout(template: PageTemplate.businessHome.id, modules: [
        ModulePlacement(module: "profile", size: .regular),
        ModulePlacement(module: "approvals", size: .regular),
        ModulePlacement(module: "verification_requests", size: .regular),
        ModulePlacement(module: "message", size: .regular),
        ModulePlacement(module: "offers", size: .regular),
        ModulePlacement(module: "rewards", size: .regular),
        ModulePlacement(module: "recent_activity", size: .regular),
    ])

    public var wireModules: [SurfaceModule] { modules.map { SurfaceModule(module: $0.module, size: $0.size) } }

    /// What a client renders from a served layout, whatever the server sent: only active registry modules, once each, the verified profile
    /// first (inserted when missing), gated modules (Loops) only when enabled, reserved ones never. A business cannot remove the profile, add
    /// navigation or reorder Viadere's security surfaces into a place where the profile does not come first.
    public static func renderable(_ modules: [SurfaceModule], registry: ModuleRegistry = .v1, loopsEnabled: Bool = false) -> [SurfaceModule] {
        var seen = Set<String>()
        var out: [SurfaceModule] = []
        for item in modules {
            guard let descriptor = registry.module(item.module), seen.insert(item.module).inserted else { continue }
            switch descriptor.availability {
            case .active: break
            case .gated: if !loopsEnabled { continue }
            case .reserved: continue
            }
            let size = descriptor.sizes.contains(item.size) ? item.size : (descriptor.sizes.contains(.regular) ? .regular : descriptor.sizes[0])
            out.append(SurfaceModule(module: item.module, size: size))
        }
        out.removeAll { $0.module == "profile" }
        out.insert(SurfaceModule(module: "profile", size: .regular), at: 0)
        return Array(out.prefix(PageTemplate.businessHome.maxModules))
    }
}

extension SurfaceLayout {
    /// The largest stored layout document.
    public static let maxBytes = 4096

    /// Strict parse of stored or submitted bytes (no floating point, size-capped) plus every layout rule.
    public static func validate(data: Data, registry: ModuleRegistry = .v1, loopsEnabled: Bool = false) -> (layout: SurfaceLayout?, issues: [ContractIssue]) {
        guard data.count <= maxBytes, let value = JSONValue.parseContract(data) else { return (nil, [ContractIssue(code: "invalid_json", path: "")]) }
        return validate(value, registry: registry, loopsEnabled: loopsEnabled)
    }

    /// Canonical JSON (§2.2) of the layout document, as stored in `business_surfaces.layout_json`.
    public func canonicalJSON() throws -> Data { try CanonicalJSON.serialize(jsonValue) }
}

// MARK: - Conversations (archive and mute, spec C4.3)

/// `PUT /v1/conversations/{sessionId}/state`. Absent members are unchanged. Per account, never shared with the business.
public struct ConversationStateUpdate: Codable, Sendable, Hashable {
    public var archived: Bool?
    public var muted: Bool?
    public init(archived: Bool? = nil, muted: Bool? = nil) {
        self.archived = archived
        self.muted = muted
    }
}

public struct ConversationStateView: Codable, Sendable, Hashable {
    public var sessionId: SessionID
    public var archived: Bool
    public var muted: Bool
    public init(sessionId: SessionID, archived: Bool, muted: Bool) {
        self.sessionId = sessionId
        self.archived = archived
        self.muted = muted
    }
}

// MARK: - Interaction kinds as alerts

extension InteractionKind {
    /// Kinds that ask the customer for an answer (they appear under "Needs you" while pending). Status updates, rewards, tickets and
    /// messages are informational.
    public var expectsResponse: Bool {
        switch self {
        case .authenticate, .authorize, .confirm, .choose, .acknowledge, .reply: true
        case .status, .reward, .ticket, .message: false
        case .unknown: true
        }
    }
}

/// The list headline of an interaction alert. Taken from the business's already-sanitized payload text (§2.19), never from free fields the
/// validator did not see; capped for the list.
public enum AlertTitles {
    public static let maxLength = 120

    public static func title(for interaction: Interaction) -> String {
        let raw: String
        switch interaction.payload {
        case .authenticate(let p): raw = "Sign-in to \(p.service)"
        case .authorize(let p): raw = p.actionDescription
        case .confirm(let p): raw = p.title
        case .choose(let p): raw = p.prompt
        case .acknowledge(let p): raw = p.title
        case .reply(let p): raw = p.prompt
        case .status(let p): raw = p.title
        case .reward(let p): raw = p.title
        case .ticket(let p): raw = p.title
        case .message(let p): raw = p.text
        case .unknown: raw = "Request"
        }
        return clip(raw)
    }

    public static func clip(_ text: String) -> String {
        let flat = text.replacingOccurrences(of: "\n", with: " ").trimmingCharacters(in: .whitespacesAndNewlines)
        guard flat.count > maxLength else { return flat.isEmpty ? "Request" : flat }
        return String(flat.prefix(maxLength - 1)) + "…"
    }
}
