import Foundation
import ViadereCore

/// In-memory Organization state of the mock server.
struct MockOrganizationState {
    var preferences: [BusinessID: BusinessPreferences] = [:]
    var seen: Set<String> = []
    var conversationState: [SessionID: ConversationStateView] = [:]
    var layouts: [BusinessID: [SurfaceModule]] = [:]
    /// Test hook: every Organization call fails as if offline.
    var offline = false
}

/// The mock server's Organization API, built from the same seeded data as the rest of the mock (interactions, relationships, rewards,
/// conversations, notices) with the server's rules: only the account's own connections, `404` for any other business, expired never pending.
extension MockViadereAPI: OrganizationAPI {
    public func setOrganizationOffline(_ offline: Bool) { org.offline = offline }
    public func setSurface(_ modules: [SurfaceModule], for business: BusinessID) { org.layouts[business] = modules }

    private func online() throws {
        if org.offline { throw APIError.transport("The Internet connection appears to be offline.") }
    }

    private func activeBusinesses() async throws -> [BusinessID: BusinessSummary] {
        let relationships = try await relationships().filter { $0.status == .active }
        return Dictionary(relationships.map { ($0.business.id, $0.business) }, uniquingKeysWith: { a, _ in a })
    }

    private func checkVisible(_ business: BusinessID?) async throws {
        guard let business else { return }
        guard try await activeBusinesses()[business] != nil else { throw APIError.server(status: 404, code: .notFound, message: "Not found.") }
    }

    public func alerts(_ query: AlertQuery) async throws -> AlertPage {
        try online()
        try await checkVisible(query.businessId)
        let now = clock()
        let visible = try await activeBusinesses()
        var entries: [AlertEntry] = []
        for envelope in try await interactions(status: nil, cursor: nil).items where visible[envelope.business.id] != nil {
            let interaction = envelope.interaction
            let responds = interaction.kind.expectsResponse
            var status: AlertStatus
            switch envelope.status {
            case .pending: status = interaction.expiresAt > now ? .pending : .expired
            case .expired: status = .expired
            case .cancelled: status = .cancelled
            default: status = .completed
            }
            if !responds { status = status == .cancelled ? .cancelled : .completed }
            let id = interaction.id.uuid
            let alertId = AlertIdentifier.make(.interaction, id)
            var entry = AlertEntry(alertId: alertId, eventId: AlertDescriptor.eventId(kind: "interaction", id: id), source: .interaction,
                                   business: envelope.business, purpose: interaction.purpose, category: responds ? .request : .update,
                                   urgency: interaction.purpose == .security ? .critical : .normal, status: status, title: AlertTitles.title(for: interaction),
                                   expiresAt: responds ? interaction.expiresAt : nil, actionRequired: responds, actionable: false,
                                   unread: !org.seen.contains(alertId), createdAt: interaction.createdAt, updatedAt: interaction.createdAt,
                                   target: AlertTarget(kind: .interaction, id: id.uuidString.lowercased()))
            entry.actionable = AlertRules.isActionable(entry.item, now: now, businessStatus: envelope.business.verificationStatus)
            entries.append(entry)
        }
        if query.businessId == nil {
            for notice in try await securityNotices() {
                let alertId = AlertIdentifier.make(.securityNotice, notice.id)
                entries.append(AlertEntry(alertId: alertId, eventId: AlertDescriptor.eventId(kind: "security_notice", id: notice.id), source: .securityNotice,
                                          business: nil, purpose: .security, category: .securityNotice, urgency: notice.action == nil ? .timeSensitive : .critical,
                                          status: .pending, title: AlertTitles.clip(notice.message), expiresAt: nil, actionRequired: notice.action != nil,
                                          actionable: notice.action != nil, unread: !org.seen.contains(alertId), createdAt: notice.createdAt,
                                          updatedAt: notice.createdAt, target: AlertTarget(kind: .securityNotice, id: notice.id.uuidString.lowercased())))
            }
        }
        entries = entries.filter { entry in
            if let business = query.businessId, entry.business?.id != business { return false }
            if let status = query.status, !AlertRules.matches(entry.item, context: .all, status: status, now: now) { return false }
            if query.unreadOnly, !entry.unread { return false }
            if let since = query.since, entry.updatedAt <= since, entry.createdAt <= since { return false }
            if let cursor = query.cursor, !cursor.precedes(createdAt: entry.createdAt, alertId: entry.alertId) { return false }
            return true
        }.sorted { a, b in
            let am = Int64((a.createdAt.timeIntervalSince1970 * 1000).rounded(.down)), bm = Int64((b.createdAt.timeIntervalSince1970 * 1000).rounded(.down))
            return am != bm ? am > bm : a.alertId < b.alertId
        }
        let page = Array(entries.prefix(query.limit))
        let next = entries.count > query.limit ? page.last.map { AlertCursor(createdAt: $0.createdAt, alertId: $0.alertId).encoded } : nil
        return AlertPage(items: page, nextCursor: next, syncToken: SyncToken.encode(now))
    }

    public func markAlertsSeen(_ alertIds: [String]) async throws {
        try online()
        guard AlertSeenRequest(alertIds: alertIds).isValid else { throw APIError.server(status: 422, code: .validationFailed, message: "Invalid alert ids.") }
        org.seen.formUnion(alertIds)
    }

    public func benefits(filter: BenefitFilter?, business: BusinessID?) async throws -> RewardsOverview {
        try online()
        try await checkVisible(business)
        let overview = try await rewardsOverview()
        return RewardsOverview(accounts: overview.accounts.filter { business == nil || $0.business.id == business },
                               rewards: BenefitRules.sorted(overview.rewards.filter { (business == nil || $0.business.id == business) && BenefitRules.matches($0, filter: filter) }))
    }

    public func businesses() async throws -> [ConnectedBusiness] {
        try online()
        let list = try await relationships()
        return BusinessDirectoryRules.ordered(list.map { relationship in
            ConnectedBusiness(business: relationship.business, category: nil, relationshipId: relationship.id,
                              status: relationship.status == .active ? .active : .disconnected, connectedAt: relationship.connectedAt,
                              lastActivityAt: relationship.connectedAt,
                              preferences: org.preferences[relationship.business.id] ?? BusinessPreferences(businessId: relationship.business.id))
        })
    }

    public func preferences(business: BusinessID) async throws -> BusinessPreferences {
        try online()
        try await checkVisible(business)
        return org.preferences[business] ?? BusinessPreferences(businessId: business)
    }

    public func updatePreferences(business: BusinessID, _ update: BusinessPreferencesUpdate) async throws -> BusinessPreferences {
        try online()
        try await checkVisible(business)
        guard !update.isEmpty else { throw APIError.server(status: 422, code: .validationFailed, message: "Change at least one preference.") }
        var prefs = org.preferences[business] ?? BusinessPreferences(businessId: business)
        if let favorite = update.favorite { prefs.favorite = favorite }
        if let level = update.muteLevel {
            prefs.muteLevel = level
            prefs.muteUntil = level == MuteLevel.none ? nil : update.muteUntil
        }
        if let blocked = update.blocked {
            prefs.blocked = blocked
            if blocked, let relationship = try await relationships().first(where: { $0.business.id == business }) { try await disconnect(relationship.id) }
        }
        prefs.updatedAt = clock()
        org.preferences[business] = prefs
        return prefs
    }

    public func surface(business: BusinessID) async throws -> BusinessSurfaceView {
        try online()
        guard let summary = try await activeBusinesses()[business] else { throw APIError.server(status: 404, code: .notFound, message: "Not found.") }
        let modules = org.layouts[business] ?? SurfaceLayout.defaultBusinessHome.wireModules
        return BusinessSurfaceView(business: summary, template: PageTemplate.businessHome.id, modules: SurfaceLayout.renderable(modules),
                                   version: org.layouts[business] == nil ? 0 : 1)
    }

    public func conversations(business: BusinessID?, includeArchived: Bool) async throws -> [ConversationSummary] {
        try online()
        try await checkVisible(business)
        return try await conversations().compactMap { thread in
            guard business == nil || thread.business.id == business else { return nil }
            var thread = thread
            let state = org.conversationState[thread.id]
            thread.archived = state?.archived ?? false
            thread.muted = state?.muted ?? false
            return thread.archived == true && !includeArchived ? nil : thread
        }
    }

    public func updateConversation(_ id: SessionID, _ update: ConversationStateUpdate) async throws -> ConversationStateView {
        try online()
        guard try await conversations().contains(where: { $0.id == id }) else { throw APIError.server(status: 404, code: .notFound, message: "Not found.") }
        var state = org.conversationState[id] ?? ConversationStateView(sessionId: id, archived: false, muted: false)
        if let archived = update.archived { state.archived = archived }
        if let muted = update.muted { state.muted = muted }
        org.conversationState[id] = state
        return state
    }
}
