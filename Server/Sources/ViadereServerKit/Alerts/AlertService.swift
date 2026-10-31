import Fluent
import Foundation
import ViadereCore

/// The Alerts read model (WP-1.1; spec C5, D2.7; SECURITY.md §2.96). Not a table: a query layer over the durable rows that already exist
/// (interactions, Approve v2 requests, verification requests, account security notices). The server rows are the source of truth; a push is
/// only a hint, and a missed push is healed by the next list or `since` sync.
///
/// Tenancy: every source query is built from the principal's `OrganizationScope`, never from a request field; the optional `business_id`
/// only narrows that scope after it was checked (`404` otherwise).
///
/// Order and paging: `(created_at descending, alert_id ascending)` with an opaque keyset cursor. Creation time never changes, so a page
/// boundary never moves when an item is answered or expires. Each source is read with the same order and `limit + 1` rows; the merged
/// window of `limit` rows decides the next cursor, then the exact status and unread filters apply (a page can be short; keep paging while
/// `nextCursor` is present).
struct AlertService {
    let db: any Database
    let ctx: ServerContext

    static let responseKinds = InteractionKind.known.filter(\.expectsResponse).map(\.rawValue)
    static let decidedInteractionStatuses: [String] = [InteractionStatus.approved, .denied, .confirmed, .declined, .selected, .replied, .acknowledged,
                                                       .reported, .delivered].map(\.rawValue)
    static let openVerificationStatuses = [ConsumerVerificationStatus.pendingConsent.rawValue, ConsumerVerificationStatus.consented.rawValue]
    static let finishedVerificationStatuses = [ConsumerVerificationStatus.released, .notVerified, .declined, .revoked].map(\.rawValue)
    /// Rows of one millisecond bucket read beyond `limit + 1` so that ties at the page edge stay in a consistent order.
    static let bucketCap = 1000

    /// One alert before the issuer's summary and the seen state are attached.
    struct Draft {
        var alertId: String
        var eventId: String
        var source: AlertSource
        var businessId: UUID?
        var purpose: InteractionPurpose
        var category: AlertCategory
        var urgency: AlertUrgency
        var status: AlertStatus
        var title: String
        var expiresAt: Date?
        var actionRequired: Bool
        /// The viewer may act on it at all (a household `viewer` grant never can).
        var canAct: Bool
        var createdAt: Date
        var updatedAt: Date
        var target: AlertTarget?

        var millis: Int64 { Int64((createdAt.timeIntervalSince1970 * 1000).rounded(.down)) }

        func item(now: Date) -> AlertItem {
            var item = AlertItem(source: source, sourceId: "", businessId: businessId.map(BusinessID.init), purpose: purpose, status: status,
                                 expiresAt: expiresAt, actionRequired: actionRequired, updatedAt: updatedAt)
            item.alertId = alertId
            return item
        }
    }

    // MARK: List

    func list(principal: ConsumerPrincipal, query: AlertQuery) async throws -> AlertPage {
        let now = ctx.now
        let fullScope = try await OrganizationScope.load(consumer: principal.consumerId, db: db, ctx: ctx)
        let filter = try fullScope.authorize(query.businessId)
        let scope = fullScope.narrowed(to: filter)
        let limit = query.limit
        var drafts: [Draft] = []
        var anySourceFull = false
        func add(_ rows: (drafts: [Draft], full: Bool)) {
            drafts += rows.drafts
            anySourceFull = anySourceFull || rows.full
        }
        add(try await interactions(scope: scope, query: query, limit: limit, now: now))
        add(try await approveRequests(principal: principal, scope: scope, query: query, limit: limit, now: now))
        add(try await verifications(scope: scope, query: query, limit: limit, now: now))
        add(try await profileRequests(scope: scope, query: query, limit: limit, now: now))
        if filter == nil { add(try await securityNotices(consumer: principal.consumerId.uuid, query: query, limit: limit)) }

        if let cursor = query.cursor { drafts = drafts.filter { cursor.precedes(createdAt: $0.createdAt, alertId: $0.alertId) } }
        drafts.sort { a, b in a.millis != b.millis ? a.millis > b.millis : a.alertId < b.alertId }
        let window = Array(drafts.prefix(limit))
        let more = window.count == limit && (drafts.count > limit || anySourceFull)
        let nextCursor = more ? window.last.map { AlertCursor(createdAt: $0.createdAt, alertId: $0.alertId).encoded } : nil

        let seen = try await seenIds(consumer: principal.consumerId.uuid, among: window.map(\.alertId))
        let summaries = try await businessSummaries(Set(window.compactMap(\.businessId)))
        var items: [AlertEntry] = []
        for draft in window {
            var business: BusinessSummary?
            if let id = draft.businessId {
                guard let summary = summaries[id] else { continue }
                business = summary
            }
            let item = draft.item(now: now)
            if let status = query.status, !AlertRules.matches(item, context: .all, status: status, now: now) { continue }
            let unread = !seen.contains(draft.alertId)
            if query.unreadOnly, !unread { continue }
            let status = AlertRules.displayStatus(item, now: now)
            let actionable = draft.canAct && draft.target != nil && AlertRules.isActionable(item, now: now, businessStatus: business?.verificationStatus)
            items.append(AlertEntry(alertId: draft.alertId, eventId: draft.eventId, source: draft.source, business: business, purpose: draft.purpose,
                                    category: draft.category, urgency: draft.urgency, status: status, title: draft.title, expiresAt: draft.expiresAt,
                                    actionRequired: draft.actionRequired, actionable: actionable, unread: unread, createdAt: draft.createdAt,
                                    updatedAt: draft.updatedAt, target: draft.target))
        }
        return AlertPage(items: items, nextCursor: nextCursor, syncToken: SyncToken.encode(now))
    }

    // MARK: Seen

    func markSeen(principal: ConsumerPrincipal, request: AlertSeenRequest) async throws {
        guard request.isValid else {
            throw APIError.validation("Send between 1 and \(AlertSeenRequest.maxIds) alert ids.", details: ["alertIds": "invalid"])
        }
        let consumer = principal.consumerId.uuid
        let ids = Array(Set(request.alertIds))
        let existing = Set(try await AlertSeenRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$alertId ~~ ids).all().map(\.alertId))
        let now = ctx.now
        for id in ids where !existing.contains(id) {
            do { try await AlertSeenRecord(consumerId: consumer, alertId: id, now: now).create(on: db) } catch let error where error.isConstraintViolation {
                // A concurrent mark of the same id: already seen.
            }
        }
    }

    private func seenIds(consumer: UUID, among ids: [String]) async throws -> Set<String> {
        guard !ids.isEmpty else { return [] }
        return Set(try await AlertSeenRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$alertId ~~ ids).all().map(\.alertId))
    }

    private func businessSummaries(_ ids: Set<UUID>) async throws -> [UUID: BusinessSummary] {
        guard !ids.isEmpty else { return [:] }
        let businesses = try await BusinessRecord.query(on: db).filter(\.$id ~~ Array(ids)).all()
        let summaries = try await DirectoryService(db: db).summaries(for: businesses)
        return Dictionary(summaries.map { ($0.id.uuid, $0) }, uniquingKeysWith: { a, _ in a })
    }

    // MARK: Keyset reads, shared by every source

    /// Reads `limit + 1` rows in list order, plus the rest of the last row's millisecond bucket. `full` = more rows may exist after these.
    private func keyset<M: Model>(_ make: () -> QueryBuilder<M>, createdAt: (M) -> Date, cursor: AlertCursor?, limit: Int) async throws -> (rows: [M], full: Bool)
        where M.IDValue == UUID {
        func bounded(_ q: QueryBuilder<M>) -> QueryBuilder<M> {
            guard let cursor else { return q }
            // Coarse bound (the whole cursor millisecond included); the exact keyset comparison runs on the merged rows.
            return q.filter("created_at", .lessThan, cursor.createdAt.addingTimeInterval(0.001))
        }
        var rows = try await bounded(make()).sort("created_at", .descending).sort("id", .ascending).limit(limit + 1).all()
        guard rows.count == limit + 1, let last = rows.last else { return (rows, false) }
        let lo = Date(timeIntervalSince1970: Double(Int64((createdAt(last).timeIntervalSince1970 * 1000).rounded(.down))) / 1000)
        let have = Set(rows.compactMap(\.id))
        let bucket = try await bounded(make()).filter("created_at", .greaterThanOrEqual, lo).filter("created_at", .lessThan, lo.addingTimeInterval(0.001))
            .limit(Self.bucketCap).all()
        rows += bucket.filter { $0.id.map { !have.contains($0) } ?? false }
        return (rows, true)
    }

    // MARK: Sources

    private func interactions(scope: OrganizationScope, query: AlertQuery, limit: Int, now: Date) async throws -> (drafts: [Draft], full: Bool) {
        let me = scope.consumerId
        let ownBusinesses = Array(scope.own)
        let grants = scope.grants.filter { !$0.businesses.isEmpty }
        guard !ownBusinesses.isEmpty || !grants.isEmpty else { return ([], false) }
        func make() -> QueryBuilder<InteractionRecord> {
            var q = InteractionRecord.query(on: db).filter(\.$livemode == true).group(.or) { or in
                if !ownBusinesses.isEmpty {
                    or.group(.and) { $0.filter(\.$consumerId == me).filter(\.$businessId ~~ ownBusinesses) }
                }
                for grant in grants {
                    or.group(.and) {
                        $0.filter(\.$consumerId == grant.grantorId).filter(\.$businessId ~~ Array(grant.businesses)).filter(\.$purpose ~~ Array(grant.purposes))
                    }
                }
            }
            switch query.status {
            case .pending?:
                q = q.filter(\.$status == InteractionStatus.pending.rawValue).filter(\.$expiresAt > now).filter(\.$kind ~~ Self.responseKinds)
            case .expired?:
                q = q.group(.or) { or in
                    or.filter(\.$status == InteractionStatus.expired.rawValue)
                    or.group(.and) { $0.filter(\.$status == InteractionStatus.pending.rawValue).filter(\.$expiresAt <= now) }
                }
            case .completed?:
                q = q.filter(\.$status != InteractionStatus.expired.rawValue)
            case nil: break
            }
            if let since = query.since {
                q = q.group(.or) { or in
                    or.filter(\.$createdAt > since)
                    or.filter(\.$decidedAt > since)
                    or.group(.and) { $0.filter(\.$expiresAt > since).filter(\.$expiresAt <= now) }
                }
            }
            return q
        }
        let (rows, full) = try await keyset(make, createdAt: \.createdAt, cursor: query.cursor, limit: limit)
        let grantByGrantor = Dictionary(grants.map { ($0.grantorId, $0) }, uniquingKeysWith: { a, _ in a })
        let drafts = rows.compactMap { record -> Draft? in
            guard let id = record.id, let purpose = InteractionPurpose(rawValue: record.purpose) else { return nil }
            let kind = InteractionKind(rawValue: record.kind)
            let responds = kind.expectsResponse
            let status: AlertStatus
            if !responds {
                status = record.statusValue == .cancelled ? .cancelled : .completed
            } else {
                switch record.statusValue {
                case .pending: status = record.expiresAt > now ? .pending : .expired
                case .expired: status = .expired
                case .cancelled: status = .cancelled
                default: status = .completed
                }
            }
            let canAct = record.consumerId == me || (grantByGrantor[record.consumerId]?.canAct ?? false)
            let title = (try? record.interaction()).map(AlertTitles.title(for:)) ?? "Request"
            let urgency: AlertUrgency
            switch (purpose, InteractionPriority(rawValue: record.priority)) {
            case (.security, _), (_, .urgent?): urgency = .critical
            case (_, .high?): urgency = .timeSensitive
            default: urgency = .normal
            }
            return Draft(alertId: AlertIdentifier.make(.interaction, id), eventId: AlertDescriptor.eventId(kind: AlertSource.interaction.rawValue, id: id),
                         source: .interaction, businessId: record.businessId, purpose: purpose, category: responds ? .request : .update, urgency: urgency,
                         status: status, title: title, expiresAt: responds ? record.expiresAt : nil, actionRequired: responds, canAct: canAct,
                         createdAt: record.createdAt, updatedAt: record.decidedAt ?? record.createdAt,
                         target: AlertTarget(kind: .interaction, id: id.uuidString.lowercased()))
        }
        return (drafts, full)
    }

    private func approveRequests(principal: ConsumerPrincipal, scope: OrganizationScope, query: AlertQuery, limit: Int, now: Date) async throws -> (drafts: [Draft], full: Bool) {
        let me = scope.consumerId
        let businesses = Array(scope.own)
        guard !businesses.isEmpty else { return ([], false) }
        func make() -> QueryBuilder<ApproveRequestRecord> {
            var q = ApproveRequestRecord.query(on: db).filter(\.$consumerId == me).filter(\.$businessId ~~ businesses)
            switch query.status {
            case .pending?: q = q.filter(\.$status == ApprovalRequestStatus.pending.rawValue).filter(\.$expiresAt > now)
            case .expired?:
                q = q.group(.or) { or in
                    or.filter(\.$status == ApprovalRequestStatus.expired.rawValue)
                    or.group(.and) { $0.filter(\.$status == ApprovalRequestStatus.pending.rawValue).filter(\.$expiresAt <= now) }
                }
            case .completed?: q = q.filter(\.$status ~~ [ApprovalRequestStatus.approved, .denied, .reported].map(\.rawValue))
            case nil: break
            }
            if let since = query.since {
                q = q.group(.or) { or in
                    or.filter(\.$createdAt > since)
                    or.filter(\.$decidedAt > since)
                    or.group(.and) { $0.filter(\.$expiresAt > since).filter(\.$expiresAt <= now) }
                }
            }
            return q
        }
        let (rows, full) = try await keyset(make, createdAt: \.createdAt, cursor: query.cursor, limit: limit)
        let freezes = ApproveFreezeService(db: db, ctx: ctx)
        var frozen: [UUID: Bool] = [:]
        var drafts: [Draft] = []
        for request in rows {
            guard let id = request.id else { continue }
            let pending = request.statusValue == .pending
            if pending {
                // While approvals are frozen the customer is not shown requests at all (§2.57).
                if frozen[request.relationshipId] == nil {
                    frozen[request.relationshipId] = try await freezes.frozenBy(consumerId: me, relationshipId: request.relationshipId) != nil
                }
                if frozen[request.relationshipId] == true { continue }
            }
            let status: AlertStatus
            switch request.statusValue {
            case .pending: status = request.expiresAt > now ? .pending : .expired
            case .approved, .denied, .reported: status = .completed
            case .expired: status = .expired
            case .cancelled, .locked: status = .cancelled
            case .unknown: status = .unknown
            }
            var target: AlertTarget?
            if pending, let device = principal.deviceId,
               let delivery = try await ApproveDeliveryRecord.query(on: db).filter(\.$requestId == id).filter(\.$deviceId == device.uuid)
                .filter(\.$consumerId == me).first(), let deliveryId = delivery.id {
                target = AlertTarget(kind: .approveDelivery, id: deliveryId.uuidString.lowercased())
            }
            let capability = Capability(rawValue: request.capability)
            let title: String
            switch capability {
            case .transactionApprove: title = "Approve a transaction"
            case .authChallenge: title = "Approve a sign-in"
            default: title = "Approval request"
            }
            drafts.append(Draft(alertId: AlertIdentifier.make(.approveRequest, id), eventId: AlertDescriptor.eventId(kind: "approve_request", id: id),
                                source: .approveRequest, businessId: request.businessId, purpose: .security, category: .approval,
                                urgency: AlertUrgency(risk: ActionRegistry.approval(for: capability)?.risk ?? .high), status: status, title: title,
                                expiresAt: request.expiresAt, actionRequired: true, canAct: true, createdAt: request.createdAt,
                                updatedAt: request.decidedAt ?? request.createdAt, target: target))
        }
        return (drafts, full)
    }

    private func verifications(scope: OrganizationScope, query: AlertQuery, limit: Int, now: Date) async throws -> (drafts: [Draft], full: Bool) {
        let me = scope.consumerId
        let businesses = Array(scope.own)
        guard !businesses.isEmpty else { return ([], false) }
        func make() -> QueryBuilder<VerificationRequestRecord> {
            var q = VerificationRequestRecord.query(on: db).filter(\.$consumerId == me).filter(\.$livemode == true).filter(\.$businessId ~~ businesses)
            switch query.status {
            case .pending?: q = q.filter(\.$status ~~ Self.openVerificationStatuses).filter(\.$expiresAt > now)
            case .expired?:
                q = q.group(.or) { or in
                    or.filter(\.$status == ConsumerVerificationStatus.expired.rawValue)
                    or.group(.and) { $0.filter(\.$status ~~ Self.openVerificationStatuses).filter(\.$expiresAt <= now) }
                }
            case .completed?: q = q.filter(\.$status ~~ Self.finishedVerificationStatuses)
            case nil: break
            }
            if let since = query.since {
                q = q.group(.or) { or in
                    or.filter(\.$createdAt > since)
                    or.filter(\.$decidedAt > since)
                    or.group(.and) { $0.filter(\.$expiresAt > since).filter(\.$expiresAt <= now) }
                }
            }
            return q
        }
        let (rows, full) = try await keyset(make, createdAt: \.createdAt, cursor: query.cursor, limit: limit)
        let drafts = rows.compactMap { record -> Draft? in
            guard let id = record.id else { return nil }
            let consumerStatus = record.consumerStatus
            let status: AlertStatus
            if consumerStatus.isOpen { status = record.expiresAt > now ? .pending : .expired } else {
                switch consumerStatus {
                case .expired: status = .expired
                case .cancelled: status = .cancelled
                default: status = .completed
                }
            }
            let title = record.capabilityValue == .ageMinimum ? "Confirm your age" : "Verify your identity"
            return Draft(alertId: AlertIdentifier.make(.verification, id), eventId: AlertDescriptor.eventId(kind: AlertSource.verification.rawValue, id: id),
                         source: .verification, businessId: record.businessId, purpose: .security, category: .verification, urgency: .timeSensitive,
                         status: status, title: title, expiresAt: record.expiresAt, actionRequired: true, canAct: true, createdAt: record.createdAt,
                         updatedAt: record.decidedAt ?? record.createdAt,
                         target: AlertTarget(kind: .verification, id: record.requestID.description))
        }
        return (drafts, full)
    }

    /// Profile requests from connected businesses (docs/PROFILES.md): the customer approves field by field in the app.
    private func profileRequests(scope: OrganizationScope, query: AlertQuery, limit: Int, now: Date) async throws -> (drafts: [Draft], full: Bool) {
        let me = scope.consumerId
        let businesses = Array(scope.own)
        guard !businesses.isEmpty else { return ([], false) }
        let pending = ProfileRequestStatus.pending.rawValue
        func make() -> QueryBuilder<ProfileRequestRecord> {
            var q = ProfileRequestRecord.query(on: db).filter(\.$consumerId == me).filter(\.$livemode == true).filter(\.$businessId ~~ businesses)
            switch query.status {
            case .pending?: q = q.filter(\.$status == pending).filter(\.$expiresAt > now)
            case .expired?:
                q = q.group(.or) { or in
                    or.filter(\.$status == ProfileRequestStatus.expired.rawValue)
                    or.group(.and) { $0.filter(\.$status == pending).filter(\.$expiresAt <= now) }
                }
            case .completed?: q = q.filter(\.$status ~~ [ProfileRequestStatus.answered.rawValue, ProfileRequestStatus.declined.rawValue])
            case nil: break
            }
            if let since = query.since {
                q = q.group(.or) { or in
                    or.filter(\.$createdAt > since)
                    or.filter(\.$answeredAt > since)
                    or.group(.and) { $0.filter(\.$expiresAt > since).filter(\.$expiresAt <= now) }
                }
            }
            return q
        }
        let (rows, full) = try await keyset(make, createdAt: \.createdAt, cursor: query.cursor, limit: limit)
        let drafts = rows.compactMap { record -> Draft? in
            guard let id = record.id else { return nil }
            let status: AlertStatus
            switch record.statusValue {
            case .pending: status = record.expiresAt > now ? .pending : .expired
            case .expired: status = .expired
            case .cancelled: status = .cancelled
            default: status = .completed
            }
            return Draft(alertId: AlertIdentifier.make(.profileRequest, id), eventId: AlertDescriptor.eventId(kind: AlertSource.profileRequest.rawValue, id: id),
                         source: .profileRequest, businessId: record.businessId, purpose: .accountService, category: .request, urgency: .normal,
                         status: status, title: "Wants to see profile details", expiresAt: record.expiresAt, actionRequired: true, canAct: true,
                         createdAt: record.createdAt, updatedAt: record.answeredAt ?? record.createdAt,
                         target: AlertTarget(kind: .profileRequest, id: id.uuidString.lowercased()))
        }
        return (drafts, full)
    }

    private func securityNotices(consumer: UUID, query: AlertQuery, limit: Int) async throws -> (drafts: [Draft], full: Bool) {
        if query.status == .expired { return ([], false) }
        func make() -> QueryBuilder<SecurityNoticeRecord> {
            var q = SecurityNoticeRecord.query(on: db).filter(\.$consumerId == consumer)
            switch query.status {
            case .pending?: q = q.filter(\.$dismissedAt == nil)
            case .completed?: q = q.filter(\.$dismissedAt != nil)
            default: break
            }
            if let since = query.since {
                q = q.group(.or) { or in
                    or.filter(\.$createdAt > since)
                    or.filter(\.$dismissedAt > since)
                }
            }
            return q
        }
        let (rows, full) = try await keyset(make, createdAt: \.createdAt, cursor: query.cursor, limit: limit)
        let drafts = rows.compactMap { notice -> Draft? in
            guard let id = notice.id else { return nil }
            let needsAction = notice.action != nil && notice.dismissedAt == nil
            return Draft(alertId: AlertIdentifier.make(.securityNotice, id), eventId: AlertDescriptor.eventId(kind: AlertSource.securityNotice.rawValue, id: id),
                         source: .securityNotice, businessId: nil, purpose: .security, category: .securityNotice,
                         urgency: needsAction ? .critical : .timeSensitive, status: notice.dismissedAt == nil ? .pending : .completed,
                         title: AlertTitles.clip(notice.message), expiresAt: nil, actionRequired: needsAction, canAct: true, createdAt: notice.createdAt,
                         updatedAt: notice.dismissedAt ?? notice.createdAt, target: AlertTarget(kind: .securityNotice, id: id.uuidString.lowercased()))
        }
        return (drafts, full)
    }
}
