import Fluent
import Foundation
import Vapor
import ViadereCore

/// Email to the people of a business: members by role plus the security contacts. Best effort (a failed send is logged by kind only and never
/// blocks the action that caused it); bodies never contain a secret.
struct Notifier {
    let db: any Database
    let ctx: ServerContext

    func recipients(businessId: UUID, roles: Set<OrgRole>, includeSecurityContacts: Bool) async -> [String] {
        var addresses = Set<String>()
        do {
            let members = try await OrgMembershipRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$removedAt == nil).all()
                .filter { OrgRole(rawValue: $0.role).map(roles.contains) ?? false }
            let users = try await DashboardUserRecord.query(on: db).filter(\.$id ~~ members.map(\.userId)).filter(\.$status == "active").all()
            for user in users {
                if let id = user.id, let email = try? ctx.cipher.openString(user.emailCiphertext, context: "dashboard_users.email", rowId: id) { addresses.insert(email) }
            }
            if includeSecurityContacts { for contact in try await SecuritySettings(db: db, ctx: ctx).contacts(businessId: businessId) { addresses.insert(contact) } }
        } catch {
            ctx.logger.warning("notification recipients unavailable", metadata: ["type": "\(type(of: error))"])
        }
        return addresses.sorted()
    }

    /// `topic` limits the mail to businesses subscribed to it (security alerts); `nil` always sends (contract and onboarding mail).
    func notifyBusiness(_ businessId: UUID, roles: Set<OrgRole>, includeSecurityContacts: Bool = true, topic: SecurityAlertTopic? = nil,
                        subject: String, text: String, kind: String) async {
        if let topic, let subscribed = try? await SecuritySettings(db: db, ctx: ctx).subscriptions(businessId: businessId), !subscribed.contains(topic) { return }
        for address in await recipients(businessId: businessId, roles: roles, includeSecurityContacts: includeSecurityContacts) {
            do { try await ctx.email.send(EmailMessage(to: address, subject: subject, text: text, kind: kind)) } catch {
                ctx.logger.warning("notification email failed", metadata: ["kind": "\(kind)"])
            }
        }
    }

    /// Stores an in-app notice for one consumer and pushes a generic alert to their devices (best effort). `kind` is a fixed vocabulary string.
    func notifyConsumer(_ consumerId: UUID, kind: String, message: String, subjectId: String? = nil) async {
        do { try await SecurityNoticeRecord(consumerId: consumerId, kind: kind, message: message, subjectId: subjectId, originDeviceId: nil, now: ctx.now).create(on: db) } catch {
            ctx.logger.warning("consumer notice could not be stored", metadata: ["kind": "\(kind)"])
        }
        await pushGeneric(to: consumerId, body: message)
    }

    func pushGeneric(to consumerId: UUID, body: String) async {
        let now = ctx.now
        do {
            let devices = try await DeviceRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$revokedAt == nil).all().filter { $0.kind == .app && !$0.isExpired(at: now) }
            let tokens = try await APNsTokenRecord.query(on: db).filter(\.$deviceId ~~ devices.compactMap(\.id)).filter(\.$invalidatedAt == nil).all()
            for token in tokens {
                if await ctx.apns.send(PushPayloadBuilder.securityNotice(body: body, token: token.record, topic: ctx.config.appBundleID)) == .tokenInvalid {
                    try await APNsTokenRecord.query(on: db).filter(\.$id == token.id!).set(\.$invalidatedAt, to: now).update()
                }
            }
        } catch {
            // Best effort.
        }
    }
}

/// G-9: an operator tells affected parties something (an incident, a key revocation, a capability switched off). Business notices go by email
/// to the owners, administrators and security contacts; consumer notices appear in the app's security notices and as a generic push. Large
/// audiences are delivered in batches by the background job, so the request that creates a notice never fans out inline.
struct OperatorNotices {
    let db: any Database
    let ctx: ServerContext

    enum Scope: String, CaseIterable, Sendable {
        case business
        case allBusinesses = "all_businesses"
        case consumersOfBusiness = "consumers_of_business"
        case allConsumers = "all_consumers"

        var audience: String { self == .business || self == .allBusinesses ? "business" : "consumer" }
    }

    static let batchSize = 200
    static let severities: Set<String> = ["info", "important", "critical"]

    @discardableResult
    func create(scope: Scope, businessId: UUID?, severity: String, title rawTitle: String, body rawBody: String, operatorId: UUID) async throws -> OperatorNoticeRecord {
        let title = rawTitle.trimmingCharacters(in: .whitespacesAndNewlines)
        let body = rawBody.trimmingCharacters(in: .whitespacesAndNewlines)
        let limit = scope.audience == "consumer" ? 300 : 2000
        guard (3...100).contains(title.count), (10...limit).contains(body.count), Self.severities.contains(severity),
              !(title + body).unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) && $0 != "\n" }) else {
            throw APIError.validation("Give a title (3-100 characters) and a message (10-\(limit) characters).", details: ["notice": "invalid"])
        }
        if scope == .business || scope == .consumersOfBusiness {
            guard let businessId, try await BusinessRecord.find(businessId, on: db) != nil else { throw APIError.notFound }
        }
        let record = OperatorNoticeRecord()
        record.id = UUID()
        record.audience = scope.audience
        record.scope = scope.rawValue
        record.businessId = scope == .business || scope == .consumersOfBusiness ? businessId : nil
        record.severity = severity
        record.title = title
        record.body = body
        record.createdBy = operatorId.uuidString.lowercased()
        record.createdAt = ctx.now
        record.status = "queued"
        record.delivered = 0
        try await record.create(on: db)
        _ = try await AuditService(db: db, ctx: ctx).record("operator.notice_created", actor: AuditActor(kind: .operator_, id: operatorId.uuidString.lowercased()),
            businessId: record.businessId.map(BusinessID.init), subjectType: "operator_notice", subjectId: record.id?.uuidString.lowercased(),
            metadata: ["scope": scope.rawValue, "severity": severity])
        return record
    }

    /// Delivers the next batch of every open notice. Returns the recipients reached.
    @discardableResult
    func deliverDue() async throws -> Int {
        var reached = 0
        for notice in try await OperatorNoticeRecord.query(on: db).filter(\.$status != "done").sort(\.$createdAt, .ascending).limit(5).all() {
            reached += try await deliver(notice)
        }
        return reached
    }

    private func deliver(_ notice: OperatorNoticeRecord) async throws -> Int {
        let notifier = Notifier(db: db, ctx: ctx)
        let after = notice.cursor.flatMap(UUID.init(uuidString:))
        var count = 0
        var lastId: UUID?
        switch Scope(rawValue: notice.scope) {
        case .business:
            if let id = notice.businessId {
                await notifier.notifyBusiness(id, roles: [.owner, .orgAdmin, .securityAdmin], subject: notice.title, text: notice.body, kind: "operator-notice")
                count = 1
            }
        case .allBusinesses:
            var query = BusinessRecord.query(on: db).filter(\.$verificationStatus == VerificationStatus.verified.rawValue).sort(\.$id, .ascending).limit(Self.batchSize)
            if let after { query = query.filter(\.$id > after) }
            for business in try await query.all() {
                guard let id = business.id else { continue }
                await notifier.notifyBusiness(id, roles: [.owner, .orgAdmin, .securityAdmin], subject: notice.title, text: notice.body, kind: "operator-notice")
                lastId = id
                count += 1
            }
            if count == Self.batchSize { notice.cursor = lastId?.uuidString.lowercased() } else { notice.cursor = nil }
        case .consumersOfBusiness, .allConsumers:
            var consumers: [UUID]
            if notice.scope == Scope.consumersOfBusiness.rawValue, let businessId = notice.businessId {
                var query = RelationshipRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$status == "active").sort(\.$consumerId, .ascending).limit(Self.batchSize)
                if let after { query = query.filter(\.$consumerId > after) }
                consumers = try await query.all().map(\.consumerId)
            } else {
                var query = ConsumerRecord.query(on: db).filter(\.$status == "active").sort(\.$id, .ascending).limit(Self.batchSize)
                if let after { query = query.filter(\.$id > after) }
                consumers = try await query.all().compactMap(\.id)
            }
            for consumer in consumers {
                await notifier.notifyConsumer(consumer, kind: "operator_notice", message: notice.body, subjectId: notice.id?.uuidString.lowercased())
                lastId = consumer
                count += 1
            }
            if count == Self.batchSize { notice.cursor = lastId?.uuidString.lowercased() } else { notice.cursor = nil }
        case nil:
            notice.status = "done"
            try await notice.update(on: db)
            return 0
        }
        notice.delivered += count
        notice.status = notice.cursor == nil ? "done" : "sending"
        try await notice.update(on: db)
        if notice.status == "done" {
            _ = try await AuditService(db: db, ctx: ctx).record("operator.notice_delivered", actor: AuditActor(kind: .system), businessId: notice.businessId.map(BusinessID.init),
                subjectType: "operator_notice", subjectId: notice.id?.uuidString.lowercased(), metadata: ["recipients": String(notice.delivered)])
        }
        return count
    }

    /// Notices a business can see under Support > Incident notices: those addressed to everyone or to it.
    func visibleToBusiness(_ businessId: UUID, limit: Int = 20) async throws -> [OperatorNoticeRecord] {
        try await OperatorNoticeRecord.query(on: db).filter(\.$audience == "business")
            .group(.or) { $0.filter(\.$businessId == nil); $0.filter(\.$businessId == businessId) }
            .sort(\.$createdAt, .descending).limit(limit).all()
    }
}
