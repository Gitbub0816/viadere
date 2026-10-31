import Fluent
import Foundation
import ViadereCore

/// Tenant export and deletion requests (Compliance > Data requests, LEG-PR-004 for business accounts).
///
/// An **export** is built immediately from the organization's own records (profile, team, credential metadata, webhooks, domains, agreements,
/// settings, audit events, usage totals; never a secret and never customer-level data), sealed at rest, downloadable for 24 hours by an Owner or
/// Organization Admin after a fresh passkey assertion. A **deletion** is requested by an Owner and carried out by a Viadere operator after review
/// (it ends the organization: keys, webhooks, team and contact data go; handles and codes stay reserved; the audit chain follows its retention).
struct TenantDataRequests {
    let db: any Database
    let ctx: ServerContext

    static let exportLifetime: TimeInterval = 24 * 3600
    static let sealContext = "data_requests.artifact"

    func list(businessId: UUID) async throws -> [DataRequestRecord] {
        try await DataRequestRecord.query(on: db).filter(\.$businessId == businessId).sort(\.$createdAt, .descending).limit(50).all()
    }

    func requestExport(businessId: UUID, by userId: UUID) async throws -> UUID {
        guard try await DataRequestRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$kind == "export")
            .filter(\.$createdAt > ctx.now.addingTimeInterval(-86_400)).count() < 3 else { throw APIError.rateLimited(retryAfter: 3600) }
        let document = try await self.document(businessId: businessId)
        let data = try JSONSerialization.data(withJSONObject: document, options: [.sortedKeys, .withoutEscapingSlashes])
        let record = DataRequestRecord()
        record.id = UUID()
        record.businessId = businessId
        record.kind = "export"
        record.status = "ready"
        record.requestedBy = userId
        record.createdAt = ctx.now
        record.artifact = try ctx.cipher.seal(data, context: Self.sealContext, rowId: record.id!)
        record.artifactExpiresAt = ctx.now.addingTimeInterval(Self.exportLifetime)
        try await record.create(on: db)
        _ = try await AuditService(db: db, ctx: ctx).record("tenant.export_requested", actor: AuditActor(kind: .business, id: userId.uuidString.lowercased()),
            businessId: BusinessID(businessId), subjectType: "data_request", subjectId: record.id?.uuidString.lowercased())
        return record.id!
    }

    func download(id: UUID, businessId: UUID, by actor: AuditActor) async throws -> Data {
        guard let record = try await DataRequestRecord.query(on: db).filter(\.$id == id).filter(\.$businessId == businessId).filter(\.$kind == "export").first(),
              record.status == "ready", let expires = record.artifactExpiresAt, expires > ctx.now, let sealed = record.artifact else { throw APIError.gone("This export is no longer available.") }
        let data = try ctx.cipher.open(sealed, context: Self.sealContext, rowId: id)
        record.downloadedAt = ctx.now
        try await record.update(on: db)
        _ = try await AuditService(db: db, ctx: ctx).record("tenant.export_downloaded", actor: actor, businessId: BusinessID(businessId), subjectType: "data_request", subjectId: id.uuidString.lowercased())
        return data
    }

    func requestDeletion(businessId: UUID, confirmation: String, by userId: UUID) async throws {
        guard confirmation.trimmingCharacters(in: .whitespaces) == "DELETE" else {
            throw APIError.validation("Type DELETE to confirm.", details: ["confirmation": "mismatch"])
        }
        guard try await DataRequestRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$kind == "delete").filter(\.$status == "requested").count() == 0 else {
            throw APIError.conflict("A deletion request is already waiting for review.")
        }
        let record = DataRequestRecord()
        record.id = UUID()
        record.businessId = businessId
        record.kind = "delete"
        record.status = "requested"
        record.requestedBy = userId
        record.createdAt = ctx.now
        try await record.create(on: db)
        _ = try await AuditService(db: db, ctx: ctx).record("tenant.deletion_requested", actor: AuditActor(kind: .business, id: userId.uuidString.lowercased()),
            businessId: BusinessID(businessId), subjectType: "data_request", subjectId: record.id?.uuidString.lowercased())
    }

    // MARK: Operator

    func openDeletions() async throws -> [DataRequestRecord] {
        try await DataRequestRecord.query(on: db).filter(\.$kind == "delete").filter(\.$status == "requested").sort(\.$createdAt, .ascending).all()
    }

    func reject(id: UUID, note: String, operatorId: UUID) async throws {
        guard let record = try await DataRequestRecord.find(id, on: db), record.status == "requested" else { throw APIError.notFound }
        record.status = "rejected"
        record.decidedBy = operatorId.uuidString.lowercased()
        record.decidedAt = ctx.now
        record.note = String(note.prefix(300))
        try await record.update(on: db)
        _ = try await AuditService(db: db, ctx: ctx).record("tenant.deletion_rejected", outcome: .denied, actor: AuditActor(kind: .operator_, id: operatorId.uuidString.lowercased()),
            businessId: BusinessID(record.businessId), subjectType: "data_request", subjectId: id.uuidString.lowercased())
    }

    /// Ends the organization's data (an operator action after review). Keys are revoked, webhooks and their deliveries removed, the team removed and
    /// signed out, domains, certificates, contacts and support text deleted, the business revoked and renamed. Handles and codes are never released.
    func complete(id: UUID, operatorId: UUID) async throws {
        guard let record = try await DataRequestRecord.find(id, on: db), record.kind == "delete", record.status == "requested" else { throw APIError.notFound }
        let businessId = record.businessId
        // A legal hold on this organization (or on everything) outranks a deletion request: the request stays open until the hold is released.
        let holds = try await RetentionPolicy(db: db, ctx: ctx).activeHolds()
        guard !holds.global, !holds.businesses.contains(businessId) else {
            throw APIError.conflict("A legal hold is active, so this organization's data cannot be deleted yet. Release the hold first.")
        }
        let now = ctx.now
        try await APIKeyLifecycle(db: db, ctx: ctx).revokeAll(businessId: businessId, live: nil, reason: "organization deletion", actor: .operatorUser(operatorId))
        try await db.transaction { tx in
            let hooks = try await WebhookSubscriptionRecord.query(on: tx).filter(\.$businessId == businessId).all().compactMap(\.id)
            let deliveries = try await WebhookDeliveryRecord.query(on: tx).filter(\.$businessId == businessId).all().compactMap(\.id)
            if !deliveries.isEmpty { try await WebhookAttemptRecord.query(on: tx).filter(\.$deliveryId ~~ deliveries).delete() }
            try await WebhookDeliveryRecord.query(on: tx).filter(\.$businessId == businessId).delete()
            if !hooks.isEmpty { try await WebhookSubscriptionRecord.query(on: tx).filter(\.$id ~~ hooks).delete() }
            try await BusinessDomainRecord.query(on: tx).filter(\.$businessId == businessId).delete()
            try await BusinessMTLSCertRecord.query(on: tx).filter(\.$businessId == businessId).delete()
            try await BusinessSecuritySettingsRecord.query(on: tx).filter(\.$businessId == businessId).delete()
            try await SupportTicketRecord.query(on: tx).filter(\.$businessId == businessId).delete()
            try await PendingChangeRecord.query(on: tx).filter(\.$businessId == businessId).delete()
            try await BusinessSurfaceRecord.query(on: tx).filter(\.$businessId == businessId).delete()
            try await LoopTenantData.delete(businessId: businessId, on: tx)
            try await OrgInviteRecord.query(on: tx).filter(\.$businessId == businessId).filter(\.$state == "open").set(\.$state, to: "revoked").update()
            let members = try await OrgMembershipRecord.query(on: tx).filter(\.$businessId == businessId).filter(\.$removedAt == nil).all()
            for member in members { member.removedAt = now; try await member.update(on: tx) }
            try await DashboardSessionRecord.query(on: tx).filter(\.$businessId == businessId).filter(\.$revokedAt == nil).set(\.$revokedAt, to: now).update()
            if let business = try await BusinessRecord.find(businessId, on: tx) {
                business.displayName = "Deleted business"
                business.legalName = nil
                business.websiteURL = nil
                business.logoURL = nil
                business.searchText = ""
                business.verificationStatus = VerificationStatus.revoked.rawValue
                try await business.update(on: tx)
            }
            record.status = "completed"
            record.decidedBy = operatorId.uuidString.lowercased()
            record.decidedAt = now
            record.completedAt = now
            try await record.update(on: tx)
            _ = try await AuditService(db: tx, ctx: ctx).record("tenant.deleted", actor: AuditActor(kind: .operator_, id: operatorId.uuidString.lowercased()),
                businessId: BusinessID(businessId), subjectType: "data_request", subjectId: id.uuidString.lowercased(), metadata: ["members_removed": String(members.count)])
        }
    }

    // MARK: Export document

    func document(businessId: UUID) async throws -> [String: Any] {
        guard let business = try await BusinessRecord.find(businessId, on: db) else { throw APIError.notFound }
        let iso = { (date: Date?) -> Any in date.map { ViadereDate.format($0) } ?? NSNull() }
        var out: [String: Any] = ["format": "viadere-tenant-export-v1", "generatedAt": ViadereDate.format(ctx.now)]
        let summary = try await DirectoryService(db: db).summary(for: business)
        out["organization"] = ["id": businessId.uuidString.lowercased(), "displayName": business.displayName, "legalName": (business.legalName as Any?) ?? NSNull(), "category": business.category,
                               "status": business.verificationStatus, "handle": (summary?.handle?.display as Any?) ?? NSNull(), "code": (summary?.code.display as Any?) ?? NSNull(), "createdAt": iso(business.createdAt)]
        let members = try await OrgMembershipRecord.query(on: db).filter(\.$businessId == businessId).all()
        let users = try await DashboardUserRecord.query(on: db).filter(\.$id ~~ members.map(\.userId)).all()
        let byId = Dictionary(users.compactMap { u in u.id.map { ($0, u) } }, uniquingKeysWith: { a, _ in a })
        out["team"] = members.map { m -> [String: Any] in
            let user = byId[m.userId]
            let email = user.flatMap { try? ctx.cipher.openString($0.emailCiphertext, context: "dashboard_users.email", rowId: $0.id!) } ?? ""
            return ["name": user?.displayName ?? "", "email": email, "role": m.role, "joinedAt": iso(m.createdAt), "removedAt": iso(m.removedAt)]
        }
        let keys = try await BusinessAPIKeyRecord.query(on: db).filter(\.$businessId == businessId).all()
        out["apiKeys"] = keys.map { ["keyId": $0.kid ?? "…" + $0.last4, "name": $0.name, "mode": $0.livemode ? "live" : "test", "scopes": $0.scopes, "capabilities": $0.capabilities,
                                    "createdAt": iso($0.createdAt), "lastUsedAt": iso($0.lastUsedAt), "expiresAt": iso($0.expiresAt), "revokedAt": iso($0.revokedAt)] }
        let hooks = try await WebhookSubscriptionRecord.query(on: db).filter(\.$businessId == businessId).all()
        out["webhooks"] = hooks.map { ["url": $0.url, "events": $0.events, "active": $0.active, "verifiedAt": iso($0.verifiedAt), "pausedAt": iso($0.pausedAt), "createdAt": iso($0.createdAt)] }
        out["domains"] = try await BusinessDomainRecord.query(on: db).filter(\.$businessId == businessId).all().map { ["domain": $0.domain, "status": $0.status, "verifiedAt": iso($0.verifiedAt)] }
        out["agreements"] = try await ContractAcceptanceRecord.query(on: db).filter(\.$businessId == businessId).all().map { ["document": $0.slug, "version": $0.version, "acceptedAt": iso($0.acceptedAt), "by": $0.acceptedBy.uuidString.lowercased()] }
        if let settings = try await SecuritySettings(db: db, ctx: ctx).existing(businessId: businessId) {
            out["security"] = ["consoleIPAllowlist": settings.consoleIPAllowlist, "privilegedInactivitySeconds": settings.privilegedInactivitySeconds, "twoPersonRequired": settings.twoPersonRequired,
                               "mtlsRequired": settings.mtlsRequired, "alertSubscriptions": settings.alertSubscriptions]
        }
        let events = try await AuditEventRecord.query(on: db).filter(\.$businessId == businessId).sort(\.$seq, .descending).limit(10_000).all()
        // The same projection as the dashboard: a consumer is this business's subject_ref, Verify events carry no oracle (AGE-005).
        out["auditEvents"] = BusinessAuditProjection(ctx: ctx).project(events).map {
            ["at": iso($0.occurredAt), "action": $0.action, "outcome": $0.outcome, "actor": ($0.actorId as Any?) ?? NSNull(), "subject": ($0.subjectId as Any?) ?? NSNull()]
        }
        let relationships = try await RelationshipRecord.query(on: db).filter(\.$businessId == businessId).all()
        out["customers"] = ["connected": relationships.filter { $0.status == "active" }.count, "disconnected": relationships.filter { $0.status != "active" }.count]
        // Hosted Loops (WP-3.4): this tenant's definitions, revisions and inbox items with what customers entered; every query is scoped to
        // `businessId`. Customers appear only as the instance id (no account id, no contact data).
        let loopDefinitions = try await LoopDefinitionRecord.query(on: db).filter(\.$businessId == businessId).all()
        let loopRevisions = try await LoopRevisionRecord.query(on: db).filter(\.$businessId == businessId).all()
        out["loops"] = loopDefinitions.map { definition -> [String: Any] in
            ["key": definition.key, "revisions": loopRevisions.filter { $0.definitionId == definition.id }.sorted { $0.revision < $1.revision }.map {
                ["revision": $0.revision, "state": $0.state, "definitionHash": $0.definitionHash, "submittedAt": iso($0.createdAt)] as [String: Any]
            }]
        }
        let runtime = LoopRuntimeService(db: db, ctx: ctx)
        var inbox: [[String: Any]] = []
        for item in try await InboxItemRecord.query(on: db).filter(\.$businessId == businessId).sort(\.$createdAt, .ascending).all() {
            guard let event = try await LoopActionEventRecord.query(on: db).filter(\.$id == item.eventId).filter(\.$businessId == businessId).first() else { continue }
            let events = try await LoopActionEventRecord.query(on: db).filter(\.$instanceId == item.instanceId).filter(\.$businessId == businessId).all()
            var answers: [String: Any] = [:]
            for e in events { for (key, value) in runtime.inputs(of: e) { answers["\(e.stepId).\(key)"] = LoopInbox.describe(value, field: nil) } }
            let outcome = try await runtime.currentOutcome(eventId: event.id!)
            inbox.append(["item": item.id!.uuidString.lowercased(), "instance": item.instanceId.uuidString.lowercased(), "queue": item.queueKey, "state": item.state,
                          "receivedAt": iso(item.createdAt), "closedAt": iso(item.closedAt), "outcome": outcome?.outcome ?? NSNull(), "answers": answers])
        }
        out["inbox"] = inbox
        return out
    }
}

/// Support tickets and appeals (Support section). A ticket is a stored record plus an email notice; the body is sealed at rest.
struct SupportDesk {
    let db: any Database
    let ctx: ServerContext

    static let kinds: Set<String> = ["ticket", "appeal"]

    func list(businessId: UUID) async throws -> [SupportTicketRecord] {
        try await SupportTicketRecord.query(on: db).filter(\.$businessId == businessId).sort(\.$createdAt, .descending).limit(50).all()
    }

    @discardableResult
    func open(businessId: UUID, kind: String, subject rawSubject: String, body rawBody: String, by userId: UUID) async throws -> SupportTicketRecord {
        let subject = rawSubject.trimmingCharacters(in: .whitespacesAndNewlines)
        let body = rawBody.trimmingCharacters(in: .whitespacesAndNewlines)
        guard Self.kinds.contains(kind), (3...120).contains(subject.count), (10...4000).contains(body.count),
              !(subject + body).unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) && $0 != "\n" && $0 != "\r" && $0 != "\t" }) else {
            throw APIError.validation("Give a subject (3-120 characters) and describe the problem (at least 10 characters).", details: ["ticket": "invalid"])
        }
        guard await ctx.limiter.allow("support-ticket", key: businessId.uuidString.lowercased(), rule: .perHour(10, burst: 5)) else { throw APIError.rateLimited(retryAfter: 600) }
        let record = SupportTicketRecord()
        record.id = UUID()
        record.businessId = businessId
        record.kind = kind
        record.subject = subject
        record.bodyCiphertext = try ctx.cipher.seal(body, context: "support_tickets.body", rowId: record.id!)
        record.status = "open"
        record.createdBy = userId
        record.createdAt = ctx.now
        record.updatedAt = ctx.now
        try await record.create(on: db)
        // Emails carry the reference and the subject line only, never the body.
        let reference = String(record.id!.uuidString.lowercased().prefix(8))
        if let user = try await DashboardUserRecord.find(userId, on: db), let email = try? ctx.cipher.openString(user.emailCiphertext, context: "dashboard_users.email", rowId: userId) {
            try? await ctx.email.send(EmailMessage(to: email, subject: "We received your \(kind == "appeal" ? "appeal" : "request") (\(reference))",
                text: "Your \(kind == "appeal" ? "appeal" : "support request") was recorded with reference \(reference). A Viadere team member will reply by email.", kind: "support-receipt"))
        }
        if let notify = ctx.config.operations.supportEmail {
            try? await ctx.email.send(EmailMessage(to: notify, subject: "[\(kind)] \(subject.prefix(80)) (\(reference))",
                text: "A business opened a \(kind) (reference \(reference)). Open the operator console > Data and retention > Support to read it.", kind: "support-operator"))
        }
        return record
    }

    func body(of ticket: SupportTicketRecord) -> String {
        (try? ctx.cipher.openString(ticket.bodyCiphertext, context: "support_tickets.body", rowId: ticket.id!)) ?? ""
    }

    func respond(id: UUID, note: String, close: Bool, operatorId: UUID) async throws {
        guard let ticket = try await SupportTicketRecord.find(id, on: db) else { throw APIError.notFound }
        ticket.operatorNote = String(note.trimmingCharacters(in: .whitespacesAndNewlines).prefix(1000))
        ticket.status = close ? "closed" : "answered"
        ticket.decidedBy = operatorId.uuidString.lowercased()
        ticket.updatedAt = ctx.now
        try await ticket.update(on: db)
        _ = try await AuditService(db: db, ctx: ctx).record("support.responded", actor: AuditActor(kind: .operator_, id: operatorId.uuidString.lowercased()),
            businessId: BusinessID(ticket.businessId), subjectType: "ticket", subjectId: id.uuidString.lowercased(), metadata: ["status": ticket.status])
        await Notifier(db: db, ctx: ctx).notifyBusiness(ticket.businessId, roles: [.owner], includeSecurityContacts: false, subject: "Viadere replied to your \(ticket.kind)",
            text: "There is a reply to your \(ticket.kind) in the console under Support.", kind: "support-reply")
    }
}
