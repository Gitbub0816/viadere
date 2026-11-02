import Fluent
import Foundation
import SQLKit
import ViadereCore

/// The sealed P-class payload of an open delivery. Never logged, never in a webhook, never returned to a business.
struct AuthSecretPayload: Codable, Sendable {
    var url: String?
    var code: String?
    var variables: [String: String]?
}

/// The business side of authentication delivery and the state machine (ADR-0020). The tenant is always the API key's business; every query filters by it.
struct AuthDeliveryService {
    let db: any Database
    let ctx: ServerContext

    var settings: AuthDeliverySettings { ctx.config.authDelivery }

    // MARK: Views

    func effectiveStatus(_ row: AuthDeliveryRecord) -> AuthDeliveryStatus {
        let status = row.statusValue
        return !status.isTerminal && row.expiresAt <= ctx.now ? .expired : status
    }

    func view(_ row: AuthDeliveryRecord, withEvents: Bool = false) async throws -> AuthDeliveryView {
        var events: [AuthDeliveryEventView]?
        if withEvents {
            events = try await AuthDeliveryEventRecord.query(on: db).filter(\.$deliveryId == row.id!).sort(\.$at, .ascending).all()
                .map { AuthDeliveryEventView(status: AuthDeliveryStatus(rawValue: $0.status) ?? .failed, at: $0.at, reason: $0.reason) }
        }
        return AuthDeliveryView(id: row.wireId, requestId: row.requestId, method: row.methodValue, purpose: row.purposeValue, status: effectiveStatus(row),
                                expiresAt: row.expiresAt, createdAt: row.createdAt, correlationId: row.correlationId, clientTransactionRef: row.clientTransactionRef,
                                reason: row.reason, events: events)
    }

    // MARK: Business credentials

    /// A live key needs mutual TLS on auth routes (ADR-0020 section 3) until request signatures exist; never a bearer alone. Test keys are exempt (sandbox only).
    func requireLiveKeyAssurance(_ principal: BusinessPrincipal) async throws {
        guard principal.livemode, settings.liveKeyAssurance == .mtls else { return }
        let key = try await BusinessAPIKeyRecord.find(principal.keyId, on: db)
        let tenant = try await BusinessSecuritySettingsRecord.query(on: db).filter(\.$businessId == principal.businessId.uuid).first()
        guard key?.requiresMTLS == true || tenant?.mtlsRequired == true else {
            throw APIError(.unauthorized, .signatureRequired, "Live keys need mutual TLS on authentication delivery routes.")
        }
    }

    /// The tenant's own delivery, or `404` (the same body for an unknown and for another tenant's id; the cross-tenant attempt is audited).
    func record(id: AuthDeliveryID, principal: BusinessPrincipal) async throws -> AuthDeliveryRecord {
        guard let row = try await AuthDeliveryRecord.find(id.uuid, on: db) else { throw APIError.notFound }
        guard row.businessId == principal.businessId.uuid, row.livemode == principal.livemode else {
            if row.businessId != principal.businessId.uuid {
                _ = try? await AuditService(db: db, ctx: ctx).record("auth_delivery.cross_tenant_refused", outcome: .denied,
                    actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()), businessId: principal.businessId,
                    subjectType: "auth_delivery", subjectId: id.description)
            }
            throw APIError.notFound
        }
        return row
    }

    // MARK: Create

    static func notDeliverable() -> APIError {
        APIError(.notFound, .notDeliverable, "This customer cannot receive this delivery.")
    }

    /// Everything decided before the transaction (reads and budgets).
    struct Plan: Sendable {
        var relationshipId: UUID
        var consumerId: UUID
        var sandbox: Bool
        var silent: Bool
        var lifetime: Int
        var channels: [AuthDeliveryChannel]
        var destination: AuthDestinationCheck.Result?
        var callback: UUID?
    }

    func create(principal: BusinessPrincipal, body: Data, key: String) async throws -> (value: AuthDeliveryView, created: Bool) {
        try await requireLiveKeyAssurance(principal)
        let request: AuthDeliveryCreateRequest
        switch AuthDeliveryValidation.decodeCreate(body) {
        case .request(let decoded): request = decoded
        case .invalid(let issue): throw APIError.validation("The request failed validation.", details: [issue.field: issue.code])
        }
        // Business-level policy first: a key that may not use the capability learns nothing about the customer.
        let policy = PolicyService(db: db, ctx: ctx)
        try await policy.enforce(PolicyInput(.authChallenge), principal: principal, auditAllowed: false)
        let hash = SecureToken.sha256Hex(Data("auth_delivery.create\n".utf8) + (try ViadereJSON.encode(request)))
        let businessId = principal.businessId
        if let existing = try await AuthDeliveryRecord.query(on: db).filter(\.$businessId == businessId.uuid).filter(\.$requestId == request.requestId).first() {
            guard ConstantTime.equals(existing.requestHash, hash) else {
                throw APIError(.conflict, .idempotencyConflict, "This request_id was already used with a different request.")
            }
            return (try await view(existing), false)
        }
        try await ctx.limiter.enforce("authdl-tenant", key: businessId.description, rule: settings.tenantRate)
        let plan = try await prepare(principal: principal, request: request)
        let ctx = self.ctx
        do {
            return try await BusinessIdempotency(db: db, ctx: ctx).once(
                businessId: businessId.uuid, operation: .authDeliveryCreate, key: key, requestHash: hash, sealResult: false,
                perform: { tx in
                    let row = try await AuthDeliveryService(db: tx, ctx: ctx).insert(principal: principal, request: request, plan: plan, hash: hash)
                    return (try await AuthDeliveryService(db: tx, ctx: ctx).view(row), row.id)
                },
                replay: { record in
                    guard let id = record.resourceId, let row = try await AuthDeliveryRecord.find(id, on: self.db) else { throw APIError.notFound }
                    return try await self.view(row)
                })
        } catch {
            // Another request with the same `request_id` won the race.
            if error.isConstraintViolation, let existing = try await AuthDeliveryRecord.query(on: db).filter(\.$businessId == businessId.uuid)
                .filter(\.$requestId == request.requestId).first(), ConstantTime.equals(existing.requestHash, hash) {
                return (try await view(existing), false)
            }
            throw error
        }
    }

    func prepare(principal: BusinessPrincipal, request: AuthDeliveryCreateRequest) async throws -> Plan {
        let businessId = principal.businessId
        // 1. Input that does not depend on the customer.
        let channels = request.channels ?? [.push, .inbox]
        // Email fallback stays off in every environment until its gate is met (ADR-0020 section 7); there is no SMS member at all.
        guard !channels.contains(.email), request.fallback == nil else {
            throw APIError.validation("Email delivery is not available.", details: [request.fallback == nil ? "channels" : "fallback": "email_unavailable"])
        }
        let lifetime = request.expiresInSeconds ?? AuthDeliveryTemplate.defaultLifetime(for: request.method)
        let expiresAt = ctx.now.addingTimeInterval(TimeInterval(lifetime))
        var destination: AuthDestinationCheck.Result?
        if request.method == .magicLink, let requested = request.destination {
            destination = try await AuthDestinationCheck(db: db, ctx: ctx).validate(requested, request: request, businessId: businessId, expiresAt: expiresAt)
        }
        var callback: UUID?
        if let requested = request.callback {
            guard let sub = try await WebhookSubscriptionRecord.query(on: db).filter(\.$id == requested.webhookId.uuid).filter(\.$businessId == businessId.uuid)
                .filter(\.$active == true).first(), sub.signatureVersion == WebhookSignatureVersion.v2.rawValue, sub.envelopeVersion == WebhookEnvelopeV2.version else {
                throw APIError.validation("callback.webhook_id is not a v2 endpoint of your business.", details: ["callback.webhook_id": "unknown"])
            }
            callback = sub.id
        }
        // 2. The customer. Every failure below is the same `404 not_deliverable` (non-disclosure).
        let notDeliverable = Self.notDeliverable()
        let relationship: RelationshipRecord
        do { relationship = try await SubjectResolver(db: db, ctx: ctx).relationship(businessId: businessId, subjectRef: request.subjectRef) } catch { throw notDeliverable }
        guard relationship.isActive, let consumer = try await ConsumerRecord.find(relationship.consumerId, on: db), consumer.isSandbox != principal.livemode else { throw notDeliverable }
        let policy = PolicyService(db: db, ctx: ctx)
        let facts = try await policy.subjectFacts(relationship: relationship, capability: .authChallenge, interactionPurpose: .security)
        do {
            try await policy.enforce(PolicyInput(.authChallenge, subjectRef: request.subjectRef, purpose: InteractionPurpose.security.rawValue, requestId: request.requestId),
                                     principal: principal, stage: .full, subject: facts)
        } catch let error as APIError where [.consentRequired, .policyDenied, .insufficientAssurance].contains(error.code) { throw notDeliverable }
        do { try await ApproveFreezeService(db: db, ctx: ctx).requireNotFrozen(consumerId: relationship.consumerId, relationshipId: relationship.id!) } catch { throw notDeliverable }
        if !consumer.isSandbox {
            let now = ctx.now
            let devices = try await DeviceRecord.query(on: db).filter(\.$consumerId == relationship.consumerId).filter(\.$revokedAt == nil).all()
            guard devices.contains(where: { $0.kind == .app && !$0.isExpired(at: now) }) else { throw notDeliverable }
        }
        // 3. Budgets limit alerting, never availability (S1-A2-6): over a budget the delivery is still created, but silent.
        let scope = "\(businessId.description)|\(relationship.consumerId.uuidString.lowercased())"
        let burst = await ctx.limiter.allow("authdl-subject", key: scope, rule: settings.subjectBurstRate)
        let daily = await ctx.limiter.allow("authdl-subject-day", key: scope, rule: settings.subjectDailyRate)
        var silent = !(burst && daily)
        if try await reportedDenials(businessId: businessId.uuid, consumerId: relationship.consumerId) >= settings.reportThreshold { silent = true }
        return Plan(relationshipId: relationship.id!, consumerId: relationship.consumerId, sandbox: consumer.isSandbox, silent: silent, lifetime: lifetime, channels: channels,
                    destination: destination, callback: callback)
    }

    /// "This wasn't me" reports for one (business, customer) inside the window. A `destination_unverified` denial is an integrity signal about the business's
    /// link, not the customer's answer to a prompt, so it never counts (ADR-0020 section 5, revision 3). The count only makes alerts quiet; it never refuses.
    func reportedDenials(businessId: UUID, consumerId: UUID) async throws -> Int {
        let since = ctx.now.addingTimeInterval(-settings.reportWindow)
        return try await AuthDeliveryRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$consumerId == consumerId)
            .filter(\.$status == AuthDeliveryStatus.denied.rawValue).filter(\.$reason == "reported").filter(\.$endedAt > since).count()
    }

    /// Inside the create transaction: the row, the sealed secret, the events, the outbox rows, the webhook event and the audit record commit together.
    func insert(principal: BusinessPrincipal, request: AuthDeliveryCreateRequest, plan: Plan, hash: String) async throws -> AuthDeliveryRecord {
        let now = ctx.now
        let row = AuthDeliveryRecord()
        row.id = UUID()
        row.businessId = principal.businessId.uuid
        row.requestId = request.requestId
        row.requestHash = hash
        row.relationshipId = plan.relationshipId
        row.consumerId = plan.consumerId
        row.apiKeyId = principal.keyId
        row.livemode = principal.livemode
        row.method = request.method.rawValue
        row.purpose = request.purpose.rawValue
        row.template = request.template
        // created -> validated -> queued happen in this one transaction (invalid requests were refused and never persisted).
        row.status = AuthDeliveryStatus.queued.rawValue
        row.version = 2
        row.channels = plan.channels.map(\.rawValue).joined(separator: ",")
        row.silent = plan.silent
        row.callbackWebhookId = plan.callback
        row.correlationId = request.correlationId
        row.clientTransactionRef = request.clientTransactionRef
        row.sessionHandle = request.sessionHandle
        row.dispatchAttempts = 0
        row.createdAt = now
        row.expiresAt = now.addingTimeInterval(TimeInterval(plan.lifetime))
        if let variables = request.variables, !variables.isEmpty {
            row.variablesSHA256 = SecureToken.sha256Hex(try CanonicalJSON.serialize(.object(variables.mapValues { .string($0) })))
        }
        if let destination = plan.destination {
            row.destinationHost = destination.host
            row.destinationStatement = destination.statement.isEmpty ? nil : destination.statement
        }
        row.codeKind = request.otp?.codeKind.rawValue
        try await row.create(on: db)
        let payload = AuthSecretPayload(url: plan.destination?.url, code: request.otp?.code, variables: request.variables)
        if payload.url != nil || payload.code != nil || !(payload.variables ?? [:]).isEmpty {
            let secret = AuthDeliverySecretRecord()
            secret.id = row.id
            secret.ciphertext = try settings.cipher.seal(try ViadereJSON.encode(payload), context: AuthDeliverySecretRecord.sealContext, rowId: row.id!)
            secret.keyId = settings.secretKeyId
            secret.expiresAt = row.expiresAt
            try await secret.create(on: db)
        }
        for status in [AuthDeliveryStatus.created, .validated, .queued] { try await writeEvent(row, status, reason: nil, actor: .api) }
        try await AuthDeliveryGrouping(db: db, ctx: ctx).applyOnCreate(new: row, sessionHandle: request.sessionHandle)
        try await Outbox.enqueue(QueueHandlers.authDeliveryDispatch, ref: row.id!, tenant: row.businessId, on: db, ctx: ctx)
        try await Outbox.enqueue(QueueHandlers.authDeliveryExpire, ref: row.id!, tenant: row.businessId, notBefore: row.expiresAt, on: db, ctx: ctx)
        try await emitWebhook(row, status: .created, reason: nil)
        // Audit: ids, method and purpose only. Never a URL, a code, a variable or a customer reference.
        _ = try await AuditService(db: db, ctx: ctx).record("auth_delivery.created", actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()),
            consumerId: ConsumerID(row.consumerId), businessId: principal.businessId, subjectType: "auth_delivery", subjectId: row.wireId.description,
            correlationId: request.correlationId, metadata: ["method": row.method, "purpose": row.purpose, "template": row.template, "silent": plan.silent ? "true" : "false"])
        return row
    }

    // MARK: State machine

    func writeEvent(_ row: AuthDeliveryRecord, _ status: AuthDeliveryStatus, reason: String?, actor: AuthDeliveryActor) async throws {
        let event = AuthDeliveryEventRecord()
        event.id = UUID()
        event.deliveryId = row.id!
        event.businessId = row.businessId
        event.status = status.rawValue
        event.reason = reason
        event.actor = actor.rawValue
        event.at = ctx.now
        try await event.create(on: db)
    }

    /// The opaque webhook event: ids only (`request_id` = the delivery id), no URL, code, variable or customer reference.
    func emitWebhook(_ row: AuthDeliveryRecord, status: AuthDeliveryStatus, reason: String?) async throws {
        guard let name = AuthDeliveryEventName.forTransition(into: status) else { return }
        try await WebhookService(db: db, ctx: ctx).enqueue(WebhookEventType(rawValue: name.rawValue), businessId: BusinessID(row.businessId),
                                                           payload: AuthDeliveryEventPayload(deliveryId: row.wireId, status: status, reason: reason),
                                                           onlySubscription: row.callbackWebhookId, opaque: OpaqueWebhookEvent(requestId: row.wireId.description, resultRef: nil))
    }

    /// One transition: allowed by the table, then a compare-and-swap on `version` (a lost race changes nothing and returns `false`). The P-class secret is
    /// deleted in the same transaction when the delivery is opened or ends. One event row and one webhook event per transition.
    @discardableResult
    func transition(_ row: AuthDeliveryRecord, to status: AuthDeliveryStatus, by actor: AuthDeliveryActor, reason: String? = nil) async throws -> Bool {
        guard AuthDeliveryStateMachine.isAllowed(from: row.statusValue, to: status, by: actor), let id = row.id else { return false }
        let now = ctx.now
        var extra: [(String, any Encodable & Sendable)] = [("status", status.rawValue)]
        if let reason { extra.append(("reason", reason)) }
        if status == .delivered { extra.append(("delivered_at", now)) }
        if status == .opened { extra.append(("opened_at", now)) }
        if status.isTerminal { extra.append(("ended_at", now)) }
        guard try await DB.swap(db, table: AuthDeliveryRecord.schema, id: id, column: "version", expected: row.version, newValue: row.version + 1, extra: extra) else { return false }
        row.status = status.rawValue
        row.version += 1
        if let reason { row.reason = reason }
        if status == .delivered { row.deliveredAt = now }
        if status == .opened { row.openedAt = now }
        if status.isTerminal { row.endedAt = now }
        if status == .opened || status.isTerminal { try await AuthDeliverySecretRecord.query(on: db).filter(\.$id == id).delete() }
        if status.isTerminal { try await AuthMatchGroups(db: db, ctx: ctx).release(refId: id) }
        try await writeEvent(row, status, reason: reason, actor: actor)
        try await emitWebhook(row, status: status, reason: reason)
        return true
    }

    /// Ends a delivery whose `expires_at` has passed (the scheduled job and the sweep).
    @discardableResult
    func expireIfDue(_ row: AuthDeliveryRecord) async throws -> Bool {
        guard !row.statusValue.isTerminal, row.expiresAt <= ctx.now else { return false }
        let done = try await transition(row, to: .expired, by: .system)
        if done {
            _ = try? await AuditService(db: db, ctx: ctx).record("auth_delivery.expired", actor: AuditActor(kind: .system), consumerId: ConsumerID(row.consumerId),
                                                               businessId: BusinessID(row.businessId), subjectType: "auth_delivery", subjectId: row.wireId.description)
        }
        return done
    }

    // MARK: Business operations

    func cancel(principal: BusinessPrincipal, id: AuthDeliveryID) async throws -> AuthDeliveryView {
        let row = try await record(id: id, principal: principal)
        if !row.statusValue.isTerminal {
            if row.expiresAt <= ctx.now { try await expireIfDue(row) } else if try await transition(row, to: .cancelled, by: .business, reason: "cancelled_by_business") {
                _ = try await AuditService(db: db, ctx: ctx).record("auth_delivery.cancelled", actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()),
                    consumerId: ConsumerID(row.consumerId), businessId: principal.businessId, subjectType: "auth_delivery", subjectId: id.description)
            }
        }
        return try await view(try await record(id: id, principal: principal))
    }

    /// The business reports **its own** verification outcome. Only from `opened`: `sent`, `delivered` and `opened` never mean success.
    func complete(principal: BusinessPrincipal, id: AuthDeliveryID, outcome: AuthDeliveryOutcome) async throws -> AuthDeliveryView {
        let row = try await record(id: id, principal: principal)
        guard row.methodValue != .notice else { throw APIError.conflict("A security notice has no completion.") }
        let target: AuthDeliveryStatus = outcome == .succeeded ? .completed : .failed
        if row.statusValue == target { return try await view(row) }
        guard row.statusValue == .opened, row.expiresAt > ctx.now || row.openedAt != nil else { throw APIError.conflict("The customer has not opened this delivery.") }
        guard try await transition(row, to: target, by: .business, reason: outcome.rawValue) else { throw APIError.conflict("The delivery changed; read it again.") }
        _ = try await AuditService(db: db, ctx: ctx).record("auth_delivery.completed", actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()),
            consumerId: ConsumerID(row.consumerId), businessId: principal.businessId, subjectType: "auth_delivery", subjectId: id.description, metadata: ["outcome": outcome.rawValue])
        return try await view(try await record(id: id, principal: principal))
    }

    // MARK: Sweeps (safety net behind the scheduled expiry jobs; also retention)

    /// Expires due deliveries, deletes pending secrets that outlived their delivery, and removes metadata 30 days after the terminal state.
    @discardableResult
    func sweep() async throws -> Int {
        let now = ctx.now
        var changed = 0
        let due = try await AuthDeliveryRecord.query(on: db).filter(\.$status !~ AuthDeliveryStatus.allCases.filter(\.isTerminal).map(\.rawValue))
            .filter(\.$expiresAt <= now).limit(500).all()
        for row in due where try await expireIfDue(row) { changed += 1 }
        // P class: a secret never outlives its delivery (terminal, or past its own expiry).
        let expiredSecrets = try await AuthDeliverySecretRecord.query(on: db).filter(\.$expiresAt <= now).all()
        for secret in expiredSecrets { try await secret.delete(on: db); changed += 1 }
        let endedIds = try await AuthDeliveryRecord.query(on: db).filter(\.$status ~~ AuthDeliveryStatus.allCases.filter(\.isTerminal).map(\.rawValue)).all().compactMap(\.id)
        if !endedIds.isEmpty { try await AuthDeliverySecretRecord.query(on: db).filter(\.$id ~~ endedIds).delete() }
        // T class: 30 days after the terminal state (owner decision 10).
        let cutoff = now.addingTimeInterval(-settings.metadataRetention)
        let old = try await AuthDeliveryRecord.query(on: db).filter(\.$endedAt < cutoff).all().compactMap(\.id)
        if !old.isEmpty {
            try await AuthDeliveryEventRecord.query(on: db).filter(\.$deliveryId ~~ old).delete()
            try await AuthDeliverySecretRecord.query(on: db).filter(\.$id ~~ old).delete()
            try await AuthDeliveryRecord.query(on: db).filter(\.$id ~~ old).delete()
            changed += old.count
        }
        return changed
    }
}

/// **Grouping of one person's open deliveries (ADR-0020 section 8, revision 3).** Everything that decides which open deliveries coexist, replace each other or
/// are numbered lives here, so a later revision (3.1: per-requester caps and collision-free code allocation) changes this one type. Today: a new `sign_in`
/// replaces an open one **only** when both carry the same `session_handle`; nothing is ever refused or cancelled by count, so someone who triggers sign-ins
/// cannot cancel or lock out the person's own request. Deliveries carry no match code in this stage (number matching belongs to approvals, ADR-0022).
struct AuthDeliveryGrouping {
    let db: any Database
    let ctx: ServerContext

    static let handleWindow: TimeInterval = 600
    static let handleDistinctLimit = 3
    static let handleHourlyAlert = 20

    func applyOnCreate(new row: AuthDeliveryRecord, sessionHandle: String?) async throws {
        var handle = sessionHandle
        // `session_handle` abuse rule (revision 3.1, S3-A2-6): a handle seen on more than 3 distinct request ids for this person within 10 minutes is treated as absent
        // for supersession from then on. The new request simply joins the group; nothing is cancelled or refused because of it.
        if let candidate = handle {
            let recent = try await AuthDeliveryRecord.query(on: db).filter(\.$businessId == row.businessId).filter(\.$consumerId == row.consumerId)
                .filter(\.$sessionHandle == candidate).filter(\.$id != row.id!).filter(\.$createdAt > ctx.now.addingTimeInterval(-Self.handleWindow)).all()
            if Set(recent.map(\.requestId)).count >= Self.handleDistinctLimit {
                handle = nil
                _ = try? await AuditService(db: db, ctx: ctx).record("auth_delivery.session_handle_abuse", outcome: .denied, actor: AuditActor(kind: .system),
                    consumerId: ConsumerID(row.consumerId), businessId: BusinessID(row.businessId), subjectType: "auth_delivery", subjectId: row.wireId.description)
            }
            let hourly = try await AuthDeliveryRecord.query(on: db).filter(\.$businessId == row.businessId).filter(\.$sessionHandle == candidate)
                .filter(\.$createdAt > ctx.now.addingTimeInterval(-3600)).count()
            if hourly > Self.handleHourlyAlert { ctx.logger.critical("auth session_handle on many requests", metadata: ["business": "\(row.businessId)"]) }
        }
        if row.purposeValue == .signIn, let handle {
            let open = try await AuthDeliveryRecord.query(on: db).filter(\.$businessId == row.businessId).filter(\.$consumerId == row.consumerId)
                .filter(\.$purpose == AuthDeliveryPurpose.signIn.rawValue).filter(\.$sessionHandle == handle).filter(\.$id != row.id!)
                .filter(\.$status ~~ [AuthDeliveryStatus.queued.rawValue, AuthDeliveryStatus.sent.rawValue, AuthDeliveryStatus.delivered.rawValue]).all()
            for older in open { _ = try await AuthDeliveryService(db: db, ctx: ctx).transition(older, to: .cancelled, by: .api, reason: "superseded") }
        }
        try await pressure(row)
    }

    /// Above 10 open requests for one person at one business the api audits `auth_delivery.group_pressure` (tenant, person, open count; no code or tag), alerts
    /// operators, and does so at most once per group per hour. Never a refusal.
    func pressure(_ row: AuthDeliveryRecord) async throws {
        let open = try await AuthDeliveryRecord.query(on: db).filter(\.$businessId == row.businessId).filter(\.$consumerId == row.consumerId)
            .filter(\.$expiresAt > ctx.now)
            .filter(\.$status ~~ [AuthDeliveryStatus.queued.rawValue, AuthDeliveryStatus.sent.rawValue, AuthDeliveryStatus.delivered.rawValue]).count()
        guard open > MatchGroupPolicy.pressureThreshold,
              await ctx.limiter.allow("authdl-pressure", key: "\(row.businessId)|\(row.consumerId)", rule: .perHour(1, burst: 1)) else { return }
        ctx.logger.warning("auth group pressure", metadata: ["business": "\(row.businessId)", "open": "\(open)"])
        _ = try? await AuditService(db: db, ctx: ctx).record("auth_delivery.group_pressure", actor: AuditActor(kind: .system), consumerId: ConsumerID(row.consumerId),
                                                           businessId: BusinessID(row.businessId), subjectType: "auth_group", metadata: ["open": String(open)])
    }
}
