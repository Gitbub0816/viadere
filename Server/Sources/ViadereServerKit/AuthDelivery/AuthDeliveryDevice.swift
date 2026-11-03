import Fluent
import Foundation
import Logging
import ViadereCore

/// The customer's side (device-signed bearer). A delivery is visible only to the devices of the **account it was addressed to**: a household delegate is a
/// different account, so it can never list, fetch, open or deny it (ST-TEN-06). App Clip devices are not eligible.
struct AuthDeliveryDeviceService {
    let db: any Database
    let ctx: ServerContext

    private var service: AuthDeliveryService { AuthDeliveryService(db: db, ctx: ctx) }

    func requireDevice(_ principal: ConsumerPrincipal) async throws -> DeviceRecord {
        guard let id = principal.deviceId, let device = try await DeviceRecord.find(id.uuid, on: db), device.consumerId == principal.consumerId.uuid,
              device.kind == .app, device.revokedAt == nil, !device.isExpired(at: ctx.now) else { throw APIError.notFound }
        return device
    }

    func record(_ id: AuthDeliveryID, principal: ConsumerPrincipal) async throws -> AuthDeliveryRecord {
        guard let row = try await AuthDeliveryRecord.find(id.uuid, on: db), row.consumerId == principal.consumerId.uuid, !row.isPushApproval else { throw APIError.notFound }
        return row
    }

    func payload(_ row: AuthDeliveryRecord) async -> AuthSecretPayload? {
        guard let id = row.id, let secret = try? await AuthDeliverySecretRecord.find(id, on: db),
              let data = try? ctx.config.authDelivery.cipher.open(secret.ciphertext, context: AuthDeliverySecretRecord.sealContext, rowId: id) else { return nil }
        return try? ViadereJSON.decode(AuthSecretPayload.self, from: data)
    }

    func display(_ row: AuthDeliveryRecord) async throws -> AuthDeliveryDisplay {
        let business = try await BusinessRecord.find(row.businessId, on: db)
        let live = !service.effectiveStatus(row).isTerminal
        let variables = live ? await payload(row)?.variables : nil
        return AuthDeliveryDisplay(id: row.wireId, method: row.methodValue, purpose: row.purposeValue, template: row.template, status: service.effectiveStatus(row),
                                   businessId: BusinessID(row.businessId), businessName: business?.displayName ?? "", expiresAt: row.expiresAt, createdAt: row.createdAt,
                                   requestId: row.requestId, destinationHost: row.destinationHost, destinationStatement: live ? row.destinationStatement : nil,
                                   codeKind: row.codeKind.flatMap(AuthCodeKind.init(rawValue:)), variables: variables, silent: row.silent)
    }

    /// The inbox: open deliveries for this device's account.
    func list(principal: ConsumerPrincipal) async throws -> [AuthDeliveryDisplay] {
        _ = try await requireDevice(principal)
        let rows = try await AuthDeliveryRecord.query(on: db).filter(\.$consumerId == principal.consumerId.uuid).filter(\.$expiresAt > ctx.now)
            .filter(\.$method != PushApprovalDelivery.method)
            .filter(\.$status ~~ [AuthDeliveryStatus.queued.rawValue, AuthDeliveryStatus.sent.rawValue, AuthDeliveryStatus.delivered.rawValue])
            .sort(\.$createdAt, .descending).limit(50).all()
        var out: [AuthDeliveryDisplay] = []
        for row in rows { out.append(try await display(row)) }
        return out
    }

    /// The display object. The first fetch marks the delivery `delivered` (never `opened`).
    func get(principal: ConsumerPrincipal, id: AuthDeliveryID) async throws -> AuthDeliveryDisplay {
        _ = try await requireDevice(principal)
        let row = try await record(id, principal: principal)
        if try await service.expireIfDue(row) { return try await display(row) }
        if [.queued, .sent].contains(row.statusValue) { try await service.transition(row, to: .delivered, by: .device) }
        return try await display(row)
    }

    /// The secret, **once**: the compare-and-swap, the secret's deletion and the event commit together, so two concurrent calls cannot both receive it.
    func open(principal: ConsumerPrincipal, id: AuthDeliveryID) async throws -> AuthDeliveryOpenResponse {
        let device = try await requireDevice(principal)
        try await ctx.limiter.enforce("authdl-open", key: device.id!.uuidString.lowercased(), rule: ctx.config.authDelivery.openRate)
        let ctx = self.ctx
        // An expiry must commit even though the open is refused, so it runs before (not inside) the transaction that a refusal rolls back.
        let existing = try await record(id, principal: principal)
        if try await service.expireIfDue(existing) { throw APIError.gone("This delivery has expired.") }
        return try await DB.retryingTransient {
            try await db.transaction { tx in
                let svc = AuthDeliveryService(db: tx, ctx: ctx)
                let device = AuthDeliveryDeviceService(db: tx, ctx: ctx)
                let row = try await device.record(id, principal: principal)
                if try await svc.expireIfDue(row) { throw APIError.gone("This delivery has expired.") }
                switch row.statusValue {
                case .opened, .completed, .failed: throw APIError(.conflict, .alreadyOpened, "This was already opened.")
                case .expired, .cancelled, .denied: throw APIError.gone("This delivery is no longer available.")
                default: break
                }
                guard row.statusValue.isOpenable else { throw APIError.gone("This delivery is no longer available.") }
                let secret = await device.payload(row)
                if row.methodValue != .notice, secret?.url == nil, secret?.code == nil { throw APIError.gone("This delivery is no longer available.") }
                // Lost race: another call opened it first. Nothing was changed; the transaction rolls back.
                guard try await svc.transition(row, to: .opened, by: .device) else { throw APIError(.conflict, .alreadyOpened, "This was already opened.") }
                _ = try await AuditService(db: tx, ctx: ctx).record("auth_delivery.opened", principal: principal, businessId: BusinessID(row.businessId),
                                                                    subjectType: "auth_delivery", subjectId: id.description, metadata: ["method": row.method])
                return AuthDeliveryOpenResponse(id: id, method: row.methodValue, url: secret?.url, code: secret?.code,
                                                codeKind: row.codeKind.flatMap(AuthCodeKind.init(rawValue:)), openedAt: ctx.now)
            }
        }
    }

    /// Deny or "This wasn't me". Reduce-only: always allowed for a live delivery of the account.
    func deny(principal: ConsumerPrincipal, id: AuthDeliveryID, body: AuthDeliveryDenyRequest) async throws -> AuthDeliveryView {
        let device = try await requireDevice(principal)
        try await ctx.limiter.enforce("authdl-deny", key: device.id!.uuidString.lowercased(), rule: ctx.config.authDelivery.denyRate)
        if let reason = body.reason, !AuthDeliveryDenyRequest.allowedReasons.contains(reason) { throw APIError.validation("Unknown reason.", details: ["reason": "invalid"]) }
        let row = try await record(id, principal: principal)
        if !row.statusValue.isTerminal {
            // A `destination_unverified` denial is an integrity report about the business's link and never counts toward fatigue (revision 3).
            let reason = body.reason ?? (body.report == true ? "reported" : "denied_by_customer")
            if try await service.transition(row, to: .denied, by: .device, reason: reason) {
                _ = try await AuditService(db: db, ctx: ctx).record("auth_delivery.denied", principal: principal, businessId: BusinessID(row.businessId),
                                                                   subjectType: "auth_delivery", subjectId: id.description, metadata: ["reason": reason])
                if body.reason == "destination_unverified" {
                    _ = try? await AuditService(db: db, ctx: ctx).record("auth_delivery.destination_unverified", outcome: .denied, principal: principal,
                                                                        businessId: BusinessID(row.businessId), subjectType: "auth_delivery", subjectId: id.description)
                    ctx.logger.warning("auth delivery destination unverified", metadata: ["delivery": "\(id.description)"])
                }
            }
        }
        return try await service.view(try await record(id, principal: principal))
    }
}

/// Sends the opaque push (ADR-0020 section 6.2): generic alert, category, opaque thread id and the delivery id. Never a business, URL, code or amount.
struct AuthDeliveryDispatcher {
    let db: any Database
    let ctx: ServerContext

    /// Returns when to try again, if a retry is due.
    func dispatch(id: UUID) async throws -> Date? {
        let settings = ctx.config.authDelivery
        guard settings.enabled, let row = try await AuthDeliveryRecord.find(id, on: db), row.statusValue == .queued, row.expiresAt > ctx.now else { return nil }
        let service = AuthDeliveryService(db: db, ctx: ctx)
        if let consumer = try await ConsumerRecord.find(row.consumerId, on: db), consumer.isSandbox {
            // Test mode never pushes: the state advances so a partner can exercise its handlers.
            try await service.transition(row, to: .sent, by: .worker)
            return nil
        }
        let channels = row.channels.split(separator: ",").compactMap { AuthDeliveryChannel(rawValue: String($0)) }
        // Silent (over a per-subject budget): created and in the inbox, but no alert push.
        if row.silent || !channels.contains(.push) { return nil }
        let now = ctx.now
        let devices = try await DeviceRecord.query(on: db).filter(\.$consumerId == row.consumerId).filter(\.$revokedAt == nil).all()
            .filter { $0.kind == .app && !$0.isExpired(at: now) }.compactMap(\.id)
        let tokens = devices.isEmpty ? [] : try await APNsTokenRecord.query(on: db).filter(\.$deviceId ~~ devices).filter(\.$invalidatedAt == nil).all()
        if tokens.isEmpty {
            if !channels.contains(.inbox) { try await service.transition(row, to: .failed, by: .worker, reason: "not_attempted") }
            return nil
        }
        var accepted = false
        for token in tokens {
            let message = PushMessage(deviceToken: token.token, environment: APNsTokenRegistration.Environment(rawValue: token.environment) ?? .production,
                                      topic: token.bundleId.isEmpty ? ctx.config.appBundleID : token.bundleId, title: AuthPushPayloadPolicy.alertTitle,
                                      body: AuthPushPayloadPolicy.alertBody, category: AuthPushPayloadPolicy.category(for: row.methodValue),
                                      threadID: "auth." + String(ctx.hasher.hmacHex("auth-thread", token.deviceId.uuidString.lowercased()).prefix(16)),
                                      interruptionLevel: "active", mutableContent: true, interactionId: nil, highPriority: true,
                                      collapseID: row.wireId.description, authDeliveryId: row.wireId.description)
            switch await ctx.apns.send(message) {
            case .delivered: accepted = true
            case .tokenInvalid: try await APNsTokenRecord.query(on: db).filter(\.$id == token.id!).set(\.$invalidatedAt, to: ctx.now).update()
            case .failed: break
            }
        }
        // `sent` means a provider accepted it, never that a person saw it. If none did, the delivery stays `queued` and retrievable from the inbox.
        if accepted { try await service.transition(row, to: .sent, by: .worker); return nil }
        row.dispatchAttempts += 1
        try await AuthDeliveryRecord.query(on: db).filter(\.$id == id).set(\.$dispatchAttempts, to: row.dispatchAttempts).update()
        if row.dispatchAttempts >= settings.maxDispatchAttempts {
            if !channels.contains(.inbox) { try await service.transition(row, to: .failed, by: .worker, reason: "not_attempted") }
            return nil
        }
        return ctx.now.addingTimeInterval(TimeInterval(30 * row.dispatchAttempts))
    }
}
