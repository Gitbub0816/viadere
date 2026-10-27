import Fluent
import Foundation
import Vapor
import ViadereCore

/// The release gate and the small pieces every Approve service shares.
enum ApproveGate {
    /// `404` while `APPROVE_V2_ENABLED` is off: the feature does not exist, whatever the credentials.
    static func require(_ ctx: ServerContext) throws {
        guard ctx.config.approve.enabled else { throw APIError.notFound }
    }
}

/// Business-facing and device-facing id helpers.
enum ApproveIdentifiers {
    /// `[A-Za-z0-9._:-]{16,64}` (the business's own request id).
    static func isValidRequestId(_ value: String) -> Bool {
        value.utf8.count >= 16 && value.utf8.count <= 64 && E2EEContext.validIdentifier(value)
    }

    static func newResultRef() -> String { "res_" + SecureToken.generate(byteCount: 16) }

    static func isValidResultRef(_ value: String) -> Bool {
        value.hasPrefix("res_") && Base64URL.isValid(String(value.dropFirst(4)), minLength: 22, maxLength: 22)
    }

    /// The `ctx.sender` of an envelope a business creates.
    static func sender(_ businessId: BusinessID) -> String { "biz_" + businessId.description }
    /// The `ctx.recipient` of an envelope for one approval key.
    static func recipient(kid: String) -> String { "ak_" + kid }
}

/// Security notices and pushes for Approve events.
struct ApproveNotifier {
    let db: any Database
    let ctx: ServerContext

    /// In-app notice (stored; failure is logged, never fatal) plus a push to the account's app devices.
    func notice(_ notice: SecurityNotices.Notice, consumerId: UUID, except: UUID? = nil, subjectId: String? = nil) async {
        await SecurityNotices(db: db, ctx: ctx).notifyOtherDevices(of: consumerId, except: except, notice: notice, subjectId: subjectId)
    }

    /// A generic push for a new approval request. Carries **no** business, amount or payee: the app fetches the request over the
    /// authenticated API (and decrypts it, for an end-to-end request).
    func pushRequest(to deviceIds: [UUID]) async {
        guard !deviceIds.isEmpty else { return }
        do {
            let tokens = try await APNsTokenRecord.query(on: db).filter(\.$deviceId ~~ deviceIds).filter(\.$invalidatedAt == nil).all()
            for token in tokens {
                let message = PushMessage(deviceToken: token.record.token, environment: token.record.environment,
                                          topic: token.record.bundleId.isEmpty ? ctx.config.appBundleID : token.record.bundleId,
                                          title: PushPayloadBuilder.genericTitle, body: "Action needed. Open to review a security request.",
                                          category: "viadere.approve", threadID: "viadere.approve", interruptionLevel: "time-sensitive",
                                          mutableContent: true, interactionId: nil, highPriority: true)
                if await ctx.apns.send(message) == .tokenInvalid {
                    try await APNsTokenRecord.query(on: db).filter(\.$id == token.id!).set(\.$invalidatedAt, to: ctx.now).update()
                }
            }
        } catch {
            // Best effort: the request stays available through the authenticated API.
        }
    }
}

/// Freezes (APP-007): a consumer or a business stops all approvals for one relationship, and a consumer can stop them for the whole
/// account. A freeze takes effect immediately on every path that creates or decides a request.
struct ApproveFreezeService {
    let db: any Database
    let ctx: ServerContext

    /// Who froze approvals for this relationship, if anyone: `consumer` (account or relationship) or `business`.
    func frozenBy(consumerId: UUID, relationshipId: UUID) async throws -> String? {
        let active = try await ApproveFreezeRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$liftedAt == nil).all()
        if active.contains(where: { $0.scopeValue == .account }) { return "consumer" }
        return active.first { $0.relationshipId == relationshipId }?.frozenBy
    }

    func requireNotFrozen(consumerId: UUID, relationshipId: UUID) async throws {
        if let by = try await frozenBy(consumerId: consumerId, relationshipId: relationshipId) {
            throw APIError(.conflict, .approvalsFrozen, by == "consumer" ? "The customer has frozen approvals." : "Approvals are frozen for this customer.",
                           details: ["frozen_by": by])
        }
    }

    func state(consumerId: UUID) async throws -> ApproveFreezeState {
        let rows = try await ApproveFreezeRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$liftedAt == nil).sort(\.$createdAt, .ascending).all()
        return ApproveFreezeState(entries: rows.map {
            ApproveFreezeEntry(scope: $0.scopeValue, relationshipId: $0.relationshipId.map(RelationshipID.init), by: $0.frozenBy, since: $0.createdAt)
        })
    }

    /// Cancels every pending request the freeze covers.
    func cancelPending(consumerId: UUID, relationshipId: UUID?, reason: String) async throws {
        var query = ApproveRequestRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$status == ApprovalRequestStatus.pending.rawValue)
        if let relationshipId { query = query.filter(\.$relationshipId == relationshipId) }
        for request in try await query.all() {
            _ = try await ApproveRequestService(db: db, ctx: ctx).finish(request, status: .cancelled, reason: reason, notify: true)
        }
    }

    // MARK: Consumer

    /// Freezes approvals. Needs only a signed device request: freezing is always safe, so it must be quick.
    func freeze(principal: ConsumerPrincipal, scope: ApproveFreezeScope, relationshipId: RelationshipID?) async throws -> ApproveFreezeState {
        let consumerId = principal.consumerId.uuid
        var relationship: RelationshipRecord?
        switch scope {
        case .account:
            guard relationshipId == nil else { throw APIError.validation("An account freeze names no relationship.", details: ["relationship_id": "invalid"]) }
        case .relationship:
            guard let relationshipId, let found = try await RelationshipRecord.find(relationshipId.uuid, on: db), found.consumerId == consumerId else { throw APIError.notFound }
            relationship = found
        }
        var query = ApproveFreezeRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$liftedAt == nil)
            .filter(\.$frozenBy == "consumer").filter(\.$scope == scope.rawValue)
        if let relationship { query = query.filter(\.$relationshipId == relationship.id!) }
        if try await query.count() == 0 {
            let row = ApproveFreezeRecord()
            row.id = UUID()
            row.consumerId = consumerId
            row.scope = scope.rawValue
            row.relationshipId = relationship?.id
            row.businessId = relationship?.businessId
            row.frozenBy = "consumer"
            row.createdAt = ctx.now
            try await row.create(on: db)
            _ = try await AuditService(db: db, ctx: ctx).record("approve.frozen", principal: principal, businessId: relationship.map { BusinessID($0.businessId) },
                subjectType: "approve_freeze", subjectId: row.id?.uuidString.lowercased(), metadata: ["scope": scope.rawValue, "by": "consumer"])
            try await cancelPending(consumerId: consumerId, relationshipId: relationship?.id, reason: "frozen")
            await ApproveNotifier(db: db, ctx: ctx).notice(.approvalsFrozen, consumerId: consumerId, except: principal.deviceId?.uuid,
                                                           subjectId: relationship?.id?.uuidString.lowercased())
            if let relationship {
                try await ApproveWebhooks(db: db, ctx: ctx).frozen(relationship: relationship, by: "consumer")
            } else {
                for related in try await RelationshipRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$status == "active").all() {
                    try await ApproveWebhooks(db: db, ctx: ctx).frozen(relationship: related, by: "consumer")
                }
            }
        }
        return try await state(consumerId: consumerId)
    }

    /// Lifts the customer's freeze. Needs a **trusted device** and a fresh **biometric proof** from it (`ApproveFreezeProof`): a thief of an
    /// unlocked phone or a new device in its cool-down cannot silently turn approvals back on.
    func unfreeze(principal: ConsumerPrincipal, scope: ApproveFreezeScope, relationshipId: RelationshipID?, proof: SignedStatement?) async throws -> ApproveFreezeState {
        let now = ctx.now
        let device = try await DeviceTrust.require(principal, db: db, now: now)
        guard let proof, let deviceId = device.id,
              let key = try await DeviceKeyRecord.query(on: db).filter(\.$deviceId == deviceId).filter(\.$purpose == DeviceKeyPurpose.approvalBiometric.rawValue).first(),
              let publicKey = try? DevicePublicKey(base64URL: key.publicKey),
              let parsed = ApproveFreezeProof.verify(proof, deviceKey: publicKey) else {
            _ = try? await AuditService(db: db, ctx: ctx).record("approve.unfreeze_rejected", outcome: .denied, principal: principal, metadata: ["reason": "proof_invalid"])
            throw APIError(.forbidden, .insufficientAssurance, "Unfreezing needs a fresh Face ID or Touch ID confirmation on a trusted device.")
        }
        guard parsed.deviceId.uuid == deviceId, parsed.scope == scope, parsed.relationshipId == relationshipId,
              parsed.signedAtDate <= now.addingTimeInterval(60), now.timeIntervalSince(parsed.signedAtDate) <= 300 else {
            _ = try? await AuditService(db: db, ctx: ctx).record("approve.unfreeze_rejected", outcome: .denied, principal: principal, metadata: ["reason": "proof_binding"])
            throw APIError(.forbidden, .insufficientAssurance, "That confirmation does not match this request.")
        }
        // The proof is single use (keyed on what was signed, never on the signature bytes).
        let fresh = try await DatabaseReplayGuard(db: db).registerIfFresh(nonce: SecureToken.sha256Hex(Data(proof.payload.utf8)), scope: "approve-unfreeze:\(deviceId)",
                                                                          expiresAt: now.addingTimeInterval(900), now: now)
        guard fresh else { throw APIError(.conflict, .replayDetected, "That confirmation was already used.") }
        let consumerId = principal.consumerId.uuid
        var query = ApproveFreezeRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$liftedAt == nil)
            .filter(\.$frozenBy == "consumer").filter(\.$scope == scope.rawValue)
        if scope == .relationship {
            guard let relationshipId, let found = try await RelationshipRecord.find(relationshipId.uuid, on: db), found.consumerId == consumerId else { throw APIError.notFound }
            query = query.filter(\.$relationshipId == found.id!)
        }
        let lifted = try await query.set(\.$liftedAt, to: now).update()
        _ = lifted
        _ = try await AuditService(db: db, ctx: ctx).record("approve.unfrozen", principal: principal, subjectType: "approve_freeze",
                                                           metadata: ["scope": scope.rawValue, "by": "consumer"])
        await ApproveNotifier(db: db, ctx: ctx).notice(.approvalsUnfrozen, consumerId: consumerId, except: principal.deviceId?.uuid)
        return try await state(consumerId: consumerId)
    }

    // MARK: Business

    /// The business stops (or resumes) approvals for one relationship. It can lift only a freeze it made itself.
    func businessFreeze(principal: BusinessPrincipal, relationship: RelationshipRecord, frozen: Bool, reason: String?) async throws -> Bool {
        let consumerId = relationship.consumerId
        let existing = try await ApproveFreezeRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$relationshipId == relationship.id!)
            .filter(\.$liftedAt == nil).filter(\.$frozenBy == "business").first()
        if frozen {
            if existing == nil {
                let row = ApproveFreezeRecord()
                row.id = UUID()
                row.consumerId = consumerId
                row.scope = ApproveFreezeScope.relationship.rawValue
                row.relationshipId = relationship.id
                row.businessId = principal.businessId.uuid
                row.frozenBy = "business"
                row.reason = reason.map { String($0.prefix(200)) }
                row.createdAt = ctx.now
                try await row.create(on: db)
                _ = try await AuditService(db: db, ctx: ctx).record("approve.frozen", actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()),
                    consumerId: ConsumerID(consumerId), businessId: principal.businessId, subjectType: "approve_freeze", subjectId: row.id?.uuidString.lowercased(),
                    metadata: ["scope": "relationship", "by": "business"])
                try await cancelPending(consumerId: consumerId, relationshipId: relationship.id, reason: "frozen")
                await ApproveNotifier(db: db, ctx: ctx).notice(.approvalsFrozen, consumerId: consumerId, subjectId: relationship.id?.uuidString.lowercased())
            }
        } else if let existing {
            existing.liftedAt = ctx.now
            try await existing.update(on: db)
            _ = try await AuditService(db: db, ctx: ctx).record("approve.unfrozen", actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()),
                consumerId: ConsumerID(consumerId), businessId: principal.businessId, subjectType: "approve_freeze", subjectId: existing.id?.uuidString.lowercased(),
                metadata: ["scope": "relationship", "by": "business"])
        }
        // What the business sees: frozen if anyone froze (it cannot lift the customer's freeze).
        return try await frozenBy(consumerId: consumerId, relationshipId: relationship.id!) != nil
    }
}

extension ApproveFreezeProof {
    var signedAtDate: Date { Date(timeIntervalSince1970: TimeInterval(signedAt)) }
}
