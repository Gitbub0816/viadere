import Fluent
import Foundation
import ViadereCore

/// Idempotency for the business API operations that had none: webhook create, webhook secret rotation and interaction cancel. Same
/// semantics as issuing an interaction: the `Idempotency-Key` header is **required**; the same key with the same request returns the
/// original result (`200`, not `201`); the same key with a different request is `409 idempotency_conflict`. One row per
/// `(business, operation, key)` (unique), so concurrent retries cannot both act.
///
/// Create and rotate return a **one-time secret**, so their result is kept AES-GCM-sealed (row-bound) for replay and wiped after 24 h;
/// a replay after that is `410 gone` (the secret can never be shown again, rotate to get a new one).
struct BusinessIdempotency {
    let db: any Database
    let ctx: ServerContext

    static let sealedLifetime: TimeInterval = 24 * 3600

    enum Operation: String {
        case webhookCreate = "webhook.create"
        case webhookRotate = "webhook.rotate"
        case interactionCancel = "interaction.cancel"
    }

    /// The required header: 1-128 characters of `A-Z a-z 0-9 _ . - :`.
    static func requireKey(_ header: String?) throws -> String {
        guard let header, !header.isEmpty, header.count <= 128, header.unicodeScalars.allSatisfy({
            $0.isASCII && (CharacterSet.alphanumerics.contains($0) || "_.-:".unicodeScalars.contains($0))
        }) else {
            throw APIError.validation("An Idempotency-Key header (1-128 characters) is required.", details: ["idempotencyKey": "invalid"])
        }
        return header
    }

    private func existing(_ businessId: UUID, _ operation: Operation, _ key: String) async throws -> BusinessIdempotencyRecord? {
        try await BusinessIdempotencyRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$operation == operation.rawValue)
            .filter(\.$idemKey == key).first()
    }

    private func checkSame(_ record: BusinessIdempotencyRecord, _ requestHash: String) throws {
        guard ConstantTime.equals(record.requestHash, requestHash) else {
            throw APIError(.conflict, .idempotencyConflict, "This Idempotency-Key was already used with a different request.")
        }
    }

    private func openSealed<T: Decodable>(_ record: BusinessIdempotencyRecord, as type: T.Type) throws -> T {
        guard let sealed = record.resultSealed, let id = record.id,
              let data = try? ctx.cipher.open(sealed, context: "business_idempotency.result", rowId: id),
              let value = try? ViadereJSON.decode(T.self, from: data) else {
            throw APIError.gone("This request was already completed and its one-time secret can no longer be shown. Rotate the secret to get a new one.")
        }
        return value
    }

    /// Runs `perform` once per key. `sealResult` stores the response for replay (one-time secrets).
    private func once<T: Codable & Sendable>(businessId: UUID, operation: Operation, key: String, requestHash: String, sealResult: Bool,
                                             perform: @escaping @Sendable (any Database) async throws -> (T, UUID?),
                                             replay: @escaping @Sendable (BusinessIdempotencyRecord) async throws -> T) async throws -> (value: T, created: Bool) {
        if let found = try await existing(businessId, operation, key) {
            try checkSame(found, requestHash)
            return (try await replay(found), false)
        }
        let now = ctx.now
        do {
            let value: T = try await db.transaction { tx in
                let (value, resource) = try await perform(tx)
                let row = BusinessIdempotencyRecord(businessId: businessId, operation: operation.rawValue, key: key, requestHash: requestHash,
                                                    resourceId: resource, now: now)
                if sealResult { row.resultSealed = try ctx.cipher.seal(try ViadereJSON.encode(value), context: "business_idempotency.result", rowId: row.id!) }
                try await row.create(on: tx)
                return value
            }
            return (value, true)
        } catch {
            // A concurrent request with the same key won: the loser's transaction rolled back, so replay the winner.
            guard error.isConstraintViolation, let found = try await existing(businessId, operation, key) else { throw error }
            try checkSame(found, requestHash)
            return (try await replay(found), false)
        }
    }

    // MARK: Operations

    func createWebhook(businessId: BusinessID, request: CreateWebhookRequest, key: String) async throws -> (value: WebhookSecretResponse, created: Bool) {
        let hash = SecureToken.sha256Hex(Data("webhook.create\n".utf8) + (try ViadereJSON.encode(request)))
        let ctx = self.ctx
        return try await once(businessId: businessId.uuid, operation: .webhookCreate, key: key, requestHash: hash, sealResult: true,
                              perform: { tx in
                                  let result = try await WebhookService(db: tx, ctx: ctx).create(businessId: businessId, request: request)
                                  return (result, result.subscription.id.uuid)
                              },
                              replay: { try openSealed($0, as: WebhookSecretResponse.self) })
    }

    func rotateWebhook(businessId: BusinessID, id: WebhookSubscriptionID, key: String) async throws -> (value: WebhookSecretResponse, created: Bool) {
        let hash = SecureToken.sha256Hex(Data("webhook.rotate\n\(id)".utf8))
        let ctx = self.ctx
        return try await once(businessId: businessId.uuid, operation: .webhookRotate, key: key, requestHash: hash, sealResult: true,
                              perform: { tx in (try await WebhookService(db: tx, ctx: ctx).rotate(businessId: businessId, id: id), id.uuid) },
                              replay: { try openSealed($0, as: WebhookSecretResponse.self) })
    }

    func cancelInteraction(principal: BusinessPrincipal, id: InteractionID, key: String) async throws -> (value: InteractionOutcome, created: Bool) {
        let hash = SecureToken.sha256Hex(Data("interaction.cancel\n\(id)".utf8))
        let ctx = self.ctx
        let businessId = principal.businessId
        let livemode = principal.livemode
        // Verify the interaction belongs to this business before a key is recorded for it.
        let service = InteractionService(db: db, ctx: ctx)
        let existing = try await service.record(id: id, businessId: businessId, livemode: livemode)
        // Cancelling (or replaying a cancel of) an approval needs the approval capability, like issuing it did.
        try await PolicyService(db: db, ctx: ctx).enforce(PolicyInput(Capability.required(forInteractionKind: InteractionKind(rawValue: existing.kind))),
                                                          principal: principal, auditAllowed: false)
        return try await once(businessId: businessId.uuid, operation: .interactionCancel, key: key, requestHash: hash, sealResult: false,
                              perform: { tx in (try await InteractionService(db: tx, ctx: ctx).cancel(principal: principal, id: id), id.uuid) },
                              replay: { _ in
                                  let record = try await InteractionService(db: self.db, ctx: ctx).record(id: id, businessId: businessId, livemode: livemode)
                                  return try InteractionService(db: self.db, ctx: ctx).outcome(record)
                              })
    }

    /// Wipes one-time secrets that outlived their replay window.
    func purge() async throws {
        let cutoff = ctx.now.addingTimeInterval(-Self.sealedLifetime)
        try await BusinessIdempotencyRecord.query(on: db).filter(\.$resultSealed != nil).filter(\.$createdAt < cutoff).set(\.$resultSealed, to: nil).update()
    }
}
