import Fluent
import Foundation
import ViadereCore

/// Test mode. A test-mode API key (`vdk_test_…`) can only address **sandbox** relationships: a consumer record with status
/// `sandbox` that has no passkey, device or phone, created through the API for exactly this purpose. A live key can never address
/// one. So test traffic can never reach a real person (push, SMS, RCS), be decided by a real device, or skip the quota, abuse and
/// billing accounting that live traffic goes through.
struct Sandbox {
    let db: any Database
    static let maxPerBusiness = 50

    func requireMatching(relationship: RelationshipRecord, livemode: Bool) async throws {
        guard let consumer = try await ConsumerRecord.find(relationship.consumerId, on: db) else { throw APIError.notFound }
        switch (livemode, consumer.isSandbox) {
        case (true, false), (false, true): return
        case (true, true): throw APIError.notFound
        case (false, false):
            throw APIError(.forbidden, .forbidden, "Test-mode keys can only be used with sandbox relationships. Create one with POST /v1/business/sandbox/relationships.")
        }
    }

    /// True when `consumerId` is on the same side of the test/live line as the key (sandbox consumer ⇔ test key).
    func matches(consumerId: UUID, livemode: Bool) async throws -> Bool {
        guard let consumer = try await ConsumerRecord.find(consumerId, on: db) else { return false }
        return consumer.isSandbox != livemode
    }

    /// Business-wide state (the loyalty program, broadcast rewards) is live-only: a test-mode key never touches it.
    static func requireLive(_ principal: BusinessPrincipal, _ what: String) throws {
        guard principal.livemode else {
            throw APIError(.forbidden, .forbidden, "Test-mode keys cannot \(what). Use a sandbox relationship (POST /v1/business/sandbox/relationships) or a live key.")
        }
    }

    func create(principal: BusinessPrincipal, now: Date, ctx: ServerContext) async throws -> SandboxRelationship {
        guard !principal.livemode else {
            throw APIError(.forbidden, .forbidden, "Sandbox relationships are created with a test-mode key.")
        }
        let related = try await RelationshipRecord.query(on: db).filter(\.$businessId == principal.businessId.uuid).all().map(\.consumerId)
        let existing = related.isEmpty ? 0 : try await ConsumerRecord.query(on: db).filter(\.$id ~~ related)
            .filter(\.$status == ConsumerRecord.sandboxStatus).count()
        guard existing < Self.maxPerBusiness else { throw APIError.conflict("Sandbox limit reached.") }
        let consumerId = UUID()
        let relationship = RelationshipRecord(consumerId: consumerId, businessId: principal.businessId.uuid, source: .link, now: now)
        try await db.transaction { tx in
            let consumer = ConsumerRecord(id: consumerId, displayName: "Sandbox consumer", userHandle: SecureToken.generate(byteCount: 32), now: now)
            consumer.status = ConsumerRecord.sandboxStatus
            try await consumer.create(on: tx)
            try await relationship.create(on: tx)
            try await ConsentService(db: tx, ctx: ctx).initialize(relationship: relationship, optIn: Set(InteractionPurpose.allCases),
                                                                  source: .system, channels: [.nativePush, .inApp])
        }
        return SandboxRelationship(relationshipId: RelationshipID(relationship.id!), createdAt: now,
                                   subjectRef: ctx.subjects.subjectRef(businessId: principal.businessId, consumerId: ConsumerID(consumerId)))
    }
}
