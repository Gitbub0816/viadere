import Fluent
import Foundation

/// A named lease row (`job_leases`): one holder at a time, and an abandoned lease frees itself at its expiry. It keeps overlapping runs of one
/// job (a slow run still going when the scheduler starts the next, two instances) from doing the same work twice. It is **not** the safety
/// mechanism: the work stays correct without it, because the rows it touches are locked or updated conditionally (`PhoneLinkService.lockNumber`).
final class JobLeaseRecord: Model, @unchecked Sendable {
    static let schema = "job_leases"
    @ID(key: .id) var id: UUID?
    @Field(key: "name") var name: String
    @Field(key: "holder") var holder: UUID
    @Field(key: "expires_at") var expiresAt: Date
    init() {}
    init(name: String, holder: UUID, expiresAt: Date) {
        id = UUID()
        self.name = name
        self.holder = holder
        self.expiresAt = expiresAt
    }
}

enum JobLease {
    /// Takes the lease `name` for `ttl` seconds when nobody holds it (or the holder's lease expired). Returns whether this caller now holds it.
    static func acquire(_ name: String, holder: UUID, ttl: TimeInterval, on db: any Database, now: Date) async throws -> Bool {
        let expires = now.addingTimeInterval(ttl)
        guard let existing = try await JobLeaseRecord.query(on: db).filter(\.$name == name).first() else {
            do { try await JobLeaseRecord(name: name, holder: holder, expiresAt: expires).create(on: db) } catch {
                if error.isConstraintViolation { return false }   // another run created it first
                throw error
            }
            return true
        }
        guard existing.expiresAt < now else { return false }
        // Take over an expired lease by a predicate on the old holder: of two racing takers only one update matches.
        try await JobLeaseRecord.query(on: db).filter(\.$name == name).filter(\.$holder == existing.holder).filter(\.$expiresAt < now)
            .set(\.$holder, to: holder).set(\.$expiresAt, to: expires).update()
        return try await JobLeaseRecord.query(on: db).filter(\.$name == name).first()?.holder == holder
    }

    /// Gives the lease back early. Only the holder's own call has any effect.
    static func release(_ name: String, holder: UUID, on db: any Database) async throws {
        try await JobLeaseRecord.query(on: db).filter(\.$name == name).filter(\.$holder == holder).delete()
    }
}
