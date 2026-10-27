import Fluent
import Foundation
import ViadereCore

/// Database-backed `DirectoryLookup` for the gateway engine. It only ever returns **verified** businesses.
struct DBDirectoryLookup: DirectoryLookup {
    let db: any Database

    func business(byCode code: BusinessCode) async throws -> BusinessSummary? {
        let directory = DirectoryService(db: db)
        guard let record = try await directory.verified(code: code) else { return nil }
        return try await directory.summary(for: record)
    }

    func business(byHandle handle: BusinessHandle) async throws -> BusinessSummary? {
        let directory = DirectoryService(db: db)
        guard let record = try await directory.verified(handle: handle) else { return nil }
        return try await directory.summary(for: record)
    }

    func business(byId id: BusinessID) async throws -> BusinessSummary? {
        let directory = DirectoryService(db: db)
        guard let record = try await directory.verified(id: id.uuid) else { return nil }
        return try await directory.summary(for: record)
    }

    func search(name: String, limit: Int) async throws -> [BusinessSummary] {
        let directory = DirectoryService(db: db)
        return try await directory.summaries(for: try await directory.search(name, limit: limit))
    }

    func recentBusinesses(consumerId: ConsumerID?, phone: PhoneNumber, limit: Int) async throws -> [BusinessSummary] {
        guard let consumerId else { return [] }
        let relationships = try await RelationshipRecord.query(on: db).filter(\.$consumerId == consumerId.uuid)
            .filter(\.$status == "active").sort(\.$lastActivityAt, .descending).limit(limit * 2).all()
        guard !relationships.isEmpty else { return [] }
        let directory = DirectoryService(db: db)
        let businesses = try await BusinessRecord.query(on: db).filter(\.$id ~~ relationships.map(\.businessId))
            .filter(\.$verificationStatus == VerificationStatus.verified.rawValue).all()
        let summaries = try await directory.summaries(for: businesses)
        let byId = Dictionary(summaries.map { ($0.id.uuid, $0) }, uniquingKeysWith: { first, _ in first })
        return Array(relationships.compactMap { byId[$0.businessId] }.prefix(limit))
    }
}
