import Fluent
import Foundation
import Vapor
import ViadereCore

/// Fills `relationships.subject_ref` whenever a relationship row is created, by any code path (so a future path cannot forget it).
struct SubjectRefMiddleware: AsyncModelMiddleware {
    typealias Model = RelationshipRecord
    let deriver: SubjectRefDeriver

    func create(model: RelationshipRecord, on db: any Database, next: any AnyAsyncModelResponder) async throws {
        if model.subjectRef == nil {
            model.subjectRef = deriver.subjectRef(businessId: BusinessID(model.businessId), consumerId: ConsumerID(model.consumerId)).rawValue
        }
        try await next.create(model, on: db)
    }
}

enum PolicyRegistration {
    /// Registers the model middleware that assigns `subject_ref` (one line in `configure`).
    static func configure(_ app: Application, config: ServerConfig) {
        app.databases.middleware.use(SubjectRefMiddleware(deriver: SubjectRefDeriver(key: config.subjectRefKey)),
                                     on: config.hasDatabase ? .psql : .sqlite)
    }
}

/// Resolves a business's customer addressing (`relationshipId` and/or `subject_ref`) to its **own** relationship. Every miss, mismatch
/// or foreign reference is the same plain 404: a business cannot learn whether a ref or id exists at another business.
struct SubjectResolver {
    let db: any Database
    let ctx: ServerContext
    /// The HTTP request, when resolving a business API body: a deprecated `relationshipId` is flagged on it (`Deprecation` / `Sunset` headers).
    var request: Request? = nil

    /// `relationshipId` addressing is deprecated (WP-C2): headers until `BusinessAddressing.relationshipIdSunset`, `400 relationship_id_sunset` after.
    func legacyAddressing() throws {
        guard ctx.now < BusinessAddressing.relationshipIdSunset else {
            throw APIError(.badRequest, .relationshipIdSunset, "relationshipId is no longer accepted. Address the customer with subjectRef (or connectionId).",
                           details: ["use": "subjectRef"])
        }
        request?.storage[LegacyAddressingKey.self] = true
    }

    /// The business-facing reference of `relationship`.
    func ref(for relationship: RelationshipRecord) -> SubjectRef {
        ctx.subjects.subjectRef(businessId: BusinessID(relationship.businessId), consumerId: ConsumerID(relationship.consumerId))
    }

    /// The relationship of `businessId` addressed by `subjectRef`, or 404.
    func relationship(businessId: BusinessID, subjectRef: SubjectRef) async throws -> RelationshipRecord {
        guard let found = try await RelationshipRecord.query(on: db).filter(\.$businessId == businessId.uuid)
            .filter(\.$subjectRef == subjectRef.rawValue).first() else { throw APIError.notFound }
        return found
    }

    /// Normalizes a request that names its customer: after this, `relationshipId` is the real relationship of the calling business and
    /// `subjectRef` is cleared, so the request hashes (and replays) identically however it was addressed.
    func resolve<R: SubjectAddressedRequest>(_ request: inout R, businessId: BusinessID) async throws {
        if !request.relationshipId.isUnaddressed { try legacyAddressing() }
        guard let subjectRef = request.subjectRef else {
            guard !request.relationshipId.isUnaddressed else { throw APIError.badRequest("relationshipId or subjectRef is required.") }
            return
        }
        let found = try await relationship(businessId: businessId, subjectRef: subjectRef)
        // Both given: they must name the same relationship (a mismatch is not distinguishable from "not found").
        if !request.relationshipId.isUnaddressed, request.relationshipId.uuid != found.id { throw APIError.notFound }
        request.relationshipId = RelationshipID(found.id!)
        request.subjectRef = nil
    }

    /// Optional addressing (reward issue): resolves `subjectRef` to `relationshipId` when given.
    func resolve(relationshipId: inout RelationshipID?, subjectRef: inout SubjectRef?, businessId: BusinessID) async throws {
        if relationshipId != nil { try legacyAddressing() }
        guard let ref = subjectRef else { return }
        let found = try await relationship(businessId: businessId, subjectRef: ref)
        if let given = relationshipId, given.uuid != found.id { throw APIError.notFound }
        relationshipId = RelationshipID(found.id!)
        subjectRef = nil
    }

    /// Assigns `subject_ref` to relationships created before it existed. Cheap when there is nothing to do (a read first), so it
    /// can run on every background tick.
    static func backfill(db: any Database, ctx: ServerContext, batch: Int = 500) async throws {
        guard try await RelationshipRecord.query(on: db).filter(\.$subjectRef == nil).count() > 0 else { return }
        let rows = try await RelationshipRecord.query(on: db).filter(\.$subjectRef == nil).limit(batch).all()
        for row in rows {
            row.subjectRef = ctx.subjects.subjectRef(businessId: BusinessID(row.businessId), consumerId: ConsumerID(row.consumerId)).rawValue
            try await row.update(on: db)
        }
    }
}

/// Set on a request whose body addressed a customer by the deprecated `relationshipId`.
struct LegacyAddressingKey: StorageKey { typealias Value = Bool }

/// Adds `Deprecation: true` and `Sunset: <HTTP date>` (RFC 8594) to responses of requests that used `relationshipId`.
struct LegacyAddressingHeadersMiddleware: AsyncMiddleware {
    static let sunsetHTTPDate: String = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "GMT")
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
        return formatter.string(from: BusinessAddressing.relationshipIdSunset)
    }()

    func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        let response = try await next.respond(to: request)
        if request.storage[LegacyAddressingKey.self] == true {
            response.headers.replaceOrAdd(name: "Deprecation", value: "true")
            response.headers.replaceOrAdd(name: "Sunset", value: Self.sunsetHTTPDate)
            response.headers.replaceOrAdd(name: .link, value: "<https://\(ViadereCore.defaultDomain)/docs/business-api#subject-ref>; rel=\"deprecation\"")
        }
        return response
    }
}
