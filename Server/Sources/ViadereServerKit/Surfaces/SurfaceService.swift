import Fluent
import Foundation
import ViadereCore

/// Neutral business surfaces (WP-1.6; spec B1, B6, C6.2; SECURITY.md §2.93 "Module layouts", §2.96). A business chooses which standard
/// Viadere modules its home shows and in what order; it never supplies text, links, navigation, styling or code. Every write is validated
/// by `SurfaceLayout.validate`; every client re-applies `SurfaceLayout.renderable` on read.
struct SurfaceService {
    let db: any Database
    let ctx: ServerContext

    static let published = "published"

    /// The newest published layout, or Viadere's default (version 0). A stored row that no longer validates (a registry change) is ignored
    /// in favor of the default rather than served.
    func current(businessId: UUID) async throws -> (layout: SurfaceLayout, version: Int) {
        let rows = try await BusinessSurfaceRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$status == Self.published)
            .sort(\.$version, .descending).limit(5).all()
        for row in rows {
            if let layout = SurfaceLayout.validate(data: Data(row.layoutJSON.utf8)).layout { return (layout, row.version) }
        }
        return (SurfaceLayout.defaultBusinessHome, 0)
    }

    /// `GET /v1/businesses/{id}/surface`: only for a verified business the caller is actively connected to (`404` otherwise).
    func view(consumer: ConsumerID, business: BusinessID) async throws -> BusinessSurfaceView {
        guard try await RelationshipRecord.query(on: db).filter(\.$consumerId == consumer.uuid).filter(\.$businessId == business.uuid)
            .filter(\.$status == "active").first() != nil,
              let record = try await DirectoryService(db: db).verified(id: business.uuid),
              let summary = try await DirectoryService(db: db).summary(for: record) else { throw APIError.notFound }
        let (layout, version) = try await current(businessId: business.uuid)
        return BusinessSurfaceView(business: summary, template: layout.template, modules: SurfaceLayout.renderable(layout.wireModules), version: version)
    }

    /// Publishes a new layout version (console, permission `manageOrganization`). Returns the version.
    @discardableResult
    func publish(businessId: UUID, layout: SurfaceLayout, actor: AuditActor) async throws -> Int {
        let validated = SurfaceLayout.validate(layout.jsonValue)
        guard let checked = validated.layout else {
            throw APIError.validation("That page layout is not allowed.", details: ["layout": validated.issues.map(\.code).joined(separator: ",")])
        }
        let json = String(decoding: try checked.canonicalJSON(), as: UTF8.self)
        let now = ctx.now
        return try await db.transaction { tx in
            let latest = try await BusinessSurfaceRecord.query(on: tx).filter(\.$businessId == businessId).sort(\.$version, .descending).first()?.version ?? 0
            let row = BusinessSurfaceRecord()
            row.id = UUID()
            row.businessId = businessId
            row.version = latest + 1
            row.status = Self.published
            row.layoutJSON = json
            row.publishedAt = now
            row.publishedBy = actor.id
            row.createdAt = now
            // Unique (business_id, version): of two concurrent publishes one fails instead of both claiming the same version.
            try await row.create(on: tx)
            _ = try await AuditService(db: tx, ctx: ctx).record("surface.published", actor: actor, businessId: BusinessID(businessId), subjectType: "business_surface",
                                                              subjectId: row.id?.uuidString.lowercased(),
                                                              metadata: ["version": String(row.version), "modules": checked.modules.map(\.module).joined(separator: ",")])
            return row.version
        }
    }
}
