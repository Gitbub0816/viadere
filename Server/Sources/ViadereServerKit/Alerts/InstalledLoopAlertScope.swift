import Fluent
import Foundation

/// Which installed Loops the customer allows alerts from (owner decision F-4; SECURITY.md §2.98 "Alerts from an installed Loop").
///
/// The scope is **a set of that Loop's own publications**, never a business: an install-only customer who allows alerts from one Loop of a
/// business sees that Loop's requests in Alerts and nothing else from the business (no other Loop, offer, message or interaction). It is
/// read on every list, so turning the permission off, uninstalling or blocking the business takes effect at once.
struct InstalledLoopAlertScope: Sendable {
    /// Publications (every revision) of the Loops with alerts allowed.
    var publicationIds: Set<UUID>
    /// The businesses those Loops belong to.
    var businesses: Set<UUID>
    private var businessByPublication: [UUID: UUID]

    static let none = InstalledLoopAlertScope(publicationIds: [], businesses: [], businessByPublication: [:])

    /// The scope restricted to one business (or unchanged for All).
    func narrowed(to business: UUID?) -> InstalledLoopAlertScope {
        guard let business else { return self }
        let kept = businessByPublication.filter { $0.value == business }
        return InstalledLoopAlertScope(publicationIds: Set(kept.keys), businesses: kept.isEmpty ? [] : [business], businessByPublication: kept)
    }

    static func load(consumer: UUID, db: any Database) async throws -> InstalledLoopAlertScope {
        let installs = try await LoopInstallRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$uninstalledAt == nil)
            .filter(\.$alertsEnabled == true).all()
        guard !installs.isEmpty else { return .none }
        // A blocked business never counts (a block is never weaker than an uninstall).
        let blocked = Set(try await BusinessPreferenceRecord.query(on: db).filter(\.$consumerId == consumer)
            .filter(\.$businessId ~~ installs.map(\.businessId)).filter(\.$blockedAt != nil).all().map(\.businessId))
        let allowed = installs.filter { !blocked.contains($0.businessId) }
        guard !allowed.isEmpty else { return .none }
        let publications = try await LoopPublicationRecord.query(on: db).filter(\.$definitionId ~~ allowed.map(\.definitionId)).all()
        var byPublication: [UUID: UUID] = [:]
        for publication in publications {
            guard let id = publication.id,
                  allowed.contains(where: { $0.definitionId == publication.definitionId && $0.businessId == publication.businessId }) else { continue }
            byPublication[id] = publication.businessId
        }
        return InstalledLoopAlertScope(publicationIds: Set(byPublication.keys), businesses: Set(byPublication.values), businessByPublication: byPublication)
    }
}
