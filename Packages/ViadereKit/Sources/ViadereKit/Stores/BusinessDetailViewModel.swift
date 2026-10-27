import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class BusinessDetailViewModel {
    public private(set) var relationship: Relationship
    public private(set) var profile: BusinessProfile?
    public private(set) var consents: [InteractionPurpose: Bool] = [:]
    public private(set) var history: [InteractionEnvelope] = []
    public private(set) var isDisconnected = false
    public private(set) var errorMessage: String?
    private let services: ViadereServices

    public init(relationship: Relationship, services: ViadereServices) {
        self.relationship = relationship
        self.services = services
    }

    public var business: BusinessSummary { relationship.business }

    public var rows: [PermissionCopy.Row] {
        PermissionCopy.rows(supported: profile?.supportedPurposes ?? InteractionPurpose.allCases, granted: consents)
    }

    public func load() async {
        async let profileResult = try? services.api.businessProfile(code: relationship.business.code)
        async let grants = try? services.api.consents(for: relationship.id)
        async let interactions = try? services.api.interactions(status: nil)
        let (p, g, i) = await (profileResult, grants, interactions)
        profile = p
        if let g {
            var latest: [InteractionPurpose: ConsentGrant] = [:]
            for grant in g where (latest[grant.purpose]?.version ?? 0) <= grant.version { latest[grant.purpose] = grant }
            consents = latest.mapValues(\.granted)
        }
        history = (i?.items ?? []).filter { $0.business.id == relationship.business.id }
            .sorted { $0.interaction.createdAt > $1.interaction.createdAt }
    }

    /// Optimistic toggle with rollback if the server refuses.
    public func setConsent(_ purpose: InteractionPurpose, granted: Bool) async {
        guard purpose.isRevocable else { return }
        let previous = consents[purpose]
        consents[purpose] = granted
        errorMessage = nil
        do {
            _ = try await services.api.updateConsents(
                for: relationship.id,
                ConsentUpdateRequest(changes: [ConsentChange(purpose: purpose, granted: granted)], policyVersion: PermissionCopy.policyVersion))
        } catch {
            consents[purpose] = previous
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't save that change."
        }
    }

    public func disconnect() async {
        do {
            try await services.api.disconnect(relationship.id)
            isDisconnected = true
        } catch {
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't disconnect."
        }
    }
}
