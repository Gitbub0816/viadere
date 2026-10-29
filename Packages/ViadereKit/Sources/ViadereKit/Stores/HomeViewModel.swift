import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class HomeViewModel {
    public enum Phase: Equatable, Sendable { case idle, loading, loaded, failed(String) }

    public private(set) var content: HomeContent = .empty
    public private(set) var phase: Phase = .idle
    /// End of this iPhone's new-device window, or `nil`. Informational: it unlocks nothing (`highRiskPaused` is what counts).
    public private(set) var approvalsLockedUntil: Date?
    /// The server says this iPhone is not approved for high-risk requests yet (not D1).
    public private(set) var highRiskPaused = false
    private let services: ViadereServices

    public init(services: ViadereServices, initial: HomeContent = .empty) {
        self.services = services
        self.content = initial
    }

    public func load() async {
        if content.isEmpty { phase = .loading }
        do {
            async let interactions = services.api.interactions(status: nil)
            async let relationships = services.api.relationships()
            let (page, rels) = try await (interactions, relationships)
            content = HomeContent.build(interactions: page.items, relationships: rels, now: services.clock())
            phase = .loaded
            approvalsLockedUntil = await services.approvalsLockedUntil()
            highRiskPaused = await services.thisDeviceApprovesHighRisk() == false
        } catch let error as APIError {
            phase = .failed(error.userMessage)
        } catch {
            phase = .failed("Something went wrong.")
        }
    }

    /// The calm explanation on Home while this iPhone is not approved for high-risk requests.
    public var coolDownNotice: String? {
        highRiskPaused ? CoolDownPolicy.notApprovedMessage : nil
    }

    /// Whether `envelope` is one this iPhone can't approve yet (a high or critical request): Home labels it.
    public func isPausedByCoolDown(_ envelope: InteractionEnvelope) -> Bool {
        let decision: Decision = envelope.interaction.kind == .confirm ? .confirm : .approve
        return highRiskPaused && CoolDownPolicy.restricts(decision, on: envelope.interaction)
    }

    /// Optimistically removes a decided request.
    public func didDecide(_ id: InteractionID) {
        content.pending.removeAll { $0.id == id }
    }
}
