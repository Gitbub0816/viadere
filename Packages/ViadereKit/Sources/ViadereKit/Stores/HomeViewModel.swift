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
    /// End of this iPhone's new-device cool-down (high-risk approvals are paused until then), or `nil` when it is trusted.
    public private(set) var approvalsLockedUntil: Date?
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
        } catch let error as APIError {
            phase = .failed(error.userMessage)
        } catch {
            phase = .failed("Something went wrong.")
        }
    }

    /// The calm explanation on Home while the new-device cool-down lasts.
    public var coolDownNotice: String? {
        guard let until = approvalsLockedUntil, CoolDownPolicy.isActive(until: until, now: services.clock()) else { return nil }
        return CoolDownPolicy.message(until: until, now: services.clock())
    }

    /// Whether `envelope` is one the cool-down pauses (a high or critical request): Home labels it.
    public func isPausedByCoolDown(_ envelope: InteractionEnvelope) -> Bool {
        let decision: Decision = envelope.interaction.kind == .confirm ? .confirm : .approve
        return CoolDownPolicy.pauses(decision, on: envelope.interaction, until: approvalsLockedUntil, now: services.clock())
    }

    /// Optimistically removes a decided request.
    public func didDecide(_ id: InteractionID) {
        content.pending.removeAll { $0.id == id }
    }
}
