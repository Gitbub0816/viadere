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
        } catch let error as APIError {
            phase = .failed(error.userMessage)
        } catch {
            phase = .failed("Something went wrong.")
        }
    }

    /// Optimistically removes a decided request.
    public func didDecide(_ id: InteractionID) {
        content.pending.removeAll { $0.id == id }
    }
}
