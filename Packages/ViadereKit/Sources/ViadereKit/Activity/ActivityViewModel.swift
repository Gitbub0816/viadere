import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

public enum ActivityActionOutcome: Equatable, Sendable {
    case done
    /// The action changes money, identity or something sensitive: present the secure approval sheet for this interaction.
    case needsSecureSheet(InteractionID)
    case cancelled
    case failed(String)
}

/// The Activity tab's brain: loads status/ticket/confirm interactions, builds the calm per-business feed, answers
/// inline actions with device-signed decisions, and tells the app which statuses may run as Live Activities.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class ActivityViewModel {
    public enum Phase: Equatable, Sendable { case idle, loading, loaded, failed(String) }

    public private(set) var content: ActivityContent = .empty
    public private(set) var phase: Phase = .idle
    public private(set) var passes: [WalletPassID: WalletPassMetadata] = [:]
    /// Statuses that may start or update a Live Activity (`LiveActivityPolicy`), for the app to sync.
    public private(set) var liveCandidates: [InteractionEnvelope] = []
    public private(set) var busyActionId: String?
    public private(set) var message: String?
    public var filter: ActivityCategory.Filter = .all

    private let services: ViadereServices

    public init(services: ViadereServices, initial: ActivityContent = .empty) {
        self.services = services
        self.content = initial
    }

    /// The feed with the selected filter applied.
    public var visible: ActivityContent { content.filtered(filter) }

    /// Badge for the tab: items waiting on the person.
    public var needsYouCount: Int { content.needsYouCount }

    public func load() async {
        if content.isEmpty { phase = .loading }
        do {
            let page = try await services.api.interactions(status: nil)
            let now = services.clock()
            content = ActivityFeed.build(interactions: page.items, now: now)
            liveCandidates = ActivityLiveEligibility.candidates(from: page.items, now: now)
            phase = .loaded
        } catch let error as APIError {
            phase = .failed(error.userMessage)
        } catch {
            phase = .failed("Something went wrong.")
        }
        // Passes are optional: a server without Wallet support answers 404 and the buttons simply don't appear.
        if let list = try? await services.api.walletPasses() {
            passes = Dictionary(list.map { ($0.id, $0) }, uniquingKeysWith: { _, new in new })
        }
    }

    public func pass(for item: ActivityItem) -> WalletPassMetadata? { item.walletPassId.flatMap { passes[$0] } }

    public func clearMessage() { message = nil }

    /// Answers an action. Inline routes sign a decision on this device; sensitive routes return `needsSecureSheet`.
    @discardableResult
    public func perform(_ action: ActivityAction, in item: ActivityItem) async -> ActivityActionOutcome {
        guard let envelope = item.pending.first(where: { $0.id == action.interactionId }) else { return .failed("That's no longer available.") }
        guard action.route == .inline else { return .needsSecureSheet(envelope.id) }
        guard busyActionId == nil else { return .cancelled }
        busyActionId = action.id
        message = nil
        defer { busyActionId = nil }
        do {
            _ = try await services.approvals.submit(envelope, decision: action.decision, selectedOptionIds: action.selectedOptionIds, channel: .inApp)
            await load()
            return .done
        } catch let error as ApprovalError {
            if error == .userCancelled { return .cancelled }
            // Handled elsewhere or expired: refresh so the item reflects reality.
            switch error {
            case .notActionable, .expired, .contextChanged: await load()
            default: break
            }
            message = error.userMessage
            return .failed(error.userMessage)
        } catch {
            message = "Couldn't send that."
            return .failed("Couldn't send that.")
        }
    }

    /// Appointments with no reschedule options from the business can still ask for a new time in the conversation.
    public func canAskToReschedule(_ item: ActivityItem) -> Bool {
        guard item.category == .appointment, item.phase != .past else { return false }
        return !item.actions.contains { $0.decision == .select }
    }
}
