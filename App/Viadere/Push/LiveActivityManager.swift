import ActivityKit
import Foundation
import UIKit
import ViadereCore
import ViadereKit

/// Starts and updates Live Activities (order, delivery, flight, appointment) from status interactions, and
/// registers their push tokens so the server can update them without the app running.
///
/// - Update tokens (`pushType: .token`) are registered per activity.
/// - Push-to-start tokens (iOS 17.2+) are registered once, letting the server start an activity remotely.
/// - Only genuinely ongoing, non-promotional events qualify (`LiveActivityPolicy` in ViadereCore).
@MainActor
final class LiveActivityManager {
    private let services: ViadereServices
    private var tracked = Set<String>()
    private var tasks: [Task<Void, Never>] = []
    private static let log = ViadereLog.notifications

    private var registrar: PushRegistrar { PushRegistrar(api: services.api, configuration: services.configuration) }

    init(services: ViadereServices) {
        self.services = services
        startObserving()
    }

    private func startObserving() {
        tasks.append(Task { [weak self] in
            for await activity in Activity<ViadereActivityAttributes>.activityUpdates { self?.observe(activity) }
        })
        if #available(iOS 17.2, *) {
            tasks.append(Task { [weak self] in
                for await token in Activity<ViadereActivityAttributes>.pushToStartTokenUpdates {
                    guard let self else { return }
                    await self.registerPushToStart(token)
                }
            })
        }
        for activity in Activity<ViadereActivityAttributes>.activities { observe(activity) }
    }

    private func observe(_ activity: Activity<ViadereActivityAttributes>) {
        guard tracked.insert(activity.id).inserted else { return }
        tasks.append(Task { [weak self] in
            for await token in activity.pushTokenUpdates {
                guard let self else { return }
                await self.registerUpdateToken(activity: activity, token: token)
            }
        })
    }

    private func registerUpdateToken(activity: Activity<ViadereActivityAttributes>, token: Data) async {
        guard (try? await services.records.load()) != nil else { return }
        do {
            try await registrar.registerLiveActivity(
                activityId: activity.id, businessId: BusinessID(activity.attributes.businessId),
                interactionId: InteractionID(activity.attributes.interactionId), pushToken: token)
        } catch {
            Self.log.error("liveactivity.token.failed")
        }
    }

    private func registerPushToStart(_ token: Data) async {
        guard (try? await services.records.load()) != nil else { return }
        try? await registrar.registerPushToStart(pushToken: token)
    }

    // MARK: Status handling

    private func running(for interactionId: String) -> Activity<ViadereActivityAttributes>? {
        Activity<ViadereActivityAttributes>.activities.first { $0.attributes.interactionId == interactionId }
    }

    /// Reconciles the foreground list of in-progress statuses with running activities.
    func sync(_ statuses: [InteractionEnvelope]) async {
        for envelope in statuses { _ = await apply(envelope) }
    }

    /// A silent push announced a status change: fetch it and start/update/end the activity.
    func handleStatusPush(interactionId: InteractionID) async -> Bool {
        guard let envelope = try? await services.api.interaction(interactionId) else { return false }
        return await apply(envelope)
    }

    @discardableResult
    private func apply(_ envelope: InteractionEnvelope) async -> Bool {
        guard ActivityAuthorizationInfo().areActivitiesEnabled else { return false }
        let interaction = envelope.interaction
        let existing = running(for: interaction.id.description)
        switch LiveActivityDecision.decide(for: interaction, isRunning: existing != nil) {
        case .ignore:
            return false
        case .start(let status):
            // ActivityKit only lets an app *start* an activity while it is in the foreground.
            guard UIApplication.shared.applicationState == .active else { return false }
            let attributes = ViadereActivityAttributes(
                businessName: envelope.business.safeName, businessId: envelope.business.id.description,
                interactionId: interaction.id.description)
            do {
                let activity = try Activity.request(
                    attributes: attributes, content: ActivityContent(state: status, staleDate: interaction.expiresAt), pushType: .token)
                observe(activity)
                return true
            } catch {
                Self.log.error("liveactivity.start.failed")
                return false
            }
        case .update(let status):
            await existing?.update(ActivityContent(state: status, staleDate: interaction.expiresAt))
            return true
        case .end(let status):
            await existing?.end(ActivityContent(state: status, staleDate: nil), dismissalPolicy: .default)
            return true
        }
    }
}
