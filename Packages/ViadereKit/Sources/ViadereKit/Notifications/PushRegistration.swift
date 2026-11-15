import Foundation
import ViadereCore

/// Registers APNs and Live Activity tokens with the API (device-signed, so only an enrolled device can).
public struct PushRegistrar: Sendable {
    private let api: any ViadereAPI
    private let configuration: ViadereConfiguration

    public init(api: any ViadereAPI, configuration: ViadereConfiguration) {
        self.api = api
        self.configuration = configuration
    }

    /// Lowercase hex of a push token.
    public static func hex(_ token: Data) -> String { Hex.encode(token) }

    public func registerAPNs(deviceToken: Data) async throws {
        try await api.registerAPNsToken(APNsTokenRegistration(token: Self.hex(deviceToken), environment: configuration.apnsEnvironment,
                                                              bundleId: configuration.bundleID))
    }

    /// Per-activity update token.
    public func registerLiveActivity(activityId: String, businessId: BusinessID?, interactionId: InteractionID?, pushToken: Data) async throws {
        try await api.registerLiveActivityToken(LiveActivityTokenRegistration(
            kind: .update, activityId: activityId, businessId: businessId, interactionId: interactionId, pushToken: Self.hex(pushToken)))
    }

    /// Push-to-start token (iOS 17.2+): lets the server start an activity without the app running.
    public func registerPushToStart(pushToken: Data) async throws {
        try await api.registerLiveActivityToken(LiveActivityTokenRegistration(kind: .pushToStart, pushToken: Self.hex(pushToken)))
    }
}

/// Decides whether a status update should start or update a Live Activity.
public enum LiveActivityDecision: Sendable, Equatable {
    case start(LiveActivityStatus)
    case update(LiveActivityStatus)
    case end(LiveActivityStatus)
    case ignore

    /// - Parameter isRunning: whether an activity for this interaction already exists.
    public static func decide(for interaction: Interaction, isRunning: Bool) -> LiveActivityDecision {
        guard case .status(let payload) = interaction.payload, let status = payload.liveActivity,
              LiveActivityPolicy.isEligible(purpose: interaction.purpose, status: status) else { return .ignore }
        if status.isTerminal { return isRunning ? .end(status) : .ignore }
        return isRunning ? .update(status) : .start(status)
    }
}
