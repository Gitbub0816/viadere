import APNS
import APNSCore
@preconcurrency import Crypto
import Foundation
import Logging
import NIOPosix
import NIOCore
import ViadereCore

/// Real APNs delivery through APNSwift with token-based (.p8) authentication.
public final class APNSwiftSender: APNsSender, Sendable {
    private let client: APNSClient<JSONDecoder, JSONEncoder>
    private let useSandbox: Bool
    private let logger: Logger

    public init(config: APNsConfig, logger: Logger) throws {
        let key = try P256.Signing.PrivateKey(pemRepresentation: config.keyPEM)
        let configuration = APNSClientConfiguration(
            authenticationMethod: .jwt(privateKey: key, keyIdentifier: config.keyID, teamIdentifier: config.teamID),
            environment: config.useSandbox ? .development : .production)
        client = APNSClient(configuration: configuration, eventLoopGroupProvider: .shared(MultiThreadedEventLoopGroup.singleton),
                            responseDecoder: JSONDecoder(), requestEncoder: JSONEncoder())
        useSandbox = config.useSandbox
        self.logger = logger
    }

    public func shutdown() async { try? await client.shutdown() }

    public func send(_ message: PushMessage) async -> PushOutcome {
        // A token minted for the other APNs environment would be rejected; skip rather than leak it.
        guard (message.environment == .sandbox) == useSandbox else { return .failed }
        struct Custom: Encodable, Sendable { var i: String? }
        let level: APNSAlertNotificationInterruptionLevel
        switch message.interruptionLevel {
        case "passive": level = .passive
        case "time-sensitive": level = .timeSensitive
        default: level = .active
        }
        let notification = APNSAlertNotification(
            alert: .init(title: .raw(message.title), body: .raw(message.body)),
            expiration: .timeIntervalSince1970InSeconds(Int(Date().timeIntervalSince1970) + 3600),
            priority: message.highPriority ? .immediately : .consideringDevicePower,
            topic: message.topic, payload: Custom(i: message.interactionId), threadID: message.threadID,
            category: message.category, mutableContent: message.mutableContent ? 1 : 0, interruptionLevel: level)
        do {
            try await client.sendAlertNotification(notification, deviceToken: message.deviceToken)
            return .delivered
        } catch let error as APNSError {
            let reason = error.responseStatus
            // 410 Gone / 400 BadDeviceToken mean the token is permanently unusable.
            if reason == 410 || error.reason == .badDeviceToken || error.reason == .unregistered { return .tokenInvalid }
            logger.warning("apns send failed", metadata: ["status": "\(reason)"])
            return .failed
        } catch {
            logger.warning("apns send failed", metadata: ["error": "\(type(of: error))"])
            return .failed
        }
    }
}
