import APNS
import APNSCore
@preconcurrency import Crypto
import Foundation
import Logging
import NIOPosix
import NIOCore
import NIOSSL
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
        let notification = Self.notification(for: message)
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

    public func sendLiveActivity(_ push: LiveActivityPush) async -> PushOutcome {
        guard (push.environment == .sandbox) == useSandbox else { return .failed }
        let expiration = APNSNotificationExpiration.timeIntervalSince1970InSeconds(push.timestamp + 3600)
        do {
            switch push.event {
            case .start:
                guard let attributes = push.attributes else { return .failed }
                let notification = APNSStartLiveActivityNotification(
                    expiration: expiration, priority: .immediately, appID: push.bundleId, contentState: push.content,
                    timestamp: push.timestamp, attributes: attributes, attributesType: LiveActivityPush.attributesType,
                    alert: .init(title: .raw(push.alertTitle ?? "Viadere"), body: .raw(push.alertBody ?? "There is an update.")))
                try await client.sendStartLiveActivityNotification(notification, pushToStartToken: push.deviceToken)
            case .update, .end:
                let notification = APNSLiveActivityNotification(
                    expiration: expiration, priority: .immediately, topic: push.topic, contentState: push.content,
                    event: push.event == .end ? .end : .update, timestamp: push.timestamp)
                try await client.sendLiveActivityNotification(notification, deviceToken: push.deviceToken)
            }
            return .delivered
        } catch let error as APNSError {
            if error.responseStatus == 410 || error.reason == .badDeviceToken || error.reason == .unregistered { return .tokenInvalid }
            logger.warning("apns live activity failed", metadata: ["status": "\(error.responseStatus)"])
            return .failed
        } catch {
            logger.warning("apns live activity failed", metadata: ["error": "\(type(of: error))"])
            return .failed
        }
    }

    struct Custom: Encodable, Sendable { var iid: String? }

    /// The exact APNs payload: generic alert, `mutable-content`, category, `thread-id`, `interruption-level`, and a
    /// top-level opaque `iid`.
    static func notification(for message: PushMessage) -> APNSAlertNotification<Custom> {
        let level: APNSAlertNotificationInterruptionLevel
        switch message.interruptionLevel {
        case "passive": level = .passive
        case "time-sensitive": level = .timeSensitive
        default: level = .active
        }
        return APNSAlertNotification(
            alert: .init(title: .raw(message.title), body: .raw(message.body)),
            expiration: .timeIntervalSince1970InSeconds(Int(Date().timeIntervalSince1970) + 3600),
            priority: message.highPriority ? .immediately : .consideringDevicePower,
            topic: message.topic, payload: Custom(iid: message.interactionId), threadID: message.threadID,
            category: message.category, mutableContent: message.mutableContent ? 1 : 0, interruptionLevel: level)
    }
}

/// Wallet pass update pushes over APNs with the Pass Type ID certificate (TLS client authentication).
public final class APNSwiftPassPushSender: PassPushSender, Sendable {
    private struct Empty: APNSMessage {}

    private let client: APNSClient<JSONDecoder, JSONEncoder>
    private let logger: Logger

    public init(config: PassConfig, logger: Logger) throws {
        let key = try NIOSSLPrivateKey(bytes: Array(config.privateKeyPEM.utf8), format: .pem)
        let certificate = try NIOSSLCertificate(bytes: Array(config.certificatePEM.utf8), format: .pem)
        let configuration = APNSClientConfiguration(
            authenticationMethod: .tls(privateKey: .privateKey(key), certificateChain: [.certificate(certificate)]),
            environment: .production)
        client = APNSClient(configuration: configuration, eventLoopGroupProvider: .shared(MultiThreadedEventLoopGroup.singleton),
                            responseDecoder: JSONDecoder(), requestEncoder: JSONEncoder())
        self.logger = logger
    }

    public func shutdown() async { try? await client.shutdown() }

    public func notify(pushToken: String, passTypeIdentifier: String) async -> PushOutcome {
        let request = APNSRequest(message: Empty(), deviceToken: pushToken, pushType: .alert, expiration: nil, priority: .immediately,
                                  apnsID: nil, topic: passTypeIdentifier, collapseID: nil)
        do {
            _ = try await client.send(request)
            return .delivered
        } catch let error as APNSError {
            if error.responseStatus == 410 || error.reason == .badDeviceToken || error.reason == .unregistered { return .tokenInvalid }
            logger.warning("apns pass push failed", metadata: ["status": "\(error.responseStatus)"])
            return .failed
        } catch {
            logger.warning("apns pass push failed", metadata: ["error": "\(type(of: error))"])
            return .failed
        }
    }
}
