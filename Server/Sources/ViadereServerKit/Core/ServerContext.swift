import Fluent
import Foundation
import Logging
import Vapor
import ViadereCore

/// Everything services need, created once at startup and injected explicitly (so tests can replace
/// the clock, push sender, SMS provider, passkey verifier and webhook transport).
public final class ServerContext: Sendable {
    public let config: ServerConfig
    public let clock: any ServerClock
    public let cipher: FieldCipher
    public let hasher: Hasher256
    public let limiter: RateLimiter
    public let apns: any APNsSender
    public let sms: any SMSProvider
    public let passkeys: any PasskeyVerifier
    public let webhookTransport: any WebhookTransport
    public let sequence: SequenceGenerator

    public init(config: ServerConfig, clock: any ServerClock = SystemClock(), apns: any APNsSender, sms: any SMSProvider,
                passkeys: any PasskeyVerifier, webhookTransport: any WebhookTransport,
                rateLimitStore: any RateLimitStore = InMemoryRateLimitStore()) {
        self.config = config
        self.clock = clock
        cipher = FieldCipher(key: config.dataEncryptionKey)
        hasher = Hasher256(pepper: config.pepper)
        limiter = RateLimiter(store: rateLimitStore, clock: clock)
        self.apns = apns
        self.sms = sms
        self.passkeys = passkeys
        self.webhookTransport = webhookTransport
        sequence = SequenceGenerator()
    }

    public var now: Date { clock.now() }
}

private struct ServerContextKey: StorageKey { typealias Value = ServerContext }

extension Application {
    public var ctx: ServerContext {
        get {
            guard let value = storage[ServerContextKey.self] else { fatalError("ServerContext not configured") }
            return value
        }
        set { storage[ServerContextKey.self] = newValue }
    }
}

extension Request {
    public var ctx: ServerContext { application.ctx }
}
