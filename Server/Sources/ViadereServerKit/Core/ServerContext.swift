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
    /// Pairwise `subject_ref` derivation (`SUBJECT_REF_KEY`).
    public let subjects: SubjectRefDeriver
    /// Short-lived cache of the operator-controlled policy state (kill switches and law/policy rules).
    let policyCache = PolicyStateCache()
    /// In-memory copy of the key-directory Merkle tree's leaf hashes (the database is the source; the cache only avoids re-reading it).
    let keyLogCache = KeyLogTreeCache()
    /// Short-lived cache of the operator switches in `platform_flags` (maintenance, sign-up stops, webhook pause, messaging restriction).
    let platformCache = PlatformFlagCache()
    /// Counters for `/metrics` (no personal data, bounded labels).
    let metrics = MetricsRegistry()
    /// Resolves and checks business domains (DNS TXT and well-known file) for onboarding and ongoing assurance.
    let domains: any DomainChecker
    /// Calls to Google Cloud (token exchange, KMS, Cloud Storage) and R2 for the audit-head export.
    let outbound: any OutboundHTTP
    public let limiter: RateLimiter
    public let apns: any APNsSender
    public let sms: any SMSProvider
    public let passkeys: any PasskeyVerifier
    public let webhookTransport: any WebhookTransport
    public let sequence: SequenceGenerator
    /// SMS, RCS and Apple Messages for Business adapters.
    public let channels: ChannelRegistry
    /// Passkey verifier for the business dashboard / operator console (RP origin may differ from consumers').
    public let dashboardPasskeys: any PasskeyVerifier
    /// Signs Wallet passes. `nil` when no pass certificate is configured.
    public let passSigner: (any PassSigner)?
    /// Pushes "pass changed" notifications to registered Wallet devices.
    public let passPush: any PassPushSender
    /// App Attest / DeviceCheck hook (a stub until Apple credentials are configured).
    public let integrity: any DeviceIntegrityVerifier
    /// Transactional email (dashboard verification codes and invitations).
    public let email: any EmailSender
    /// Security alerts (budget exhaustion, ...) that operators should be able to alert on.
    public let logger = Logger(label: "viadere.security")

    public init(config: ServerConfig, clock: any ServerClock = SystemClock(), apns: any APNsSender, sms: any SMSProvider,
                passkeys: any PasskeyVerifier, webhookTransport: any WebhookTransport,
                rateLimitStore: any RateLimitStore = InMemoryRateLimitStore(), rcs: (any RCSProvider)? = nil,
                dashboardPasskeys: (any PasskeyVerifier)? = nil, passSigner: (any PassSigner)? = nil,
                passPush: any PassPushSender = DisabledPassPushSender(),
                integrity: any DeviceIntegrityVerifier = UnconfiguredDeviceIntegrityVerifier(),
                email: any EmailSender = DisabledEmailSender(), domains: (any DomainChecker)? = nil, outbound: (any OutboundHTTP)? = nil) {
        self.config = config
        self.clock = clock
        cipher = FieldCipher(key: config.dataEncryptionKey, keyId: config.operations.dataKeyId, previous: config.operations.previousDataKeys)
        hasher = Hasher256(pepper: config.pepper, pepperId: config.operations.pepperId, previous: config.operations.previousPeppers)
        subjects = SubjectRefDeriver(key: config.subjectRefKey)
        limiter = RateLimiter(store: rateLimitStore, clock: clock)
        self.apns = apns
        self.sms = sms
        self.passkeys = passkeys
        self.webhookTransport = webhookTransport
        sequence = SequenceGenerator()
        channels = ChannelRegistry(sms: SMSChannelAdapter(provider: sms), rcs: RCSChannelAdapter(provider: rcs),
                                   appleMessagesForBusiness: AppleMessagesForBusinessAdapter(flagEnabled: config.channelFlags.appleMessagesForBusiness))
        self.dashboardPasskeys = dashboardPasskeys ?? passkeys
        self.passSigner = passSigner
        self.passPush = passPush
        self.integrity = integrity
        self.email = email
        self.domains = domains ?? UnconfiguredDomainChecker()
        self.outbound = outbound ?? UnconfiguredOutboundHTTP()
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
