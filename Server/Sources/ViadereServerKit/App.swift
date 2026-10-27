import Fluent
import FluentPostgresDriver
import FluentSQLiteDriver
import Foundation
import Logging
import Vapor
import ViadereCore

/// Builds the application: database, migrations, middleware (outermost first) and routes.
public func configure(_ app: Application, config: ServerConfig, overrides: Overrides = Overrides()) async throws {
    // MARK: Collaborators
    let clock = overrides.clock ?? SystemClock()
    let apns: any APNsSender
    if let override = overrides.apns { apns = override } else if let apnsConfig = config.apns {
        let sender = try APNSwiftSender(config: apnsConfig, logger: app.logger)
        app.lifecycle.use(APNsShutdown(sender: sender))
        apns = sender
    } else {
        apns = DisabledAPNsSender()
    }
    let sms: any SMSProvider
    if let override = overrides.sms { sms = override } else if let twilio = config.twilio {
        sms = TwilioProvider(config: twilio, client: app.client, logger: app.logger)
    } else {
        sms = UnconfiguredSMSProvider()
    }
    let transport: any WebhookTransport
    if let override = overrides.webhookTransport { transport = override } else {
        app.http.client.configuration.redirectConfiguration = .disallow
        app.http.client.configuration.timeout = .init(connect: .seconds(5), read: .seconds(10))
        transport = VaporWebhookTransport(client: app.client, allowInsecure: config.allowInsecureWebhookURLs)
    }
    let rcs: (any RCSProvider)?
    if let override = overrides.rcs { rcs = override } else if let rcsConfig = config.rcs {
        rcs = GenericRBMProvider(config: rcsConfig, http: VaporRCSHTTPClient(client: app.client))
    } else {
        rcs = nil
    }
    let passkeys = overrides.passkeys ?? WebAuthnPasskeyVerifier(config: config)
    let dashboardPasskeys: any PasskeyVerifier
    if overrides.passkeys == nil, let origin = config.dashboardOrigin, origin != config.relyingPartyOrigin {
        dashboardPasskeys = WebAuthnPasskeyVerifier(config: config, origin: origin)
    } else {
        dashboardPasskeys = passkeys
    }
    // Wallet: the signer is validated here, so a bad certificate fails the deploy instead of the first pass request.
    var passSigner: (any PassSigner)?
    var passPush: any PassPushSender = DisabledPassPushSender()
    if let override = overrides.passSigner {
        passSigner = override
    } else if let passes = config.passes {
        passSigner = try X509PassSigner(config: passes, teamIdentifier: config.appleTeamID, now: clock.now())
    }
    if let override = overrides.passPush {
        passPush = override
    } else if let passes = config.passes {
        let sender = try APNSwiftPassPushSender(config: passes, logger: app.logger)
        app.lifecycle.use(PassPushShutdown(sender: sender))
        passPush = sender
    }
    app.ctx = ServerContext(config: config, clock: clock, apns: apns, sms: sms, passkeys: passkeys, webhookTransport: transport,
                            rateLimitStore: overrides.rateLimitStore ?? InMemoryRateLimitStore(), rcs: rcs,
                            dashboardPasskeys: dashboardPasskeys, passSigner: passSigner, passPush: passPush,
                            integrity: overrides.integrity ?? UnconfiguredDeviceIntegrityVerifier())

    // MARK: Database
    if let url = config.databaseURL {
        try app.databases.use(.postgres(url: url), as: .psql)
    } else {
        guard !config.isProduction else { throw ServerConfigError.missing("DATABASE_URL") }
        app.databases.use(.sqlite(.memory), as: .sqlite)
    }
    app.migrations.add(Migrations.all)
    if config.databaseURL == nil || overrides.autoMigrate || config.autoMigrate { try await app.autoMigrate() }

    // MARK: HTTP
    app.routes.defaultMaxBodySize = ByteCount(value: config.maxBodyBytes)
    app.http.server.configuration.hostname = config.bindHost
    app.http.server.configuration.port = config.port
    app.http.server.configuration.supportPipelining = false
    app.middleware = Middlewares()
    app.middleware.use(SecurityHeadersMiddleware())
    app.middleware.use(RequestLoggingMiddleware())
    app.middleware.use(APIErrorMiddleware())
    app.middleware.use(CORSLockdownMiddleware())
    app.middleware.use(GlobalRateLimitMiddleware())
    app.middleware.use(RequestGuardMiddleware())
    try Routes.register(app)

    if config.runBackgroundJobs { app.lifecycle.use(BackgroundJobRunner(interval: .milliseconds(Int(config.jobIntervalSeconds * 1000)))) }
}

/// Test/dev seams. Production code never sets these.
public struct Overrides: Sendable {
    public var clock: (any ServerClock)?
    public var apns: (any APNsSender)?
    public var sms: (any SMSProvider)?
    public var passkeys: (any PasskeyVerifier)?
    public var webhookTransport: (any WebhookTransport)?
    public var rateLimitStore: (any RateLimitStore)?
    public var rcs: (any RCSProvider)?
    public var autoMigrate: Bool = false
    public var passSigner: (any PassSigner)?
    public var passPush: (any PassPushSender)?
    public var integrity: (any DeviceIntegrityVerifier)?

    public init(clock: (any ServerClock)? = nil, apns: (any APNsSender)? = nil, sms: (any SMSProvider)? = nil,
                passkeys: (any PasskeyVerifier)? = nil, webhookTransport: (any WebhookTransport)? = nil,
                rateLimitStore: (any RateLimitStore)? = nil, rcs: (any RCSProvider)? = nil, autoMigrate: Bool = false,
                passSigner: (any PassSigner)? = nil, passPush: (any PassPushSender)? = nil,
                integrity: (any DeviceIntegrityVerifier)? = nil) {
        self.clock = clock
        self.apns = apns
        self.sms = sms
        self.passkeys = passkeys
        self.webhookTransport = webhookTransport
        self.rateLimitStore = rateLimitStore
        self.rcs = rcs
        self.autoMigrate = autoMigrate
        self.passSigner = passSigner
        self.passPush = passPush
        self.integrity = integrity
    }
}

/// Development/CI entry used by the executable and tests.
public func makeApplication(environment: Environment, config: ServerConfig, overrides: Overrides = Overrides()) async throws -> Application {
    let app = try await Application.make(environment)
    do {
        try await configure(app, config: config, overrides: overrides)
    } catch {
        try? await app.asyncShutdown()
        throw error
    }
    return app
}

/// Closes the APNs HTTP/2 client when the application shuts down.
struct APNsShutdown: LifecycleHandler {
    let sender: APNSwiftSender
    func shutdown(_ application: Application) {}
    func shutdownAsync(_ application: Application) async { await sender.shutdown() }
}

/// Closes the pass-push APNs client when the application shuts down.
struct PassPushShutdown: LifecycleHandler {
    let sender: APNSwiftPassPushSender
    func shutdown(_ application: Application) {}
    func shutdownAsync(_ application: Application) async { await sender.shutdown() }
}
