import Fluent
import FluentPostgresDriver
import FluentSQLiteDriver
import Foundation
import Logging
import Vapor
import ViadereCore

/// Builds the application: database, migrations, middleware (outermost first) and routes.
public func configure(_ app: Application, config initialConfig: ServerConfig, overrides: Overrides = Overrides()) async throws {
    var config = initialConfig
    let migrating = app.environment.arguments.dropFirst().contains("migrate")
    // The migration job's configuration holds no service secret: it may run migrations and nothing else.
    if config.role == .migrate, !migrating { throw ServerConfigError.invalid("ROLE (migrate runs only `ViadereServer migrate`)") }

    // MARK: Collaborators
    let clock = overrides.clock ?? SystemClock()
    // Every outbound client refuses the managed-identity endpoint and the metadata services (SSRF, SECURITY.md §1).
    let destinationGuard = OutboundDestinationGuard.fromEnvironment()
    let client: any Client = GuardedClient(base: app.client, guard: destinationGuard)
    let outbound: any OutboundHTTP = overrides.outboundHTTP ?? VaporOutboundHTTP(client: app.client, guard: destinationGuard)
    // Azure: managed-identity tokens, Key Vault, the audit container, Service Bus.
    let tokens: (any AccessTokenSource)? = overrides.accessTokens ?? AzureManagedIdentity.fromEnvironment(ProcessInfo.processInfo.environment)
    var kms = overrides.kms
    if kms == nil, let vault = config.azure.keyVaultURL, let tokens {
        kms = try AzureKeyVaultKMS(vaultURL: vault, tokens: tokens, http: outbound, now: { clock.now() })
    }
    if config.azure.usesKeyVault, kms == nil { throw ServerConfigError.missing("AZURE_KEY_VAULT_URL with a managed identity (a Key Vault key is configured)") }
    if config.isStrict, let kms, kms is LocalKMS { throw ServerConfigError.invalid("KMS (the local software KMS is for development and tests)") }
    // The key-directory log key stays in Key Vault; its public key is fetched now, so a missing key fails the boot.
    if let ref = config.azure.kdLogKey {
        guard let kms else { throw ServerConfigError.missing("AZURE_KEY_VAULT_URL (for AZURE_KEY_VAULT_KD_LOG_KEY)") }
        config.approve.logKey = try await KMSSigningKey.load(kms: kms, keyRef: ref)
    }
    // The link-descriptor key likewise (WP-C1); on Fly and in development it is the environment secret `LINK_DESCRIPTOR_SIGNING_KEY`.
    if let ref = config.azure.linkDescriptorKey {
        guard let kms else { throw ServerConfigError.missing("AZURE_KEY_VAULT_URL (for AZURE_KEY_VAULT_LINK_DESCRIPTOR_KEY)") }
        config.approve.linkDescriptorKey = try await KMSSigningKey.load(kms: kms, keyRef: ref)
    }
    // The Loop publication key likewise (WP-3.2); elsewhere the environment secret `LOOP_PUBLICATION_SIGNING_KEY`.
    if let ref = config.azure.loopPublicationKey {
        guard let kms else { throw ServerConfigError.missing("AZURE_KEY_VAULT_URL (for AZURE_KEY_VAULT_LOOP_PUBLICATION_KEY)") }
        config.loops.publicationKey = try await KMSSigningKey.load(kms: kms, keyRef: ref)
    }
    // One key, one role, checked again now that Key Vault public keys are known.
    try config.requireDistinctSigningKeys()
    try config.requireDistinctLoopKey()
    // Brand Kits (WP-2.1): the `brand-manifest` key (Key Vault on Azure), one key, one role.
    try await BrandKitRegistration.resolveSigningKey(config: &config, kms: kms)
    var auditStore = overrides.auditObjectStore
    if auditStore == nil, let export = config.operations.auditExport, export.kind == .azureBlob, let endpoint = export.endpoint {
        guard let tokens else { throw ServerConfigError.missing("a managed identity (for AZURE_AUDIT_BLOB_ENDPOINT)") }
        auditStore = try AzureBlobObjectStore(endpoint: endpoint, container: export.target, tokens: tokens, http: outbound, now: { clock.now() })
    }
    var queueTransport = overrides.queueTransport
    if queueTransport == nil, config.queueTransport == .servicebus, let fqdn = config.azure.serviceBusFQDN {
        guard let tokens else { throw ServerConfigError.missing("a managed identity (for QUEUE_TRANSPORT=servicebus)") }
        queueTransport = ServiceBusRESTTransport(fqdn: fqdn, tokens: tokens, http: outbound)
    }
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
        sms = TwilioProvider(config: twilio, client: client, logger: app.logger)
    } else if let mailerSend = config.mailerSendSMS {
        sms = MailerSendSMSProvider(config: mailerSend, client: client)
    } else {
        sms = UnconfiguredSMSProvider()
    }
    let transport: any WebhookTransport
    if let override = overrides.webhookTransport { transport = override } else {
        app.http.client.configuration.redirectConfiguration = .disallow
        app.http.client.configuration.timeout = .init(connect: .seconds(5), read: .seconds(10))
        transport = VaporWebhookTransport(client: app.client, allowInsecure: config.allowInsecureWebhookURLs, guard: destinationGuard)
    }
    let rcs: (any RCSProvider)?
    if let override = overrides.rcs { rcs = override } else if let rcsConfig = config.rcs {
        rcs = GenericRBMProvider(config: rcsConfig, http: VaporRCSHTTPClient(client: client))
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
    let email: any EmailSender
    let domains: any DomainChecker = overrides.domainChecker ?? NetworkDomainChecker(client: client, allowInsecure: config.allowInsecureWebhookURLs)
    if let override = overrides.emailSender { email = override } else if let emailConfig = config.email {
        email = HTTPEmailSender(config: emailConfig, client: client)
    } else {
        email = LoggingEmailSender(environment: config.environment)
    }
    // Rate limits: the shared database store (global across instances) unless memory is requested (development, tests).
    let rateStore: any RateLimitStore = overrides.rateLimitStore
        ?? (config.rateLimitStore == .database ? DatabaseRateLimitStore.forApplication(app) : InMemoryRateLimitStore())
    app.ctx = ServerContext(config: config, clock: clock, apns: apns, sms: sms, passkeys: passkeys, webhookTransport: transport,
                            rateLimitStore: rateStore, rcs: rcs,
                            dashboardPasskeys: dashboardPasskeys, passSigner: passSigner, passPush: passPush,
                            integrity: try overrides.integrity ?? AppAttestVerifier.apple(config: config, clock: clock), email: email,
                            domains: domains, outbound: outbound, kms: kms, auditObjectStore: auditStore, accessTokens: tokens,
                            queueTransport: queueTransport)
    app.brandKits = BrandKitRuntime(store: try BrandKitRegistration.store(config: config, override: overrides.brandAssetStore, tokens: tokens, http: outbound,
                                                                          now: { clock.now() }),
                                    maxConcurrent: config.brandKits.maxConcurrentIngestions)

    // MARK: Database
    // `ViadereServer migrate` connects as the schema owner (DATABASE_MIGRATION_URL, or the migrator's Entra identity); every other process uses
    // the runtime role (DATABASE_URL, or its own Entra identity).
    try DatabaseRoles.requireMigrationURL(config: config, migrating: migrating)
    if migrating, let url = config.operations.migrationDatabaseURL {
        try app.databases.use(.postgres(url: url), as: .psql)
    } else if let entra = config.databaseEntra {
        // A fresh Entra token for every new connection; a failure refuses the connection and never falls back to a password (ADR-0011).
        guard let tokens else { throw ServerConfigError.missing("a managed identity (for DATABASE_AUTH=entra)") }
        let source = TokenAuthPostgresConnectionSource(host: entra.host, port: entra.port, username: entra.user, database: entra.database,
                                                       tls: try TokenAuthPostgresConnectionSource.verifyFullTLS(caFile: entra.caFile),
                                                       passwordSource: EntraPostgresPassword(tokens: tokens))
        app.databases.use(.postgresTokenAuth(source), as: .psql)
    } else if let url = config.databaseURL {
        try app.databases.use(.postgres(url: url), as: .psql)
    } else {
        guard !config.isStrict else { throw ServerConfigError.missing("DATABASE_URL") }
        // sqlite-kit backs `.memory` with a temporary file it never deletes, so every test run left one behind in /tmp (gigabytes
        // over a full suite). Own the file instead and remove it at shutdown.
        let path = FileManager.default.temporaryDirectory.appendingPathComponent("viadere-test-\(UUID().uuidString).sqlite3").path
        app.databases.use(.sqlite(.file(path)), as: .sqlite)
        app.lifecycle.use(TemporaryDatabaseCleanup(path: path))
    }
    app.migrations.add(Migrations.all)
    // Brand Kits (WP-2.4): pin the selected kit to each new interaction.
    app.databases.middleware.use(BrandPinMiddleware(ctx: app.ctx))
    // The database transport needs the database; Service Bus was chosen above.
    app.ctx.queue.install(DatabaseQueueTransport(database: { [app] in app.db }, now: { clock.now() }))
    // The serving process must not hold DDL rights: the role split is mandatory in staging and production (Infra/fly/README.md, docs/ops/RUNBOOKS.md).
    if DatabaseRoles.mustVerifyRuntimeRole(config: config, migrating: migrating), try await DatabaseRoles.runtimeCanChangeSchema(app.db) {
        throw ServerConfigError.invalid("DATABASE_URL (the runtime role can change the schema; use a data-only role and DATABASE_MIGRATION_URL for migrations)")
    }
    PolicyRegistration.configure(app, config: config)
    VerifyRegistration.configure(app, config: config)
    // Wallet identity-encryption keys wrapped under the Key Vault key-encryption key (plan 5.6).
    if app.verify.keyUnwrapper == nil, let kms, let kek = config.azure.kekKey, let name = KMSKeyRef.parse(kek)?.name {
        app.verify.keyUnwrapper = KMSWalletKeyUnwrapper(kms: kms, kekName: name)
    }
    if !config.hasDatabase || overrides.autoMigrate || config.autoMigrate { try await app.autoMigrate() }

    // MARK: HTTP
    app.routes.defaultMaxBodySize = ByteCount(value: config.maxBodyBytes)
    app.http.server.configuration.hostname = config.bindHost
    app.http.server.configuration.port = config.port
    app.http.server.configuration.supportPipelining = false
    app.middleware = Middlewares()
    app.middleware.use(SecurityHeadersMiddleware())
    app.middleware.use(MetricsMiddleware())
    app.middleware.use(RequestLoggingMiddleware())
    // Origin lock (G-10): before routing, authentication and any database access. It answers 421 itself, so it sits outside the error mapper.
    app.middleware.use(EdgeLockMiddleware())
    // The dedicated asset host answers only `/b/{sha256}.png` and never sets a cookie (ADR-0017).
    app.middleware.use(AssetHostMiddleware())
    app.middleware.use(APIErrorMiddleware())
    app.middleware.use(LegacyAddressingHeadersMiddleware())
    // Operator switches: read-only mode (G-1). The sign-up stops (G-15) are route-group middleware on the sign-up and invitation routes.
    app.middleware.use(MaintenanceMiddleware())
    app.middleware.use(CORSLockdownMiddleware())
    app.middleware.use(GlobalRateLimitMiddleware())
    app.middleware.use(RequestGuardMiddleware())
    // The worker has no ingress and serves health checks only; every other role serves the API.
    if config.role == .worker { HealthRoutes.register(app.routes) } else { try Routes.register(app) }

    if let port = config.operations.metricsPort {
        app.lifecycle.use(InternalMetricsServer(host: config.operations.metricsHost, port: port, token: config.operations.metricsToken) { [app] in await MetricsService(db: app.db, ctx: app.ctx).render() })
    }
    if config.runBackgroundJobs, config.role != .migrate { app.lifecycle.use(BackgroundJobRunner(interval: .milliseconds(Int(config.jobIntervalSeconds * 1000)))) }
    // Process roles (ADR-0010): the api publishes the outbox right after commits; the worker also consumes every queue.
    switch config.role {
    case .api: app.lifecycle.use(QueueWorker(consume: false))
    case .worker: app.lifecycle.use(QueueWorker(consume: true))
    case .migrate, .combined: break
    }
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
    public var emailSender: (any EmailSender)?
    /// Domain checks for onboarding (DNS TXT and well-known file). `nil` = the network checker.
    public var domainChecker: (any DomainChecker)?
    /// Service keys (`LocalKMS` in tests). `nil` = Key Vault when configured.
    public var kms: (any KeyManagementService)?
    /// Audit-head storage. `nil` = Azure Blob when configured, else the directory of the settings.
    public var auditObjectStore: (any ObjectStore)?
    /// Azure tokens. `nil` = the managed identity when the process has one.
    public var accessTokens: (any AccessTokenSource)?
    /// Queue transport. `nil` = Service Bus when `QUEUE_TRANSPORT=servicebus`, else the database transport.
    public var queueTransport: (any QueueTransport)?
    /// Cloud API calls of the audit-head export. `nil` = the real HTTPS client.
    public var outboundHTTP: (any OutboundHTTP)?
    /// Brand asset storage. `nil` = Azure Blob when configured, a development directory, or memory outside staging and production.
    public var brandAssetStore: (any ObjectStore)?

    public init(clock: (any ServerClock)? = nil, apns: (any APNsSender)? = nil, sms: (any SMSProvider)? = nil,
                passkeys: (any PasskeyVerifier)? = nil, webhookTransport: (any WebhookTransport)? = nil,
                rateLimitStore: (any RateLimitStore)? = nil, rcs: (any RCSProvider)? = nil, autoMigrate: Bool = false,
                passSigner: (any PassSigner)? = nil, passPush: (any PassPushSender)? = nil,
                integrity: (any DeviceIntegrityVerifier)? = nil, emailSender: (any EmailSender)? = nil,
                domainChecker: (any DomainChecker)? = nil, outboundHTTP: (any OutboundHTTP)? = nil) {
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
        self.emailSender = emailSender
        self.domainChecker = domainChecker
        self.outboundHTTP = outboundHTTP
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

/// Deletes the throwaway SQLite database (and its journal files) when the application shuts down.
struct TemporaryDatabaseCleanup: LifecycleHandler {
    let path: String
    func shutdown(_ application: Application) {
        for suffix in ["", "-wal", "-shm", "-journal"] { try? FileManager.default.removeItem(atPath: path + suffix) }
    }
}

/// Closes the pass-push APNs client when the application shuts down.
struct PassPushShutdown: LifecycleHandler {
    let sender: APNSwiftPassPushSender
    func shutdown(_ application: Application) {}
    func shutdownAsync(_ application: Application) async { await sender.shutdown() }
}
