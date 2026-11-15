import Foundation
import ViadereCore

/// What this process does (`ROLE`, WP-B2). One image, roles chosen by configuration (ADR-0010).
public enum ProcessRole: String, Sendable, CaseIterable {
    /// HTTP API, dashboard and operator console. Publishes the transactional outbox right after commit; runs no consumers unless
    /// `RUN_BACKGROUND_JOBS=true` (the lean profile before a worker exists).
    case api
    /// Queue consumers and the outbox publisher. Serves only `/healthz` and `/readyz` (it has no ingress).
    case worker
    /// `ViadereServer migrate`: a database-only configuration, no service secrets (ADR-0011, plan 5.9).
    case migrate
    /// `ROLE` unset: today's single process (Fly, development, tests): every route plus the in-process job loop when `RUN_BACKGROUND_JOBS` is on.
    case combined

    static func parse(_ raw: String?) throws -> ProcessRole {
        switch (raw ?? "").lowercased() {
        case "": return .combined
        case "api": return .api
        case "worker": return .worker
        case "migrate": return .migrate
        default: throw ServerConfigError.invalid("ROLE (api, worker or migrate)")
        }
    }
}

/// Where queue messages travel (`QUEUE_TRANSPORT`, WP-B3).
public enum QueueTransportMode: String, Sendable {
    /// The `queue_messages` table with peek-lock leases (development, tests, Fly, emergency fallback).
    case database
    /// Azure Service Bus over REST with the managed identity.
    case servicebus
}

/// How the server reaches PostgreSQL with a Microsoft Entra token instead of a password (`DATABASE_AUTH=entra`, ADR-0011).
public struct EntraDatabaseSettings: Sendable, Equatable {
    public var host: String
    public var port: Int
    public var database: String
    /// The PostgreSQL role of the Entra principal (`viadere_app`, `viadere_worker` or `viadere_migrator`).
    public var user: String
    /// PEM bundle of the server's root CAs for `verify-full` (`DATABASE_CA_FILE`); `nil` = the image's system trust store.
    public var caFile: String?
}

/// Azure resources the process uses (all optional outside Azure). Names match `Infra/azure/containerapps.tf` exactly.
public struct AzureSettings: Sendable, Equatable {
    /// `AZURE_CLIENT_ID`: the user-assigned identity this process uses (never another identity attached to the app).
    public var clientId: String?
    public var tenantId: String?
    /// `AZURE_KEY_VAULT_URL`: `https://<vault>.vault.azure.net/`.
    public var keyVaultURL: String?
    /// `AZURE_KEY_VAULT_KEK_KEY`: RSA key-encryption key that unwraps `*_WRAPPED` secrets and Wallet keys at boot.
    public var kekKey: String?
    /// `AZURE_KEY_VAULT_KD_LOG_KEY`: EC P-256 key that signs key-directory tree heads (replaces `KEY_DIRECTORY_LOG_KEY`).
    public var kdLogKey: String?
    /// `AZURE_KEY_VAULT_LINK_DESCRIPTOR_KEY`: EC P-256 key for link-session descriptors (WP-C1).
    public var linkDescriptorKey: String?
    /// `AZURE_KEY_VAULT_LOOP_PUBLICATION_KEY`: EC P-256 key that signs Loop publication manifests only (WP-3.2, SECURITY.md §2.92).
    public var loopPublicationKey: String?
    /// `AZURE_KEY_VAULT_AUDIT_HEAD_KEY`: EC P-256 key that signs exported audit heads (replaces `AUDIT_HEAD_KMS_KEY`).
    public var auditHeadKey: String?
    /// `AZURE_AUDIT_BLOB_ENDPOINT`, `AZURE_AUDIT_BLOB_CONTAINER`: the immutable audit-head container.
    public var auditBlobEndpoint: String?
    public var auditBlobContainer: String?
    /// `AZURE_SERVICEBUS_FQDN`: `<namespace>.servicebus.windows.net`.
    public var serviceBusFQDN: String?

    public init() {}

    /// Whether any Key Vault key is configured (the process then needs `AZURE_KEY_VAULT_URL` and a managed identity).
    var usesKeyVault: Bool { [kekKey, kdLogKey, linkDescriptorKey, auditHeadKey, loopPublicationKey].contains { $0 != nil } }
}

extension ServerConfig {
    /// `ROLE`, `QUEUE_TRANSPORT`, `AZURE_*`, `DATABASE_AUTH` (+ `DATABASE_HOST`, `DATABASE_PORT`, `DATABASE_NAME`, `DATABASE_USER`,
    /// `DATABASE_CA_FILE`).
    mutating func applyAzureEnvironment(_ env: [String: String], strict: Bool) throws {
        func value(_ name: String) -> String? { env[name].flatMap { $0.isEmpty ? nil : $0 } }
        role = try ProcessRole.parse(env["ROLE"])
        var azure = AzureSettings()
        azure.clientId = value("AZURE_CLIENT_ID")
        azure.tenantId = value("AZURE_TENANT_ID")
        if let raw = value("AZURE_KEY_VAULT_URL") {
            guard AzureKeyVaultKMS.normalizedVaultURL(raw) != nil else { throw ServerConfigError.invalid("AZURE_KEY_VAULT_URL (https://<vault>.vault.azure.net/)") }
            azure.keyVaultURL = raw
        }
        for (name, path) in [("AZURE_KEY_VAULT_KEK_KEY", \AzureSettings.kekKey), ("AZURE_KEY_VAULT_KD_LOG_KEY", \.kdLogKey),
                             ("AZURE_KEY_VAULT_LINK_DESCRIPTOR_KEY", \.linkDescriptorKey), ("AZURE_KEY_VAULT_AUDIT_HEAD_KEY", \.auditHeadKey),
                             ("AZURE_KEY_VAULT_LOOP_PUBLICATION_KEY", \.loopPublicationKey)] {
            guard let raw = value(name) else { continue }
            guard KMSKeyRef.parse(raw) != nil else { throw ServerConfigError.invalid("\(name) (a key name, optionally /version)") }
            azure[keyPath: path] = raw
        }
        if azure.usesKeyVault, azure.keyVaultURL == nil { throw ServerConfigError.missing("AZURE_KEY_VAULT_URL (required with an AZURE_KEY_VAULT_*_KEY)") }
        if let raw = value("AZURE_AUDIT_BLOB_ENDPOINT") {
            guard AzureBlobObjectStore.normalizedEndpoint(raw) != nil else { throw ServerConfigError.invalid("AZURE_AUDIT_BLOB_ENDPOINT (https://<account>.blob.core.windows.net/)") }
            azure.auditBlobEndpoint = raw
            guard let container = value("AZURE_AUDIT_BLOB_CONTAINER"), AzureBlobObjectStore.isContainerName(container) else {
                throw ServerConfigError.invalid("AZURE_AUDIT_BLOB_CONTAINER (a container name; required with AZURE_AUDIT_BLOB_ENDPOINT)")
            }
            azure.auditBlobContainer = container
        }
        if let raw = value("AZURE_SERVICEBUS_FQDN") {
            guard Self.isServiceBusFQDN(raw) else { throw ServerConfigError.invalid("AZURE_SERVICEBUS_FQDN (<namespace>.servicebus.windows.net)") }
            azure.serviceBusFQDN = raw.lowercased()
        }
        switch (env["QUEUE_TRANSPORT"] ?? "").lowercased() {
        case "", "database": queueTransport = .database
        case "servicebus":
            guard azure.serviceBusFQDN != nil else { throw ServerConfigError.missing("AZURE_SERVICEBUS_FQDN (required for QUEUE_TRANSPORT=servicebus)") }
            queueTransport = .servicebus
        default: throw ServerConfigError.invalid("QUEUE_TRANSPORT (database or servicebus)")
        }
        // Anything that talks to Azure needs this process's managed identity: fail at boot, not at the first call.
        if azure.usesKeyVault || azure.auditBlobEndpoint != nil || queueTransport == .servicebus || databaseEntra != nil {
            guard azure.clientId != nil, value("IDENTITY_ENDPOINT") != nil, value("IDENTITY_HEADER") != nil else {
                throw ServerConfigError.missing("AZURE_CLIENT_ID with a managed identity (IDENTITY_ENDPOINT, IDENTITY_HEADER) for the configured Azure resources")
            }
        }
        self.azure = azure
    }

    static func isServiceBusFQDN(_ raw: String) -> Bool {
        let host = raw.lowercased()
        guard host.hasSuffix(".servicebus.windows.net") else { return false }
        let namespace = host.dropLast(".servicebus.windows.net".count)
        return (6...50).contains(namespace.count) && namespace.unicodeScalars.allSatisfy { ("a"..."z").contains($0) || ("0"..."9").contains($0) || $0 == "-" }
    }

    /// `DATABASE_AUTH` = `password` (`DATABASE_URL`, the default) or `entra` (token per new connection). Returns the Entra settings, if chosen.
    static func entraDatabase(_ env: [String: String]) throws -> EntraDatabaseSettings? {
        func value(_ name: String) -> String? { env[name].flatMap { $0.isEmpty ? nil : $0 } }
        switch (env["DATABASE_AUTH"] ?? "").lowercased() {
        case "", "password": return nil
        case "entra":
            guard let host = value("DATABASE_HOST"), host.count <= 253, host.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" }) else {
                throw ServerConfigError.missing("DATABASE_HOST (required for DATABASE_AUTH=entra)")
            }
            guard let user = value("DATABASE_USER"), GrantRuntimeRolePrivileges.isSafeRoleName(user) else { throw ServerConfigError.missing("DATABASE_USER (a role name, required for DATABASE_AUTH=entra)") }
            let name = value("DATABASE_NAME") ?? "viadere"
            guard GrantRuntimeRolePrivileges.isSafeRoleName(name) else { throw ServerConfigError.invalid("DATABASE_NAME") }
            let port = Int(value("DATABASE_PORT") ?? "5432") ?? -1
            guard (1...65535).contains(port) else { throw ServerConfigError.invalid("DATABASE_PORT") }
            if env["DATABASE_URL"].map({ !$0.isEmpty }) == true { throw ServerConfigError.invalid("DATABASE_URL (unset it with DATABASE_AUTH=entra: no password is used)") }
            return EntraDatabaseSettings(host: host.lowercased(), port: port, database: name, user: user, caFile: value("DATABASE_CA_FILE"))
        default:
            throw ServerConfigError.invalid("DATABASE_AUTH (password or entra)")
        }
    }

    /// The configuration of `ROLE=migrate` (the migration job): only what migrations need (the database and its runtime role name). It holds **no**
    /// service secret: every key is a throwaway random value that nothing can persist, because the migrate command writes no application data
    /// (migrations are schema and grants only) and `configure` refuses to serve HTTP or run jobs in this role.
    public static func migrationOnly(_ env: [String: String]) throws -> ServerConfig {
        guard let raw = env["ENVIRONMENT"], let environment = DeploymentEnvironment.parse(raw) else {
            throw ServerConfigError.missing("ENVIRONMENT (development, test, staging or production)")
        }
        var config = ServerConfig.testing()
        config.environment = environment
        config.role = .migrate
        config.runBackgroundJobs = false
        config.allowInsecureWebhookURLs = false
        config.connectLinkKey = .init(size: .bits256)
        config.pepper = SecureToken.randomBytes(32)
        config.dataEncryptionKey = .init(size: .bits256)
        config.auditChainKey = .init(size: .bits256)
        config.subjectRefKey = .init(size: .bits256)
        config.approve.enabled = false
        config.databaseURL = env["DATABASE_URL"].flatMap { $0.isEmpty ? nil : $0 }
        config.databaseEntra = try entraDatabase(env)
        if let url = env["DATABASE_MIGRATION_URL"], !url.isEmpty {
            guard url.hasPrefix("postgres://") || url.hasPrefix("postgresql://") else { throw ServerConfigError.invalid("DATABASE_MIGRATION_URL (postgres URL)") }
            config.operations.migrationDatabaseURL = url
        }
        if environment.isStrict, !config.hasDatabase, config.operations.migrationDatabaseURL == nil {
            throw ServerConfigError.missing("DATABASE_AUTH=entra (DATABASE_HOST, DATABASE_USER) or DATABASE_MIGRATION_URL")
        }
        try config.applyAzureEnvironment(env, strict: environment.isStrict)
        config.role = .migrate
        return config
    }
}
