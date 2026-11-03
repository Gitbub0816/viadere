import Fluent
import FluentPostgresDriver
import FluentSQLiteDriver
import Foundation
import Vapor
import ViadereCore
import ViadereServiceSupport

/// Test and development seams.
public struct AuthorityOverrides: Sendable {
    public var kms: (any KeyManagementService)?
    public var callerVerifier: (any AuthorityCallerVerifier)?
    public var clock: (@Sendable () -> Date)?
    /// Called after migrations and before keys load (tests register clients and pins here).
    public var prepare: (@Sendable (any Database) async throws -> Void)?
    public init() {}
}

extension Application {
    private struct AuthorityContextKey: StorageKey { typealias Value = AuthorityContext }
    public var authority: AuthorityContext {
        get { storage[AuthorityContextKey.self]! }
        set { storage[AuthorityContextKey.self] = newValue }
    }
}

/// Builds the authority application: database, migrations, keys (only when enabled), routes. Nothing here links the ordinary server.
public enum AuthorityApplication {
    public static func configure(_ app: Application, config: AuthorityConfig, overrides: AuthorityOverrides = AuthorityOverrides(),
                                 migrateInMemory: Bool = false, loadKeys: Bool = true) async throws {
        let clock = overrides.clock ?? { Date() }
        app.http.server.configuration.hostname = config.bindHost
        app.http.server.configuration.port = config.port
        // The authority accepts small JSON and form bodies only.
        app.routes.defaultMaxBodySize = "16kb"

        // Outbound: allow-list mode (Entra login, its Key Vault, its database), after the identity-endpoint guard.
        let outbound = AllowListOutboundHTTP(allowed: config.outboundAllowlist, base: StandaloneOutboundHTTP(guard: .fromEnvironment()))
        let identity = AzureManagedIdentity.fromEnvironment(ProcessInfo.processInfo.environment)

        // Database.
        if let entra = config.entraDatabase {
            guard let identity else { throw AuthorityConfigError.missing("a managed identity (DATABASE_AUTH=entra)") }
            let source = TokenAuthPostgresConnectionSource(host: entra.host, port: entra.port, username: entra.user, database: entra.name,
                                                           tls: try TokenAuthPostgresConnectionSource.verifyFullTLS(caFile: entra.caFile),
                                                           passwordSource: EntraPostgresPassword(tokens: identity))
            app.databases.use(.postgresTokenAuth(source), as: .psql)
        } else if let url = config.databaseURL {
            guard !config.deployment.isStrict else { throw AuthorityConfigError.refused("DATABASE_URL in staging or production") }
            try app.databases.use(.postgres(url: url), as: .psql)
        } else {
            guard !config.deployment.isStrict else { throw AuthorityConfigError.missing("database") }
            app.databases.use(.sqlite(.memory), as: .sqlite)
        }
        app.migrations.add(CreateAuthoritySchema())
        app.migrations.add(CreateAuthorityOIDCMethodsSchema())
        if migrateInMemory {
            // Tests: a fresh schema every time (PostgreSQL test databases are reused between tests).
            try await app.autoRevert()
            try await app.autoMigrate()
        }
        if let prepare = overrides.prepare { try await prepare(app.db) }

        // KMS: Key Vault in staging and production; LocalKMS only in development and tests.
        let kms: any KeyManagementService
        if let override = overrides.kms {
            guard !config.deployment.isStrict else { throw AuthorityConfigError.refused("a KMS override in staging or production") }
            kms = override
        } else if let vault = config.keyVaultURL {
            guard let identity else { throw AuthorityConfigError.missing("a managed identity (Key Vault)") }
            kms = try AzureKeyVaultKMS(vaultURL: vault, tokens: identity, http: outbound)
        } else {
            guard !config.deployment.isStrict else { throw AuthorityConfigError.missing("AZURE_KEY_VAULT_URL") }
            kms = LocalKMS()
        }

        // Callers: Entra tokens; a verifier override only outside staging and production.
        let verifier: any AuthorityCallerVerifier
        if let override = overrides.callerVerifier {
            guard !config.deployment.isStrict else { throw AuthorityConfigError.refused("a caller-verifier override in staging or production") }
            verifier = override
        } else {
            verifier = EntraCallerVerifier(tenantId: config.tenantId, audience: config.entraAudience, callers: config.callerObjectIds,
                                           keys: EntraJWKSKeySource(tenantId: config.tenantId, http: outbound))
        }

        // Keys load only when enabled and only when serving (the migrate and admin jobs hold no Key Vault role).
        var keys: AuthorityKeyRing?
        if config.enabled, loadKeys {
            for line in await AuthorityKeyInventory.lines(kms: kms, config: config, db: app.db) { app.logger.notice("\(line)") }
            // Reviewed key imports staged by the admin job need ACCOUNT_REF_KEY, which only the serving authority holds.
            try await AuthorityAdmin.applyPendingImports(db: app.db, config: config, now: clock())
            keys = try await AuthorityKeyRing.load(kms: kms, config: config, db: app.db)
        }
        app.authority = AuthorityContext(config: config, kms: kms, keys: keys, clock: clock)
        try routes(app, verifier: verifier)
    }

    /// The complete route list (L-14: no debug endpoints; `AuthorityRouteListTests` pins it).
    static func routes(_ app: Application, verifier: any AuthorityCallerVerifier) throws {
        app.get("healthz") { _ in HTTPStatus.ok }
        app.get("readyz") { req async throws -> HTTPStatus in
            // The database answers, and (PostgreSQL) its clock is within 5 s of ours (ADR-0023 §8).
            _ = try await AuthorityKeyPin.query(on: req.db).count()
            if let sql = req.db as? any SQLDatabase, sql.dialect.name == "postgresql" {
                struct Row: Decodable { let now: Date }
                if let row = try await sql.raw("SELECT now() AS now").first(decoding: Row.self), abs(row.now.timeIntervalSince(req.application.authority.now)) > 5 {
                    throw Abort(.serviceUnavailable, reason: "clock_skew")
                }
            }
            return .ok
        }
        let evidence = app.grouped(AuthorityRoleMiddleware(verifier: verifier, roles: [.evidenceSubmit], callerNames: ["api"]))
        evidence.post("v1", "challenges") { req async throws -> Response in
            let body = try decodeStrict(AuthorityChallengeCreateRequest.self, req)
            let response = try await AuthorityChallengeService(ctx: req.application.authority, db: req.db).create(body, caller: req.authorityCaller)
            return try json(response, status: .created)
        }
        evidence.post("v1", "evidence") { req async throws -> Response in
            let body = try decodeStrict(AuthorityEvidenceRequest.self, req)
            let response = try await EvidenceVerifier(ctx: req.application.authority, db: req.db).submit(body, caller: req.authorityCaller)
            return try json(response, status: .ok)
        }
        evidence.get("v1", "oidc", "client-check") { req async throws -> Response in
            let ctx = req.application.authority
            guard ctx.config.oidcEnabled, ctx.config.enabled else { throw Abort(.notFound) }
            let clientId = try req.query.get(String.self, at: "client_id")
            let redirect: String? = req.query["redirect_uri"]
            let logout: String? = req.query["post_logout_redirect_uri"]
            guard (redirect == nil) != (logout == nil) else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
            // A database lookup only: no Key Vault call and no challenge (ADR-0024 §4, ST-OIDC-17).
            guard let client = try await AuthorityOIDCClient.find(clientId, on: req.db), client.status == "active" else {
                return try json(AuthorityClientCheckResponse(valid: false, displayName: nil), status: .ok)
            }
            let list = redirect != nil ? OIDCClientRules.redirectURIs(client) : OIDCClientRules.jsonArray(client.postLogoutRedirectURIs)
            let valid = list.contains(redirect ?? logout ?? "")
            return try json(AuthorityClientCheckResponse(valid: valid, displayName: valid ? client.displayName : nil), status: .ok)
        }
        evidence.post("v1", "oidc", "token") { req async throws -> Response in
            let body = req.body.string ?? ""
            do {
                let tokens = try await OIDCTokenService(ctx: req.application.authority, db: req.db).exchange(form: body)
                let response = Response(status: .ok, body: .init(data: try CanonicalJSON.serialize(.object(tokens))))
                response.headers.contentType = .json
                response.headers.replaceOrAdd(name: .cacheControl, value: "no-store")
                response.headers.replaceOrAdd(name: .pragma, value: "no-cache")
                return response
            } catch let error as OAuthError {
                let response = Response(status: error.status, body: .init(data: try CanonicalJSON.serialize(.object(["error": .string(error.code)]))))
                response.headers.contentType = .json
                response.headers.replaceOrAdd(name: .cacheControl, value: "no-store")
                return response
            }
        }
        evidence.get("v1", "oidc", "keys") { req async throws -> Response in
            let ctx = req.application.authority
            guard ctx.config.oidcEnabled else { throw Abort(.notFound) }
            let keys = try ctx.requireKeys()
            return try json(AuthorityPublicKeySet(keys: keys.oidcPublicJWKs), status: .ok)
        }
        // Reduce-only: the api and the worker (whose only route this is, ADR-0028 §9).
        let revocations = app.grouped(AuthorityRoleMiddleware(verifier: verifier, roles: [.revocations, .evidenceSubmit], callerNames: ["api", "worker"]))
        revocations.post("v1", "revocations") { req async throws -> Response in
            let body = try decodeStrict(AuthorityRevocationRequest.self, req)
            let revoked = try await AuthorityKeyLog.revoke(req.db, kid: body.kid, reason: body.reason, caller: req.authorityCaller, now: req.application.authority.now)
            return try json(["revoked": revoked], status: .ok)
        }
        // Passkey method and consents (ADR-0023 §3a, ADR-0024 §4, §8).
        AuthorityOIDCMethodRoutes.register(evidence: evidence, revocations: revocations)
    }

    static func decodeStrict<T: Decodable>(_ type: T.Type, _ req: Request) throws -> T {
        guard req.headers.contentType == .json, let buffer = req.body.data else { throw Abort(.unsupportedMediaType) }
        do { return try ViadereJSON.decode(T.self, from: Data(buffer: buffer)) } catch { throw Abort(.unprocessableEntity, reason: "invalid_request") }
    }

    static func json<T: Encodable>(_ value: T, status: HTTPResponseStatus) throws -> Response {
        let response = Response(status: status, body: .init(data: try ViadereJSON.encode(value)))
        response.headers.contentType = .json
        response.headers.replaceOrAdd(name: .cacheControl, value: "no-store")
        return response
    }
}

/// `ViadereAuthority admin <command> --change-file <path> --commit <sha>` (the reviewer-gated admin job; no Key Vault role, no keys loaded).
public struct AuthorityAdminCommand: AsyncCommand {
    public struct Signature: CommandSignature {
        @Argument(name: "command") var command: String
        @Option(name: "change-file") var changeFile: String?
        @Option(name: "commit") var commit: String?
        public init() {}
    }

    public var help: String { "Runs one reviewed authority admin command: \(AuthorityAdmin.commands.joined(separator: ", "))" }
    public init() {}

    public func run(using context: CommandContext, signature: Signature) async throws {
        guard let path = signature.changeFile, let commit = signature.commit else { throw AuthorityAdmin.Failure.invalid("--change-file and --commit are required") }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        try await AuthorityAdmin.run(command: signature.command, changeFile: data, commit: commit, db: context.application.db, config: context.application.authority.config)
        context.console.print("authority admin \(signature.command): done (commit \(commit))")
    }
}
