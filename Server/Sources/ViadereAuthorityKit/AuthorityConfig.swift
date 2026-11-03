@preconcurrency import Crypto
import Foundation
import ViadereCore

/// Where the authority runs. Staging and production use the strict rules (every secret mandatory, PostgreSQL with Entra, Key Vault, Entra callers).
public enum AuthorityDeployment: String, Sendable {
    case development, testing, staging, production

    public static func parse(_ raw: String) -> AuthorityDeployment? {
        switch raw.lowercased() {
        case "development": .development
        case "test", "testing": .testing
        case "staging": .staging
        case "production": .production
        default: nil
        }
    }

    public var isStrict: Bool { self == .staging || self == .production }
    public var statementEnvironment: AuthorityEnvironment { self == .production ? .production : .staging }
}

public enum AuthorityConfigError: Error, Sendable, Equatable, CustomStringConvertible {
    case missing(String)
    case invalid(String)
    case refused(String)

    public var description: String {
        switch self {
        case .missing(let name): "missing configuration: \(name)"
        case .invalid(let name): "invalid configuration: \(name)"
        case .refused(let reason): "refused configuration: \(reason)"
        }
    }
}

/// The authority's configuration. Variable names are the ones `Infra/azure-authority/containerapps.tf` sets (the interface the infra root
/// assumed; this type is the other side of that contract and `AuthorityConfigTests` pins it).
public struct AuthorityConfig: Sendable {
    public var deployment: AuthorityDeployment
    public var port = 8080
    public var bindHost = "0.0.0.0"
    /// `AUTHORITY_ENABLED` (default **off**): the process runs and answers health checks, but every grant, challenge, evidence and token route
    /// answers `503 authority_disabled` and no key is loaded. The api then fails closed for link service and OIDC (ADR-0019 §6).
    public var enabled = false
    /// `AUTHORITY_OIDC_ENABLED` (default **off**; refused with `ENVIRONMENT=production` until a new ADR and owner approval, ADR-0024 §1).
    public var oidcEnabled = false
    /// `OIDC_ISSUER`: the exact issuer string (`https://id.<staging domain>`, no trailing slash). Grants use `<issuer>/grant`.
    public var issuer = "https://id.viadere.test"
    /// `AUTHORITY_WEBAUTHN_RP_ID`: the existing Viadere WebAuthn RP id (so existing account passkeys work at `/oidc/authorize`, ADR-0024 §4 method 1).
    /// The issuer host must be this id or a subdomain of it. The accepted WebAuthn origins come from `OIDCProfile.passkeyOrigins` (the issuer
    /// origin only for `oidc_login`), never from this setting.
    public var webAuthnRelyingPartyID = "viadere.test"

    // Entra callers (ADR-0019 §4.2).
    public var tenantId = ""
    public var entraAudience = ""
    /// `AUTHORITY_CALLER_OIDS` = `name:oid,name:oid` (the api and the worker identities).
    public var callerObjectIds: [String: String] = [:]
    /// `AUTHORITY_OUTBOUND_ALLOWLIST`: the only hosts the authority may call (allow-list mode of the outbound guard).
    public var outboundAllowlist: Set<String> = []

    // Keys: explicit NAMES from the environment; the VERSION of each comes from the reviewed pin table (`authority_key_pins`), never "latest".
    public var keyVaultURL: String?
    public var grantKeyName = "grant-signing"
    public var oidcRS256KeyName = "oidc-signing-rs256"
    public var oidcES256KeyName = "oidc-signing-es256"
    public var deviceStatementKeyName = "device-statement-signing"

    // Authority-only secrets (TRUST_BOUNDARIES §4.1).
    public var oidcPairwiseKey = SymmetricKey(size: .bits256)
    public var accountRefKey = SymmetricKey(size: .bits256)
    public var subjectRefKey = SymmetricKey(size: .bits256)

    // Database.
    public var databaseURL: String?
    public var entraDatabase: EntraDatabase?

    /// Development and tests only: statement-key thumbprints accepted in place of the app-pinned Core constants (refused when strict).
    public var developmentStatementPins: [String] = []

    /// Challenge lifetime and the per-tenant challenge-signing bulkhead (ADR-0033 §2).
    public var challengeLifetime: TimeInterval = 120
    public var challengeBudgetPerTenantPerMinute = 30

    public struct EntraDatabase: Sendable, Equatable {
        public var host: String
        public var port: Int
        public var name: String
        public var user: String
        public var caFile: String?
    }

    public init(deployment: AuthorityDeployment) { self.deployment = deployment }

    /// Tests: everything enabled, SQLite in memory, no Entra (the test supplies its own caller verifier).
    public static func testing() -> AuthorityConfig {
        var config = AuthorityConfig(deployment: .testing)
        config.enabled = true
        config.oidcEnabled = true
        return config
    }

    public static func fromEnvironment(_ env: [String: String] = ProcessInfo.processInfo.environment) throws -> AuthorityConfig {
        guard let deployment = AuthorityDeployment.parse(env["ENVIRONMENT"] ?? "development") else { throw AuthorityConfigError.invalid("ENVIRONMENT") }
        var config = AuthorityConfig(deployment: deployment)
        let strict = deployment.isStrict

        func flag(_ name: String) throws -> Bool {
            switch env[name]?.lowercased() {
            case nil, "", "false": false
            case "true": true
            default: throw AuthorityConfigError.invalid("\(name) (true or false)")
            }
        }
        if let raw = env["PORT"], !raw.isEmpty { guard let port = Int(raw), (1...65535).contains(port) else { throw AuthorityConfigError.invalid("PORT") }; config.port = port }
        if let raw = env["BIND_HOST"], !raw.isEmpty { config.bindHost = raw }
        config.enabled = try flag("AUTHORITY_ENABLED")
        config.oidcEnabled = try flag("AUTHORITY_OIDC_ENABLED")
        if config.oidcEnabled, deployment == .production {
            throw AuthorityConfigError.refused("AUTHORITY_OIDC_ENABLED is refused with ENVIRONMENT=production (ADR-0024 §1: staging only until a new ADR and owner approval)")
        }
        if let raw = env["OIDC_ISSUER"], !raw.isEmpty {
            guard Self.isValidIssuer(raw) else { throw AuthorityConfigError.invalid("OIDC_ISSUER (https, host only, no trailing slash)") }
            config.issuer = raw
        } else if strict && config.enabled {
            throw AuthorityConfigError.missing("OIDC_ISSUER")
        }
        if let raw = env["AUTHORITY_WEBAUTHN_RP_ID"], !raw.isEmpty {
            guard raw.utf8.count <= 253, raw.range(of: "^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", options: .regularExpression) != nil else { throw AuthorityConfigError.invalid("AUTHORITY_WEBAUTHN_RP_ID (a lowercase host)") }
            config.webAuthnRelyingPartyID = raw
        } else if strict && config.enabled && config.oidcEnabled {
            throw AuthorityConfigError.missing("AUTHORITY_WEBAUTHN_RP_ID (required when AUTHORITY_OIDC_ENABLED is true)")
        }
        if config.oidcEnabled, !Self.issuer(config.issuer, isWithin: config.webAuthnRelyingPartyID), strict || env["AUTHORITY_WEBAUTHN_RP_ID"] != nil {
            throw AuthorityConfigError.invalid("AUTHORITY_WEBAUTHN_RP_ID (the OIDC_ISSUER host must be the RP id or a subdomain of it)")
        }

        config.tenantId = env["AZURE_TENANT_ID"] ?? ""
        config.entraAudience = env["AUTHORITY_ENTRA_AUDIENCE"] ?? ""
        config.callerObjectIds = try Self.parseCallers(env["AUTHORITY_CALLER_OIDS"] ?? "")
        config.outboundAllowlist = Set((env["AUTHORITY_OUTBOUND_ALLOWLIST"] ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces).lowercased() }.filter { !$0.isEmpty })
        if strict {
            guard UUID(uuidString: config.tenantId) != nil else { throw AuthorityConfigError.missing("AZURE_TENANT_ID") }
            guard config.entraAudience.hasPrefix("api://") || UUID(uuidString: config.entraAudience) != nil else { throw AuthorityConfigError.missing("AUTHORITY_ENTRA_AUDIENCE") }
            guard !config.callerObjectIds.isEmpty else { throw AuthorityConfigError.missing("AUTHORITY_CALLER_OIDS") }
            guard !config.outboundAllowlist.isEmpty else { throw AuthorityConfigError.missing("AUTHORITY_OUTBOUND_ALLOWLIST") }
        }

        config.keyVaultURL = env["AZURE_KEY_VAULT_URL"].flatMap { $0.isEmpty ? nil : $0 }
        if strict && config.keyVaultURL == nil { throw AuthorityConfigError.missing("AZURE_KEY_VAULT_URL") }
        func keyName(_ variable: String, _ fallback: String) throws -> String {
            guard let raw = env[variable], !raw.isEmpty else { return fallback }
            // Names only: a version in the environment would bypass the reviewed pin (ADR-0028 §2).
            guard !raw.contains("/"), raw.count <= 127, raw.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }) else {
                throw AuthorityConfigError.invalid("\(variable) (a Key Vault key name; versions come from the pin table)")
            }
            return raw
        }
        config.grantKeyName = try keyName("AUTHORITY_KEY_GRANT_SIGNING", config.grantKeyName)
        config.oidcRS256KeyName = try keyName("AUTHORITY_KEY_OIDC_RS256", config.oidcRS256KeyName)
        config.oidcES256KeyName = try keyName("AUTHORITY_KEY_OIDC_ES256", config.oidcES256KeyName)
        config.deviceStatementKeyName = try keyName("AUTHORITY_KEY_DEVICE_STATEMENT", config.deviceStatementKeyName)

        func secret(_ name: String) throws -> SymmetricKey? {
            guard let raw = env[name], !raw.isEmpty else {
                if strict && config.enabled { throw AuthorityConfigError.missing(name) }
                return nil
            }
            guard let bytes = Base64URL.decode(raw) ?? Data(base64Encoded: raw), bytes.count >= 32 else { throw AuthorityConfigError.invalid("\(name) (base64url, at least 32 bytes)") }
            return SymmetricKey(data: bytes)
        }
        if let key = try secret("OIDC_PAIRWISE_KEY") { config.oidcPairwiseKey = key }
        if let key = try secret("ACCOUNT_REF_KEY") { config.accountRefKey = key }
        if let key = try secret("SUBJECT_REF_KEY") { config.subjectRefKey = key }
        let distinct = Set([config.oidcPairwiseKey, config.accountRefKey, config.subjectRefKey].map { $0.withUnsafeBytes { Data($0) } })
        guard distinct.count == 3 else { throw AuthorityConfigError.refused("OIDC_PAIRWISE_KEY, ACCOUNT_REF_KEY and SUBJECT_REF_KEY must be different values") }

        switch (env["DATABASE_AUTH"] ?? "").lowercased() {
        case "entra":
            guard let host = env["DATABASE_HOST"], !host.isEmpty, let user = env["DATABASE_USER"], !user.isEmpty else {
                throw AuthorityConfigError.missing("DATABASE_HOST and DATABASE_USER (DATABASE_AUTH=entra)")
            }
            let port = Int(env["DATABASE_PORT"] ?? "5432") ?? 5432
            config.entraDatabase = EntraDatabase(host: host, port: port, name: env["DATABASE_NAME"].flatMap { $0.isEmpty ? nil : $0 } ?? "viadere_authority", user: user,
                                                 caFile: env["DATABASE_CA_FILE"].flatMap { $0.isEmpty ? nil : $0 })
        case "", "password":
            config.databaseURL = env["DATABASE_URL"].flatMap { $0.isEmpty ? nil : $0 }
        default: throw AuthorityConfigError.invalid("DATABASE_AUTH (password or entra)")
        }
        if strict {
            guard config.entraDatabase != nil else { throw AuthorityConfigError.refused("staging and production use DATABASE_AUTH=entra (no static password)") }
        }

        if let raw = env["AUTHORITY_DEV_STATEMENT_PINS"], !raw.isEmpty {
            guard !strict else { throw AuthorityConfigError.refused("AUTHORITY_DEV_STATEMENT_PINS is development only") }
            config.developmentStatementPins = raw.split(separator: ",").map(String.init)
        }
        return config
    }

    static func parseCallers(_ raw: String) throws -> [String: String] {
        var out: [String: String] = [:]
        for item in raw.split(separator: ",") where !item.trimmingCharacters(in: .whitespaces).isEmpty {
            let parts = item.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard parts.count == 2, ["api", "worker"].contains(parts[0]), UUID(uuidString: parts[1]) != nil else {
                throw AuthorityConfigError.invalid("AUTHORITY_CALLER_OIDS (api:<oid>,worker:<oid>)")
            }
            out[parts[0]] = parts[1].lowercased()
        }
        return out
    }

    static func isValidIssuer(_ raw: String) -> Bool {
        guard let components = URLComponents(string: raw), components.scheme == "https", let host = components.host, !host.isEmpty,
              components.path.isEmpty, components.query == nil, components.fragment == nil, components.user == nil, !raw.hasSuffix("/") else { return false }
        return true
    }

    /// WebAuthn: the origin's host must equal the RP id or end with `.` + RP id.
    static func issuer(_ issuer: String, isWithin rpId: String) -> Bool {
        guard let host = URLComponents(string: issuer)?.host?.lowercased() else { return false }
        return host == rpId || host.hasSuffix("." + rpId)
    }

    /// The app-pinned statement keys for this deployment (Core constants), or the development override.
    public var statementPins: [String] {
        deployment.isStrict ? AuthorityPinnedKeys.deviceStatementKids(deployment.statementEnvironment) : developmentStatementPins
    }
}
