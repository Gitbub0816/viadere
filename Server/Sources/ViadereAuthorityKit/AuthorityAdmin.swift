@preconcurrency import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore

/// Commands that **increase** authority (ADR-0019 §5): run only as `job-viadere-authority-admin`, started by `authority-admin.yml` in a reviewer-gated
/// environment, from a change file that is a reviewed commit on protected `main`. Each writes an audit event naming the commit. There is no web console.
///
///     ViadereAuthority admin <command> --change-file <path> --commit <sha>
///
/// Commands: `client-register` (OIDC relying party), `link-client-register`, `keylog-import` (the one-time reviewed import, R-16), `key-version-pin`.
public enum AuthorityAdmin {
    public enum Failure: Error, Sendable, Equatable, CustomStringConvertible {
        case unknownCommand(String)
        case invalid(String)
        public var description: String {
            switch self {
            case .unknownCommand(let c): "unknown admin command: \(c)"
            case .invalid(let reason): "invalid change file: \(reason)"
            }
        }
    }

    public static let commands = ["client-register", "link-client-register", "keylog-import", "key-version-pin"]

    public static func run(command: String, changeFile: Data, commit: String, db: any Database, config: AuthorityConfig, now: Date = Date()) async throws {
        guard commit.count == 40, commit.allSatisfy({ $0.isHexDigit }) else { throw Failure.invalid("--commit must be the 40-character commit of the change file") }
        guard case .object(let change)? = try? JSONDecoder().decode(JSONValue.self, from: changeFile) else { throw Failure.invalid("not a JSON object") }
        switch command {
        case "client-register": try await registerOIDCClient(change, commit: commit, db: db, now: now)
        case "link-client-register": try await registerLinkClient(change, commit: commit, db: db, now: now)
        case "keylog-import": try await importKeys(change, commit: commit, db: db, config: config, now: now)
        case "key-version-pin": try await pinKeyVersion(change, commit: commit, db: db, now: now)
        default: throw Failure.unknownCommand(command)
        }
        await AuthorityAudit.record(db, "authority.admin.\(command)", outcome: "success", caller: "admin", detail: "commit:\(commit)", at: now)
    }

    static func string(_ o: [String: JSONValue], _ key: String, max: Int = 512) throws -> String {
        guard let value = o[key]?.stringValue, !value.isEmpty, value.utf8.count <= max else { throw Failure.invalid(key) }
        return value
    }

    static func strings(_ o: [String: JSONValue], _ key: String) throws -> [String] {
        guard case .array(let items)? = o[key] else { throw Failure.invalid(key) }
        let values = items.compactMap(\.stringValue)
        guard values.count == items.count, values.count <= 20 else { throw Failure.invalid(key) }
        return values
    }

    static func displayName(_ raw: String) throws -> String {
        let name = raw.precomposedStringWithCanonicalMapping
        guard (1...60).contains(name.count), !name.unicodeScalars.contains(where: { $0.properties.generalCategory == .control || $0.properties.generalCategory == .format }) else {
            throw Failure.invalid("display_name")
        }
        return name
    }

    /// ADR-0024 §3: `ocl_` ids, confidential clients with `private_key_jwt` keys, exact https redirect URIs on one host (the sector), reviewed name.
    static func registerOIDCClient(_ o: [String: JSONValue], commit: String, db: any Database, now: Date) async throws {
        let allowed: Set<String> = ["client_id", "tenant_id", "display_name", "redirect_uris", "post_logout_redirect_uris", "jwks", "id_token_signed_response_alg",
                                    "require_acr", "require_biometric"]
        guard Set(o.keys).isSubset(of: allowed) else { throw Failure.invalid("unknown member") }
        let clientId = try string(o, "client_id", max: 64)
        guard clientId.hasPrefix("ocl_"), clientId.dropFirst(4).allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_" || $0 == "-") }), clientId.count >= 8 else {
            throw Failure.invalid("client_id (ocl_ prefix)")
        }
        let redirects = try strings(o, "redirect_uris")
        let logouts = (o["post_logout_redirect_uris"] == nil) ? [] : try strings(o, "post_logout_redirect_uris")
        guard !redirects.isEmpty, (redirects + logouts).allSatisfy(OIDCProfile.isRegistrableRedirectURI) else { throw Failure.invalid("redirect_uris") }
        let hosts = Set(redirects.compactMap(OIDCProfile.host(of:)))
        // One sector per client; several hosts need a reviewed sector_identifier_uri, which is not offered yet (ADR-0024 §3).
        guard hosts.count == 1, let sector = hosts.first else { throw Failure.invalid("redirect_uris must share one host (the sector)") }
        guard case .object(let jwks)? = o["jwks"], case .array(let keys)? = jwks["keys"], !keys.isEmpty, keys.count <= 5,
              keys.allSatisfy({ $0.objectValue.map(OIDCClientKeys.isRegistrable) ?? false }) else { throw Failure.invalid("jwks (public EC P-256 or RSA keys with kid and alg)") }
        let alg = o["id_token_signed_response_alg"]?.stringValue ?? "RS256"
        guard ["RS256", "ES256"].contains(alg) else { throw Failure.invalid("id_token_signed_response_alg") }
        var requirePasskey = false
        if let acr = o["require_acr"] {
            guard acr.stringValue == OIDCProfile.acrPasskey || acr.stringValue == OIDCProfile.acrApp else { throw Failure.invalid("require_acr") }
            requirePasskey = acr.stringValue == OIDCProfile.acrPasskey
        }
        var requireBiometric = false
        if let raw = o["require_biometric"] { guard case .bool(let value) = raw else { throw Failure.invalid("require_biometric") }; requireBiometric = value }
        guard try await AuthorityOIDCClient.find(clientId, on: db) == nil, try await AuthorityLinkClient.find(clientId, on: db) == nil else {
            throw Failure.invalid("client_id exists (changes are a separate reviewed command)")
        }
        let client = AuthorityOIDCClient()
        client.id = clientId
        client.tenantId = try string(o, "tenant_id", max: 64)
        client.displayName = try displayName(try string(o, "display_name", max: 240))
        client.redirectURIs = String(decoding: try JSONEncoder().encode(redirects), as: UTF8.self)
        client.postLogoutRedirectURIs = String(decoding: try JSONEncoder().encode(logouts), as: UTF8.self)
        client.sectorIdentifier = sector
        client.jwks = String(decoding: try CanonicalJSON.serialize(.object(jwks)), as: UTF8.self)
        client.idTokenAlg = alg
        client.requirePasskey = requirePasskey
        client.requireBiometric = requireBiometric
        client.status = "active"
        client.changeCommit = commit
        client.createdAt = now
        try await client.create(on: db)
    }

    static func registerLinkClient(_ o: [String: JSONValue], commit: String, db: any Database, now: Date) async throws {
        let allowed: Set<String> = ["client_id", "tenant_id", "business_id", "tenant_name", "display_name", "return_urls", "require_biometric"]
        guard Set(o.keys).isSubset(of: allowed) else { throw Failure.invalid("unknown member") }
        let clientId = try string(o, "client_id", max: 64)
        guard clientId.hasPrefix("lcl_"), clientId.count >= 8 else { throw Failure.invalid("client_id (lcl_ prefix)") }
        let urls = try strings(o, "return_urls")
        guard !urls.isEmpty, urls.allSatisfy(OIDCProfile.isRegistrableRedirectURI) else { throw Failure.invalid("return_urls") }
        guard let business = UUID(uuidString: try string(o, "business_id", max: 64)) else { throw Failure.invalid("business_id") }
        guard try await AuthorityLinkClient.find(clientId, on: db) == nil, try await AuthorityOIDCClient.find(clientId, on: db) == nil else { throw Failure.invalid("client_id exists") }
        var requireBiometric = false
        if let raw = o["require_biometric"] { guard case .bool(let value) = raw else { throw Failure.invalid("require_biometric") }; requireBiometric = value }
        let client = AuthorityLinkClient()
        client.id = clientId
        client.tenantId = try string(o, "tenant_id", max: 64)
        client.businessId = business
        client.tenantName = try displayName(try string(o, "tenant_name", max: 240))
        client.displayName = try displayName(try string(o, "display_name", max: 240))
        client.returnURLs = String(decoding: try JSONEncoder().encode(urls), as: UTF8.self)
        client.requireBiometric = requireBiometric
        client.status = "active"
        client.changeCommit = commit
        client.createdAt = now
        try await client.create(on: db)
    }

    /// The one-time reviewed import of pre-existing device keys (ADR-0023 §4 migration, residual R-16). One account per key: a `kid` already in a
    /// non-revoked entry of any account is refused (`key_in_use`).
    static func importKeys(_ o: [String: JSONValue], commit: String, db: any Database, config: AuthorityConfig, now: Date) async throws {
        guard Set(o.keys) == ["accounts"], case .array(let accounts)? = o["accounts"], !accounts.isEmpty, accounts.count <= 10_000 else { throw Failure.invalid("accounts") }
        try await db.transaction { tx in
            for item in accounts {
                guard case .object(let a) = item, Set(a.keys) == ["account_id", "keys"], let accountId = a["account_id"]?.stringValue.flatMap(UUID.init(uuidString:)),
                      case .array(let keys)? = a["keys"], !keys.isEmpty, keys.count <= 10 else { throw Failure.invalid("account") }
                let ref = OIDCProfile.accountRef(key: config.accountRefKey, accountId: accountId)
                if try await AuthorityAccount.find(accountId, on: tx) == nil {
                    let account = AuthorityAccount()
                    account.id = accountId
                    account.accountRef = ref
                    account.origin = "imported"
                    account.frozen = false
                    account.createdAt = now
                    try await account.create(on: tx)
                }
                for keyValue in keys {
                    guard case .object(let k) = keyValue, Set(k.keys).isSubset(of: ["public_key", "key_purpose", "hardware_attested"]),
                          let publicText = k["public_key"]?.stringValue, let publicKey = try? DevicePublicKey(base64URL: publicText),
                          let purpose = k["key_purpose"]?.stringValue,
                          [DeviceKeyPurpose.approvalBiometric.rawValue, DeviceKeyPurpose.approvalUserPresence.rawValue].contains(purpose) else { throw Failure.invalid("key") }
                    var attested = false
                    if let raw = k["hardware_attested"] { guard case .bool(let value) = raw else { throw Failure.invalid("hardware_attested") }; attested = value }
                    let kid = KeyIdentifier.make(try publicKey.signingKey())
                    if let existing = try await AuthorityKey.find(kid, on: tx), existing.revokedAt == nil { throw Failure.invalid("key_in_use") }
                    let key = AuthorityKey()
                    key.id = kid
                    key.accountRef = ref
                    key.publicKey = publicKey.base64URL
                    key.keyPurpose = purpose
                    key.hardwareAttested = attested
                    key.grantCapable = true
                    key.usableFrom = now
                    try await key.create(on: tx)
                    try await AuthorityKeyLog.append(tx, accountRef: ref, type: "imported", kid: kid, publicKey: publicKey.base64URL, keyPurpose: purpose,
                                                     detail: ["commit": .string(commit), "hardware_attested": .bool(attested)], now: now)
                }
            }
        }
    }

    /// Pins `name` to an explicit version whose RFC 7638 thumbprint the attested inventory recorded (ADR-0028 §2). The running authority checks the
    /// thumbprint against Key Vault at its next start and refuses to start on a mismatch.
    static func pinKeyVersion(_ o: [String: JSONValue], commit: String, db: any Database, now: Date) async throws {
        guard Set(o.keys) == ["name", "version", "thumbprint"] else { throw Failure.invalid("members (name, version, thumbprint)") }
        let name = try string(o, "name", max: 127), version = try string(o, "version", max: 64), thumbprint = try string(o, "thumbprint", max: 43)
        guard ["grant-signing", "oidc-signing-rs256", "oidc-signing-es256", "device-statement-signing"].contains(name) else { throw Failure.invalid("name") }
        guard version.count == 32, version.allSatisfy({ $0.isHexDigit }) else { throw Failure.invalid("version") }
        guard Base64URL.isValid(thumbprint, minLength: 43, maxLength: 43) else { throw Failure.invalid("thumbprint") }
        let pin = try await AuthorityKeyPin.find(name, on: db) ?? AuthorityKeyPin()
        let isNew = pin.id == nil
        pin.id = name
        pin.version = version.lowercased()
        pin.thumbprint = thumbprint
        pin.changeCommit = commit
        pin.pinnedAt = now
        if isNew { try await pin.create(on: db) } else { try await pin.update(on: db) }
    }
}
