@preconcurrency import Crypto
import Foundation
import NIOHTTP1
import ViadereCore

/// `KeyManagementService` on the Azure Key Vault keys data plane (ADR-0012; Key Vault Standard in the lean profile and Premium in the standard
/// profile use the same REST API and key types). Every call carries a managed-identity bearer token for `https://vault.azure.net`; the
/// workload holds **Key Vault Crypto User** on individual keys only (sign, wrap, unwrap, get public key), never on the vault.
///
/// - `sign`: `POST {vault}/keys/{name}/{version}/sign` with `{"alg":"ES256","value":b64url(digest)}`. The current version is resolved first
///   (`GET {vault}/keys/{name}`), the request always names an explicit version, the response's `kid` must name that version, and the returned
///   `r ‖ s` must verify against that version's public key before it is used (a wrong version or a substituted key fails closed).
/// - `wrap`/`unwrap`: `POST …/wrapkey|unwrapkey` with `RSA-OAEP-256`; the wrapped result records the exact version.
public actor AzureKeyVaultKMS: KeyManagementService {
    /// Pinned data-plane version: the newest GA version of the Key Vault keys REST API on 2026-10-30 (Microsoft Learn, "sign", default moniker
    /// `rest-keyvault-keys-2025-07-01`). Tracked in CLAUDE.md "Current versions".
    public static let apiVersion = "2025-07-01"
    static let currentVersionTTL: TimeInterval = 600

    let vaultURL: String
    let tokens: any AccessTokenSource
    let http: any OutboundHTTP
    let now: @Sendable () -> Date
    private var publicKeys: [String: P256.Signing.PublicKey] = [:]          // "name/version"
    private var current: [String: (version: String, fetchedAt: Date)] = [:] // name

    public init(vaultURL: String, tokens: any AccessTokenSource, http: any OutboundHTTP, now: @escaping @Sendable () -> Date = { Date() }) throws {
        guard let normalized = Self.normalizedVaultURL(vaultURL) else { throw KMSError.unknownKey }
        self.vaultURL = normalized
        self.tokens = tokens
        self.http = http
        self.now = now
    }

    /// `https://<vault>.vault.azure.net` (or a Managed HSM pool) with no path, query, user info or port; returned without the trailing slash.
    public static func normalizedVaultURL(_ raw: String) -> String? {
        guard let url = URL(string: raw), url.scheme == "https", let host = url.host?.lowercased(), url.user == nil, url.password == nil,
              url.query == nil, url.fragment == nil, url.port == nil, url.path.isEmpty || url.path == "/",
              host.hasSuffix(".vault.azure.net") || host.hasSuffix(".managedhsm.azure.net") else { return nil }
        return "https://\(host)"
    }

    // MARK: Requests

    private func call(_ method: NIOHTTP1.HTTPMethod, _ path: String, body: [String: Any]?) async throws -> [String: Any] {
        let token = try await tokens.token(for: .keyVault)
        let data = try body.map { try JSONSerialization.data(withJSONObject: $0) }
        var headers = ["Authorization": "Bearer \(token)"]
        if data != nil { headers["Content-Type"] = "application/json" }
        let response = try await http.send(method: method, url: "\(vaultURL)/\(path)?api-version=\(Self.apiVersion)", headers: headers, body: data)
        guard response.status == 200, let object = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any] else {
            throw KMSError.service(status: response.status)
        }
        return object
    }

    /// Resolves `keyRef` to an explicit `(name, version)`; an unversioned reference uses the current version (cached for 10 minutes).
    private func resolve(_ keyRef: String) async throws -> (name: String, version: String) {
        guard let (name, version) = KMSKeyRef.parse(keyRef) else { throw KMSError.unknownKey }
        if let version { return (name, version) }
        if let cached = current[name], now().timeIntervalSince(cached.fetchedAt) < Self.currentVersionTTL { return (name, cached.version) }
        let object = try await call(.GET, "keys/\(name)", body: nil)
        guard let key = object["key"] as? [String: Any], let kid = key["kid"] as? String, let parsed = Self.parseKid(kid), parsed.name == name else {
            throw KMSError.unknownKey
        }
        current[name] = (parsed.version, now())
        if let ec = Self.ecPublicKey(key) { publicKeys["\(name)/\(parsed.version)"] = ec }
        return (name, parsed.version)
    }

    /// `https://<vault>/keys/<name>/<version>` → (name, version).
    static func parseKid(_ kid: String) -> (name: String, version: String)? {
        guard let url = URL(string: kid) else { return nil }
        let parts = url.path.split(separator: "/").map(String.init)
        guard parts.count == 3, parts[0] == "keys", KMSKeyRef.isName(parts[1]), !parts[2].isEmpty, parts[2].allSatisfy({ $0.isHexDigit }) else { return nil }
        return (parts[1], parts[2].lowercased())
    }

    static func ecPublicKey(_ jwk: [String: Any]) -> P256.Signing.PublicKey? {
        guard (jwk["kty"] as? String)?.hasPrefix("EC") == true, jwk["crv"] as? String == "P-256",
              let x = (jwk["x"] as? String).flatMap(Base64URL.decode), let y = (jwk["y"] as? String).flatMap(Base64URL.decode),
              x.count == 32, y.count == 32 else { return nil }
        return try? P256.Signing.PublicKey(rawRepresentation: x + y)
    }

    // MARK: KeyManagementService

    public func resolveVersion(keyRef: String) async throws -> String {
        let (name, version) = try await resolve(keyRef)
        return "\(name)/\(version)"
    }

    public func publicKey(keyRef: String) async throws -> P256.Signing.PublicKey {
        let (name, version) = try await resolve(keyRef)
        if let cached = publicKeys["\(name)/\(version)"] { return cached }
        let object = try await call(.GET, "keys/\(name)/\(version)", body: nil)
        guard let key = object["key"] as? [String: Any] else { throw KMSError.unknownKey }
        guard let kid = key["kid"] as? String, let parsed = Self.parseKid(kid), parsed.name == name, parsed.version == version else { throw KMSError.unknownKey }
        guard let ec = Self.ecPublicKey(key) else { throw KMSError.wrongKeyType }
        publicKeys["\(name)/\(version)"] = ec
        return ec
    }

    public func sign(keyRef: String, digest: Data) async throws -> Data {
        guard digest.count == 32 else { throw KMSError.invalidDigest }
        let (name, version) = try await resolve(keyRef)
        let expected = try await publicKey(keyRef: "\(name)/\(version)")
        let object = try await call(.POST, "keys/\(name)/\(version)/sign", body: ["alg": "ES256", "value": Base64URL.encode(digest)])
        guard let kid = object["kid"] as? String, let parsed = Self.parseKid(kid), parsed.name == name, parsed.version == version else {
            throw KMSError.signatureMismatch
        }
        guard let value = (object["value"] as? String).flatMap(Base64URL.decode), value.count == 64 else { throw KMSError.signatureMismatch }
        let raw = ViadereSignatureEncoding.normalizedRaw(value)
        guard let signature = try? P256.Signing.ECDSASignature(rawRepresentation: raw),
              expected.isValidSignature(signature, for: SHA256Digest(bytes: digest)) else { throw KMSError.signatureMismatch }
        return raw
    }

    public func wrap(keyRef: String, plaintext: Data) async throws -> KMSWrappedKey {
        let (name, version) = try await resolve(keyRef)
        let object = try await call(.POST, "keys/\(name)/\(version)/wrapkey", body: ["alg": "RSA-OAEP-256", "value": Base64URL.encode(plaintext)])
        guard let kid = object["kid"] as? String, let parsed = Self.parseKid(kid), parsed.name == name, parsed.version == version,
              let value = (object["value"] as? String).flatMap(Base64URL.decode), !value.isEmpty else { throw KMSError.service(status: 200) }
        return KMSWrappedKey(keyRef: "\(name)/\(version)", ciphertext: value)
    }

    public func unwrap(keyRef: String, ciphertext: Data) async throws -> Data {
        guard let (name, version) = KMSKeyRef.parse(keyRef), let version else { throw KMSError.unknownKey }
        let object: [String: Any]
        do {
            object = try await call(.POST, "keys/\(name)/\(version)/unwrapkey", body: ["alg": "RSA-OAEP-256", "value": Base64URL.encode(ciphertext)])
        } catch KMSError.service(let status) where status == 400 {
            throw KMSError.unwrapFailed
        }
        guard let value = (object["value"] as? String).flatMap(Base64URL.decode), !value.isEmpty else { throw KMSError.unwrapFailed }
        return value
    }
}
