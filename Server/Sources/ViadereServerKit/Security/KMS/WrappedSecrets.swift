import AsyncHTTPClient
import Foundation
import NIOCore
import NIOHTTP1
import ViadereCore

/// Envelope-wrapped server secrets (WP-B2, plan 5.6). On Azure the symmetric service keys live in Key Vault secrets **wrapped** under the
/// key-encryption key `kek-data` (RSA 3072, RSA-OAEP-256) and reach the process as `<NAME>_WRAPPED`; they are unwrapped once at boot, held only in
/// memory, and never written anywhere. Elsewhere (Fly staging, development, tests) the plain variables keep working.
///
/// Wire form (SECURITY.md §2.25): `kms1:<key name>/<key version>:<base64url ciphertext>`. The plaintext is the exact text the plain variable
/// would hold (for example base64url of 32 random bytes, or an `id:key,…` list). A value may be set plain **or** wrapped, never both; it must be
/// wrapped under the configured `AZURE_KEY_VAULT_KEK_KEY` (any other key name is refused), and the version must be explicit.
public enum WrappedSecrets {
    public static let prefix = "kms1:"

    /// The variables that may be supplied wrapped.
    public static let names = [
        "DATA_ENCRYPTION_KEY", "SERVER_PEPPER", "AUDIT_CHAIN_KEY", "SUBJECT_REF_KEY", "CONNECT_LINK_SIGNING_KEY",
        "DATA_ENCRYPTION_KEYS_PREVIOUS", "SERVER_PEPPERS_PREVIOUS", "AUDIT_CHAIN_KEYS_PREVIOUS", "CONNECT_LINK_SIGNING_KEYS_PREVIOUS",
    ]
    /// Wrapped values unwrapped later, by their own consumer (the Wallet identity-encryption keys, `WalletKeyUnwrapper`).
    static let deferred: Set<String> = ["WALLET_ENCRYPTION_KEY_WRAPPED"]

    public static func encode(_ wrapped: KMSWrappedKey) -> String { "\(prefix)\(wrapped.keyRef):\(Base64URL.encode(wrapped.ciphertext))" }

    /// `(name/version, ciphertext)`; `nil` for anything malformed (including an unversioned key reference).
    public static func decode(_ text: String) -> (keyRef: String, ciphertext: Data)? {
        guard text.hasPrefix(prefix) else { return nil }
        let parts = text.dropFirst(prefix.count).split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 2, let ref = KMSKeyRef.parse(parts[0]), ref.version != nil, let ciphertext = Base64URL.decode(parts[1]), !ciphertext.isEmpty,
              ciphertext.count <= 1024 else { return nil }
        return (parts[0], ciphertext)
    }

    /// Returns `env` with every `<NAME>_WRAPPED` replaced by the unwrapped `<NAME>`. Throws `ServerConfigError` (naming variables, never values).
    public static func resolve(_ env: [String: String], kms: (any KeyManagementService)?) async throws -> [String: String] {
        var out = env
        let wrappedNames = env.keys.filter { $0.hasSuffix("_WRAPPED") && !(env[$0] ?? "").isEmpty }
        for name in wrappedNames where !deferred.contains(name) {
            let base = String(name.dropLast("_WRAPPED".count))
            guard names.contains(base) else { throw ServerConfigError.invalid("\(name) (only these may be wrapped: \(names.joined(separator: ", ")))") }
            if let plain = env[base], !plain.isEmpty { throw ServerConfigError.invalid("\(base) and \(name) (set one of them, not both)") }
        }
        let pending = names.filter { env["\($0)_WRAPPED"].map { !$0.isEmpty } ?? false }
        guard !pending.isEmpty else { return out }
        guard let kek = env["AZURE_KEY_VAULT_KEK_KEY"].flatMap({ $0.isEmpty ? nil : $0 }), let kekName = KMSKeyRef.parse(kek)?.name else {
            throw ServerConfigError.missing("AZURE_KEY_VAULT_KEK_KEY (required to unwrap *_WRAPPED secrets)")
        }
        guard let kms else { throw ServerConfigError.missing("AZURE_KEY_VAULT_URL with a managed identity (required to unwrap *_WRAPPED secrets)") }
        for base in pending {
            let name = "\(base)_WRAPPED"
            guard let (keyRef, ciphertext) = decode(env[name] ?? ""), KMSKeyRef.parse(keyRef)?.name == kekName else {
                throw ServerConfigError.invalid("\(name) (kms1:<AZURE_KEY_VAULT_KEK_KEY name>/<version>:<base64url>)")
            }
            let plaintext: Data
            do { plaintext = try await kms.unwrap(keyRef: keyRef, ciphertext: ciphertext) } catch {
                throw ServerConfigError.invalid("\(name) (could not be unwrapped with \(keyRef))")
            }
            guard let text = String(data: plaintext, encoding: .utf8), !text.isEmpty,
                  text.unicodeScalars.allSatisfy({ $0.isASCII && $0.value > 0x20 && $0.value < 0x7F }) else {
                throw ServerConfigError.invalid("\(name) (the unwrapped value is not a printable configuration value)")
            }
            out[base] = text
            out[name] = nil
        }
        return out
    }

    /// The boot path of the executable: builds the managed identity and the Key Vault client only when a wrapped value is present.
    public static func resolveFromEnvironment(_ env: [String: String] = ProcessInfo.processInfo.environment) async throws -> [String: String] {
        guard names.contains(where: { env["\($0)_WRAPPED"].map { !$0.isEmpty } ?? false }) else { return try await resolve(env, kms: nil) }
        let http = StandaloneOutboundHTTP(guard: .fromEnvironment(env))
        guard let identity = AzureManagedIdentity.fromEnvironment(env), let vault = env["AZURE_KEY_VAULT_URL"], !vault.isEmpty else {
            return try await resolve(env, kms: nil)
        }
        let kms = try AzureKeyVaultKMS(vaultURL: vault, tokens: identity, http: http)
        return try await resolve(env, kms: kms)
    }
}

/// `WalletKeyUnwrapper` on the KMS (the HANDOFF open item): a `WALLET_ENCRYPTION_KEY_WRAPPED` entry in the `kms1:` form is unwrapped with the
/// key-encryption key; the result is the PKCS#8/SEC1 DER of the identity-encryption key, held only in memory.
struct KMSWalletKeyUnwrapper: WalletKeyUnwrapper {
    let kms: any KeyManagementService
    let kekName: String

    func unwrap(_ wrapped: Data) async throws -> Data {
        guard let text = String(data: wrapped, encoding: .utf8), let (keyRef, ciphertext) = WrappedSecrets.decode(text),
              KMSKeyRef.parse(keyRef)?.name == kekName else { throw WalletConfigurationError.unreadableKey }
        return try await kms.unwrap(keyRef: keyRef, ciphertext: ciphertext)
    }
}

/// An `OutboundHTTP` on AsyncHTTPClient for the boot path (before Vapor's client exists): https only, no redirects, short timeouts, behind the
/// identity-endpoint guard.
struct StandaloneOutboundHTTP: OutboundHTTP {
    let destinationGuard: OutboundDestinationGuard

    init(guard destinationGuard: OutboundDestinationGuard) { self.destinationGuard = destinationGuard }

    func send(method: NIOHTTP1.HTTPMethod, url: String, headers: [String: String], body: Data?) async throws -> (status: Int, body: Data) {
        guard url.hasPrefix("https://"), let parsed = URL(string: url) else { throw OutboundDestinationGuard.Refusal.unresolvable }
        try await destinationGuard.check(parsed)
        var configuration = HTTPClient.Configuration()
        configuration.redirectConfiguration = .disallow
        configuration.timeout = .init(connect: .seconds(5), read: .seconds(15))
        let client = HTTPClient(eventLoopGroupProvider: .singleton, configuration: configuration)
        do {
            var request = HTTPClientRequest(url: url)
            request.method = method
            for (name, value) in headers { request.headers.replaceOrAdd(name: name, value: value) }
            if let body { request.body = .bytes(ByteBuffer(data: body)) }
            let response = try await client.execute(request, timeout: .seconds(20))
            let bytes = try await response.body.collect(upTo: 256 * 1024)
            try await client.shutdown()
            return (Int(response.status.code), Data(bytes.readableBytesView))
        } catch {
            try? await client.shutdown()
            throw error
        }
    }
}
