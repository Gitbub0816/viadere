import Crypto
import Foundation
import ViadereCore

/// Credential Exchange (FIDO Alliance CXF) import: the platform-neutral half. iOS 26's `ASCredentialImportManager` hands the app the exported
/// data; this maps its JSON form (accounts, collections, items, credentials) onto vault items, strictly and with a per-item report of what could
/// not be imported. Only ES256 (P-256) passkeys and TOTP are supported (the vault's authenticator engine signs nothing else); everything else
/// is reported, never silently dropped or mangled.
///
/// Verification status: the field names follow the CXF 1.0 draft. They have NOT been checked against a real iOS 26 export (needs a device or
/// Simulator with Passwords' export UI): see `CredentialExchangeImportCoordinator` in the app.
public enum CredentialExchange {
    public struct Skipped: Sendable, Equatable {
        public var title: String
        public var reason: String
    }

    public struct Result: Sendable, Equatable {
        public var items: [VaultItemPayload]
        public var skipped: [Skipped]
    }

    public enum ImportError: Error, Equatable, Sendable {
        case malformed, unsupportedVersion, tooLarge
    }

    public static let maxBytes = 8 * 1024 * 1024

    public static func parse(_ data: Data, now: Date) throws -> Result {
        guard data.count <= maxBytes else { throw ImportError.tooLarge }
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any], let accounts = root["accounts"] as? [[String: Any]] else { throw ImportError.malformed }
        if let version = root["version"] as? [String: Any], let major = version["major"] as? Int, major != 1 { throw ImportError.unsupportedVersion }
        var items: [VaultItemPayload] = []
        var skipped: [Skipped] = []
        for account in accounts {
            for collection in (account["collections"] as? [[String: Any]]) ?? [] {
                for item in (collection["items"] as? [[String: Any]]) ?? [] {
                    let title = clean((item["title"] as? String) ?? "Untitled")
                    for credential in (item["credentials"] as? [[String: Any]]) ?? [] {
                        switch credential["type"] as? String {
                        case "passkey":
                            if let payload = passkey(credential, now: now) { items.append(payload) } else { skipped.append(Skipped(title: title, reason: "Passkey could not be read (only ES256 passkeys are supported)")) }
                        case "totp":
                            if let payload = totp(credential, title: title, now: now) { items.append(payload) } else { skipped.append(Skipped(title: title, reason: "One-time code could not be read")) }
                        case let other?:
                            skipped.append(Skipped(title: title, reason: "\(clean(other)) isn't stored in Authenticator"))
                        case nil:
                            skipped.append(Skipped(title: title, reason: "Unknown item"))
                        }
                    }
                }
            }
        }
        return Result(items: items, skipped: skipped)
    }

    private static func clean(_ text: String) -> String { DisplayTextSanitizer.sanitize(text, maxCharacters: 80) }

    private static func passkey(_ c: [String: Any], now: Date) -> VaultItemPayload? {
        guard let idText = c["credentialId"] as? String, let id = Base64URL.decode(idText), !id.isEmpty, id.count <= 1023, let rpId = c["rpId"] as? String,
              WebAuthnAuthenticator.isValidRelyingPartyID(rpId), let userName = c["username"] as? String,
              let handleText = c["userHandle"] as? String, let handle = Base64URL.decode(handleText), !handle.isEmpty, handle.count <= WebAuthnAuthenticator.userHandleLimit,
              let keyText = c["key"] as? String, let der = Base64URL.decode(keyText), let key = try? P256.Signing.PrivateKey(derRepresentation: der) else { return nil }
        let credential = PasskeyCredential(credentialId: id, rpId: rpId, userHandle: handle, userName: clean(userName), displayName: (c["userDisplayName"] as? String).map(clean),
                                           privateKey: key.rawRepresentation, createdAt: now)
        return VaultItemPayload(body: .passkey(credential), createdAt: now)
    }

    private static func totp(_ c: [String: Any], title: String, now: Date) -> VaultItemPayload? {
        guard let secretText = c["secret"] as? String, let secret = Base32.decode(secretText) else { return nil }
        let algorithm = (c["algorithm"] as? String).flatMap { TOTPAlgorithm(rawValue: $0.uppercased()) } ?? .sha1
        let parameters = TOTPParameters(secret: secret, algorithm: algorithm, digits: (c["digits"] as? Int) ?? 6, period: (c["period"] as? Int) ?? 30,
                                        issuer: (c["issuer"] as? String).map(clean) ?? title, accountName: clean((c["username"] as? String) ?? title))
        guard (try? TOTP.validate(parameters)) != nil, !parameters.accountName.isEmpty else { return nil }
        return VaultItemPayload(body: .totp(parameters), createdAt: now)
    }
}

extension VaultEngine {
    /// Imports parsed Credential Exchange items. Items that already exist (same credential id, or same TOTP secret and account) are skipped.
    @discardableResult
    public func importExchange(_ result: CredentialExchange.Result) async throws -> Int {
        let existing = try await items()
        func isDuplicate(_ item: VaultItemPayload) -> Bool {
            existing.contains { other in
                switch (item.body, other.body) {
                case (.passkey(let a), .passkey(let b)): a.credentialId == b.credentialId
                case (.totp(let a), .totp(let b)): a.secret == b.secret && a.accountName == b.accountName
                default: false
                }
            }
        }
        let fresh = result.items.filter { !isDuplicate($0) }
        if !fresh.isEmpty { try await upsert(fresh) }
        return fresh.count
    }
}
