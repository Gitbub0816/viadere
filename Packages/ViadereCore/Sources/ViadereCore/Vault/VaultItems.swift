import Crypto
import Foundation

public enum VaultItemKind: String, Sendable, Codable, Equatable {
    case passkey, totp
}

/// What a vault item holds.
public enum VaultItemBody: Sendable, Equatable {
    case passkey(PasskeyCredential)
    case totp(TOTPParameters)

    public var kind: VaultItemKind {
        switch self {
        case .passkey: .passkey
        case .totp: .totp
        }
    }
}

/// A decrypted vault item. `id` is the item's identifier in the manifest (random, carries no meaning).
public struct VaultItemPayload: Sendable, Equatable, Identifiable {
    public var id: UUID
    public var body: VaultItemBody
    public var createdAt: Date
    public var updatedAt: Date

    public init(id: UUID = UUID(), body: VaultItemBody, createdAt: Date, updatedAt: Date? = nil) {
        self.id = id
        self.body = body
        self.createdAt = createdAt
        self.updatedAt = updatedAt ?? createdAt
    }

    // MARK: Plaintext encoding (CBOR; sealed by `VaultItemBlob`)

    func encoded() -> Data {
        var fields: [(String, CBORValue)] = [("v", .unsigned(1)), ("kind", .text(body.kind.rawValue)),
                                             ("created", .unsigned(UInt64(max(0, createdAt.timeIntervalSince1970)))),
                                             ("updated", .unsigned(UInt64(max(0, updatedAt.timeIntervalSince1970))))]
        switch body {
        case .passkey(let p):
            var map: [(String, CBORValue)] = [("cred", .bytes(p.credentialId)), ("rp", .text(p.rpId)), ("uh", .bytes(p.userHandle)),
                                              ("user", .text(p.userName)), ("key", .bytes(p.privateKey)),
                                              ("at", .unsigned(UInt64(max(0, p.createdAt.timeIntervalSince1970))))]
            if let name = p.displayName { map.append(("display", .text(name))) }
            fields.append(("passkey", .textMap(map)))
        case .totp(let t):
            var map: [(String, CBORValue)] = [("secret", .bytes(t.secret)), ("alg", .text(t.algorithm.rawValue)), ("digits", .unsigned(UInt64(t.digits))),
                                              ("period", .unsigned(UInt64(t.period))), ("account", .text(t.accountName))]
            if let issuer = t.issuer { map.append(("issuer", .text(issuer))) }
            fields.append(("totp", .textMap(map)))
        }
        return CBOR.encode(.textMap(fields), deterministic: true)
    }

    static func decode(_ data: Data, id: UUID) throws -> VaultItemPayload {
        guard let root = try? CBOR.decode(data, limits: .init(maxDepth: 4, maxBytes: VaultFormat.maxItemBlobBytes, maxItems: 32)),
              root["v"]?.unsignedValue == 1, let kind = root["kind"]?.textString,
              let created = root["created"]?.unsignedValue, let updated = root["updated"]?.unsignedValue else { throw VaultError.malformed("item") }
        let createdAt = Date(timeIntervalSince1970: TimeInterval(min(created, 4_000_000_000)))
        let updatedAt = Date(timeIntervalSince1970: TimeInterval(min(updated, 4_000_000_000)))
        switch VaultItemKind(rawValue: kind) {
        case .passkey:
            guard let p = root["passkey"], let cred = p["cred"]?.byteString, let rp = p["rp"]?.textString, let uh = p["uh"]?.byteString,
                  let user = p["user"]?.textString, let key = p["key"]?.byteString, key.count == 32, let at = p["at"]?.unsignedValue,
                  !cred.isEmpty, WebAuthnAuthenticator.isValidRelyingPartyID(rp) else { throw VaultError.malformed("passkey") }
            let credential = PasskeyCredential(credentialId: cred, rpId: rp, userHandle: uh, userName: user, displayName: p["display"]?.textString,
                                               privateKey: key, createdAt: Date(timeIntervalSince1970: TimeInterval(min(at, 4_000_000_000))))
            return VaultItemPayload(id: id, body: .passkey(credential), createdAt: createdAt, updatedAt: updatedAt)
        case .totp:
            guard let t = root["totp"], let secret = t["secret"]?.byteString, let alg = t["alg"]?.textString.flatMap(TOTPAlgorithm.init(rawValue:)),
                  let digits = t["digits"]?.unsignedValue, let period = t["period"]?.unsignedValue, let account = t["account"]?.textString,
                  digits <= 8, period <= 300 else { throw VaultError.malformed("totp") }
            let parameters = TOTPParameters(secret: secret, algorithm: alg, digits: Int(digits), period: Int(period),
                                            issuer: t["issuer"]?.textString, accountName: account)
            guard (try? TOTP.validate(parameters)) != nil else { throw VaultError.malformed("totp") }
            return VaultItemPayload(id: id, body: .totp(parameters), createdAt: createdAt, updatedAt: updatedAt)
        case nil:
            throw VaultError.malformed("item kind")
        }
    }
}

/// An item as stored and synced: `version(1) | wrapped item key (62) | sealed padded payload`.
///
/// Per-item keys: each seal draws a fresh 256-bit item key `IK`. The payload is sealed under `IK`; `IK` is sealed (wrapped) under
/// `KEK = HKDF(vaultKey, salt = itemId, info = "viadere.vault.v1.item-kek")`. Both seals bind `(vaultId, itemId, epoch, revision)` as
/// AAD, so a blob cannot be moved to another item, vault, revision or key epoch.
public enum VaultItemBlob {
    static func context(vaultId: UUID, itemId: UUID, epoch: UInt64, revision: UInt64, purpose: String) -> Data {
        VaultAAD.make(purpose, [VaultBytes.uuid(vaultId), VaultBytes.uuid(itemId), VaultBytes.be64(epoch), VaultBytes.be64(revision)])
    }

    static func kek(_ vaultKey: VaultKey, itemId: UUID) -> SymmetricKey {
        VaultKDF.deriveKey(vaultKey.key, salt: VaultBytes.uuid(itemId), label: VaultFormat.Label.itemKeyEncryptionKey)
    }

    public static func seal(_ item: VaultItemPayload, vaultId: UUID, epoch: UInt64, revision: UInt64, vaultKey: VaultKey) throws -> Data {
        let itemKey = SymmetricKey(size: .bits256)
        let wrapped = try VaultSeal.seal(itemKey.withUnsafeBytes { Data($0) }, key: kek(vaultKey, itemId: item.id),
                                         aad: context(vaultId: vaultId, itemId: item.id, epoch: epoch, revision: revision, purpose: "item-key"))
        let payload = try VaultSeal.seal(VaultPadding.pad(item.encoded()), key: itemKey,
                                         aad: context(vaultId: vaultId, itemId: item.id, epoch: epoch, revision: revision, purpose: "item"))
        let blob = Data([VaultFormat.version]) + wrapped + payload
        guard blob.count <= VaultFormat.maxItemBlobBytes else { throw VaultError.limitExceeded("item size") }
        return blob
    }

    public static func open(_ blob: Data, itemId: UUID, vaultId: UUID, epoch: UInt64, revision: UInt64, vaultKey: VaultKey) throws -> VaultItemPayload {
        let blob = Data(blob)
        guard blob.count <= VaultFormat.maxItemBlobBytes, blob.count > 1 + VaultFormat.sealedBoxOverhead + 32 + VaultFormat.sealedBoxOverhead else {
            throw VaultError.malformed("item blob")
        }
        guard blob[0] == VaultFormat.version else { throw VaultError.unsupportedVersion(Int(blob[0])) }
        let wrapped = blob.dropFirst().prefix(VaultFormat.sealedBoxOverhead + 32)
        let payload = blob.dropFirst(1 + VaultFormat.sealedBoxOverhead + 32)
        let itemKeyBytes = try VaultSeal.open(Data(wrapped), key: kek(vaultKey, itemId: itemId),
                                              aad: context(vaultId: vaultId, itemId: itemId, epoch: epoch, revision: revision, purpose: "item-key"))
        guard itemKeyBytes.count == 32 else { throw VaultError.malformed("item key") }
        let padded = try VaultSeal.open(Data(payload), key: SymmetricKey(data: itemKeyBytes),
                                        aad: context(vaultId: vaultId, itemId: itemId, epoch: epoch, revision: revision, purpose: "item"))
        return try VaultItemPayload.decode(try VaultPadding.unpad(padded), id: itemId)
    }
}
