import Crypto
import Foundation

/// Every way vault handling can fail. Messages never carry key material or plaintext.
public enum VaultError: Error, Equatable, Sendable {
    case malformed(String)
    case unsupportedVersion(Int)
    /// An AEAD tag did not verify: wrong key, wrong context or tampered ciphertext.
    case authenticationFailed
    case invalidManifest(String)
    case badSignature
    case unknownSigner
    /// A manifest older than one already trusted, or a chain that does not reach the trusted version.
    case rollback
    /// Two different manifests for the same version, or a chain whose links do not connect.
    case fork
    case invalidChain(String)
    case blobMismatch
    case keyCheckMismatch
    case notAMember
    case limitExceeded(String)
    case invalidRecoveryKey
    case invalidPairingCode
    case forbidden(String)
}

/// Wire-format and algorithm identifiers for the vault (SEC-CR-007). Documented in `docs/SECURITY.md` §2.28; changing any of them is a
/// new format version, never an in-place change.
public enum VaultFormat {
    /// Version of every vault structure below (manifest, item blob, envelope, sealed box).
    public static let version: UInt8 = 1

    /// AEAD identifiers. `1` = AES-256-GCM with a random 96-bit nonce and a 128-bit tag.
    public static let aeadAES256GCM: UInt8 = 1
    /// HPKE suite identifiers. `1` = DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM (RFC 9180, base mode).
    public static let suiteP256SHA256AES256GCM: UInt8 = 1

    /// `version | aead | nonce(12) | tag(16)` around the ciphertext.
    public static let sealedBoxOverhead = 2 + 12 + 16
    /// `version | suite | enc(65) | AES-GCM ciphertext of the 32-byte vault key + tag(16)`.
    public static let envelopeLength = 2 + 65 + 32 + 16
    public static let itemPaddingBucket = 256

    public static let maxItems = 2000
    public static let maxDevices = 16
    public static let maxItemBlobBytes = 32 * 1024
    public static let maxManifestBytes = 256 * 1024
    public static let maxLabelBytes = 64

    /// HKDF `info` labels. Every derived key has its own label (key separation); none is ever used for two purposes.
    enum Label {
        static let itemKeyEncryptionKey = "viadere.vault.v1.item-kek"
        static let deviceLabelKey = "viadere.vault.v1.label-key"
        static let keyCheck = "viadere.vault.v1.key-check"
        static let recoveryBinding = "viadere.vault.v1.recovery-binding"
        static let recoveryAgreement = "viadere.vault.v1.recovery-agreement"
        static let recoverySigning = "viadere.vault.v1.recovery-signing"
        static let joinIdentifier = "viadere.vault.v1.join-id"
        static let joinRequest = "viadere.vault.v1.join-request"
        static let joinApproval = "viadere.vault.v1.join-approval"
        static let envelopeInfo = "viadere.vault.v1.envelope"
        static let manifestSignature = "viadere.vault.v1.manifest"
    }
}

/// The 256-bit vault key. It exists in memory while the vault is unlocked and otherwise only as HPKE envelopes (one per device) and the
/// recovery envelope; it never reaches a server in plaintext.
public struct VaultKey: Sendable {
    let key: SymmetricKey
    public init(_ key: SymmetricKey) { self.key = key }
    public init(rawBytes: Data) throws {
        guard rawBytes.count == 32 else { throw VaultError.malformed("vault key length") }
        key = SymmetricKey(data: rawBytes)
    }
    public static func generate() -> VaultKey { VaultKey(SymmetricKey(size: .bits256)) }
    var bytes: Data { key.withUnsafeBytes { Data($0) } }

    /// A public, signed commitment to this key at `epoch`. A device that unseals an envelope compares it with the manifest's `check`,
    /// so a server cannot hand it a different key (HPKE base mode does not authenticate its sender).
    public func keyCheck(epoch: UInt64) -> Data {
        VaultKDF.derive(key, salt: VaultBytes.be64(epoch), label: VaultFormat.Label.keyCheck)
    }
}

enum VaultBytes {
    static func be64(_ value: UInt64) -> Data {
        Data((0..<8).reversed().map { UInt8((value >> (8 * UInt64($0))) & 0xFF) })
    }
    static func be32(_ value: UInt32) -> Data {
        Data((0..<4).reversed().map { UInt8((value >> (8 * UInt32($0))) & 0xFF) })
    }
    static func uuid(_ id: UUID) -> Data { withUnsafeBytes(of: id.uuid) { Data($0) } }
    static func uuid(from data: Data) -> UUID? {
        guard data.count == 16 else { return nil }
        return UUID(uuid: data.withUnsafeBytes { $0.loadUnaligned(as: uuid_t.self) })
    }
}

enum VaultKDF {
    /// HKDF-SHA256 with an explicit label as `info`; 32 bytes out.
    static func derive(_ input: SymmetricKey, salt: Data, label: String, extra: Data = Data()) -> Data {
        let out = HKDF<SHA256>.deriveKey(inputKeyMaterial: input, salt: salt, info: Data(label.utf8) + extra, outputByteCount: 32)
        return out.withUnsafeBytes { Data($0) }
    }
    static func deriveKey(_ input: SymmetricKey, salt: Data, label: String, extra: Data = Data()) -> SymmetricKey {
        SymmetricKey(data: derive(input, salt: salt, label: label, extra: extra))
    }
}

/// Unambiguous additional authenticated data: a fixed prefix, the purpose, then length-prefixed fields.
enum VaultAAD {
    static func make(_ purpose: String, _ fields: [Data]) -> Data {
        var out = Data("viadere.vault.v1".utf8)
        out.append(0)
        out.append(Data(purpose.utf8))
        out.append(0)
        for field in fields {
            out.append(VaultBytes.be32(UInt32(field.count)))
            out.append(field)
        }
        return out
    }
}

/// `version(1) | aead(1) | nonce(12) | ciphertext | tag(16)`.
///
/// **Nonces.** Every seal draws a fresh random 96-bit nonce from the system CSPRNG (`AES.GCM.Nonce()`); nothing derives or counts them.
/// Item payload keys are single-use (a new key per revision), and every long-lived key (vault key derivations, recovery wrap key) seals
/// at most a few hundred messages in its life, far below the 2^32 random-nonce bound of NIST SP 800-38D.
public enum VaultSeal {
    public static func seal(_ plaintext: Data, key: SymmetricKey, aad: Data) throws -> Data {
        let box = try AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce(), authenticating: aad)
        return Data([VaultFormat.version, VaultFormat.aeadAES256GCM]) + Data(box.nonce) + box.ciphertext + box.tag
    }

    public static func open(_ sealed: Data, key: SymmetricKey, aad: Data) throws -> Data {
        let sealed = Data(sealed)
        guard sealed.count >= VaultFormat.sealedBoxOverhead else { throw VaultError.malformed("sealed box") }
        guard sealed[0] == VaultFormat.version else { throw VaultError.unsupportedVersion(Int(sealed[0])) }
        guard sealed[1] == VaultFormat.aeadAES256GCM else { throw VaultError.malformed("aead") }
        let body = sealed.dropFirst(2)
        do {
            let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: body.prefix(12)), ciphertext: body.dropFirst(12).dropLast(16), tag: body.suffix(16))
            return try AES.GCM.open(box, using: key, authenticating: aad)
        } catch {
            throw VaultError.authenticationFailed
        }
    }

    /// The nonce of a sealed box (tests check that no two seals share one).
    public static func nonce(of sealed: Data) -> Data? { sealed.count >= 14 ? Data(sealed.dropFirst(2).prefix(12)) : nil }
}

/// Plaintext padding: `length(4, big endian) | bytes | zeros` up to a multiple of `VaultFormat.itemPaddingBucket`, so a blob's size reveals
/// only a coarse bucket, not whether an item is a passkey or a TOTP secret.
enum VaultPadding {
    static func pad(_ data: Data) -> Data {
        var out = VaultBytes.be32(UInt32(data.count)) + data
        let bucket = VaultFormat.itemPaddingBucket
        let remainder = out.count % bucket
        if remainder != 0 { out.append(Data(repeating: 0, count: bucket - remainder)) }
        return out
    }

    static func unpad(_ padded: Data) throws -> Data {
        guard padded.count >= 4, padded.count % VaultFormat.itemPaddingBucket == 0 else { throw VaultError.malformed("padding") }
        let bytes = [UInt8](padded)
        let length = bytes[0..<4].reduce(0) { $0 << 8 | Int($1) }
        guard length <= bytes.count - 4, bytes[(4 + length)...].allSatisfy({ $0 == 0 }) else { throw VaultError.malformed("padding") }
        return Data(bytes[4..<(4 + length)])
    }
}
