import Crypto
import Foundation

/// Crockford base32 (no `I L O U`), the alphabet recovery keys and pairing codes are written in: unambiguous when read aloud or typed.
enum CrockfordBase32 {
    private static let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ".utf8)

    static func encode(_ data: Data) -> String {
        var out = [UInt8]()
        var buffer: UInt32 = 0
        var bits = 0
        for byte in data {
            buffer = buffer << 8 | UInt32(byte)
            bits += 8
            while bits >= 5 {
                out.append(alphabet[Int(buffer >> UInt32(bits - 5)) & 31])
                bits -= 5
            }
            buffer &= (1 << UInt32(bits)) - 1
        }
        if bits > 0 { out.append(alphabet[Int(buffer << UInt32(5 - bits)) & 31]) }
        return String(decoding: out, as: UTF8.self)
    }

    /// Decodes `byteCount` bytes from exactly the number of characters `encode` produces; the unused trailing bits must be zero.
    static func decode(_ text: String, byteCount: Int) -> Data? {
        let expected = (byteCount * 8 + 4) / 5
        var buffer: UInt32 = 0
        var bits = 0
        var out = Data()
        var count = 0
        for scalar in text.uppercased().unicodeScalars {
            var char = scalar.value
            guard char < 128 else { return nil }
            if scalar == "I" || scalar == "L" { char = UInt32(UInt8(ascii: "1")) }
            if scalar == "O" { char = UInt32(UInt8(ascii: "0")) }
            guard let value = alphabet.firstIndex(of: UInt8(char)) else { return nil }
            count += 1
            buffer = buffer << 5 | UInt32(value)
            bits += 5
            if bits >= 8 {
                out.append(UInt8((buffer >> UInt32(bits - 8)) & 0xFF))
                bits -= 8
                buffer &= (1 << UInt32(bits)) - 1
            }
        }
        guard count == expected, out.count == byteCount, buffer == 0 else { return nil }
        return out
    }

    /// Normalises user input: drops spaces and hyphens.
    static func stripped(_ text: String) -> String { text.filter { $0 != "-" && $0 != " " && !$0.isNewline } }

    static func grouped(_ text: String, size: Int) -> String {
        var groups: [String] = []
        var index = text.startIndex
        while index < text.endIndex {
            let end = text.index(index, offsetBy: size, limitedBy: text.endIndex) ?? text.endIndex
            groups.append(String(text[index..<end]))
            index = end
        }
        return groups.joined(separator: "-")
    }
}

/// `memberId = base64url(SHA-256(signing public key, X9.63))`: a member is identified by the key that signs for it.
public enum VaultMemberID {
    public static func make(signingKey x963: Data) -> String { Base64URL.encode(Data(SHA256.hash(data: x963))) }
}

/// A private P-256 key agreement key that can open HPKE envelopes. On a device it is a Secure Enclave key (user presence required to use
/// it); in tests and for the recovery key it is a software key.
public protocol VaultAgreementKey: Sendable {
    var publicKey: P256.KeyAgreement.PublicKey { get }
    /// An HPKE recipient context for the suite `DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM`.
    func recipient(info: Data, encapsulatedKey: Data) throws -> HPKE.Recipient
}

public struct SoftwareVaultAgreementKey: VaultAgreementKey {
    private let raw: Data
    public let publicKey: P256.KeyAgreement.PublicKey

    public init() {
        let key = P256.KeyAgreement.PrivateKey()
        raw = key.rawRepresentation
        publicKey = key.publicKey
    }

    public init(rawRepresentation: Data) throws {
        let key = try P256.KeyAgreement.PrivateKey(rawRepresentation: rawRepresentation)
        raw = key.rawRepresentation
        publicKey = key.publicKey
    }

    public func recipient(info: Data, encapsulatedKey: Data) throws -> HPKE.Recipient {
        try HPKE.Recipient(privateKey: try P256.KeyAgreement.PrivateKey(rawRepresentation: raw), ciphersuite: .P256_SHA256_AES_GCM_256,
                           info: info, encapsulatedKey: encapsulatedKey)
    }
}

/// A vault participant's keys: one signing key (approves manifests) and one agreement key (receives the vault key).
public struct VaultDeviceIdentity: Sendable {
    public let signingKey: any DeviceSigningKey
    public let agreementKey: any VaultAgreementKey

    public init(signingKey: any DeviceSigningKey, agreementKey: any VaultAgreementKey) {
        self.signingKey = signingKey
        self.agreementKey = agreementKey
    }

    /// A software identity (tests).
    public static func software() -> VaultDeviceIdentity {
        VaultDeviceIdentity(signingKey: SoftwareP256SigningKey(), agreementKey: SoftwareVaultAgreementKey())
    }

    public var signingPublicKey: Data { signingKey.publicKey.x963 }
    public var agreementPublicKey: Data { agreementKey.publicKey.x963Representation }
    public var memberId: String { VaultMemberID.make(signingKey: signingPublicKey) }
}

/// HPKE envelope that carries the vault key to one member: `version | suite | enc(65) | ciphertext(32) + tag(16)`.
///
/// `info` and `aad` both bind `(vaultId, epoch, recipient member id)`, so an envelope cannot be replayed for another vault, key epoch or
/// member. Base mode is deliberate: the sender is authenticated by the **signed manifest** (its `check` commits to the key inside), not by HPKE.
public enum VaultEnvelope {
    static func info(vaultId: UUID, epoch: UInt64, memberId: String) -> Data {
        VaultAAD.make(VaultFormat.Label.envelopeInfo, [VaultBytes.uuid(vaultId), VaultBytes.be64(epoch), Data(memberId.utf8)])
    }

    static func aad(vaultId: UUID, epoch: UInt64, memberId: String) -> Data {
        VaultAAD.make("envelope", [VaultBytes.uuid(vaultId), VaultBytes.be64(epoch), Data(memberId.utf8)])
    }

    public static func seal(_ vaultKey: VaultKey, to agreementPublicKey: Data, vaultId: UUID, epoch: UInt64, memberId: String) throws -> Data {
        let recipient = try P256.KeyAgreement.PublicKey(x963Representation: agreementPublicKey)
        var sender = try HPKE.Sender(recipientKey: recipient, ciphersuite: .P256_SHA256_AES_GCM_256,
                                     info: info(vaultId: vaultId, epoch: epoch, memberId: memberId))
        let ciphertext = try sender.seal(vaultKey.bytes, authenticating: aad(vaultId: vaultId, epoch: epoch, memberId: memberId))
        let envelope = Data([VaultFormat.version, VaultFormat.suiteP256SHA256AES256GCM]) + sender.encapsulatedKey + ciphertext
        guard envelope.count == VaultFormat.envelopeLength else { throw VaultError.malformed("envelope length") }
        return envelope
    }

    public static func open(_ envelope: Data, with key: any VaultAgreementKey, vaultId: UUID, epoch: UInt64, memberId: String) throws -> VaultKey {
        let envelope = Data(envelope)
        guard envelope.count == VaultFormat.envelopeLength else { throw VaultError.malformed("envelope length") }
        guard envelope[0] == VaultFormat.version else { throw VaultError.unsupportedVersion(Int(envelope[0])) }
        guard envelope[1] == VaultFormat.suiteP256SHA256AES256GCM else { throw VaultError.malformed("suite") }
        let encapsulated = envelope.dropFirst(2).prefix(65)
        let ciphertext = envelope.dropFirst(67)
        do {
            var recipient = try key.recipient(info: info(vaultId: vaultId, epoch: epoch, memberId: memberId), encapsulatedKey: Data(encapsulated))
            return try VaultKey(rawBytes: try recipient.open(ciphertext, authenticating: aad(vaultId: vaultId, epoch: epoch, memberId: memberId)))
        } catch let error as VaultError {
            throw error
        } catch {
            throw VaultError.authenticationFailed
        }
    }

    public static func hash(_ envelope: Data) -> Data { Data(SHA256.hash(data: envelope)) }
}

/// The vault **recovery key**: 256 random bits shown once, written as `VRK1-` plus 11 groups of five Crockford base32 characters (the last
/// two bytes are a checksum, so a typo is caught before any cryptography). It is distinct from the account recovery codes and unrelated to
/// identity proofing: nothing but this string (or an enrolled device's approval) restores the vault.
///
/// It derives a *recovery member*: a P-256 signing key and a P-256 agreement key (HKDF with distinct labels, deterministic). The manifest
/// lists the member's public keys and the vault key is HPKE-sealed to the agreement key like for any device, so any device can re-seal to
/// the recovery member at a key rotation without ever holding the recovery key.
public struct RecoveryKey: Sendable, Equatable {
    let bytes: Data
    public static let prefix = "VRK1"

    public static func generate() -> RecoveryKey { RecoveryKey(bytes: SecureToken.randomBytes(32)) }
    init(bytes: Data) { self.bytes = bytes }

    static func checksum(_ bytes: Data) -> Data {
        Data(SHA256.hash(data: Data("viadere.vault.v1.recovery-checksum".utf8) + bytes).prefix(2))
    }

    public var displayString: String { Self.prefix + "-" + CrockfordBase32.grouped(CrockfordBase32.encode(bytes + Self.checksum(bytes)), size: 5) }

    public init(parsing text: String) throws {
        let stripped = CrockfordBase32.stripped(text).uppercased()
        guard stripped.hasPrefix(Self.prefix), let decoded = CrockfordBase32.decode(String(stripped.dropFirst(Self.prefix.count)), byteCount: 34) else {
            throw VaultError.invalidRecoveryKey
        }
        let key = decoded.prefix(32)
        guard ConstantTime.equals(decoded.suffix(2), Self.checksum(Data(key))) else { throw VaultError.invalidRecoveryKey }
        bytes = Data(key)
    }

    private func derivedPrivateScalar(label: String, vaultId: UUID) -> Data {
        // A P-256 scalar must be in 1...n-1; the chance a random 256-bit value is not is about 2^-32. Count up until one is valid.
        let input = SymmetricKey(data: bytes)
        for counter in 0..<UInt8.max {
            let candidate = VaultKDF.derive(input, salt: VaultBytes.uuid(vaultId), label: label, extra: Data([counter]))
            if (try? P256.Signing.PrivateKey(rawRepresentation: candidate)) != nil { return candidate }
        }
        preconditionFailure("unreachable: no valid scalar in 255 HKDF outputs")
    }

    /// The tag a device computes while it holds this key (when it installs the recovery member) so that a later holder of the key can
    /// authenticate the installing device's signing key.
    func binding(vaultId: UUID, memberId: String, installerKey: Data) -> Data {
        let key = VaultKDF.deriveKey(SymmetricKey(data: bytes), salt: VaultBytes.uuid(vaultId), label: VaultFormat.Label.recoveryBinding)
        let message = VaultAAD.make("recovery-binding", [VaultBytes.uuid(vaultId), Data(memberId.utf8), installerKey])
        return Data(HMAC<SHA256>.authenticationCode(for: message, using: key))
    }

    /// The recovery member's keys for `vaultId`.
    public func identity(vaultId: UUID) throws -> VaultDeviceIdentity {
        let signing = derivedPrivateScalar(label: VaultFormat.Label.recoverySigning, vaultId: vaultId)
        let agreement = derivedPrivateScalar(label: VaultFormat.Label.recoveryAgreement, vaultId: vaultId)
        return VaultDeviceIdentity(signingKey: try SoftwareP256SigningKey(rawRepresentation: signing),
                                   agreementKey: try SoftwareVaultAgreementKey(rawRepresentation: agreement))
    }
}

/// The one-time secret shared out of band (QR code or typed) from the approving device to the new device: 128 random bits plus a checksum
/// byte, written as seven groups of four Crockford characters. It keys a channel through the (untrusted) server in both directions, so the
/// server learns neither side's keys and cannot substitute its own. It is useless once the join ends.
public struct PairingSecret: Sendable, Equatable {
    let bytes: Data

    public static func generate() -> PairingSecret { PairingSecret(bytes: SecureToken.randomBytes(16)) }
    init(bytes: Data) { self.bytes = bytes }

    private static func checksum(_ bytes: Data) -> UInt8 {
        Array(SHA256.hash(data: Data("viadere.vault.v1.pairing-checksum".utf8) + bytes))[0]
    }

    public var displayString: String { CrockfordBase32.grouped(CrockfordBase32.encode(bytes + Data([Self.checksum(bytes)])), size: 4) }

    public init(parsing text: String) throws {
        guard let decoded = CrockfordBase32.decode(CrockfordBase32.stripped(text), byteCount: 17), Self.checksum(decoded.prefix(16)) == decoded[16] else {
            throw VaultError.invalidPairingCode
        }
        bytes = Data(decoded.prefix(16))
    }

    private var input: SymmetricKey { SymmetricKey(data: bytes) }

    /// The public identifier of the join on the server (derived, so the server cannot link it to the secret).
    public var joinId: String { Base64URL.encode(VaultKDF.derive(input, salt: Data(), label: VaultFormat.Label.joinIdentifier).prefix(16)) }
    var requestKey: SymmetricKey { VaultKDF.deriveKey(input, salt: Data(), label: VaultFormat.Label.joinRequest) }
    var approvalKey: SymmetricKey { VaultKDF.deriveKey(input, salt: Data(), label: VaultFormat.Label.joinApproval) }
}

/// What a new device sends to the approving device, sealed under the pairing secret.
public struct JoinRequest: Sendable, Equatable {
    public var signingKey: Data
    public var agreementKey: Data
    public var label: String

    public init(signingKey: Data, agreementKey: Data, label: String) {
        self.signingKey = signingKey
        self.agreementKey = agreementKey
        self.label = label
    }

    public static func make(for identity: VaultDeviceIdentity, label: String) -> JoinRequest {
        JoinRequest(signingKey: identity.signingPublicKey, agreementKey: identity.agreementPublicKey, label: label)
    }

    public func sealed(with secret: PairingSecret) throws -> Data {
        let plain = CBOR.encode(.textMap([("sign", .bytes(signingKey)), ("agree", .bytes(agreementKey)), ("label", .text(label))]), deterministic: true)
        return try VaultSeal.seal(plain, key: secret.requestKey, aad: VaultAAD.make("join-request", [Data(secret.joinId.utf8)]))
    }

    public static func open(_ sealed: Data, with secret: PairingSecret) throws -> JoinRequest {
        let plain = try VaultSeal.open(sealed, key: secret.requestKey, aad: VaultAAD.make("join-request", [Data(secret.joinId.utf8)]))
        guard let map = try? CBOR.decode(plain, limits: .init(maxDepth: 2, maxBytes: 1024, maxItems: 8)), let sign = map["sign"]?.byteString,
              let agree = map["agree"]?.byteString, let label = map["label"]?.textString, sign.count == 65, agree.count == 65,
              (try? P256.Signing.PublicKey(x963Representation: sign)) != nil, (try? P256.KeyAgreement.PublicKey(x963Representation: agree)) != nil,
              label.utf8.count <= VaultFormat.maxLabelBytes, !DisplayTextSanitizer.containsDisallowedScalars(label) else {
            throw VaultError.malformed("join request")
        }
        return JoinRequest(signingKey: sign, agreementKey: agree, label: label)
    }
}

/// What the approving device sends back, sealed under the pairing secret: who approved (so the new device can pin the signer) and the hash of
/// the manifest that adds it.
struct JoinApproval: Equatable {
    var vaultId: UUID
    var approverSigningKey: Data
    var manifestHash: Data

    func sealed(with secret: PairingSecret) throws -> Data {
        let plain = CBOR.encode(.textMap([("vault", .bytes(VaultBytes.uuid(vaultId))), ("approver", .bytes(approverSigningKey)), ("hash", .bytes(manifestHash))]),
                                deterministic: true)
        return try VaultSeal.seal(plain, key: secret.approvalKey, aad: VaultAAD.make("join-approval", [Data(secret.joinId.utf8)]))
    }

    static func open(_ sealed: Data, with secret: PairingSecret) throws -> JoinApproval {
        let plain = try VaultSeal.open(sealed, key: secret.approvalKey, aad: VaultAAD.make("join-approval", [Data(secret.joinId.utf8)]))
        guard let map = try? CBOR.decode(plain, limits: .init(maxDepth: 2, maxBytes: 1024, maxItems: 8)), let vault = map["vault"]?.byteString.flatMap(VaultBytes.uuid(from:)),
              let approver = map["approver"]?.byteString, approver.count == 65, let hash = map["hash"]?.byteString, hash.count == 32 else {
            throw VaultError.malformed("join approval")
        }
        return JoinApproval(vaultId: vault, approverSigningKey: approver, manifestHash: hash)
    }
}
