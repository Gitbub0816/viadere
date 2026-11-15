@preconcurrency import Crypto
import Foundation

// The production seal construction of ADR-0034 §9 (condition C-16): compact JWE (RFC 7516) with `alg: RSA-OAEP-256` and `enc: A256GCM` (RFC 7518
// §4.3, §5.3) to a non-exportable `recovery-seal-rsa` key whose private half never leaves the HSM. Core holds only the format: the strict parse, the
// header and AAD rules, the content encryption and the digest. The RSA step is the caller's: the device encrypts the content key with the pinned
// public key (iOS `SecKeyAlgorithm.rsaEncryptionOAEPSHA256`; Android `OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, ...)`), and the
// authority asks Key Vault to `decrypt` it, at most once per challenge. The plaintext is the ADR-0034 §2 object, unchanged.

public enum RecoverySealJWE {
    public static let algorithm = "RSA-OAEP-256"
    public static let encryption = "A256GCM"
    /// RSA 3072: the encrypted content key is exactly 384 bytes.
    public static let encryptedKeyBytes = 384
    public static let maxBytes = 4096
    static let headerMembers: Set<String> = ["alg", "enc", "kid", "typ", "env", "ach", "nonce"]

    /// `viadere-recovery-set+jwe` / `viadere-recovery-start+jwe`: the purpose separation that `info` gives in the HPKE construction.
    public static func type(_ purpose: RecoverySealPurpose) -> String {
        purpose == .codesSet ? "viadere-recovery-set+jwe" : "viadere-recovery-start+jwe"
    }

    /// One parsed compact JWE. `protected` is the base64url header exactly as received: its ASCII is the AES-GCM AAD (RFC 7516 §5.1 step 14).
    public struct Envelope: Sendable, Hashable {
        public let compact: String
        public let protected: String
        public let kid: String
        public let type: String
        public let environment: AuthorityEnvironment
        public let challengeId: String
        public let nonce: String
        public let encryptedKey: Data
        public let iv: Data
        public let ciphertext: Data
        public let tag: Data

        /// `base64url(SHA-256(ASCII of the compact serialization))`: what the authorizing device signature or PoP commits to (§9.2).
        public var digest: String { RecoverySealJWE.digest(compact) }

        public var purpose: RecoverySealPurpose? { RecoverySealPurpose.allCases.first { RecoverySealJWE.type($0) == type } }
    }

    public static func digest(_ compact: String) -> String { Base64URL.encode(Data(SHA256.hash(data: Data(compact.utf8)))) }

    /// The protected header, canonical JSON, exactly the seven members.
    public static func header(kid: String, purpose: RecoverySealPurpose, environment: AuthorityEnvironment, challengeId: String, nonce: String) -> JSONValue {
        .object(["alg": .string(algorithm), "enc": .string(encryption), "kid": .string(kid), "typ": .string(type(purpose)), "env": .string(environment.rawValue),
                 "ach": .string(challengeId), "nonce": .string(nonce)])
    }

    /// Device side. `encryptKey` is RSA-OAEP-256 (SHA-256 and MGF1-SHA-256) of the 32-byte content key under the pinned `recovery-seal-rsa` public key.
    /// The content key and the IV come from the CSPRNG; the content key is wiped after use.
    public static func seal(_ plaintext: JSONValue, kid: String, purpose: RecoverySealPurpose, environment: AuthorityEnvironment, challengeId: String,
                            nonce: String, encryptKey: (Data) throws -> Data) throws -> Envelope {
        let protected = Base64URL.encode(try CanonicalJSON.serialize(header(kid: kid, purpose: purpose, environment: environment, challengeId: challengeId, nonce: nonce)))
        var cek = SecureToken.randomBytes(32)
        defer { cek.resetBytes(in: 0..<cek.count) }
        let iv = SecureToken.randomBytes(12)
        let box = try AES.GCM.seal(try CanonicalJSON.serialize(plaintext), using: SymmetricKey(data: cek), nonce: try AES.GCM.Nonce(data: iv),
                                   authenticating: Data(protected.utf8))
        let encryptedKey = try encryptKey(cek)
        let compact = [protected, Base64URL.encode(encryptedKey), Base64URL.encode(iv), Base64URL.encode(box.ciphertext), Base64URL.encode(box.tag)].joined(separator: ".")
        return try parse(compact)
    }

    /// Strict compact parse (§9.3): at most 4096 bytes, five parts of strict unpadded base64url, encrypted key exactly 384 bytes, IV 12, tag 16,
    /// ciphertext 17-3000 bytes; the header is canonical JSON with exactly the seven members (no `zip`, `jku`, `jwk`, `x5u`, `crit` or anything else),
    /// `alg` `RSA-OAEP-256`, `enc` `A256GCM`, one of the two types, a thumbprint `kid`, a known `env`, a challenge id and a 256-bit nonce.
    public static func parse(_ compact: String) throws -> Envelope {
        guard compact.utf8.count <= maxBytes, compact.utf8.allSatisfy({ $0 < 0x80 }) else { throw RecoverySealError.malformed("size") }
        let parts = compact.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 5 else { throw RecoverySealError.malformed("parts") }
        guard let headerBytes = AuthorityKeyLogFormat.strictBytes(parts[0], maxBytes: 1024),
              let encryptedKey = AuthorityKeyLogFormat.strictBytes(parts[1], minBytes: encryptedKeyBytes, maxBytes: encryptedKeyBytes),
              let iv = AuthorityKeyLogFormat.strictBytes(parts[2], minBytes: 12, maxBytes: 12),
              let ciphertext = AuthorityKeyLogFormat.strictBytes(parts[3], minBytes: 17, maxBytes: 3000),
              let tag = AuthorityKeyLogFormat.strictBytes(parts[4], minBytes: 16, maxBytes: 16) else { throw RecoverySealError.malformed("encoding") }
        guard case .object(let h)? = try? JSONDecoder().decode(JSONValue.self, from: headerBytes), (try? CanonicalJSON.serialize(.object(h))) == headerBytes,
              Set(h.keys) == headerMembers else { throw RecoverySealError.malformed("header") }
        guard h["alg"]?.stringValue == algorithm, h["enc"]?.stringValue == encryption,
              let type = h["typ"]?.stringValue, RecoverySealPurpose.allCases.contains(where: { Self.type($0) == type }),
              let kid = h["kid"]?.stringValue, Base64URL.isValid(kid, minLength: 43, maxLength: 43),
              let environment = h["env"]?.stringValue.flatMap(AuthorityEnvironment.init(rawValue:)),
              let ach = h["ach"]?.stringValue, AuthorityChallengeID.isValid(ach), let nonce = h["nonce"]?.stringValue, AuthorityNonce.isValid(nonce) else {
            throw RecoverySealError.malformed("header")
        }
        return Envelope(compact: compact, protected: parts[0], kid: kid, type: type, environment: environment, challengeId: ach, nonce: nonce,
                        encryptedKey: encryptedKey, iv: iv, ciphertext: ciphertext, tag: tag)
    }

    /// The header checks the authority runs **before** any Key Vault call (§9.3): the active seal key, the type of the challenge's purpose, and the
    /// environment, challenge id and nonce of the pending challenge named in the request (constant time).
    public static func check(_ envelope: Envelope, kid: String, purpose: RecoverySealPurpose, environment: AuthorityEnvironment, challengeId: String,
                             nonce: String) throws {
        guard ConstantTime.equals(envelope.kid, kid) else { throw RecoverySealError.wrongKey }
        guard envelope.type == type(purpose), envelope.environment == environment, ConstantTime.equals(envelope.challengeId, challengeId),
              ConstantTime.equals(envelope.nonce, nonce) else { throw RecoverySealError.malformed("binding") }
    }

    /// Opens with the content key the HSM returned. A content key that is not 32 bytes, an AES-GCM failure and a non-canonical plaintext are all
    /// `openFailed` or `plaintext`, never a padding distinction (the RSA step happened in the HSM, and its failure is reported the same way).
    public static func open(_ envelope: Envelope, contentKey: Data) throws -> [String: JSONValue] {
        guard contentKey.count == 32 else { throw RecoverySealError.openFailed }
        let bytes: Data
        do {
            let box = try AES.GCM.SealedBox(nonce: try AES.GCM.Nonce(data: envelope.iv), ciphertext: envelope.ciphertext, tag: envelope.tag)
            bytes = try AES.GCM.open(box, using: SymmetricKey(data: contentKey), authenticating: Data(envelope.protected.utf8))
        } catch { throw RecoverySealError.openFailed }
        guard case .object(let o)? = try? JSONDecoder().decode(JSONValue.self, from: bytes), (try? CanonicalJSON.serialize(.object(o))) == bytes else {
            throw RecoverySealError.plaintext("encoding")
        }
        return o
    }
}
