@preconcurrency import Crypto
import Foundation
import ViadereCore

/// The HPKE envelope Wallet's identity presentment returns (Apple, "Verifying Wallet identity requests"):
///
/// ```
/// HPKEEnvelope = { "algorithm": "APPLE-HPKE-v1", "params": { "mode": 0, "pkEm": bstr, "pkRHash": bstr, "infoHash": bstr }, "data": bstr }
/// ```
///
/// Suite: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM (RFC 9180 base mode). `info` is the **session transcript**, which is not
/// sent: both sides build it and must agree, so a response only opens for the request (nonce, merchant, team, key) it was made for.
struct AppleIdentityEnvelope: Sendable {
    static let algorithm = "APPLE-HPKE-v1"
    static let handoverVersion = "AppleIdentityPresentment_1.0"
    static let maxBytes = 128 * 1024
    static let ciphersuite = HPKE.Ciphersuite(kem: .P256_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_128)

    var encapsulatedKey: Data
    var recipientKeyHash: Data
    var infoHash: Data
    var ciphertext: Data

    /// Strict parse: exactly these members, exact types, no extras.
    init(parsing data: Data) throws {
        guard data.count <= Self.maxBytes, let root = try? CBOR.decode(data, limits: CBOR.Limits(maxDepth: 4, maxBytes: Self.maxBytes, maxItems: 8)),
              case .map(let top) = root, top.count == 3, root["algorithm"]?.textString == Self.algorithm,
              let params = root["params"], case .map(let entries) = params, entries.count == 4, params["mode"]?.unsignedValue == 0,
              let pkEm = params["pkEm"]?.byteString, let pkRHash = params["pkRHash"]?.byteString, let infoHash = params["infoHash"]?.byteString,
              let ciphertext = root["data"]?.byteString else { throw MDocFailure.envelopeMalformed }
        // An uncompressed P-256 point; hashes are SHA-256; the AES-GCM tag alone is 16 bytes.
        guard pkEm.count == 65, pkEm.first == 0x04, pkRHash.count == 32, infoHash.count == 32, ciphertext.count > 16 else { throw MDocFailure.envelopeMalformed }
        encapsulatedKey = pkEm
        recipientKeyHash = pkRHash
        self.infoHash = infoHash
        self.ciphertext = ciphertext
    }

    /// The `SessionTranscript` Apple defines: `[nil, nil, AppleHandover]` with
    /// `AppleHandover = ["AppleIdentityPresentment_1.0", nonce (bstr), merchantId (tstr), teamID (tstr), pkRHash (bstr)]`.
    static func sessionTranscript(nonce: Data, merchantIdentifier: String, teamIdentifier: String, recipientKeyHash: Data) -> Data {
        CBOR.encode(.array([.null, .null, .array([.text(handoverVersion), .bytes(nonce), .text(merchantIdentifier), .text(teamIdentifier), .bytes(recipientKeyHash)])]))
    }

    /// The hashes of a recipient public key that `pkRHash` may carry. Apple's page says "a SHA256 hash of the recipient public key"
    /// without naming the encoding, so the uncompressed X9.63 point and the DER `SubjectPublicKeyInfo` are both accepted; the server
    /// computes both from its **own** key, so this widens nothing for an attacker. The envelope's own value is used in the transcript.
    static func recipientKeyHashes(_ key: P256.KeyAgreement.PublicKey) -> [Data] {
        [Data(SHA256.hash(data: key.x963Representation)), Data(SHA256.hash(data: key.derRepresentation))]
    }

    struct Opened {
        var plaintext: Data
        var sessionTranscript: Data
    }

    /// Opens the envelope with one of `keys` (the current key and, during a rotation, the previous one). Checks, in this order:
    /// `pkRHash` names one of our keys, `SHA256(transcript) == infoHash`, then the HPKE decryption itself (which fails if `info` or the
    /// key differ). Any failure is a distinct internal reason and the same refusal to the caller.
    func open(keys: [P256.KeyAgreement.PrivateKey], nonce: Data, merchantIdentifier: String, teamIdentifier: String) throws -> Opened {
        guard let key = keys.first(where: { candidate in
            Self.recipientKeyHashes(candidate.publicKey).contains { ConstantTime.equals($0, recipientKeyHash) }
        }) else { throw MDocFailure.wrongRecipientKey }
        let transcript = Self.sessionTranscript(nonce: nonce, merchantIdentifier: merchantIdentifier, teamIdentifier: teamIdentifier, recipientKeyHash: recipientKeyHash)
        guard ConstantTime.equals(Data(SHA256.hash(data: transcript)), infoHash) else { throw MDocFailure.transcriptMismatch }
        do {
            var recipient = try HPKE.Recipient(privateKey: key, ciphersuite: Self.ciphersuite, info: transcript, encapsulatedKey: encapsulatedKey)
            let plaintext = try recipient.open(ciphertext, authenticating: Data())
            return Opened(plaintext: plaintext, sessionTranscript: transcript)
        } catch {
            throw MDocFailure.decryptionFailed
        }
    }
}

/// The merchant encryption key(s) for Wallet presentments (the private key of the "identity encryption certificate" created in the
/// Apple developer portal). The server only ever holds it in memory, loaded through this protocol.
///
/// Production wraps the key with the platform KMS (ADR-03): `WrappedWalletEncryptionKeys` takes the wrapped bytes from configuration and a
/// `WalletKeyUnwrapper` that calls the KMS decrypt operation (WP8 provides the Google Cloud KMS implementation). `LocalWalletEncryptionKeys`
/// reads PEM files and is for development and tests.
protocol WalletEncryptionKeySource: Sendable {
    /// The current key first, then any previous key still needed for responses to requests made before a rotation.
    func keys() async throws -> [P256.KeyAgreement.PrivateKey]
}

protocol WalletKeyUnwrapper: Sendable {
    /// Returns the PKCS#8 DER (or SEC1 DER) bytes of the private key.
    func unwrap(_ wrapped: Data) async throws -> Data
}

struct LocalWalletEncryptionKeys: WalletEncryptionKeySource {
    var keys: [P256.KeyAgreement.PrivateKey]
    init(_ keys: [P256.KeyAgreement.PrivateKey]) { self.keys = keys }

    /// Reads PEM files (`PRIVATE KEY` PKCS#8 or `EC PRIVATE KEY` SEC1). Paths come from configuration; a file with the wrong mode is refused.
    init(paths: [String]) throws {
        keys = try paths.map { path in
            guard let text = try? String(contentsOfFile: path, encoding: .utf8), text.utf8.count <= 4096,
                  let key = try? P256.KeyAgreement.PrivateKey(pemRepresentation: text) else { throw WalletConfigurationError.unreadableKey }
            return key
        }
    }

    func keys() async throws -> [P256.KeyAgreement.PrivateKey] { keys }
}

struct WrappedWalletEncryptionKeys: WalletEncryptionKeySource {
    var wrapped: [Data]
    var unwrapper: any WalletKeyUnwrapper

    func keys() async throws -> [P256.KeyAgreement.PrivateKey] {
        var out: [P256.KeyAgreement.PrivateKey] = []
        for blob in wrapped {
            let der = try await unwrapper.unwrap(blob)
            guard let key = try? P256.KeyAgreement.PrivateKey(derRepresentation: der) else { throw WalletConfigurationError.unreadableKey }
            out.append(key)
        }
        return out
    }
}

enum WalletConfigurationError: Error, Equatable {
    case unreadableKey
    case noKey
    case noTrustAnchors
}
