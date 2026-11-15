@preconcurrency import Crypto
import Foundation
import ViadereCore

/// The Play Integrity nonce of an enrollment (SECURITY.md §2.114): base64url (no padding) of the **same** client-data hash App Attest signs
/// (`AppAttestBinding.clientDataHash`: the reserved account, the single-use challenge and the exact key list). A verdict made for another
/// ceremony, account or key list never matches.
public enum PlayIntegrityBinding {
    public static func nonce(consumerId: ConsumerID, challenge: String, keys: [DeviceKeyRegistration]) -> String {
        Base64URL.encode(AppAttestBinding.clientDataHash(consumerId: consumerId, challenge: challenge, keys: keys))
    }
}

/// Local verification of a **classic** Play Integrity token with the owner's response keys (Play Console, "manage your own response encryption"):
/// a compact JWE (`alg` `A256KW`, `enc` `A256GCM`, nothing else) whose plaintext is a compact JWS (`ES256`) over the verdict. Every check fails
/// closed, in this order: shape, decryption, signature, the request (package, nonce, freshness), the app (Play-recognized, package, signing
/// certificate) and the device (`MEETS_DEVICE_INTEGRITY` or `MEETS_STRONG_INTEGRITY`).
public struct PlayIntegrityVerifier: Sendable {
    public enum Failure: String, Error, Sendable {
        case malformed = "play_integrity_malformed"
        case decryption = "play_integrity_decryption"
        case signature = "play_integrity_signature"
        case package = "play_integrity_package"
        case nonce = "play_integrity_nonce"
        case stale = "play_integrity_stale"
        case app = "play_integrity_app_not_recognized"
        case certificate = "play_integrity_certificate"
        case device = "play_integrity_device"
    }

    /// A verdict older than this (by its server timestamp) is refused; one up to `futureSkew` ahead of this server's clock is tolerated.
    public static let maxAge: TimeInterval = 300
    public static let futureSkew: TimeInterval = 60
    static let maxTokenLength = 16 * 1024

    let keys: PlayIntegrityKeys
    let packageName: String
    /// base64url (no padding) of each allowed signing certificate's SHA-256: the form of `appIntegrity.certificateSha256Digest`.
    let certificateDigests: Set<String>
    let clock: any ServerClock

    public init(keys: PlayIntegrityKeys, packageName: String, certificateFingerprints: [Data], clock: any ServerClock) {
        self.keys = keys
        self.packageName = packageName
        certificateDigests = Set(certificateFingerprints.map { Base64URL.encode($0) })
        self.clock = clock
    }

    public func verify(token: String, nonce expected: String) throws {
        let payload = try decryptAndVerify(token)
        guard let root = try? JSONSerialization.jsonObject(with: payload) as? [String: Any],
              let request = root["requestDetails"] as? [String: Any] else { throw Failure.malformed }
        guard request["requestPackageName"] as? String == packageName else { throw Failure.package }
        guard let nonce = request["nonce"] as? String, ConstantTime.equals(Data(Self.unpadded(nonce).utf8), Data(expected.utf8)) else { throw Failure.nonce }
        let millis: Double? = (request["timestampMillis"] as? String).flatMap(Double.init) ?? (request["timestampMillis"] as? NSNumber)?.doubleValue
        guard let millis else { throw Failure.malformed }
        let issued = Date(timeIntervalSince1970: millis / 1000)
        let now = clock.now()
        guard now.timeIntervalSince(issued) <= Self.maxAge, issued.timeIntervalSince(now) <= Self.futureSkew else { throw Failure.stale }
        guard let app = root["appIntegrity"] as? [String: Any], app["appRecognitionVerdict"] as? String == "PLAY_RECOGNIZED",
              app["packageName"] as? String == packageName else { throw Failure.app }
        let digests = (app["certificateSha256Digest"] as? [String] ?? []).map(Self.unpadded)
        guard !digests.isEmpty, digests.allSatisfy({ certificateDigests.contains($0) }) else { throw Failure.certificate }
        let device = (root["deviceIntegrity"] as? [String: Any])?["deviceRecognitionVerdict"] as? [String] ?? []
        guard device.contains("MEETS_DEVICE_INTEGRITY") || device.contains("MEETS_STRONG_INTEGRITY") else { throw Failure.device }
    }

    /// The JWS payload bytes, after decrypting the JWE and verifying the JWS signature.
    func decryptAndVerify(_ token: String) throws -> Data {
        guard token.count <= Self.maxTokenLength else { throw Failure.malformed }
        let parts = token.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 5, let headerData = Base64URL.decode(parts[0]),
              let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any],
              header["alg"] as? String == "A256KW", header["enc"] as? String == "A256GCM", header["zip"] == nil, header["crit"] == nil,
              let wrapped = Base64URL.decode(parts[1]), let iv = Base64URL.decode(parts[2]), iv.count == 12,
              let ciphertext = Base64URL.decode(parts[3]), let tag = Base64URL.decode(parts[4]), tag.count == 16 else { throw Failure.malformed }
        let plaintext: Data
        do {
            let cek = try AES.KeyWrap.unwrap(wrapped, using: keys.decryptionKey)
            guard cek.bitCount == 256 else { throw Failure.decryption }
            let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: iv), ciphertext: ciphertext, tag: tag)
            plaintext = try AES.GCM.open(box, using: cek, authenticating: Data(parts[0].utf8))
        } catch {
            throw Failure.decryption
        }
        let jws = String(decoding: plaintext, as: UTF8.self).split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard jws.count == 3, let jwsHeaderData = Base64URL.decode(jws[0]),
              let jwsHeader = try? JSONSerialization.jsonObject(with: jwsHeaderData) as? [String: Any], jwsHeader["alg"] as? String == "ES256",
              jwsHeader["crit"] == nil, let payload = Base64URL.decode(jws[1]), let signatureBytes = Base64URL.decode(jws[2]) else { throw Failure.malformed }
        guard let signature = try? P256.Signing.ECDSASignature(rawRepresentation: signatureBytes),
              keys.verificationKey.isValidSignature(signature, for: Data("\(jws[0]).\(jws[1])".utf8)) else { throw Failure.signature }
        return payload
    }

    static func unpadded(_ value: String) -> String {
        var out = Substring(value)
        while out.hasSuffix("=") { out = out.dropLast() }
        return String(out)
    }
}
