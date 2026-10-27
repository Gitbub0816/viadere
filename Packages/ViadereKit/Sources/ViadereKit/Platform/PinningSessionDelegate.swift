import Foundation
#if canImport(Security)
import Crypto
import Security

/// Pins the server's public keys (SPKI SHA-256) on top of the system's normal trust evaluation.
///
/// Flow: (1) the system must first consider the chain valid; (2) at least one certificate in the chain must
/// match a configured pin. A mismatch cancels the connection. See `PinningConfiguration` for how to
/// generate pins and the release TODO.
public final class PinningSessionDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let pinning: PinningConfiguration
    private let failClosed: Bool
    private static let log = ViadereLog.security

    public init(pinning: PinningConfiguration, failClosed: Bool) {
        self.pinning = pinning
        self.failClosed = failClosed
    }

    public func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                           completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        let host = challenge.protectionSpace.host
        guard pinning.applies(to: host) else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        // 1. Ordinary system evaluation (hostname, expiry, anchors).
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else {
            Self.log.error("tls.untrusted")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        // 2. Pin check.
        let hashes = Self.spkiHashes(of: trust)
        switch PinEvaluator.evaluate(host: host, chainSPKIHashes: hashes, configuration: pinning, failClosed: failClosed) {
        case .allow:
            completionHandler(.useCredential, URLCredential(trust: trust))
        case .useDefaultEvaluation:
            completionHandler(.performDefaultHandling, nil)
        case .deny:
            Self.log.error("tls.pin.mismatch")
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    // MARK: SPKI hashing

    /// ASN.1 SubjectPublicKeyInfo headers: `SecKeyCopyExternalRepresentation` returns the bare key, so the
    /// algorithm header is prepended to hash the full SPKI structure (same value `openssl` produces).
    private static let headers: [String: Data] = [
        "ec256": Data([0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08,
                       0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00]),
        "ec384": Data([0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05,
                       0x2B, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00]),
        "rsa2048": Data([0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
                         0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00]),
        "rsa4096": Data([0x30, 0x82, 0x02, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
                         0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0F, 0x00]),
    ]

    static func spkiHashes(of trust: SecTrust) -> [String] {
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate] else { return [] }
        return chain.compactMap { certificate in
            guard let key = SecCertificateCopyKey(certificate),
                  let raw = SecKeyCopyExternalRepresentation(key, nil) as Data?,
                  let attributes = SecKeyCopyAttributes(key) as? [String: Any],
                  let type = attributes[kSecAttrKeyType as String] as? String,
                  let bits = attributes[kSecAttrKeySizeInBits as String] as? Int else { return nil }
            let header: Data?
            if type == (kSecAttrKeyTypeECSECPrimeRandom as String) {
                header = bits == 256 ? headers["ec256"] : (bits == 384 ? headers["ec384"] : nil)
            } else if type == (kSecAttrKeyTypeRSA as String) {
                header = bits == 2048 ? headers["rsa2048"] : (bits == 4096 ? headers["rsa4096"] : nil)
            } else {
                header = nil
            }
            guard let header else { return nil }
            return Data(SHA256.hash(data: header + raw)).base64EncodedString()
        }
    }
}
#endif
