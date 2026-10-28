import Crypto
import Foundation

/// Signatures on webhooks Viadere sends to businesses.
///
/// Header: `Viadere-Signature: t={unix seconds},v1={hex HMAC-SHA256(secret, "{t}.{raw body}")}`.
/// During secret rotation several `v1=` entries may appear; any match is accepted.
/// Verification is constant-time and enforces a timestamp tolerance (default 300 s).
public enum WebhookSignature {
    public static let defaultTolerance: TimeInterval = 300
    /// Prefix of generated webhook secrets.
    public static let secretPrefix = "whsec_"

    /// Verification failures.
    public enum Error: Swift.Error, Sendable, Equatable {
        case malformedHeader
        case timestampOutsideTolerance
        case noMatchingSignature
    }

    /// Generates a webhook secret: `whsec_` + base64url(32 random bytes).
    public static func generateSecret() -> String { secretPrefix + SecureToken.generate(byteCount: 32) }

    /// HMAC key bytes for a secret string (its UTF-8 bytes, prefix included).
    public static func key(for secret: String) -> SymmetricKey { SymmetricKey(data: Data(secret.utf8)) }

    /// Computes the hex `v1` value.
    public static func v1(secret: String, timestamp: Int64, body: Data) -> String {
        let message = Data("\(timestamp).".utf8) + body
        return Hex.encode(HMAC<SHA256>.authenticationCode(for: message, using: key(for: secret)))
    }

    /// The answer to the ownership challenge (`webhook.verification`): `{"challenge_response": "<this value>"}`. Hex HMAC-SHA256 keyed by the
    /// endpoint's signing secret over `viadere.webhook.verification.v1:` + the challenge. Only someone who holds the secret can compute it, so an
    /// endpoint that merely reflects the request (an echo server, a mirror) cannot prove it is the registrant's.
    public static func verificationResponse(secret: String, challenge: String) -> String {
        Hex.encode(HMAC<SHA256>.authenticationCode(for: Data((verificationContext + challenge).utf8), using: key(for: secret)))
    }

    static let verificationContext = "viadere.webhook.verification.v1:"

    /// Builds the header value. Pass several secrets during rotation.
    public static func header(secrets: [String], body: Data, now: Date) -> String {
        let t = ViadereDate.unixSeconds(now)
        return (["t=\(t)"] + secrets.map { "v1=" + v1(secret: $0, timestamp: t, body: body) }).joined(separator: ",")
    }

    /// Builds the header value for a single secret.
    public static func header(secret: String, body: Data, now: Date) -> String {
        header(secrets: [secret], body: body, now: now)
    }

    /// Verifies a header against any of `secrets`. Returns the signed timestamp.
    @discardableResult
    public static func verify(header: String, body: Data, secrets: [String], now: Date,
                              tolerance: TimeInterval = defaultTolerance) throws -> Int64 {
        guard header.count <= 4096 else { throw Error.malformedHeader }
        var timestamp: Int64?
        var candidates: [Data] = []
        for part in header.split(separator: ",") {
            let pair = part.trimmingCharacters(in: .whitespaces).split(separator: "=", maxSplits: 1)
            guard pair.count == 2 else { throw Error.malformedHeader }
            switch pair[0] {
            case "t":
                guard timestamp == nil, pair[1].count <= 12, pair[1].allSatisfy({ $0.isASCII && $0.isNumber }),
                      let t = Int64(pair[1]) else { throw Error.malformedHeader }
                timestamp = t
            case "v1":
                guard pair[1].count == 64, let mac = Hex.decode(String(pair[1])) else { throw Error.malformedHeader }
                candidates.append(mac)
            default:
                continue // Unknown schemes (future versions) are ignored.
            }
        }
        guard let t = timestamp, !candidates.isEmpty else { throw Error.malformedHeader }
        guard abs(now.timeIntervalSince1970 - TimeInterval(t)) <= tolerance else { throw Error.timestampOutsideTolerance }
        let message = Data("\(t).".utf8) + body
        var matched = false
        for secret in secrets {
            let key = key(for: secret)
            for candidate in candidates where HMAC<SHA256>.isValidAuthenticationCode(candidate, authenticating: message, using: key) {
                matched = true
            }
        }
        guard matched else { throw Error.noMatchingSignature }
        return t
    }
}
