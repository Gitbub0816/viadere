import Crypto
import Foundation

/// The retry schedule of webhook deliveries (the one table the sender and the receivers' dedup horizon are derived from, ADR-0025 section 2 rule 4).
public enum WebhookRetrySchedule {
    /// Attempts per delivery (the first send plus seven retries).
    public static let maxAttempts = 8
    /// Delay before retry N, in seconds: 30 s, 2 min, 10 min, 1 h, 6 h, 12 h, 24 h.
    public static let backoff: [TimeInterval] = [30, 120, 600, 3600, 6 * 3600, 12 * 3600, 24 * 3600]
    /// From the first attempt to the last one: the sum of the delays (about 43 h).
    public static var maxHorizon: TimeInterval { backoff.reduce(0, +) }
    /// The signature window: a captured delivery cannot be replayed after this, so a receiver keeps an event id for `maxHorizon + replayMargin`.
    public static let replayMargin: TimeInterval = 300
    public static var dedupHorizon: TimeInterval { maxHorizon + replayMargin }
    /// The same value written down. `WebhookRetrySchedule.dedupHorizon` must equal it, so a change to the backoff table cannot silently shorten the
    /// horizon receivers rely on: a Core test fails until this constant (and the documentation) are updated together.
    public static let documentedDedupHorizon: TimeInterval = 155_850
    /// What the developer documentation tells receivers to keep an event id for, measured from **first receipt**: 72 h (comfortably above the horizon).
    public static let documentedMinimumRetention: TimeInterval = 72 * 3600
}

/// Webhook signature `v2` (ADR-0025): HMAC-SHA256 over the method, host, path, timestamp, event id, tenant, key id and body digest.
///
/// ```
/// Viadere-Signature: t=<unix>,v2=<kid>:<base64url mac>[,v2=<kid>:<base64url mac>…][,v1=<hex>]
/// string to sign (UTF-8, LF-separated, no trailing LF):
///   VIADERE-WEBHOOK-V2 / METHOD / host / path?query / t / event id / tenant id / kid / lowercase hex SHA-256(body)
/// ```
///
/// A receiver recomputes the string from the request as received and the endpoint URL **it registered** (never proxy-rewritten values), once for each
/// `v2=` entry whose `kid` it holds, and compares in constant time. No field can contain LF (each has a closed charset), so no field can be shifted into
/// the next. A v2 verifier never accepts a `v1=` entry alone.
public enum WebhookSignatureV2 {
    public static let scheme = "VIADERE-WEBHOOK-V2"

    public enum Error: Swift.Error, Sendable, Equatable {
        /// Duplicate `kid`, two `t=`, a field outside its charset, an LF or a wrong MAC length.
        case malformedHeader
        case timestampOutsideTolerance
        case noMatchingSignature
        /// `Viadere-Tenant` is not the receiver's own tenant id.
        case tenantMismatch
        /// `Content-Digest` is missing or is not the digest of the received body.
        case digestMismatch
    }

    /// The request-derived fields that are signed. `host` and `pathAndQuery` come from the endpoint URL the receiver registered.
    public struct Context: Sendable, Hashable {
        public var method: String
        public var host: String
        public var pathAndQuery: String
        public var eventId: String
        public var tenantId: String

        public init(method: String = "POST", host: String, pathAndQuery: String, eventId: String, tenantId: String) {
            self.method = method
            self.host = host
            self.pathAndQuery = pathAndQuery
            self.eventId = eventId
            self.tenantId = tenantId
        }

        /// The host and `path?query` of a registered endpoint URL: lowercase host (the port only if it is not the scheme's default), the path and query
        /// exactly as registered (`/` for an empty path).
        public init?(endpoint: URL, method: String = "POST", eventId: String, tenantId: String) {
            guard let parts = URLComponents(url: endpoint, resolvingAgainstBaseURL: false), let host = parts.host?.lowercased(), !host.isEmpty else { return nil }
            var hostPart = host
            if let port = parts.port, !((parts.scheme == "https" && port == 443) || (parts.scheme == "http" && port == 80)) { hostPart += ":\(port)" }
            let path = parts.percentEncodedPath.isEmpty ? "/" : parts.percentEncodedPath
            self.init(method: method, host: hostPart, pathAndQuery: path + (parts.percentEncodedQuery.map { "?" + $0 } ?? ""), eventId: eventId, tenantId: tenantId)
        }
    }

    // MARK: Charsets (no field can contain LF)

    static func isMethod(_ s: String) -> Bool { (1...16).contains(s.utf8.count) && s.utf8.allSatisfy { $0 >= 0x41 && $0 <= 0x5A } }

    static func isHost(_ s: String) -> Bool {
        let parts = s.split(separator: ":", omittingEmptySubsequences: false)
        guard (1...2).contains(parts.count), !parts[0].isEmpty, parts[0].utf8.allSatisfy({ ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2E || $0 == 0x2D }) else { return false }
        if parts.count == 2 { return (1...5).contains(parts[1].utf8.count) && parts[1].utf8.allSatisfy { $0 >= 0x30 && $0 <= 0x39 } }
        return true
    }

    /// RFC 3986 `pchar`, `/`, `?` and well-formed `%HH` only.
    static func isPathAndQuery(_ s: String) -> Bool {
        let bytes = Array(s.utf8)
        guard !bytes.isEmpty, bytes.count <= 2048, bytes[0] == 0x2F else { return false }
        var i = 0
        let extra = Set("-._~!$&'()*+,;=:@/?".utf8)
        while i < bytes.count {
            let b = bytes[i]
            if b == 0x25 {
                guard i + 2 < bytes.count, isHex(bytes[i + 1]), isHex(bytes[i + 2]) else { return false }
                i += 3
                continue
            }
            guard (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) || extra.contains(b) else { return false }
            i += 1
        }
        return true
    }

    private static func isHex(_ b: UInt8) -> Bool { (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x46) || (b >= 0x61 && b <= 0x66) }

    static func isEventId(_ s: String) -> Bool {
        s.hasPrefix("evt_") && (5...68).contains(s.utf8.count) && s.dropFirst(4).utf8.allSatisfy { isIdByte($0) }
    }

    static func isTenantId(_ s: String) -> Bool { (1...64).contains(s.utf8.count) && s.utf8.allSatisfy { isIdByte($0) } }

    private static func isIdByte(_ b: UInt8) -> Bool { (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) || b == 0x5F || b == 0x2D }

    /// `whk_<prefix>_v<n>`: lowercase letters, digits and `_`, at most 64.
    public static func isKeyId(_ s: String) -> Bool {
        (1...64).contains(s.utf8.count) && s.utf8.allSatisfy { ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x5F }
    }

    // MARK: Signing

    /// `sha-256=:<base64 of SHA-256(body)>:` (RFC 9530 `Content-Digest`).
    public static func contentDigest(_ body: Data) -> String { "sha-256=:" + Data(SHA256.hash(data: body)).base64EncodedString() + ":" }

    /// The string to sign, or `nil` when a field is outside its charset.
    public static func stringToSign(_ context: Context, timestamp: Int64, kid: String, body: Data) -> String? {
        guard isMethod(context.method), isHost(context.host), isPathAndQuery(context.pathAndQuery), isEventId(context.eventId), isTenantId(context.tenantId),
              isKeyId(kid), timestamp > 0, String(timestamp).utf8.count <= 12 else { return nil }
        return [scheme, context.method, context.host, context.pathAndQuery, String(timestamp), context.eventId, context.tenantId, kid, SecureToken.sha256Hex(body)]
            .joined(separator: "\n")
    }

    /// The 43-character base64url MAC for one `(kid, secret)`.
    public static func mac(secret: String, context: Context, timestamp: Int64, kid: String, body: Data) -> String? {
        guard let message = stringToSign(context, timestamp: timestamp, kid: kid, body: body) else { return nil }
        return Base64URL.encode(Data(HMAC<SHA256>.authenticationCode(for: Data(message.utf8), using: WebhookSignature.key(for: secret))))
    }

    /// The `Viadere-Signature` value: one `v2=` entry per `(kid, secret)` (rotation sends two) and, during the 30-day migration only, the legacy `v1=`
    /// entry. **`auth.*` events never pass `legacySecret`**: they are v2-only from the first release.
    public static func header(secrets: [(kid: String, secret: String)], context: Context, body: Data, now: Date, legacySecret: String? = nil) -> String? {
        let t = ViadereDate.unixSeconds(now)
        var parts = ["t=\(t)"]
        for entry in secrets {
            guard let mac = mac(secret: entry.secret, context: context, timestamp: t, kid: entry.kid, body: body) else { return nil }
            parts.append("v2=\(entry.kid):\(mac)")
        }
        if let legacySecret { parts.append("v1=" + WebhookSignature.v1(secret: legacySecret, timestamp: t, body: body)) }
        return parts.joined(separator: ",")
    }

    // MARK: Verification (receivers)

    /// Verifies a delivery. `context` is built from the endpoint **the receiver registered** and the request's `Viadere-Event-Id` and `Viadere-Tenant`;
    /// `expectedTenant` is the receiver's own tenant id; `keys` maps each `kid` the receiver holds to its secret. Returns the signed timestamp.
    @discardableResult
    public static func verify(header: String, body: Data, contentDigestHeader: String?, context: Context, expectedTenant: String, keys: [String: String],
                              now: Date, tolerance: TimeInterval = WebhookSignature.defaultTolerance) throws(Error) -> Int64 {
        guard header.utf8.count <= 4096, !header.contains("\n"), !header.contains("\r") else { throw .malformedHeader }
        // Every signed field has a closed charset (no LF): anything outside it is malformed, not merely a wrong MAC.
        guard isMethod(context.method), isHost(context.host), isPathAndQuery(context.pathAndQuery), isEventId(context.eventId), isTenantId(context.tenantId),
              isTenantId(expectedTenant) else { throw .malformedHeader }
        var timestamp: Int64?
        var entries: [(kid: String, mac: String)] = []
        var kids = Set<String>()
        for raw in header.split(separator: ",", omittingEmptySubsequences: false) {
            let part = raw.trimmingCharacters(in: .whitespaces)
            guard let eq = part.firstIndex(of: "=") else { throw .malformedHeader }
            let name = String(part[part.startIndex..<eq])
            let value = String(part[part.index(after: eq)...])
            switch name {
            case "t":
                guard timestamp == nil, (1...12).contains(value.utf8.count), value.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }), let t = Int64(value) else { throw .malformedHeader }
                timestamp = t
            case "v2":
                guard let colon = value.firstIndex(of: ":") else { throw .malformedHeader }
                let kid = String(value[value.startIndex..<colon])
                let mac = String(value[value.index(after: colon)...])
                guard isKeyId(kid), Base64URL.isValid(mac, minLength: 43, maxLength: 43), kids.insert(kid).inserted else { throw .malformedHeader }
                entries.append((kid, mac))
            default:
                continue // v1 and unknown schemes are ignored; a v2 verifier never accepts `v1=` alone.
            }
        }
        guard let t = timestamp, !entries.isEmpty else { throw .malformedHeader }
        guard abs(now.timeIntervalSince1970 - TimeInterval(t)) <= tolerance else { throw .timestampOutsideTolerance }
        guard ConstantTime.equals(Data(context.tenantId.utf8), Data(expectedTenant.utf8)) else { throw .tenantMismatch }
        // The digest is compared with the one computed from the received bytes; the header is never copied into the string to sign.
        guard let contentDigestHeader, ConstantTime.equals(Data(contentDigestHeader.utf8), Data(contentDigest(body).utf8)) else { throw .digestMismatch }
        var matched = false
        for entry in entries {
            guard let secret = keys[entry.kid], let expected = mac(secret: secret, context: context, timestamp: t, kid: entry.kid, body: body) else { continue }
            if ConstantTime.equals(Data(entry.mac.utf8), Data(expected.utf8)) { matched = true }
        }
        guard matched else { throw .noMatchingSignature }
        return t
    }
}
