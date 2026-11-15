import Foundation

/// The one Safe Action Viadere issues and accepts: `signin.request`, the Viadere code on "Sign in with Viadere" (SECURITY.md §2.104).
///
/// Issuer: the build's link-domain host. App: the Viadere app's bundle id. Scope: cross-device (it approves a sign-in in a browser, so it
/// is never automatic). `request_id`: the authority challenge id (`ach_…`), already single use and short-lived at the authority. No params.
/// Shared by the server (issuer) and the app (reader) so neither can drift from the other.
public enum ViadereSignInSafeAction {
    public static let action = "signin.request"
    public static let appId = "\(ViadereCore.bundlePrefix).app"
    /// A sign-in code lives at most this long (spec: "a minute or two for sign-in"); the reader refuses a longer one.
    public static let lifetimeSeconds = 120
    public static let keyFilePath = "/.well-known/ckey-safe-actions.json"
    public static let requestInfoPrefix = "/ckey/requests/"

    /// The `request_info` template the issuer publishes and the app derives from the pinned issuer: always on the issuer's own host.
    public static func requestInfoTemplate(issuer: String) -> String { "https://\(issuer)\(requestInfoPrefix){request_id}" }

    /// `nil` unless the issuer is a DNS name and the request id is a challenge id (so nothing needs escaping and nothing can change the host or path).
    public static func requestInfoURL(issuer: String, requestId: String) -> URL? {
        guard LinkDomain(issuer)?.host == issuer, AuthorityChallengeID.isValid(requestId) else { return nil }
        return URL(string: "https://\(issuer)\(requestInfoPrefix)\(requestId)")
    }

    /// The envelope for one challenge: issued now, expiring at `notAfter` or after `lifetimeSeconds`, whichever is sooner. `nil` when the
    /// challenge id is not one or no positive lifetime is left.
    public static func envelope(issuer: LinkDomain, keyId: String, challengeId: String, now: Date, notAfter: Date) -> CKeySafeAction? {
        guard AuthorityChallengeID.isValid(challengeId), now.timeIntervalSince1970 >= 0 else { return nil }
        let issued = UInt64(now.timeIntervalSince1970)
        let limit = notAfter.timeIntervalSince1970 < 0 ? 0 : UInt64(notAfter.timeIntervalSince1970)
        let expires = min(limit, issued + UInt64(lifetimeSeconds))
        guard expires > issued else { return nil }
        return CKeySafeAction(scope: .crossDevice, issuer: issuer.host, app: appId, action: action, keyId: keyId, requestId: challengeId,
                              issuedAt: issued, expiresAt: expires)
    }

    /// The longest text a sign-in envelope from `issuer` can have (a 32-byte key id, the longest allowed): what a scanner has to admit and
    /// no more. 264 bytes for `viadere.com`.
    public static func maxTextBytes(issuer: String) -> Int {
        // version, scope; five length bytes; app, action, key id (max 32), challenge id (26); two timestamps; params length; signature.
        let envelope = 2 + 5 + issuer.utf8.count + appId.utf8.count + action.utf8.count + 32 + 26 + 16 + 2 + CKeySafeAction.signatureBytes
        return CKeySafeAction.prefix.utf8.count + (envelope * 4 + 2) / 3
    }
}

/// `GET https://{issuer}/.well-known/ckey-safe-actions.json` (spec "Issuer keys").
public struct CKeySafeActionKeyFile: Codable, Sendable, Equatable {
    public struct Key: Codable, Sendable, Equatable {
        public var id: String
        public var alg: String
        /// 64 lower-case hex digits.
        public var publicKey: String
        /// RFC 3339, when the issuer set one.
        public var notAfter: String?

        public init(id: String, alg: String = "Ed25519", publicKey: String, notAfter: String? = nil) {
            self.id = id
            self.alg = alg
            self.publicKey = publicKey
            self.notAfter = notAfter
        }

        enum CodingKeys: String, CodingKey {
            case id, alg
            case publicKey = "public_key"
            case notAfter = "not_after"
        }
    }

    public var issuer: String
    public var keys: [Key]
    public var requestInfo: String

    public init(issuer: String, keys: [Key], requestInfo: String) {
        self.issuer = issuer
        self.keys = keys
        self.requestInfo = requestInfo
    }

    enum CodingKeys: String, CodingKey {
        case issuer, keys
        case requestInfo = "request_info"
    }
}

/// `GET {request_info}` (spec "Request information"): who is asking, for the cross-device confirmation.
public struct CKeySafeActionRequestInfo: Codable, Sendable, Equatable {
    public static let pending = "pending"
    public static let maxDeviceCharacters = 120
    public static let maxLocationCharacters = 120
    public static let maxRequestedAtCharacters = 40

    public var requestId: String
    public var device: String?
    public var location: String?
    /// RFC 3339.
    public var requestedAt: String?
    public var status: String

    public init(requestId: String, device: String?, location: String?, requestedAt: String?, status: String) {
        self.requestId = requestId
        self.device = device
        self.location = location
        self.requestedAt = requestedAt
        self.status = status
    }

    enum CodingKeys: String, CodingKey {
        case device, location, status
        case requestId = "request_id"
        case requestedAt = "requested_at"
    }
}
