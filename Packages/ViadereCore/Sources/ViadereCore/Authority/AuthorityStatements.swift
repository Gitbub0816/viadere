@preconcurrency import Crypto
import Foundation

// Authority challenges, authority-built displays and the device-side checks of `viadere-challenge+jws` (ADR-0033 §1, §2, §4).

/// What an authority challenge is for (ADR-0023 §3). The authority builds a display for every purpose; Stage 6 serves `link_open` and `oidc_login`
/// (the key-log and recovery purposes parse here so one definition exists, and the authority refuses them until their stage lands).
public enum AuthorityPurpose: String, Sendable, Codable, CaseIterable, Hashable {
    case linkOpen = "link_open"
    case oidcLogin = "oidc_login"
    case keylogDeviceAdded = "keylog_device_added"
    case keylogPasskeyAdded = "keylog_passkey_added"
    case recoveryCancel = "recovery_cancel"
    case recoveryCodesSet = "recovery_codes_set"
    case enrollmentConfirmed = "enrollment_confirmed"

    /// Purposes whose evidence yields a grant or a token: the signing key must be grant-capable (ADR-0023 §3 step 2).
    public var yieldsGrant: Bool { self == .linkOpen || self == .oidcLogin }
}

/// Authority challenge ids: `ach_` + 22 base64url characters (16 random bytes).
public enum AuthorityChallengeID {
    public static let prefix = "ach_"
    public static func generate() -> String { prefix + Base64URL.encode(SecureToken.randomBytes(16)) }
    public static func isValid(_ value: String) -> Bool {
        guard value.hasPrefix(prefix) else { return false }
        let body = String(value.dropFirst(prefix.count))
        return Base64URL.isValid(body, minLength: 22, maxLength: 22) && Base64URL.decode(body)?.count == 16
    }
}

/// 256-bit challenge nonces (43 base64url characters).
public enum AuthorityNonce {
    public static func generate() -> String { Base64URL.encode(SecureToken.randomBytes(32)) }
    public static func isValid(_ value: String) -> Bool { Base64URL.isValid(value, minLength: 43, maxLength: 43) && Base64URL.decode(value)?.count == 32 }
}

/// The display object the **authority** builds from its own records (ADR-0033 §1). The api never supplies display text; it relays this object unchanged
/// inside the signed challenge statement, and the device signs its digest.
public enum AuthorityDisplay {
    public static let digestDomain = "VIADERE-DISPLAY-V1\n"

    /// `oidc_login`: the reviewed client name, the exact redirect URI and its host, and the number length the app asks for (app path).
    public static func oidcLogin(clientName: String, redirectURI: String, matchDigits: Int?) -> JSONValue {
        var object: [String: JSONValue] = ["v": .integer(1), "purpose": .string(AuthorityPurpose.oidcLogin.rawValue), "client_name": .string(clientName),
                                           "redirect_uri": .string(redirectURI), "redirect_host": .string(host(of: redirectURI))]
        if let matchDigits { object["match_digits"] = .integer(Int64(matchDigits)) }
        return .object(object)
    }

    /// `link_open`: the reviewed tenant and link-client names, the exact return URL and its host.
    public static func linkOpen(tenantName: String, clientName: String, returnURL: String, matchDigits: Int?) -> JSONValue {
        var object: [String: JSONValue] = ["v": .integer(1), "purpose": .string(AuthorityPurpose.linkOpen.rawValue), "tenant_name": .string(tenantName),
                                           "client_name": .string(clientName), "return_url": .string(returnURL), "return_host": .string(host(of: returnURL))]
        if let matchDigits { object["match_digits"] = .integer(Int64(matchDigits)) }
        return .object(object)
    }

    /// `lowercase hex SHA-256("VIADERE-DISPLAY-V1\n" ‖ canonical(display))`.
    public static func digest(_ display: JSONValue) throws -> String {
        SecureToken.sha256Hex(Data(digestDomain.utf8) + (try CanonicalJSON.serialize(display)))
    }

    static func host(of url: String) -> String { URLComponents(string: url)?.host?.lowercased() ?? "" }
}

/// The payload of a `viadere-challenge+jws` (ADR-0033 §2): exactly these members.
public struct AuthorityChallengeStatement: Sendable, Hashable {
    public static let type = "viadere-challenge+jws"
    public var environment: AuthorityEnvironment
    public var challengeId: String
    public var nonce: String
    public var purpose: AuthorityPurpose
    public var display: JSONValue
    /// `link_open` only.
    public var returnURL: String?
    /// `oidc_login` only.
    public var redirectURI: String?
    public var matchRequired: Bool
    public var issuedAt: Int64
    public var expiresAt: Int64

    public init(environment: AuthorityEnvironment, challengeId: String, nonce: String, purpose: AuthorityPurpose, display: JSONValue, returnURL: String? = nil,
                redirectURI: String? = nil, matchRequired: Bool, issuedAt: Int64, expiresAt: Int64) {
        self.environment = environment
        self.challengeId = challengeId
        self.nonce = nonce
        self.purpose = purpose
        self.display = display
        self.returnURL = returnURL
        self.redirectURI = redirectURI
        self.matchRequired = matchRequired
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
    }

    public var payload: [String: JSONValue] {
        var o: [String: JSONValue] = [
            "v": .integer(1), "iss": .string(environment.authorityURN), "aud": .string(AuthorityAudience.device), "env": .string(environment.rawValue),
            "ach": .string(challengeId), "nonce": .string(nonce), "purpose": .string(purpose.rawValue), "display": display,
            "match_required": .bool(matchRequired), "iat": .integer(issuedAt), "exp": .integer(expiresAt),
        ]
        if let returnURL { o["return_url"] = .string(returnURL) }
        if let redirectURI { o["redirect_uri"] = .string(redirectURI) }
        return o
    }

    static let required: Set<String> = ["v", "iss", "aud", "env", "ach", "nonce", "purpose", "display", "match_required", "iat", "exp"]
}

/// Device-side verification of authority statements (ADR-0033 §2, §3): signature by a pinned, non-revoked statement key (looked up by its RFC 7638
/// thumbprint in the JOSE header), exact `typ`, `iss` and `env` of the build's environment, `aud`, exact member set, time bounds.
public enum AuthorityStatementVerifier {
    public static let skew: Int64 = 60

    public static func verifyChallenge(_ compact: String, pinnedKeys: [P256.Signing.PublicKey], revokedKids: Set<String> = [], environment: AuthorityEnvironment,
                                       now: Date) throws -> AuthorityChallengeStatement {
        let parts = try AuthorityJWS.parse(compact, expectedType: AuthorityChallengeStatement.type, allowedAlgorithms: ["ES256"])
        guard !revokedKids.contains(parts.kid), let key = pinnedKeys.first(where: { JWKThumbprint.p256($0) == parts.kid }) else { throw AuthorityJOSEError.unknownKey }
        try AuthorityJWS.verifyES256(parts, key: key)
        let o = parts.payload
        let keys = Set(o.keys)
        guard AuthorityChallengeStatement.required.isSubset(of: keys),
              keys.isSubset(of: AuthorityChallengeStatement.required.union(["return_url", "redirect_uri"])) else { throw AuthorityJOSEError.claims("members") }
        guard o["v"]?.authorityInteger == 1, o["iss"]?.stringValue == environment.authorityURN, o["aud"]?.stringValue == AuthorityAudience.device,
              o["env"]?.stringValue == environment.rawValue else { throw AuthorityJOSEError.claims("issuer") }
        guard let ach = o["ach"]?.stringValue, AuthorityChallengeID.isValid(ach), let nonce = o["nonce"]?.stringValue, AuthorityNonce.isValid(nonce),
              let purpose = o["purpose"]?.stringValue.flatMap(AuthorityPurpose.init(rawValue:)), case .object? = o["display"], let display = o["display"],
              case .bool(let matchRequired)? = o["match_required"], let iat = o["iat"]?.authorityInteger, let exp = o["exp"]?.authorityInteger, exp > iat else {
            throw AuthorityJOSEError.claims("values")
        }
        // The display must describe the purpose it is signed for, and URLs appear only where their purpose defines them.
        guard display.objectValue?["purpose"]?.stringValue == purpose.rawValue else { throw AuthorityJOSEError.claims("display") }
        let returnURL = o["return_url"]?.stringValue, redirectURI = o["redirect_uri"]?.stringValue
        guard (returnURL != nil) == (purpose == .linkOpen), (redirectURI != nil) == (purpose == .oidcLogin) else { throw AuthorityJOSEError.claims("url") }
        let t = Int64(now.timeIntervalSince1970)
        guard iat <= t + skew else { throw AuthorityJOSEError.notYetValid }
        guard t <= exp + skew else { throw AuthorityJOSEError.expired }
        return AuthorityChallengeStatement(environment: environment, challengeId: ach, nonce: nonce, purpose: purpose, display: display, returnURL: returnURL,
                                           redirectURI: redirectURI, matchRequired: matchRequired, issuedAt: iat, expiresAt: exp)
    }
}

/// The statement keys the app pins per environment (ADR-0033 §3.1): `[active, standby]` as RFC 7638 thumbprints. Empty until the attested key
/// inventory of the first authority deploy supplies them (KEY-ROTATION.md): with an empty list every statement fails closed on the device, and the
/// authority refuses to start with grant routes enabled outside development (ADR-0028 §2 startup check).
public enum AuthorityPinnedKeys {
    public static func deviceStatementKids(_ environment: AuthorityEnvironment) -> [String] {
        switch environment {
        case .staging: []
        case .production: []
        }
    }
}
