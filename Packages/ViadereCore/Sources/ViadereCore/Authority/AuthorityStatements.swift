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
    /// The sealed recovery start (ADR-0032 §3.2): the challenge whose nonce the envelope and every new key's PoP commit to. No factor JWS answers it.
    case recoveryStarted = "recovery_started"

    /// Purposes whose evidence yields a grant or a token: the signing key must be grant-capable (ADR-0023 §3 step 2).
    public var yieldsGrant: Bool { self == .linkOpen || self == .oidcLogin }

    /// Key-log and recovery purposes: only their statements may carry `account_ref` and `kids` (ADR-0033 §2).
    public var isKeyLog: Bool { !(self == .linkOpen || self == .oidcLogin) }
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
    /// Key-log purposes only: the account the challenge is about (an approving device requires it to equal its own, ADR-0033 §2).
    public var accountRef: String?
    /// Key-log purposes only: the keys of the entry being proved (a new device requires them to be exactly its own, ADR-0033 §4.1).
    public var kids: [String]?

    public init(environment: AuthorityEnvironment, challengeId: String, nonce: String, purpose: AuthorityPurpose, display: JSONValue, returnURL: String? = nil,
                redirectURI: String? = nil, matchRequired: Bool, issuedAt: Int64, expiresAt: Int64, accountRef: String? = nil, kids: [String]? = nil) {
        self.accountRef = accountRef
        self.kids = kids
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
        if let accountRef { o["account_ref"] = .string(accountRef) }
        if let kids { o["kids"] = .array(kids.map { .string($0) }) }
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
              keys.isSubset(of: AuthorityChallengeStatement.required.union(["return_url", "redirect_uri", "account_ref", "kids"])) else { throw AuthorityJOSEError.claims("members") }
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
        // `account_ref` and `kids` belong to key-log purposes only.
        var accountRef: String?
        var kids: [String]?
        if let raw = o["account_ref"] {
            guard purpose.isKeyLog, let value = raw.stringValue, AuthorityKeyLogFormat.isAccountRef(value) else { throw AuthorityJOSEError.claims("account_ref") }
            accountRef = value
        }
        if let raw = o["kids"] {
            guard purpose.isKeyLog, case .array(let items) = raw, (1...8).contains(items.count) else { throw AuthorityJOSEError.claims("kids") }
            let values = items.compactMap(\.stringValue)
            guard values.count == items.count, values.allSatisfy(KeyIdentifier.isValid), Set(values).count == values.count else { throw AuthorityJOSEError.claims("kids") }
            kids = values
        }
        let t = Int64(now.timeIntervalSince1970)
        guard iat <= t + skew else { throw AuthorityJOSEError.notYetValid }
        guard t <= exp + skew else { throw AuthorityJOSEError.expired }
        return AuthorityChallengeStatement(environment: environment, challengeId: ach, nonce: nonce, purpose: purpose, display: display, returnURL: returnURL,
                                           redirectURI: redirectURI, matchRequired: matchRequired, issuedAt: iat, expiresAt: exp, accountRef: accountRef, kids: kids)
    }
}

/// The authority keys the app pins per environment (ADR-0033 §3.1, ADR-0034 §5.4): `VIADERE_AUTHORITY_DEVICE_KEYS = [active, standby]`
/// (`device-statement-signing`, ES256) and `VIADERE_AUTHORITY_SEAL_KEYS = [active, standby]` (`recovery-seal`, HPKE P-256), as the public JWK
/// coordinates `x`, `y` (base64url). The `kid` of each is its RFC 7638 thumbprint.
///
/// **The values come from the owner** (KEY-ROTATION.md): only public halves that the authority itself verified against Key Vault (statement keys)
/// or against its unwrapped seal key (seal keys) in the reviewed key inventory (`key-inventory-record` / `key-inventory-check`, SECURITY §2.103)
/// may be copied here, in a reviewed change. Until then every slot holds `placeholder`, which never parses as a key: the list resolves to **empty**,
/// every statement fails closed on the device, the device refuses to seal, and a strict authority refuses to start (ADR-0028 §2 startup check).
/// A list resolves all-or-nothing: one placeholder or invalid slot, a duplicate, or a key that is also pinned for the other environment empties it.
public enum AuthorityPinnedKeys {
    /// The value of a slot the owner has not filled yet (never a valid base64url coordinate).
    public static let placeholder = "OWNER-SUPPLIED-PUBLIC-KEY-REQUIRED"

    /// One pinned public key: the `x` and `y` members of its JWK (EC P-256).
    public struct Slot: Sendable, Hashable {
        public let x: String
        public let y: String
        public init(x: String, y: String) {
            self.x = x
            self.y = y
        }
        public static let unfilled = Slot(x: placeholder, y: placeholder)
    }

    // OWNER: replace each `.unfilled` with `Slot(x: "<x>", y: "<y>")` from the verified inventory. Order: [active, standby].
    static let deviceStatementSlots: [AuthorityEnvironment: [Slot]] = [
        .staging: [.unfilled, .unfilled],
        .production: [.unfilled, .unfilled],
    ]
    static let sealSlots: [AuthorityEnvironment: [Slot]] = [
        .staging: [.unfilled, .unfilled],
        .production: [.unfilled, .unfilled],
    ]

    /// The raw 64-byte `x ‖ y` of every slot, or `nil` when any slot is unfilled or invalid, or two slots are equal (all-or-nothing).
    public static func resolve(_ slots: [Slot]) -> [Data]? {
        guard !slots.isEmpty, slots.count <= 2 else { return nil }
        var out: [Data] = []
        for slot in slots {
            guard slot.x != placeholder, slot.y != placeholder, Base64URL.isValid(slot.x, minLength: 43, maxLength: 43), Base64URL.isValid(slot.y, minLength: 43, maxLength: 43),
                  let x = Base64URL.decode(slot.x), let y = Base64URL.decode(slot.y), x.count == 32, y.count == 32,
                  (try? P256.Signing.PublicKey(rawRepresentation: x + y)) != nil else { return nil }
            out.append(x + y)
        }
        return Set(out).count == out.count ? out : nil
    }

    /// Resolves the table for `environment`, refusing any key that is also pinned for the other environment (ADR-0034 §10.4: a production build never
    /// carries a staging key).
    static func resolved(_ table: [AuthorityEnvironment: [Slot]], _ environment: AuthorityEnvironment) -> [Data] {
        guard let own = table[environment].flatMap(resolve) else { return [] }
        let others = AuthorityEnvironment.allCases.filter { $0 != environment }.flatMap { table[$0].flatMap(resolve) ?? [] }
        return own.contains(where: others.contains) ? [] : own
    }

    /// Statement keys `[active, standby]`; empty (fail closed) while any slot is a placeholder.
    public static func deviceStatementKeys(_ environment: AuthorityEnvironment) -> [P256.Signing.PublicKey] {
        resolved(deviceStatementSlots, environment).compactMap { try? P256.Signing.PublicKey(rawRepresentation: $0) }
    }

    /// RFC 7638 thumbprints of `deviceStatementKeys` (the authority's startup reference set, ADR-0033 §3.7).
    public static func deviceStatementKids(_ environment: AuthorityEnvironment) -> [String] { deviceStatementKeys(environment).map(JWKThumbprint.p256) }

    /// Seal keys `[active, standby]`; empty (the device refuses to seal) while any slot is a placeholder.
    public static func sealKeys(_ environment: AuthorityEnvironment) -> [P256.KeyAgreement.PublicKey] {
        resolved(sealSlots, environment).compactMap { try? P256.KeyAgreement.PublicKey(rawRepresentation: $0) }
    }

    public static func sealKids(_ environment: AuthorityEnvironment) -> [String] { sealKeys(environment).map(RecoverySeal.kid) }

    /// True once both lists of `environment` resolve (the release check for a build that enables authority flows).
    public static func isProvisioned(_ environment: AuthorityEnvironment) -> Bool {
        deviceStatementKeys(environment).count == 2 && sealKeys(environment).count == 2
    }
}
