import Foundation

// The api ↔ authority interface on the internal network (ADR-0019 §4, TRUST_BOUNDARIES §9). Every call carries an Entra access token for the
// authority's application; the token is necessary, never sufficient: evidence is verified against the authority's own records. Bodies are strict
// (unknown members refused) so a relay cannot smuggle a field the authority would act on.

private struct AuthorityStrictKey: CodingKey {
    var stringValue: String
    var intValue: Int? { nil }
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { nil }
}

/// Refuses a JSON object with any member outside `allowed` (closed request bodies).
private func authorityRequireOnly(_ decoder: any Decoder, _ allowed: Set<String>) throws {
    let keys = try decoder.container(keyedBy: AuthorityStrictKey.self).allKeys.map(\.stringValue)
    guard Set(keys).isSubset(of: allowed) else {
        throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "unknown member"))
    }
}

public enum AuthorityRoute {
    public static let challenges = "/v1/challenges"
    public static let evidence = "/v1/evidence"
    public static let oidcClientCheck = "/v1/oidc/client-check"
    public static let oidcToken = "/v1/oidc/token"
    public static let oidcKeys = "/v1/oidc/keys"
    public static let revocations = "/v1/revocations"
    public static func challenge(_ id: String) -> String { "/v1/challenges/\(id)" }
}

/// App roles of the authority's Entra application (ADR-0019 §4.2, ADR-0028 §9).
public enum AuthorityAppRole: String, Sendable, CaseIterable {
    case evidenceSubmit = "Authority.Evidence.Submit"
    case revocations = "Authority.Revocations"
}

/// `POST /v1/challenges` (ADR-0033 §1): references only, never display text.
public struct AuthorityChallengeCreateRequest: Codable, Sendable, Hashable {
    public var purpose: AuthorityPurpose
    public var oidc: OIDCAuthorization?
    public var link: LinkOpen?

    /// The authorization request the code will be bound to. `state` stays at the api (it is the RP's value, returned in the redirect).
    public struct OIDCAuthorization: Codable, Sendable, Hashable {
        public var clientId: String
        public var redirectURI: String
        public var codeChallenge: String
        public var codeChallengeMethod: String
        public var nonce: String
        public var acrValues: [String]?

        public init(clientId: String, redirectURI: String, codeChallenge: String, codeChallengeMethod: String, nonce: String, acrValues: [String]? = nil) {
            self.clientId = clientId
            self.redirectURI = redirectURI
            self.codeChallenge = codeChallenge
            self.codeChallengeMethod = codeChallengeMethod
            self.nonce = nonce
            self.acrValues = acrValues
        }

        enum CodingKeys: String, CodingKey {
            case clientId = "client_id", redirectURI = "redirect_uri", codeChallenge = "code_challenge", codeChallengeMethod = "code_challenge_method", nonce
            case acrValues = "acr_values"
        }

        public init(from decoder: any Decoder) throws {
            try authorityRequireOnly(decoder, ["client_id", "redirect_uri", "code_challenge", "code_challenge_method", "nonce", "acr_values"])
            let c = try decoder.container(keyedBy: CodingKeys.self)
            clientId = try c.decode(String.self, forKey: .clientId)
            redirectURI = try c.decode(String.self, forKey: .redirectURI)
            codeChallenge = try c.decode(String.self, forKey: .codeChallenge)
            codeChallengeMethod = try c.decode(String.self, forKey: .codeChallengeMethod)
            nonce = try c.decode(String.self, forKey: .nonce)
            acrValues = try c.decodeIfPresent([String].self, forKey: .acrValues)
        }
    }

    public struct LinkOpen: Codable, Sendable, Hashable {
        public var linkClientId: String
        public var returnURL: String
        public var deliveryId: String
        public var codeChallenge: String
        public var purpose: String
        public var crossDevice: Bool

        public init(linkClientId: String, returnURL: String, deliveryId: String, codeChallenge: String, purpose: String, crossDevice: Bool) {
            self.linkClientId = linkClientId
            self.returnURL = returnURL
            self.deliveryId = deliveryId
            self.codeChallenge = codeChallenge
            self.purpose = purpose
            self.crossDevice = crossDevice
        }

        enum CodingKeys: String, CodingKey {
            case linkClientId = "link_client_id", returnURL = "return_url", deliveryId = "delivery_id", codeChallenge = "code_challenge", purpose
            case crossDevice = "cross_device"
        }

        public init(from decoder: any Decoder) throws {
            try authorityRequireOnly(decoder, ["link_client_id", "return_url", "delivery_id", "code_challenge", "purpose", "cross_device"])
            let c = try decoder.container(keyedBy: CodingKeys.self)
            linkClientId = try c.decode(String.self, forKey: .linkClientId)
            returnURL = try c.decode(String.self, forKey: .returnURL)
            deliveryId = try c.decode(String.self, forKey: .deliveryId)
            codeChallenge = try c.decode(String.self, forKey: .codeChallenge)
            purpose = try c.decode(String.self, forKey: .purpose)
            crossDevice = try c.decode(Bool.self, forKey: .crossDevice)
        }
    }

    public init(purpose: AuthorityPurpose, oidc: OIDCAuthorization? = nil, link: LinkOpen? = nil) {
        self.purpose = purpose
        self.oidc = oidc
        self.link = link
    }

    enum CodingKeys: String, CodingKey { case purpose, oidc, link }

    public init(from decoder: any Decoder) throws {
        try authorityRequireOnly(decoder, ["purpose", "oidc", "link"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        purpose = try c.decode(AuthorityPurpose.self, forKey: .purpose)
        oidc = try c.decodeIfPresent(OIDCAuthorization.self, forKey: .oidc)
        link = try c.decodeIfPresent(LinkOpen.self, forKey: .link)
    }
}

public struct AuthorityChallengeCreateResponse: Codable, Sendable, Hashable {
    public var challengeId: String
    /// The compact `viadere-challenge+jws` the device verifies against its pinned keys.
    public var statement: String
    /// The number the browser page shows (app path); the device asks for it and never displays it.
    public var matchCode: String?
    public var expiresAt: Int64

    public init(challengeId: String, statement: String, matchCode: String?, expiresAt: Int64) {
        self.challengeId = challengeId
        self.statement = statement
        self.matchCode = matchCode
        self.expiresAt = expiresAt
    }

    enum CodingKeys: String, CodingKey { case challengeId = "ach", statement, matchCode = "match_code", expiresAt = "expires_at" }
}

/// `POST /v1/evidence`: a device factor JWS relayed unchanged. `account_id`, when the api names one, is checked against the signing key's
/// `account_ref` (ADR-0023 §3 step 3a); it never selects the account.
public struct AuthorityEvidenceRequest: Codable, Sendable, Hashable {
    public var factor: String
    public var accountId: UUID?

    public init(factor: String, accountId: UUID? = nil) {
        self.factor = factor
        self.accountId = accountId
    }

    enum CodingKeys: String, CodingKey { case factor, accountId = "account_id" }

    public init(from decoder: any Decoder) throws {
        try authorityRequireOnly(decoder, ["factor", "account_id"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        factor = try c.decode(String.self, forKey: .factor)
        accountId = try c.decodeIfPresent(UUID.self, forKey: .accountId)
    }
}

public struct AuthorityEvidenceResponse: Codable, Sendable, Hashable {
    public var challengeId: String
    public var decision: FactorDecision
    /// `oidc_login` approve: the authorization code (256-bit, single use, 60 s) the api carries in the redirect.
    public var code: String?
    /// `link_open` approve: the `viadere-grant+jwt` for the business.
    public var grant: String?

    public init(challengeId: String, decision: FactorDecision, code: String? = nil, grant: String? = nil) {
        self.challengeId = challengeId
        self.decision = decision
        self.code = code
        self.grant = grant
    }

    enum CodingKeys: String, CodingKey { case challengeId = "ach", decision, code, grant }
}

/// `GET /v1/oidc/client-check?client_id=…&redirect_uri=…`: a database lookup; no Key Vault call, no challenge (ADR-0024 §4).
public struct AuthorityClientCheckResponse: Codable, Sendable, Hashable {
    public var valid: Bool
    public var displayName: String?

    public init(valid: Bool, displayName: String?) {
        self.valid = valid
        self.displayName = displayName
    }

    enum CodingKeys: String, CodingKey { case valid, displayName = "display_name" }
}

/// `POST /v1/revocations` (reduce-only; the worker's only route).
public struct AuthorityRevocationRequest: Codable, Sendable, Hashable {
    public var kid: String
    public var reason: String

    public init(kid: String, reason: String) {
        self.kid = kid
        self.reason = reason
    }

    enum CodingKeys: String, CodingKey { case kid, reason }

    public init(from decoder: any Decoder) throws {
        try authorityRequireOnly(decoder, ["kid", "reason"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        kid = try c.decode(String.self, forKey: .kid)
        reason = try c.decode(String.self, forKey: .reason)
    }
}

/// `GET /v1/oidc/keys`: the public halves of the active OIDC token keys, so the api can verify access tokens at `/oidc/userinfo` (verify, never sign).
public struct AuthorityPublicKeySet: Codable, Sendable, Hashable {
    public var keys: [JSONValue]
    public init(keys: [JSONValue]) { self.keys = keys }
}
