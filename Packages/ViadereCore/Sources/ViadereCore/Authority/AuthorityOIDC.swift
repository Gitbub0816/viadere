@preconcurrency import Crypto
import Foundation

// OpenID Connect for staging (ADR-0024): the protocol surface, pairwise subjects, account references, PKCE, redirect URI rules, acr/amr mapping and the
// discovery document. Tokens are **signed only by the authority**; the api may verify, never sign.

public enum OIDCProfile {
    public static let acrPasskey = "urn:viadere:acr:passkey"
    public static let acrApp = "urn:viadere:acr:app"
    /// Authorization codes live 60 s and are single use (ADR-0023 §7, ADR-0024 §6).
    public static let codeLifetime: TimeInterval = 60
    /// id_token and access token lifetime (`exp = iat + 300`).
    public static let tokenLifetime: Int64 = 300
    /// Client assertions (`private_key_jwt`): `exp` at most 5 minutes ahead, `jti` single use until `exp` + 60 s.
    public static let clientAssertionMaxLifetime: Int64 = 300
    public static let clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

    /// The discovery document (OpenID Connect Discovery 1.0) for `issuer` (exact string, no trailing slash). Static: published by
    /// `authority-publish.yml` under `Site/content/id/`, never served by the api (ADR-0024 §7).
    public static func discoveryDocument(issuer: String) -> JSONValue {
        func strings(_ values: [String]) -> JSONValue { .array(values.map { .string($0) }) }
        return .object([
            "issuer": .string(issuer),
            "authorization_endpoint": .string(issuer + "/oidc/authorize"),
            "token_endpoint": .string(issuer + "/oidc/token"),
            "userinfo_endpoint": .string(issuer + "/oidc/userinfo"),
            "jwks_uri": .string(issuer + "/oidc/jwks.json"),
            "end_session_endpoint": .string(issuer + "/oidc/logout"),
            "response_types_supported": strings(["code"]),
            "response_modes_supported": strings(["query"]),
            "grant_types_supported": strings(["authorization_code"]),
            "code_challenge_methods_supported": strings(["S256"]),
            "scopes_supported": strings(["openid"]),
            "subject_types_supported": strings(["pairwise"]),
            "id_token_signing_alg_values_supported": strings(["RS256", "ES256"]),
            "token_endpoint_auth_methods_supported": strings(["private_key_jwt"]),
            "token_endpoint_auth_signing_alg_values_supported": strings(["ES256", "RS256", "PS256"]),
            "authorization_response_iss_parameter_supported": .bool(true),
            "claims_parameter_supported": .bool(false),
            "request_parameter_supported": .bool(false),
            "request_uri_parameter_supported": .bool(false),
            "acr_values_supported": strings([acrPasskey, acrApp]),
            "claims_supported": strings(["iss", "sub", "aud", "azp", "exp", "iat", "auth_time", "nonce", "acr", "amr", "jti"]),
        ])
    }

    /// `sub = base64url(HMAC-SHA256(OIDC_PAIRWISE_KEY, "oidc-sub\n" ‖ sector_host ‖ "\n" ‖ accountId_lowercase_uuid))`, no truncation (43 characters).
    public static func pairwiseSubject(key: SymmetricKey, sectorHost: String, accountId: UUID) -> String {
        let input = "oidc-sub\n" + sectorHost.lowercased() + "\n" + accountId.uuidString.lowercased()
        return Base64URL.encode(Data(HMAC<SHA256>.authenticationCode(for: Data(input.utf8), using: key)))
    }

    /// `acct_` + lowercase hex of the first 16 bytes of `HMAC-SHA256(ACCOUNT_REF_KEY, "account-ref\n" ‖ account_id)` (ADR-0023 §4).
    public static func accountRef(key: SymmetricKey, accountId: UUID) -> String {
        let mac = Data(HMAC<SHA256>.authenticationCode(for: Data(("account-ref\n" + accountId.uuidString.lowercased()).utf8), using: key))
        return "acct_" + Hex.encode(mac.prefix(16))
    }

    /// RFC 7636 §4.1: 43-128 characters of `[A-Za-z0-9-._~]`.
    public static func isValidCodeVerifier(_ verifier: String) -> Bool {
        (43...128).contains(verifier.utf8.count) && verifier.unicodeScalars.allSatisfy {
            $0.isASCII && (("A"..."Z").contains($0) || ("a"..."z").contains($0) || ("0"..."9").contains($0) || "-._~".unicodeScalars.contains($0))
        }
    }

    /// An S256 challenge is 43 base64url characters (a SHA-256 digest).
    public static func isValidCodeChallenge(_ challenge: String) -> Bool { Base64URL.isValid(challenge, minLength: 43, maxLength: 43) }

    /// `BASE64URL(SHA256(ASCII(code_verifier))) == code_challenge`, compared in constant time. `plain` does not exist here.
    public static func pkceMatches(verifier: String, challenge: String) -> Bool {
        guard isValidCodeVerifier(verifier), isValidCodeChallenge(challenge) else { return false }
        return ConstantTime.equals(Base64URL.encode(Data(SHA256.hash(data: Data(verifier.utf8)))), challenge)
    }

    /// Registration rule for redirect and post-logout URIs (ADR-0024 §3): absolute `https`, a lowercase A-label host that is not loopback, no user
    /// info, no fragment, no wildcard, at most 512 bytes. Matching at runtime is **exact string equality** with a registered value.
    public static func isRegistrableRedirectURI(_ uri: String) -> Bool {
        guard uri.utf8.count <= 512, !uri.contains("*"), !uri.contains("#"), let components = URLComponents(string: uri), components.scheme == "https",
              components.user == nil, components.password == nil, components.fragment == nil, let host = components.host, !host.isEmpty,
              host == host.lowercased(), host.unicodeScalars.allSatisfy({ $0.isASCII && ($0.properties.isAlphabetic || ("0"..."9").contains($0) || $0 == "-" || $0 == ".") }),
              host.contains("."), host != "localhost", !host.hasSuffix(".localhost"), !Self.isIPLiteral(host) else { return false }
        return true
    }

    static func isIPLiteral(_ host: String) -> Bool { host.split(separator: ".").allSatisfy { Int($0) != nil } || host.contains(":") }

    /// The host of a registered redirect URI (the sector of a client with one host).
    public static func host(of uri: String) -> String? { URLComponents(string: uri)?.host?.lowercased() }

    /// `amr` for app approval (ADR-0024 §5, ADR-0023 §5): `hwk` only for hardware-attested keys, `swk` otherwise; `user` only for `uv = biometric`.
    public static func appAMR(userVerification: FactorUserVerification, hardwareAttested: Bool) -> [String] {
        let holder = hardwareAttested ? "hwk" : "swk"
        return userVerification == .biometric ? [holder, "user", "mfa"] : [holder, "mfa"]
    }
}

/// Grant `viadere-grant+jwt` claims (ADR-0023 §5) and the verifier the SDKs run (signature against the static grant JWKS, `typ`, `iss`, `aud`, `exp`,
/// `cch`; the caller consumes `jti` once).
public struct AuthorityGrantClaims: Sendable, Hashable {
    public static let type = "viadere-grant+jwt"
    public static let lifetime: Int64 = 60
    public var issuer: String
    public var audience: String
    public var subject: String
    public var tenantId: String
    public var transaction: String
    public var purpose: String
    public var acr: String
    public var amr: [String]
    public var authTime: Int64
    public var issuedAt: Int64
    public var expiresAt: Int64
    public var jti: String
    public var codeChallenge: String

    public init(issuer: String, audience: String, subject: String, tenantId: String, transaction: String, purpose: String, acr: String, amr: [String],
                authTime: Int64, issuedAt: Int64, expiresAt: Int64, jti: String, codeChallenge: String) {
        self.issuer = issuer
        self.audience = audience
        self.subject = subject
        self.tenantId = tenantId
        self.transaction = transaction
        self.purpose = purpose
        self.acr = acr
        self.amr = amr
        self.authTime = authTime
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.jti = jti
        self.codeChallenge = codeChallenge
    }

    public var payload: [String: JSONValue] {
        ["iss": .string(issuer), "aud": .string(audience), "sub": .string(subject), "tid": .string(tenantId), "txn": .string(transaction), "purpose": .string(purpose),
         "acr": .string(acr), "amr": .array(amr.map { .string($0) }), "auth_time": .integer(authTime), "iat": .integer(issuedAt), "exp": .integer(expiresAt),
         "jti": .string(jti), "cch": .string(codeChallenge)]
    }
}

public enum AuthorityGrantVerifier {
    public static let skew: Int64 = 60

    /// Verifies a grant for `audience` (the business's link client id) and the `code_challenge` the business sent. Returns the claims; the caller
    /// must then consume `jti` once in its own replay store.
    public static func verify(_ compact: String, keys: [String: P256.Signing.PublicKey], issuer: String, audience: String, codeChallenge: String,
                              now: Date) throws -> AuthorityGrantClaims {
        let parts = try AuthorityJWS.parse(compact, expectedType: AuthorityGrantClaims.type, allowedAlgorithms: ["ES256"])
        guard let key = keys[parts.kid], JWKThumbprint.p256(key) == parts.kid else { throw AuthorityJOSEError.unknownKey }
        try AuthorityJWS.verifyES256(parts, key: key)
        let o = parts.payload
        guard Set(o.keys) == Set(["iss", "aud", "sub", "tid", "txn", "purpose", "acr", "amr", "auth_time", "iat", "exp", "jti", "cch"]) else {
            throw AuthorityJOSEError.claims("members")
        }
        guard o["iss"]?.stringValue == issuer, let aud = o["aud"]?.stringValue, ConstantTime.equals(aud, audience) else { throw AuthorityJOSEError.claims("audience") }
        guard let cch = o["cch"]?.stringValue, ConstantTime.equals(cch, codeChallenge) else { throw AuthorityJOSEError.claims("cch") }
        guard let sub = o["sub"]?.stringValue, let tid = o["tid"]?.stringValue, let txn = o["txn"]?.stringValue, let purpose = o["purpose"]?.stringValue,
              let acr = o["acr"]?.stringValue, case .array(let amrValues)? = o["amr"], let authTime = o["auth_time"]?.authorityInteger,
              let iat = o["iat"]?.authorityInteger, let exp = o["exp"]?.authorityInteger, exp > iat, exp - iat <= AuthorityGrantClaims.lifetime,
              let jti = o["jti"]?.stringValue, Base64URL.isValid(jti, minLength: 22, maxLength: 22) else { throw AuthorityJOSEError.claims("values") }
        let t = Int64(now.timeIntervalSince1970)
        guard iat <= t + skew else { throw AuthorityJOSEError.notYetValid }
        guard t <= exp + skew else { throw AuthorityJOSEError.expired }
        let amr = amrValues.compactMap(\.stringValue)
        guard amr.count == amrValues.count else { throw AuthorityJOSEError.claims("amr") }
        return AuthorityGrantClaims(issuer: issuer, audience: aud, subject: sub, tenantId: tid, transaction: txn, purpose: purpose, acr: acr, amr: amr,
                                    authTime: authTime, issuedAt: iat, expiresAt: exp, jti: jti, codeChallenge: cch)
    }
}

/// The platform floor compiled into the authority (`AuthorityPolicy.v1`, ADR-0023 §6). Tenants and clients can only **raise** it
/// (`authority_policy_versions`); lowering is an admin-job change. Every grant records `version`.
public struct AuthorityPolicy: Sendable, Hashable {
    public static let v1 = AuthorityPolicy(version: "AuthorityPolicy.v1", requireBiometric: false, requirePasskey: false)

    public var version: String
    /// Raise: only `uv = biometric` satisfies.
    public var requireBiometric: Bool
    /// Raise (`require_acr = urn:viadere:acr:passkey`): app approval can never satisfy it.
    public var requirePasskey: Bool

    public init(version: String, requireBiometric: Bool, requirePasskey: Bool) {
        self.version = version
        self.requireBiometric = requireBiometric
        self.requirePasskey = requirePasskey
    }

    /// Combines the floor with a raise; a raise can never lower anything.
    public func raised(requireBiometric: Bool, requirePasskey: Bool) -> AuthorityPolicy {
        AuthorityPolicy(version: version, requireBiometric: self.requireBiometric || requireBiometric, requirePasskey: self.requirePasskey || requirePasskey)
    }

    public enum Outcome: Sendable, Equatable {
        case allow
        case deny(String)
    }

    /// App-approval evidence (a factor JWS) against this policy. Number matching is part of the challenge and checked before policy.
    public func evaluateAppEvidence(userVerification: FactorUserVerification, decision: FactorDecision) -> Outcome {
        guard decision == .approve else { return .deny("not_approved") }
        if requirePasskey { return .deny("passkey_required") }
        if requireBiometric, userVerification != .biometric { return .deny("biometric_required") }
        return .allow
    }
}
