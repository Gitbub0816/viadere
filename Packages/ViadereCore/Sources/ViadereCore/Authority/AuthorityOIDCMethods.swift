import Foundation

// Stage 6 OIDC methods and consent (ADR-0023 §3a, ADR-0024 §4, §8): the passkey method verified by the authority, consent records kept by the
// authority, the QR universal link of the app path and the `login_hint` push path. The api relays every value here unchanged; it decides nothing.

private struct OIDCMethodStrictKey: CodingKey {
    var stringValue: String
    var intValue: Int? { nil }
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { nil }
}

/// Refuses a JSON object with any member outside `allowed` (closed request bodies, as in `AuthorityWire`).
private func oidcRequireOnly(_ decoder: any Decoder, _ allowed: Set<String>) throws {
    let keys = try decoder.container(keyedBy: OIDCMethodStrictKey.self).allKeys.map(\.stringValue)
    guard Set(keys).isSubset(of: allowed) else { throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "unknown member")) }
}

extension AuthorityRoute {
    /// `POST`: a passkey challenge for an authorization request (the person chose "Use your Viadere passkey").
    public static let oidcPasskeyChallenges = "/v1/oidc/passkey/challenges"
    /// `POST`: a WebAuthn assertion, relayed unchanged; the authority verifies it against its own passkey log.
    public static let oidcPasskeyEvidence = "/v1/oidc/passkey/evidence"
    /// `POST`: the consents of one account (the account id travels in the body, never in a URL or a log line).
    public static let oidcConsents = "/v1/oidc/consents"
    /// `POST` (reduce-only): deletes one consent.
    public static let oidcConsentRevoke = "/v1/oidc/consents/revoke"
}

extension OIDCProfile {
    /// `amr` for a UV passkey assertion (ADR-0024 §5): `user` and `mfa`, plus `hwk` only when the credential is known to be device-bound,
    /// otherwise `swk` (so `hwk` is never implied by omission).
    public static func passkeyAMR(hardwareBound: Bool) -> [String] { [hardwareBound ? "hwk" : "swk", "user", "mfa"] }

    /// WebAuthn origins the authority accepts per purpose (ADR-0023 §3a item 2). `oidc_login` → exactly the issuer origin (`https://id.<domain>`).
    /// Every other purpose has no passkey origin in this stage (an empty list refuses every assertion).
    public static func passkeyOrigins(for purpose: AuthorityPurpose, issuer: String) -> [String] {
        switch purpose {
        case .oidcLogin: [issuer]
        default: []
        }
    }
}

/// `POST /v1/oidc/passkey/challenges`: the authorization request the code will be bound to (the same members and checks as the app path).
public struct AuthorityPasskeyChallengeRequest: Codable, Sendable, Hashable {
    public var oidc: AuthorityChallengeCreateRequest.OIDCAuthorization

    public init(oidc: AuthorityChallengeCreateRequest.OIDCAuthorization) { self.oidc = oidc }

    enum CodingKeys: String, CodingKey { case oidc }

    public init(from decoder: any Decoder) throws {
        try oidcRequireOnly(decoder, ["oidc"])
        oidc = try decoder.container(keyedBy: CodingKeys.self).decode(AuthorityChallengeCreateRequest.OIDCAuthorization.self, forKey: .oidc)
    }
}

/// The WebAuthn request options for the browser. `challenge` is the authority's 256-bit nonce (base64url); there is no `allowCredentials`
/// (discoverable credentials) and user verification is required.
public struct AuthorityPasskeyChallengeResponse: Codable, Sendable, Hashable {
    public var challengeId: String
    public var challenge: String
    public var relyingPartyId: String
    public var timeoutMilliseconds: Int
    public var expiresAt: Int64

    public init(challengeId: String, challenge: String, relyingPartyId: String, timeoutMilliseconds: Int, expiresAt: Int64) {
        self.challengeId = challengeId
        self.challenge = challenge
        self.relyingPartyId = relyingPartyId
        self.timeoutMilliseconds = timeoutMilliseconds
        self.expiresAt = expiresAt
    }

    enum CodingKeys: String, CodingKey {
        case challengeId = "ach", challenge, relyingPartyId = "rp_id", timeoutMilliseconds = "timeout_ms", expiresAt = "expires_at"
    }
}

/// `POST /v1/oidc/passkey/evidence`: the browser's assertion, relayed unchanged.
public struct AuthorityPasskeyEvidenceRequest: Codable, Sendable, Hashable {
    public var challengeId: String
    public var credential: PasskeyAssertionCredential

    public init(challengeId: String, credential: PasskeyAssertionCredential) {
        self.challengeId = challengeId
        self.credential = credential
    }

    enum CodingKeys: String, CodingKey { case challengeId = "ach", credential }

    public init(from decoder: any Decoder) throws {
        try oidcRequireOnly(decoder, ["ach", "credential"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        challengeId = try c.decode(String.self, forKey: .challengeId)
        credential = try c.decode(PasskeyAssertionCredential.self, forKey: .credential)
    }
}

/// One consent as the authority keeps it (ADR-0024 §8): client, reviewed display name and redirect host, granted at, last used.
public struct AuthorityConsent: Codable, Sendable, Hashable {
    public var clientId: String
    public var clientName: String
    public var host: String
    public var grantedAt: Int64
    public var lastUsedAt: Int64

    public init(clientId: String, clientName: String, host: String, grantedAt: Int64, lastUsedAt: Int64) {
        self.clientId = clientId
        self.clientName = clientName
        self.host = host
        self.grantedAt = grantedAt
        self.lastUsedAt = lastUsedAt
    }

    enum CodingKeys: String, CodingKey { case clientId = "client_id", clientName = "client_name", host, grantedAt = "granted_at", lastUsedAt = "last_used_at" }
}

/// `POST /v1/oidc/consents`: the signed-in account named by the api (the device's own account; the authority returns only that account's rows).
public struct AuthorityConsentListRequest: Codable, Sendable, Hashable {
    public var accountId: UUID
    public init(accountId: UUID) { self.accountId = accountId }

    enum CodingKeys: String, CodingKey { case accountId = "account_id" }

    public init(from decoder: any Decoder) throws {
        try oidcRequireOnly(decoder, ["account_id"])
        accountId = try decoder.container(keyedBy: CodingKeys.self).decode(UUID.self, forKey: .accountId)
    }
}

public struct AuthorityConsentListResponse: Codable, Sendable, Hashable {
    public var consents: [AuthorityConsent]
    public init(consents: [AuthorityConsent]) { self.consents = consents }
}

/// `POST /v1/oidc/consents/revoke` (reduce-only): deletes the consent of `accountId` for `clientId`. Revoking a consent that does not exist
/// changes nothing and answers the same.
public struct AuthorityConsentRevokeRequest: Codable, Sendable, Hashable {
    public var accountId: UUID
    public var clientId: String

    public init(accountId: UUID, clientId: String) {
        self.accountId = accountId
        self.clientId = clientId
    }

    enum CodingKeys: String, CodingKey { case accountId = "account_id", clientId = "client_id" }

    public init(from decoder: any Decoder) throws {
        try oidcRequireOnly(decoder, ["account_id", "client_id"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        accountId = try c.decode(UUID.self, forKey: .accountId)
        clientId = try c.decode(String.self, forKey: .clientId)
    }
}

/// OIDC client ids (`ocl_` + 4 to 60 characters of `[A-Za-z0-9_-]`), as the admin job registers them.
public enum OIDCClientID {
    public static func isValid(_ value: String) -> Bool {
        value.hasPrefix("ocl_") && (8...64).contains(value.utf8.count)
            && value.dropFirst(4).unicodeScalars.allSatisfy { $0.isASCII && (CharacterSet.alphanumerics.contains($0) || $0 == "_" || $0 == "-") }
    }
}

// MARK: Device

/// One app the person signed in to with Viadere (UX_COPY OIDC-09).
public struct OIDCConsentView: Codable, Sendable, Hashable, Identifiable {
    public var clientId: String
    /// The reviewed client name from the authority's registration.
    public var clientName: String
    /// The redirect host (the sector), shown next to the name.
    public var host: String
    public var grantedAt: Date
    public var lastUsedAt: Date
    public var id: String { clientId }

    public init(clientId: String, clientName: String, host: String, grantedAt: Date, lastUsedAt: Date) {
        self.clientId = clientId
        self.clientName = clientName
        self.host = host
        self.grantedAt = grantedAt
        self.lastUsedAt = lastUsedAt
    }
}

public struct OIDCConsentListResponse: Codable, Sendable, Hashable {
    public var consents: [OIDCConsentView]
    public init(consents: [OIDCConsentView]) { self.consents = consents }
}

public struct OIDCConsentRevokeResponse: Codable, Sendable, Hashable {
    public var revoked: Bool
    public init(revoked: Bool) { self.revoked = revoked }
}

extension APIRoutes {
    /// "Apps you've signed in to with Viadere" (ADR-0024 §8): the authority's consent records of the signed-in account.
    public static let oidcConsentsList = Endpoint<EmptyBody, OIDCConsentListResponse>(
        "oidc.consents.list", .GET, "/v1/oidc/consents", auth: .deviceSignedBearer)
    /// "Stop {Client} recognizing me": reduce-only; it deletes the consent and nothing else.
    public static let oidcConsentRevoke = Endpoint<EmptyBody, OIDCConsentRevokeResponse>(
        "oidc.consents.revoke", .POST, "/v1/oidc/consents/{clientId}/revoke", auth: .deviceSignedBearer)

    public static let oidcConsentEndpoints: [AnyEndpoint] = [oidcConsentsList.descriptor, oidcConsentRevoke.descriptor]
}

extension APIRoutes.Web {
    /// The QR universal link of the OIDC app path: `/o/{ach}` (ADR-0024 §4 method 2). The system camera opens it in the Viadere app, on its confirm
    /// screen; it never completes anything in a browser.
    public static let oidcChallengePrefix = "/o/"
}

/// `https://{link domain}/o/{ach}`: carries the authority challenge id only (no number, no client, no secret). Possession of the link does not
/// approve anything: the app fetches the authority-signed statement, shows its display and needs the number shown on the authorize page.
public enum OIDCChallengeLink {
    public static func build(challengeId: String, domain: LinkDomain = .current) -> String {
        "\(domain.origin)\(APIRoutes.Web.oidcChallengePrefix)\(challengeId)"
    }

    /// Strict: https, exactly the link domain (no `www.`, no port, no user info), path `/o/{ach}` with a valid challenge id, no query, no fragment.
    public static func parse(_ link: URL, domain: LinkDomain = .current) -> String? {
        guard link.scheme == "https", domain.matches(link.host), link.host == link.host?.lowercased(), link.user == nil, link.password == nil,
              link.port == nil, let components = URLComponents(url: link, resolvingAgainstBaseURL: false), components.query == nil,
              components.fragment == nil else { return nil }
        let parts = components.percentEncodedPath.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3, parts[0].isEmpty, parts[1] == "o", AuthorityChallengeID.isValid(parts[2]) else { return nil }
        return parts[2]
    }
}

/// What a `login_hint` push may contain (ADR-0024 §4 method 2, ADR-0022 §5.5): a generic alert, category `viadere.oidc`, interruption level
/// `active`, and one custom key `ach` (the authority challenge id). No client name, host or number.
public enum OIDCPushPayloadPolicy {
    public static let category = "viadere.oidc"
    public static let interruptionLevel = "active"
    public static let challengeKey = "ach"
    public static let customKeys: Set<String> = [challengeKey]

    public static func isAllowed(_ payload: [String: Any]) -> Bool {
        guard Set(payload.keys) == customKeys.union(["aps"]), let aps = payload["aps"] as? [String: Any],
              Set(aps.keys).isSubset(of: ["alert", "category", "thread-id", "interruption-level", "mutable-content"]),
              let alert = aps["alert"] as? [String: Any], Set(alert.keys).isSubset(of: ["title", "body"]),
              aps["category"] as? String == category, aps["interruption-level"] as? String == interruptionLevel,
              let ach = payload[challengeKey] as? String, AuthorityChallengeID.isValid(ach) else { return false }
        return true
    }
}
